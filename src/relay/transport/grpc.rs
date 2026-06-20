//! Shared gun-lite gRPC framing helpers.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use h2::client::SendRequest;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::buf as buf_pool;
use crate::relay::activity::RelayActivity;

/// A cached HTTP/2 `SendRequest` for a given TLS endpoint.
struct PooledConn {
    id: u64,
    send_request: SendRequest<Bytes>,
    last_used: Instant,
}

pub struct GrpcPool {
    conns: DashMap<String, Arc<Mutex<Option<PooledConn>>>>,
    tls_config: Arc<rustls::ClientConfig>,
    next_conn_id: AtomicU64,
}

const IDLE_CONN_TTL: Duration = Duration::from_secs(300);

impl GrpcPool {
    pub fn new() -> Result<Self> {
        let tls_config = build_tls_config()?;
        Ok(Self {
            conns: DashMap::new(),
            tls_config: Arc::new(tls_config),
            next_conn_id: AtomicU64::new(1),
        })
    }

    fn pool_key(addr: &str, tls_sni: &str) -> String {
        format!("{}:{}", tls_sni, addr)
    }

    /// Get a cloned `SendRequest` for the given endpoint, creating a new
    /// TLS+H2 connection if the pool entry is absent or the connection is gone.
    ///
    /// The slot mutex is intentionally held while a new connection is being
    /// established so bursts to the same endpoint share a single handshake
    /// instead of racing multiple TLS/H2 connections.
    pub async fn get_or_create(&self, addr: &str, tls_sni: &str) -> Result<SendRequest<Bytes>> {
        let key = Self::pool_key(addr, tls_sni);
        let slot = self
            .conns
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();

        let mut guard = slot.lock().await;
        if let Some(conn) = guard.as_mut() {
            tracing::debug!("reusing cached H2 connection for {}", key);
            conn.last_used = Instant::now();
            return Ok(conn.send_request.clone());
        }

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let send_request = connect_h2(
            addr,
            tls_sni,
            self.tls_config.clone(),
            key.clone(),
            slot.clone(),
            conn_id,
        )
        .await?;
        *guard = Some(PooledConn {
            id: conn_id,
            send_request: send_request.clone(),
            last_used: Instant::now(),
        });

        Ok(send_request)
    }

    /// Remove a dead connection from the pool.
    pub fn evict(&self, addr: &str, tls_sni: &str) {
        let key = Self::pool_key(addr, tls_sni);
        if let Some(slot) = self.conns.get(&key) {
            if let Ok(mut g) = slot.try_lock() {
                *g = None;
            }
        }
    }

    /// Drop cached connections that are no longer present in the active routing table.
    pub async fn prune_to_endpoints(&self, active: &HashSet<(String, String)>) {
        let active_keys: HashSet<String> = active
            .iter()
            .map(|(addr, tls_sni)| Self::pool_key(addr, tls_sni))
            .collect();
        let stale: Vec<_> = self
            .conns
            .iter()
            .filter(|entry| !active_keys.contains(entry.key()))
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        let mut removed = 0usize;

        if tracing::enabled!(tracing::Level::DEBUG) {
            let (pool_slots, cached_conns) = self.pool_counts().await;
            tracing::debug!(
                active_endpoint_count = active_keys.len(),
                pool_slots,
                cached_conns,
                stale_slot_count = stale.len(),
                "pruning gRPC pool to active endpoints"
            );
        }

        for (key, slot) in stale {
            let strong_count_before_remove = Arc::strong_count(&slot);
            if self.conns.remove(&key).is_some() {
                let strong_count_after_remove = Arc::strong_count(&slot);
                let mut guard = slot.lock().await;
                *guard = None;
                tracing::debug!(
                    key,
                    strong_count_before_remove,
                    strong_count_after_remove,
                    "cleared stale cached H2 connection slot"
                );
                removed += 1;
            }
        }

        if removed > 0 {
            tracing::info!("pruned {} stale gRPC pool connection(s)", removed);
        }

        if tracing::enabled!(tracing::Level::DEBUG) {
            let (pool_slots, cached_conns) = self.pool_counts().await;
            tracing::debug!(
                pool_slots,
                cached_conns,
                "finished pruning gRPC pool to active endpoints"
            );
        }
    }

    /// Drop cached connections that have not been used recently.
    pub async fn prune_idle(&self) {
        self.prune_idle_older_than(IDLE_CONN_TTL).await;
    }

    async fn prune_idle_older_than(&self, max_idle: Duration) {
        let now = Instant::now();
        let slots: Vec<_> = self
            .conns
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        let mut removed = 0usize;

        if tracing::enabled!(tracing::Level::DEBUG) {
            let cached_conns = self.count_cached_conns(&slots).await;
            tracing::debug!(
                pool_slots = slots.len(),
                cached_conns,
                max_idle_secs = max_idle.as_secs(),
                "scanning idle gRPC pool connections"
            );
        }

        for (key, slot) in slots {
            let mut guard = slot.lock().await;
            let idle = guard
                .as_ref()
                .is_some_and(|conn| now.duration_since(conn.last_used) >= max_idle);
            if idle {
                let strong_count = Arc::strong_count(&slot);
                tracing::debug!(key, strong_count, "closing idle cached H2 connection slot");
                *guard = None;
                removed += 1;
            }
        }

        if removed > 0 {
            tracing::info!("closed {} idle gRPC pool connection(s)", removed);
        }
    }

    async fn pool_counts(&self) -> (usize, usize) {
        let slots: Vec<_> = self
            .conns
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        let cached_conns = self.count_cached_conns(&slots).await;
        (slots.len(), cached_conns)
    }

    async fn count_cached_conns(
        &self,
        slots: &[(String, Arc<Mutex<Option<PooledConn>>>)],
    ) -> usize {
        let mut cached_conns = 0usize;
        for (_, slot) in slots {
            if slot.lock().await.is_some() {
                cached_conns += 1;
            }
        }
        cached_conns
    }
}

async fn connect_h2(
    addr: &str,
    tls_sni: &str,
    tls_config: Arc<rustls::ClientConfig>,
    key: String,
    slot: Arc<Mutex<Option<PooledConn>>>,
    conn_id: u64,
) -> Result<SendRequest<Bytes>> {
    tracing::debug!(
        "establishing new H2/TLS connection -> {} (sni={})",
        addr,
        tls_sni
    );
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("connect timeout: {}", addr))??;
    tcp.set_nodelay(true)?;

    let connector = TlsConnector::from(tls_config);
    let domain = ServerName::try_from(tls_sni.to_owned())
        .map_err(|_| anyhow!("invalid TLS SNI: {}", tls_sni))?;
    let tls = timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(domain, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake timeout: {} (sni={})", addr, tls_sni))??;

    let (send_request, connection) = timeout(H2_HANDSHAKE_TIMEOUT, h2::client::handshake(tls))
        .await
        .map_err(|_| anyhow!("H2 handshake timeout: {} (sni={})", addr, tls_sni))??;
    tracing::debug!("H2 connection established -> {} (sni={})", addr, tls_sni);

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("gRPC H2 connection closed: {}", e);
        }
        let strong_count = Arc::strong_count(&slot);
        let mut guard = slot.lock().await;
        if guard.as_ref().is_some_and(|conn| conn.id == conn_id) {
            *guard = None;
            tracing::debug!(
                key,
                conn_id,
                strong_count,
                "cleared closed cached H2 connection slot"
            );
        }
    });

    Ok(send_request)
}

fn build_tls_config() -> Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        let _ = root_store.add(cert);
    }
    if !cert_result.errors.is_empty() {
        tracing::warn!(
            "some native certs failed to load: {} error(s)",
            cert_result.errors.len()
        );
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

struct PooledFrameOwner {
    buf: Option<BytesMut>,
}

impl AsRef<[u8]> for PooledFrameOwner {
    fn as_ref(&self) -> &[u8] {
        self.buf
            .as_ref()
            .expect("pooled frame owner must hold a buffer")
            .as_ref()
    }
}

impl Drop for PooledFrameOwner {
    fn drop(&mut self) {
        if let Some(mut buf) = self.buf.take() {
            buf.clear();
            buf_pool::put(buf);
        }
    }
}

/// Number of bytes required to encode `v` as a protobuf varint.
pub(crate) fn varint_size(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Write `v` as a protobuf varint into `buf`.
pub(crate) fn write_varint(buf: &mut BytesMut, mut v: u64) {
    loop {
        if v < 0x80 {
            buf.put_u8(v as u8);
            break;
        }
        buf.put_u8((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
}

/// Read a protobuf varint from `bytes`. Returns `(value, bytes_consumed)`.
pub(crate) fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b < 0x80 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Encode raw bytes as a gun-lite gRPC frame.
///
/// Format: `[0x00][outer_len:4BE][0x0A][varint(inner_len)][data]`
/// where `outer_len = 1 + varint_size(data.len()) + data.len()`
pub(crate) fn encode_grpc_frame(data: &[u8]) -> Bytes {
    let inner_len = data.len() as u64;
    let var_size = varint_size(inner_len);
    let outer_len = 1 + var_size + data.len();
    let mut buf = buf_pool::get(5 + outer_len);
    buf.put_u8(0);
    buf.put_u32(outer_len as u32);
    buf.put_u8(0x0A);
    write_varint(&mut buf, inner_len);
    buf.put_slice(data);
    Bytes::from_owner(PooledFrameOwner { buf: Some(buf) })
}

/// Decode a gun-lite protobuf payload: `0x0A` + `varint(len)` + `data`.
pub(crate) fn decode_gun_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.is_empty() {
        return Some(&[]);
    }
    if payload[0] != 0x0A {
        return None;
    }
    let (inner_len, varint_len) = read_varint(&payload[1..])?;
    let inner_len = inner_len as usize;
    let data_start = 1 + varint_len;
    if payload.len() < data_start + inner_len {
        return None;
    }
    Some(&payload[data_start..data_start + inner_len])
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RAW_TO_GRPC_READ_BUF_SIZE: usize = 16 * 1024;
const GRPC_TO_RAW_INIT_BUF_SIZE: usize = 16 * 1024;
const MAX_GRPC_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Read raw bytes from `reader`, wrap in gRPC frames, send to `send_stream`.
pub(crate) async fn raw_to_grpc(
    mut reader: impl AsyncRead + Unpin,
    mut send_stream: h2::SendStream<Bytes>,
) -> Result<()> {
    raw_to_grpc_with_activity(&mut reader, &mut send_stream, None).await
}

pub(crate) async fn raw_to_grpc_with_activity(
    reader: &mut (impl AsyncRead + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    activity: Option<RelayActivity>,
) -> Result<()> {
    use bytes::BufMut;

    let mut read_buf = buf_pool::get(RAW_TO_GRPC_READ_BUF_SIZE);

    let result = async {
        loop {
            // `read_buf` writes through `BufMut` into spare capacity, so the
            // pooled buffer doesn't need to be zero-initialized first.
            let mut limited = (&mut read_buf).limit(RAW_TO_GRPC_READ_BUF_SIZE);
            let n = reader.read_buf(&mut limited).await?;
            if n == 0 {
                break;
            }
            if let Some(activity) = &activity {
                activity.mark();
            }
            let frame = encode_grpc_frame(&read_buf[..n]);
            send_grpc_data(send_stream, frame, false).await?;
            if let Some(activity) = &activity {
                activity.mark();
            }
            read_buf.clear();
        }
        let _ = send_grpc_data(send_stream, Bytes::new(), true).await;
        Ok(())
    }
    .await;

    buf_pool::put(read_buf);
    result
}

/// Send a DATA frame while respecting HTTP/2 flow-control capacity.
pub(crate) async fn send_grpc_data(
    send_stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_of_stream: bool,
) -> Result<()> {
    if data.is_empty() {
        send_stream
            .send_data(data, end_of_stream)
            .context("send grpc data")?;
        return Ok(());
    }

    while !data.is_empty() {
        send_stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("gRPC send stream closed"))?
            .context("poll grpc send capacity")?;
        if capacity == 0 {
            continue;
        }

        let n = capacity.min(data.len());
        let chunk = data.split_to(n);
        let is_end = end_of_stream && data.is_empty();
        send_stream
            .send_data(chunk, is_end)
            .context("send grpc data")?;
    }

    Ok(())
}

pub(crate) struct GrpcFrameReader {
    recv_stream: h2::RecvStream,
    buf: BytesMut,
}

impl GrpcFrameReader {
    pub(crate) fn new(recv_stream: h2::RecvStream) -> Self {
        Self {
            recv_stream,
            buf: buf_pool::get(GRPC_TO_RAW_INIT_BUF_SIZE),
        }
    }

    pub(crate) async fn next_frame(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.buf.len() >= 5 {
                let outer_len = u32::from_be_bytes(self.buf[1..5].try_into().unwrap()) as usize;
                if outer_len > MAX_GRPC_FRAME_SIZE {
                    return Err(anyhow!("gRPC frame too large: {} bytes", outer_len));
                }
                if self.buf.len() >= 5 + outer_len {
                    return Ok(Some(self.buf.split_to(5 + outer_len).freeze()));
                }
            }

            match self.recv_stream.data().await {
                Some(Ok(chunk)) => {
                    let _ = self
                        .recv_stream
                        .flow_control()
                        .release_capacity(chunk.len());
                    self.buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(e).context("recv grpc data"),
                None => return Ok(None),
            }
        }
    }
}

impl Drop for GrpcFrameReader {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        buf_pool::put(buf);
    }
}

pub(crate) fn decode_grpc_frame_data(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 5 {
        return None;
    }
    let outer_len = u32::from_be_bytes(frame[1..5].try_into().ok()?) as usize;
    if outer_len > MAX_GRPC_FRAME_SIZE || frame.len() < 5 + outer_len {
        return None;
    }
    decode_gun_payload(&frame[5..5 + outer_len])
}

/// Read gRPC frames from `recv_stream`, decode gun-lite protobuf payload, write raw data to `writer`.
#[cfg(test)]
pub(crate) async fn grpc_to_raw(
    recv_stream: h2::RecvStream,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    grpc_to_raw_with_activity(recv_stream, &mut writer, None).await
}

pub(crate) async fn grpc_to_raw_with_activity(
    recv_stream: h2::RecvStream,
    writer: &mut (impl AsyncWrite + Unpin),
    activity: Option<RelayActivity>,
) -> Result<()> {
    let mut reader = GrpcFrameReader::new(recv_stream);

    while let Some(frame) = reader.next_frame().await? {
        if let Some(data) = decode_grpc_frame_data(&frame) {
            if !data.is_empty() {
                if let Some(activity) = &activity {
                    activity.mark();
                }
                writer.write_all(data).await?;
                if let Some(activity) = &activity {
                    activity.mark();
                }
            }
        }
    }

    writer.flush().await?;
    writer.shutdown().await?;
    Ok(())
}

pub(crate) async fn grpc_frames_to_grpc(
    mut reader: GrpcFrameReader,
    mut send_stream: h2::SendStream<Bytes>,
) -> Result<()> {
    while let Some(frame) = reader.next_frame().await? {
        send_grpc_data(&mut send_stream, frame, false).await?;
    }
    let _ = send_grpc_data(&mut send_stream, Bytes::new(), true).await;
    Ok(())
}

pub(crate) fn is_h2_connection_error(error: &h2::Error) -> bool {
    error.is_io() || error.is_go_away()
}

pub(crate) fn is_grpc_connection_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<h2::Error>()
            .is_some_and(is_h2_connection_error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_grpc_frame_roundtrips_through_decoder() {
        for data in [&b""[..], b"hello", &[0xAB; 256][..]] {
            let frame = encode_grpc_frame(data);
            assert_eq!(decode_grpc_frame_data(&frame), Some(data));
        }
    }

    #[test]
    fn decode_grpc_frame_data_rejects_malformed_frames() {
        assert_eq!(decode_grpc_frame_data(&[0, 0, 0, 0]), None);

        let mut truncated = encode_grpc_frame(b"hello").to_vec();
        truncated.pop();
        assert_eq!(decode_grpc_frame_data(&truncated), None);

        let mut wrong_tag = encode_grpc_frame(b"hello").to_vec();
        wrong_tag[5] = 0x0B;
        assert_eq!(decode_grpc_frame_data(&wrong_tag), None);

        let mut too_large = vec![0; 5];
        too_large[1..5].copy_from_slice(&((MAX_GRPC_FRAME_SIZE as u32) + 1).to_be_bytes());
        assert_eq!(decode_grpc_frame_data(&too_large), None);
    }

    #[test]
    fn grpc_stream_cancel_does_not_evict_connection() {
        let h2_error = h2::Error::from(h2::Reason::CANCEL);
        assert!(!is_h2_connection_error(&h2_error));

        let wrapped = Err::<(), _>(h2_error)
            .context("send grpc data")
            .unwrap_err();
        assert!(!is_grpc_connection_error(&wrapped));
    }

    #[test]
    fn pool_key_is_stable_and_endpoint_specific() {
        assert_eq!(
            GrpcPool::pool_key("example.com:443", "example.com"),
            GrpcPool::pool_key("example.com:443", "example.com")
        );
        assert_ne!(
            GrpcPool::pool_key("example.com:443", "example.com"),
            GrpcPool::pool_key("example.com:443", "alt.example.com")
        );
        assert_ne!(
            GrpcPool::pool_key("example.com:443", "example.com"),
            GrpcPool::pool_key("example.com:8443", "example.com")
        );
    }

    #[tokio::test]
    async fn prune_to_endpoints_drops_stale_pool_entries_and_closes_slot() {
        let pool = GrpcPool::new().unwrap();
        let (stale_send_request, _) = h2::client::handshake(tokio::io::duplex(1024).0)
            .await
            .unwrap();
        let stale_slot = Arc::new(Mutex::new(Some(PooledConn {
            id: 1,
            send_request: stale_send_request,
            last_used: Instant::now(),
        })));
        let stale_weak = Arc::downgrade(&stale_slot);
        pool.conns.insert(
            GrpcPool::pool_key("one.example.com:443", "one.example.com"),
            Arc::new(Mutex::new(None)),
        );
        pool.conns.insert(
            GrpcPool::pool_key("old.example.com:443", "old.example.com"),
            stale_slot.clone(),
        );

        let active = HashSet::from([(
            "one.example.com:443".to_string(),
            "one.example.com".to_string(),
        )]);
        pool.prune_to_endpoints(&active).await;

        assert_eq!(pool.conns.len(), 1);
        assert!(pool.conns.contains_key(&GrpcPool::pool_key(
            "one.example.com:443",
            "one.example.com"
        )));
        assert!(stale_slot.try_lock().unwrap().is_none());
        drop(stale_slot);
        assert!(stale_weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn prune_idle_clears_only_expired_cached_connections() {
        let pool = GrpcPool::new().unwrap();
        let (fresh_send_request, _) = h2::client::handshake(tokio::io::duplex(1024).0)
            .await
            .unwrap();
        let (stale_send_request, _) = h2::client::handshake(tokio::io::duplex(1024).0)
            .await
            .unwrap();

        let fresh_key = GrpcPool::pool_key("fresh.example.com:443", "fresh.example.com");
        let stale_key = GrpcPool::pool_key("stale.example.com:443", "stale.example.com");
        pool.conns.insert(
            fresh_key.clone(),
            Arc::new(Mutex::new(Some(PooledConn {
                id: 1,
                send_request: fresh_send_request,
                last_used: Instant::now(),
            }))),
        );
        pool.conns.insert(
            stale_key.clone(),
            Arc::new(Mutex::new(Some(PooledConn {
                id: 2,
                send_request: stale_send_request,
                last_used: Instant::now() - Duration::from_secs(10),
            }))),
        );

        pool.prune_idle_older_than(Duration::from_secs(5)).await;

        assert!(pool
            .conns
            .get(&fresh_key)
            .unwrap()
            .try_lock()
            .unwrap()
            .is_some());
        assert!(pool
            .conns
            .get(&stale_key)
            .unwrap()
            .try_lock()
            .unwrap()
            .is_none());
    }
}
