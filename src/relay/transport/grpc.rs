//! Shared gun-lite gRPC framing helpers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use h2::client::SendRequest;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::buf as buf_pool;

/// A cached HTTP/2 `SendRequest` for a given TLS endpoint.
struct PooledConn {
    send_request: SendRequest<Bytes>,
}

pub struct GrpcPool {
    conns: DashMap<String, Arc<Mutex<Option<PooledConn>>>>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl GrpcPool {
    pub fn new() -> Result<Self> {
        let tls_config = build_tls_config()?;
        Ok(Self {
            conns: DashMap::new(),
            tls_config: Arc::new(tls_config),
        })
    }

    fn pool_key(addr: &str, tls_sni: &str) -> String {
        format!("{}:{}", tls_sni, addr)
    }

    /// Get a cloned `SendRequest` for the given endpoint, creating a new
    /// TLS+H2 connection if the pool entry is absent or the connection is gone.
    pub async fn get_or_create(&self, addr: &str, tls_sni: &str) -> Result<SendRequest<Bytes>> {
        let key = Self::pool_key(addr, tls_sni);
        let slot = self
            .conns
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();

        let mut guard = slot.lock().await;

        if let Some(conn) = &*guard {
            tracing::debug!("reusing cached H2 connection for {}", key);
            return Ok(conn.send_request.clone());
        }

        let send_request = connect_h2(addr, tls_sni, self.tls_config.clone()).await?;
        *guard = Some(PooledConn {
            send_request: send_request.clone(),
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
}

async fn connect_h2(
    addr: &str,
    tls_sni: &str,
    tls_config: Arc<rustls::ClientConfig>,
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
    let mut read_buf = buf_pool::get(RAW_TO_GRPC_READ_BUF_SIZE);
    read_buf.resize(RAW_TO_GRPC_READ_BUF_SIZE, 0);

    let result = async {
        loop {
            let n = reader.read(&mut read_buf[..]).await?;
            if n == 0 {
                break;
            }
            let frame = encode_grpc_frame(&read_buf[..n]);
            send_grpc_data(&mut send_stream, frame, false).await?;
        }
        let _ = send_grpc_data(&mut send_stream, Bytes::new(), true).await;
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
            .map_err(|e| anyhow!("send grpc data: {}", e))?;
        return Ok(());
    }

    while !data.is_empty() {
        send_stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send_stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("gRPC send stream closed"))?
            .map_err(|e| anyhow!("poll grpc send capacity: {}", e))?;
        if capacity == 0 {
            continue;
        }

        let n = capacity.min(data.len());
        let chunk = data.split_to(n);
        let is_end = end_of_stream && data.is_empty();
        send_stream
            .send_data(chunk, is_end)
            .map_err(|e| anyhow!("send grpc data: {}", e))?;
    }

    Ok(())
}

/// Read gRPC frames from `recv_stream`, decode gun-lite protobuf payload, write raw data to `writer`.
pub(crate) async fn grpc_to_raw(
    mut recv_stream: h2::RecvStream,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut buf = buf_pool::get(GRPC_TO_RAW_INIT_BUF_SIZE);

    let result = async {
        loop {
            loop {
                if buf.len() < 5 {
                    break;
                }
                let outer_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
                if outer_len > MAX_GRPC_FRAME_SIZE {
                    return Err(anyhow!("gRPC frame too large: {} bytes", outer_len));
                }
                if buf.len() < 5 + outer_len {
                    break;
                }
                let proto = &buf[5..5 + outer_len];
                if let Some(data) = decode_gun_payload(proto) {
                    if !data.is_empty() {
                        writer.write_all(data).await?;
                    }
                }
                buf.advance(5 + outer_len);
                if buf.is_empty() {
                    buf.clear();
                }
            }

            match recv_stream.data().await {
                Some(Ok(chunk)) => {
                    let _ = recv_stream.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(anyhow!("recv grpc data: {}", e)),
                None => break,
            }
        }

        writer.flush().await?;
        Ok(())
    }
    .await;

    buf_pool::put(buf);
    result
}
