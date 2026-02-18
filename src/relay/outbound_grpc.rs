/// gRPC (VMess+TLS+gRPC) outbound relay.
///
/// Maintains a connection pool keyed by `"<tls_sni>:<host>:<port>"`.
/// Each relay creates a new gRPC stream (HTTP/2 stream) on the pooled connection.
///
/// gRPC framing: [1-byte flags=0][4-byte big-endian data_len][data]
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use h2::client::SendRequest;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::vmess::validator::Upstream;

// ──────────────────────────────────────────────────────────────────────────────
// Connection pool
// ──────────────────────────────────────────────────────────────────────────────

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
    pub async fn get_or_create(
        &self,
        addr: &str,
        tls_sni: &str,
    ) -> Result<SendRequest<Bytes>> {
        let key = Self::pool_key(addr, tls_sni);
        let slot = self
            .conns
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();

        let mut guard = slot.lock().await;

        // Try to reuse existing connection
        if let Some(conn) = &mut *guard {
            // Clone the SendRequest; if the connection is still alive it will work
            let sr = conn.send_request.clone();
            // A quick readiness check — if it's ready we reuse
            let mut probe = sr.clone();
            let ready = std::future::poll_fn(|cx| probe.poll_ready(cx)).await;
            if ready.is_ok() {
                return Ok(sr);
            }
            // Connection dead — fall through to reconnect
            *guard = None;
        }

        // Establish a new TLS+H2 connection
        let send_request = connect_h2(addr, tls_sni, self.tls_config.clone()).await?;
        *guard = Some(PooledConn { send_request: send_request.clone() });
        Ok(send_request)
    }

    /// Remove a dead connection from the pool.
    pub fn evict(&self, addr: &str, tls_sni: &str) {
        let key = Self::pool_key(addr, tls_sni);
        if let Some(slot) = self.conns.get(&key) {
            // Best-effort: clear the slot (non-blocking via try_lock)
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
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    let connector = TlsConnector::from(tls_config);
    let domain = ServerName::try_from(tls_sni.to_owned())
        .map_err(|_| anyhow!("invalid TLS SNI: {}", tls_sni))?;
    let tls = connector.connect(domain, tcp).await?;

    let (send_request, connection) = h2::client::handshake(tls).await?;

    // Drive the connection in the background
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
        tracing::warn!("some native certs failed to load: {} error(s)", cert_result.errors.len());
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ALPN for HTTP/2
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

// ──────────────────────────────────────────────────────────────────────────────
// gRPC frame helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Encode raw bytes as a single gRPC data frame: [0x00][len:4BE][data]
fn encode_grpc_frame(data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + data.len());
    buf.put_u8(0); // compressed-flag = 0
    buf.put_u32(data.len() as u32);
    buf.put_slice(data);
    buf.freeze()
}

// ──────────────────────────────────────────────────────────────────────────────
// Relay entry point
// ──────────────────────────────────────────────────────────────────────────────

pub async fn relay_grpc(
    inbound: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    upstream: Arc<Upstream>,
    pool: Arc<GrpcPool>,
    initial_data: Bytes,
) -> Result<()> {
    use crate::vmess::validator::Transport;

    let (service_name, tls_sni) = match &upstream.transport {
        Transport::Grpc { service_name, tls_sni } => (service_name.clone(), tls_sni.clone()),
        _ => return Err(anyhow!("relay_grpc called on non-gRPC upstream")),
    };

    let mut send_request = pool.get_or_create(&upstream.addr, &tls_sni).await?;

    // Build gRPC/HTTP2 request
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("/{}/Tun", service_name))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header(":authority", &upstream.addr)
        .body(())
        .map_err(|e| anyhow!("build request: {}", e))?;

    let (response_future, mut send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| anyhow!("send_request: {}", e))?;

    // Write the initial buffered data (auth ID) as first gRPC frame
    if !initial_data.is_empty() {
        let frame = encode_grpc_frame(&initial_data);
        send_stream
            .send_data(frame, false)
            .map_err(|e| anyhow!("send initial grpc frame: {}", e))?;
    }

    // Await server response headers
    let response = response_future.await.map_err(|e| anyhow!("response headers: {}", e))?;
    let recv_stream = response.into_body();

    // Split inbound for bidirectional relay
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound);

    // Task 1: inbound → gRPC frames → upstream send_stream
    let upstream_addr = upstream.addr.clone();
    let tls_sni2 = tls_sni.clone();
    let pool2 = pool.clone();
    let t1 = tokio::spawn(async move {
        let result = raw_to_grpc(inbound_reader, send_stream).await;
        if result.is_err() {
            pool2.evict(&upstream_addr, &tls_sni2);
        }
        result
    });

    // Task 2: upstream recv_stream → raw bytes → inbound writer
    let t2 = tokio::spawn(async move { grpc_to_raw(recv_stream, inbound_writer).await });

    // Wait for both directions; ignore benign EOF errors
    let (r1, r2) = tokio::join!(t1, t2);
    let _ = r1.map_err(|e| tracing::debug!("grpc relay t1 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc relay t1: {}", e)));
    let _ = r2.map_err(|e| tracing::debug!("grpc relay t2 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc relay t2: {}", e)));

    Ok(())
}

/// Read raw bytes from `reader`, wrap in gRPC frames, send to `send_stream`.
async fn raw_to_grpc(
    mut reader: impl AsyncRead + Unpin,
    mut send_stream: h2::SendStream<Bytes>,
) -> Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let frame = encode_grpc_frame(&buf[..n]);
        send_stream
            .send_data(frame, false)
            .map_err(|e| anyhow!("send grpc data: {}", e))?;
    }
    // Signal end-of-stream
    let _ = send_stream.send_data(Bytes::new(), true);
    Ok(())
}

/// Read gRPC frames from `recv_stream`, strip the 5-byte header, write raw data to `writer`.
async fn grpc_to_raw(
    mut recv_stream: h2::RecvStream,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut buf = BytesMut::new();

    loop {
        // Process any complete gRPC frames in the buffer
        loop {
            if buf.len() < 5 {
                break;
            }
            let data_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() < 5 + data_len {
                break;
            }
            // Write the payload (skip 5-byte header)
            writer.write_all(&buf[5..5 + data_len]).await?;
            buf.advance(5 + data_len);
        }

        // Read the next HTTP/2 DATA frame
        match recv_stream.data().await {
            Some(Ok(chunk)) => {
                // Release flow-control window
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

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_grpc_frame_empty() {
        let frame = encode_grpc_frame(&[]);
        assert_eq!(frame.len(), 5);
        assert_eq!(frame[0], 0); // flags
        assert_eq!(&frame[1..5], &[0u8; 4]); // length = 0
    }

    #[test]
    fn test_encode_grpc_frame_data() {
        let data = b"hello world";
        let frame = encode_grpc_frame(data);
        assert_eq!(frame.len(), 5 + data.len());
        assert_eq!(frame[0], 0);
        let len = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(len as usize, data.len());
        assert_eq!(&frame[5..], data);
    }

    #[test]
    fn test_encode_grpc_frame_large() {
        let data = vec![0xABu8; 65536];
        let frame = encode_grpc_frame(&data);
        assert_eq!(frame.len(), 5 + 65536);
        let len = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(len, 65536);
    }

    #[test]
    fn test_encode_grpc_frame_boundary_sizes() {
        // Test various boundary sizes for the 5-byte header
        for size in [0usize, 1, 4, 5, 255, 256, 1000] {
            let data = vec![0u8; size];
            let frame = encode_grpc_frame(&data);
            assert_eq!(frame.len(), 5 + size);
            let decoded_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
            assert_eq!(decoded_len, size);
        }
    }

    #[tokio::test]
    async fn test_grpc_frame_decode_from_buffer() {
        // Simulate decoding gRPC frames from a pre-filled buffer
        let payload1 = b"first message";
        let payload2 = b"second message";

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&encode_grpc_frame(payload1));
        combined.extend_from_slice(&encode_grpc_frame(payload2));

        let mut out = Vec::new();
        let mut buf = combined;

        // Parse frames
        loop {
            if buf.len() < 5 {
                break;
            }
            let data_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() < 5 + data_len {
                break;
            }
            out.extend_from_slice(&buf[5..5 + data_len]);
            buf.advance(5 + data_len);
        }

        assert_eq!(out, b"first messagesecond message");
    }

    #[tokio::test]
    async fn test_grpc_frame_decode_fragmented() {
        // Test that partial frames are handled correctly
        let payload = b"full message here";
        let frame = encode_grpc_frame(payload);

        let mut buf = BytesMut::new();
        let mut out = Vec::new();

        // Feed frame in two parts — simulate network fragmentation
        buf.extend_from_slice(&frame[..3]); // only 3 bytes: not enough for header

        // Can't decode yet
        if buf.len() < 5 {
            // correct — do nothing
        }

        buf.extend_from_slice(&frame[3..]); // rest of frame

        // Now decode
        if buf.len() >= 5 {
            let data_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() >= 5 + data_len {
                out.extend_from_slice(&buf[5..5 + data_len]);
            }
        }

        assert_eq!(out, payload);
    }
}
