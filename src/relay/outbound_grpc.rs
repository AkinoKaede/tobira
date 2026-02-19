/// gRPC (VMess+TLS+gRPC) outbound relay.
///
/// Maintains a connection pool keyed by `"<tls_sni>:<host>:<port>"`.
/// Each relay creates a new gRPC stream (HTTP/2 stream) on the pooled connection.
///
/// Protocol: gun-lite gRPC framing
///   gRPC outer frame: [0x00][outer_len:4BE][protobuf_payload]
///   protobuf_payload: [0x0A][varint(inner_len)][raw_data]
///   (protobuf message Hunk { bytes data = 1; })
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
// Protobuf varint helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Number of bytes required to encode `v` as a protobuf varint.
fn varint_size(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Write `v` as a protobuf varint into `buf`.
fn write_varint(buf: &mut BytesMut, mut v: u64) {
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
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
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
    None // truncated varint
}

// ──────────────────────────────────────────────────────────────────────────────
// gun-lite gRPC frame helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Encode raw bytes as a gun-lite gRPC frame.
///
/// Format: `[0x00][outer_len:4BE][0x0A][varint(inner_len)][data]`
/// where `outer_len = 1 + varint_size(data.len()) + data.len()`
fn encode_grpc_frame(data: &[u8]) -> Bytes {
    let inner_len = data.len() as u64;
    let var_size = varint_size(inner_len);
    let outer_len = 1 + var_size + data.len();
    let mut buf = BytesMut::with_capacity(5 + outer_len);
    buf.put_u8(0);                      // gRPC compressed flag = 0
    buf.put_u32(outer_len as u32);      // gRPC message length
    buf.put_u8(0x0A);                   // protobuf field 1, wire type 2
    write_varint(&mut buf, inner_len);  // protobuf inner length
    buf.put_slice(data);                // raw tunnel data
    buf.freeze()
}

/// Decode a gun-lite protobuf payload: `0x0A` + `varint(len)` + `data`.
/// Returns a slice of the raw tunnel data, or `None` on malformed input.
fn decode_gun_payload(payload: &[u8]) -> Option<&[u8]> {
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

    // Build :authority from SNI + port (SNI may differ from the raw IP addr)
    let port = upstream.addr.rsplit(':').next().unwrap_or("443");
    let authority = format!("{}:{}", tls_sni, port);

    // Build gRPC/HTTP2 request
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("/{}/Tun", service_name))
        .header("content-type", "application/grpc")
        .header("user-agent", "grpc-go/1.48.0")
        .header("te", "trailers")
        .header(":authority", &authority)
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

/// Read gRPC frames from `recv_stream`, decode gun-lite protobuf payload, write raw data to `writer`.
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
            let outer_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() < 5 + outer_len {
                break;
            }
            // Decode gun-lite protobuf payload: 0x0A + varint(inner_len) + data
            let proto = &buf[5..5 + outer_len];
            let write_range = if !proto.is_empty() && proto[0] == 0x0A {
                read_varint(&proto[1..]).and_then(|(inner_len, varint_len)| {
                    let data_start = 5 + 1 + varint_len;
                    let data_end = data_start + inner_len as usize;
                    if data_end <= 5 + outer_len { Some(data_start..data_end) } else { None }
                })
            } else {
                None
            };
            if let Some(range) = write_range {
                if !range.is_empty() {
                    writer.write_all(&buf[range]).await?;
                }
            }
            buf.advance(5 + outer_len);
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

    // ── varint helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 300, 16383, 16384, 65535, 65536, 1 << 21, u32::MAX as u64] {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, v);
            let expected_size = varint_size(v);
            assert_eq!(buf.len(), expected_size, "varint_size mismatch for {}", v);
            let (decoded, consumed) = read_varint(&buf).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {}", v);
            assert_eq!(consumed, expected_size);
        }
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(127), 1);
        assert_eq!(varint_size(128), 2);
        assert_eq!(varint_size(16383), 2);
        assert_eq!(varint_size(16384), 3);
    }

    // ── encode_grpc_frame (gun-lite format) ───────────────────────────────────

    #[test]
    fn test_encode_grpc_frame_empty() {
        // inner_len=0 → varint=[0x00] (1 byte) → outer_len=2
        let frame = encode_grpc_frame(&[]);
        assert_eq!(frame[0], 0); // gRPC flags
        let outer_len = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(outer_len, 2); // 1 (0x0A) + 1 (varint 0)
        assert_eq!(frame[5], 0x0A); // protobuf field tag
        assert_eq!(frame[6], 0x00); // varint(0)
        assert_eq!(frame.len(), 7);
    }

    #[test]
    fn test_encode_grpc_frame_data() {
        // "hello world" = 11 bytes
        // inner_len=11 → varint=[0x0B] (1 byte) → outer_len=13
        let data = b"hello world";
        let frame = encode_grpc_frame(data);
        assert_eq!(frame[0], 0);
        let outer_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
        assert_eq!(outer_len, 1 + 1 + data.len()); // 0x0A + varint + data
        assert_eq!(frame[5], 0x0A);
        assert_eq!(frame[6], data.len() as u8); // varint for 11
        assert_eq!(&frame[7..], data);
    }

    #[test]
    fn test_encode_grpc_frame_large() {
        // 65536 bytes → varint is 3 bytes → outer_len = 1+3+65536 = 65540
        let data = vec![0xABu8; 65536];
        let frame = encode_grpc_frame(&data);
        assert_eq!(frame[0], 0);
        let outer_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
        assert_eq!(outer_len, 1 + varint_size(65536) + 65536);
        assert_eq!(frame[5], 0x0A);
        // verify full frame length
        assert_eq!(frame.len(), 5 + outer_len);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for size in [0usize, 1, 127, 128, 255, 256, 1000, 16384] {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let frame = encode_grpc_frame(&data);

            // Parse the frame manually
            assert_eq!(frame[0], 0);
            let outer_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
            assert_eq!(frame.len(), 5 + outer_len);

            // Decode the gun-lite protobuf payload
            let proto = &frame[5..5 + outer_len];
            assert_eq!(proto[0], 0x0A);
            let (inner_len, varint_len) = read_varint(&proto[1..]).unwrap();
            assert_eq!(inner_len as usize, size);
            let decoded = &proto[1 + varint_len..];
            assert_eq!(decoded, data.as_slice());
        }
    }

    // ── decode_gun_payload ────────────────────────────────────────────────────

    #[test]
    fn test_decode_gun_payload() {
        // Build a valid payload manually
        let data = b"test data";
        let mut payload = BytesMut::new();
        payload.put_u8(0x0A);
        write_varint(&mut payload, data.len() as u64);
        payload.put_slice(data);

        let decoded = decode_gun_payload(&payload).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_gun_payload_empty() {
        assert_eq!(decode_gun_payload(&[]).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn test_decode_gun_payload_wrong_tag() {
        // Wrong field tag
        assert!(decode_gun_payload(&[0x0B, 0x05, 0, 0, 0, 0, 0]).is_none());
    }

    // ── multi-frame decoding ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_grpc_frame_decode_from_buffer() {
        let payload1 = b"first message";
        let payload2 = b"second message";

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&encode_grpc_frame(payload1));
        combined.extend_from_slice(&encode_grpc_frame(payload2));

        let mut out = Vec::new();
        let mut buf = combined;

        loop {
            if buf.len() < 5 {
                break;
            }
            let outer_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() < 5 + outer_len {
                break;
            }
            let proto = &buf[5..5 + outer_len];
            let write_range = if !proto.is_empty() && proto[0] == 0x0A {
                read_varint(&proto[1..]).and_then(|(inner_len, varint_len)| {
                    let data_start = 5 + 1 + varint_len;
                    let data_end = data_start + inner_len as usize;
                    if data_end <= 5 + outer_len { Some(data_start..data_end) } else { None }
                })
            } else {
                None
            };
            if let Some(range) = write_range {
                out.extend_from_slice(&buf[range]);
            }
            buf.advance(5 + outer_len);
        }

        assert_eq!(out, b"first messagesecond message");
    }

    #[tokio::test]
    async fn test_grpc_frame_decode_fragmented() {
        let payload = b"full message here";
        let frame = encode_grpc_frame(payload);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&frame[..3]); // partial — can't decode yet
        assert!(buf.len() < 5);

        buf.extend_from_slice(&frame[3..]); // rest

        let outer_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
        let proto = &buf[5..5 + outer_len];
        assert_eq!(proto[0], 0x0A);
        let (inner_len, varint_len) = read_varint(&proto[1..]).unwrap();
        let decoded = &proto[1 + varint_len..1 + varint_len + inner_len as usize];
        assert_eq!(decoded, payload);
    }

    // ── gun-lite compatibility (integration) ──────────────────────────────────

    /// Decode all gun-lite gRPC frames from a contiguous byte buffer.
    fn decode_all_frames(mut buf: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while buf.len() >= 5 {
            let outer_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
            if buf.len() < 5 + outer_len {
                break;
            }
            if let Some(data) = decode_gun_payload(&buf[5..5 + outer_len]) {
                out.extend_from_slice(data);
            }
            buf = &buf[5 + outer_len..];
        }
        out
    }

    /// End-to-end gun-lite compatibility test over an in-memory H2 pair (no TLS).
    ///
    /// Flow:
    ///   raw bytes → raw_to_grpc → [H2] → echo server (gun-lite decode/re-encode)
    ///           → [H2] → grpc_to_raw → raw bytes
    ///
    /// The echo server is structured following the canonical h2 pattern:
    ///   - A spawned task drives `conn.accept()` in a loop (this is what keeps the
    ///     H2 connection alive and delivers DATA frames to existing stream buffers).
    ///   - Each accepted request is handled in a further spawned task.
    ///   - Results are communicated back via a oneshot channel.
    #[tokio::test]
    async fn test_gun_lite_compat_full_relay() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        // In-memory H2 pair — no TLS needed
        let (client_io, server_io) = duplex(256 * 1024);
        let (mut send_request, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move { let _ = conn.await; });

        let server_conn: h2::server::Connection<_, Bytes> =
            h2::server::handshake(server_io).await.unwrap();

        // Channel to receive what the server decoded from the client's gun-lite frames.
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let result_tx = Arc::new(Mutex::new(Some(result_tx)));

        // Spawn the server connection driver.
        //
        // IMPORTANT: `conn.accept()` must keep being polled in a loop so that the
        // H2 connection continues processing DATA frames for existing streams.
        // Without this, the handler task's `body.data().await` would stall because
        // nobody is delivering DATA frames into the stream's receive buffer.
        tokio::spawn(async move {
            let mut conn = server_conn;
            while let Some(result) = conn.accept().await {
                let (req, mut respond) = result.unwrap();
                let tx = result_tx.clone();
                // Handle each stream in a separate task so `conn.accept()` keeps
                // driving the connection on the next loop iteration.
                tokio::spawn(async move {
                    let mut body = req.into_body();
                    let mut raw = BytesMut::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        let _ = body.flow_control().release_capacity(chunk.len());
                        raw.extend_from_slice(&chunk);
                    }
                    let decoded = decode_all_frames(&raw);

                    // Echo back the decoded payload as a gun-lite frame
                    let resp = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    send.send_data(encode_grpc_frame(&decoded), true).unwrap();

                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send(decoded);
                    }
                });
            }
        });

        // Open an H2 stream (mimics relay_grpc's request)
        std::future::poll_fn(|cx| send_request.poll_ready(cx)).await.unwrap();
        let req = http::Request::builder()
            .method("POST")
            .uri("/TestService/Tun")
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-go/1.48.0")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let (resp_fut, send_stream) = send_request.send_request(req, false).unwrap();

        // Feed raw bytes into raw_to_grpc (simulates the VMess inbound)
        let (inbound_r, mut inbound_w) = duplex(64 * 1024);
        let t_send = tokio::spawn(async move { raw_to_grpc(inbound_r, send_stream).await });

        let payload = b"hello from the gun-lite relay compatibility test";
        inbound_w.write_all(payload).await.unwrap();
        drop(inbound_w); // EOF → raw_to_grpc sends H2 EOS

        // Receive server response headers (blocks until server has read all request data)
        let response = resp_fut.await.unwrap();
        assert_eq!(response.status(), 200);

        // Decode server's gun-lite response through grpc_to_raw
        let (mut out_r, out_w) = duplex(64 * 1024);
        let t_recv = tokio::spawn(async move { grpc_to_raw(response.into_body(), out_w).await });

        let mut client_got = Vec::new();
        out_r.read_to_end(&mut client_got).await.unwrap();

        t_send.await.unwrap().unwrap();
        t_recv.await.unwrap().unwrap();
        let server_got = result_rx.await.unwrap();

        assert_eq!(server_got, payload, "server could not decode client gun-lite frames");
        assert_eq!(client_got, payload, "client could not decode server gun-lite response");
    }
}
