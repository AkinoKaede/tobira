/// gRPC (VMess+TLS+gRPC) outbound relay.
///
/// Protocol: gun-lite gRPC framing
///   gRPC outer frame: [0x00][outer_len:4BE][protobuf_payload]
///   protobuf_payload: [0x0A][varint(inner_len)][raw_data]
///   (protobuf message Hunk { bytes data = 1; })
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::client::ResponseFuture;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay::activity::{idle_check_interval, RelayActivity};
use crate::relay::outbound::{InboundStream, Outbound, OutboundContext, OutboundFuture};
use crate::relay::transport::grpc::{
    encode_grpc_frame, grpc_to_raw_with_activity, raw_to_grpc_with_activity, send_grpc_data,
    GrpcPool,
};
use crate::vmess::validator::Upstream;

// ──────────────────────────────────────────────────────────────────────────────
// Relay entry point
// ──────────────────────────────────────────────────────────────────────────────

pub struct GrpcOutbound;

impl Outbound for GrpcOutbound {
    fn relay(
        self: Box<Self>,
        inbound: Box<dyn InboundStream>,
        ctx: OutboundContext,
    ) -> OutboundFuture {
        Box::pin(async move {
            let idle_timeout = *ctx.runtime.relay_idle_timeout.read().await;
            relay_grpc(
                inbound,
                ctx.upstream,
                ctx.runtime.grpc_pool.clone(),
                ctx.auth_id,
                ctx.peer,
                idle_timeout,
            )
            .await
        })
    }
}

async fn relay_grpc(
    inbound: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    upstream: Arc<Upstream>,
    pool: Arc<GrpcPool>,
    auth_id: [u8; 16],
    peer: std::net::SocketAddr,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let GrpcTunnel {
        service_name,
        tls_sni,
        response_future,
        mut send_stream,
    } = open_grpc_tunnel(upstream.clone(), pool.clone()).await?;

    // Write the auth ID as the first gRPC frame
    let frame = encode_grpc_frame(&auth_id);
    send_grpc_data(&mut send_stream, frame, false).await?;

    // Split inbound for bidirectional relay
    let (inbound_reader, inbound_writer) = tokio::io::split(inbound);

    // Start inbound → gRPC relay BEFORE awaiting response headers.
    // The upstream VMess server needs the encrypted request header (which
    // follows the 16-byte Auth ID) before it can send response headers.
    // Awaiting response_future first would deadlock.
    let upstream_addr = upstream.addr.clone();
    let tls_sni2 = tls_sni.clone();
    let pool2 = pool.clone();
    let activity = idle_timeout.map(|_| RelayActivity::new());
    let t1_activity = activity.clone();
    let t1 = tokio::spawn(async move {
        let mut inbound_reader = inbound_reader;
        let mut send_stream = send_stream;
        let result =
            raw_to_grpc_with_activity(&mut inbound_reader, &mut send_stream, t1_activity).await;
        if result.is_err() {
            pool2.evict(&upstream_addr, &tls_sni2);
        }
        result
    });

    // Now await server response headers (unblocked because t1 is sending data)
    let response = match response_future.await {
        Ok(response) => response,
        Err(e) => {
            pool.evict(&upstream.addr, &tls_sni);
            t1.abort();
            let _ = t1.await;
            return Err(anyhow!("response headers: {}", e));
        }
    };
    tracing::info!(
        "{} → {} [grpc/{} sni={}] relaying",
        peer,
        upstream.addr,
        service_name,
        tls_sni,
    );
    let recv_stream = response.into_body();

    // Task 2: upstream recv_stream → raw bytes → inbound writer
    let t2_activity = activity.clone();
    let t2 = tokio::spawn(async move {
        let mut inbound_writer = inbound_writer;
        grpc_to_raw_with_activity(recv_stream, &mut inbound_writer, t2_activity).await
    });

    // Wait for both directions; half-close is valid proxy behavior.
    let started = std::time::Instant::now();
    let (r1, r2) = wait_grpc_relay(
        t1,
        t2,
        GrpcRelayWaitContext {
            activity,
            idle_timeout,
            pool: pool.clone(),
            upstream_addr: upstream.addr.clone(),
            tls_sni: tls_sni.clone(),
            peer,
        },
    )
    .await;
    let _ = r1
        .map_err(|e| tracing::debug!("grpc relay t1 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc relay t1: {}", e)));
    let _ = r2
        .map_err(|e| tracing::debug!("grpc relay t2 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc relay t2: {}", e)));

    tracing::info!(
        "{} → {} [grpc/{} sni={}] closed ({:.2}s)",
        peer,
        upstream.addr,
        service_name,
        tls_sni,
        started.elapsed().as_secs_f64(),
    );

    Ok(())
}

struct GrpcRelayWaitContext {
    activity: Option<RelayActivity>,
    idle_timeout: Option<Duration>,
    pool: Arc<GrpcPool>,
    upstream_addr: String,
    tls_sni: String,
    peer: std::net::SocketAddr,
}

async fn wait_grpc_relay(
    t1: tokio::task::JoinHandle<Result<()>>,
    t2: tokio::task::JoinHandle<Result<()>>,
    ctx: GrpcRelayWaitContext,
) -> (
    std::result::Result<Result<()>, tokio::task::JoinError>,
    std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    let GrpcRelayWaitContext {
        activity,
        idle_timeout,
        pool,
        upstream_addr,
        tls_sni,
        peer,
    } = ctx;
    let Some((activity, idle_timeout)) = activity.zip(idle_timeout) else {
        return tokio::join!(t1, t2);
    };

    tokio::pin!(t1);
    tokio::pin!(t2);
    let mut interval = tokio::time::interval(idle_check_interval(idle_timeout));
    let mut r1 = None;
    let mut r2 = None;

    loop {
        tokio::select! {
            result = &mut t1, if r1.is_none() => {
                r1 = Some(result);
            }
            result = &mut t2, if r2.is_none() => {
                r2 = Some(result);
            }
            _ = interval.tick() => {
                let idle_for = activity.idle_for();
                if idle_for >= idle_timeout {
                    tracing::debug!(
                        "{} -> {} [grpc sni={}] idle timeout after {:.2}s",
                        peer,
                        upstream_addr,
                        tls_sni,
                        idle_for.as_secs_f64()
                    );
                    pool.evict(&upstream_addr, &tls_sni);
                    if r1.is_none() {
                        t1.as_mut().abort();
                        r1 = Some((&mut t1).await);
                    }
                    if r2.is_none() {
                        t2.as_mut().abort();
                        r2 = Some((&mut t2).await);
                    }
                    break;
                }
            }
        }

        if r1.is_some() && r2.is_some() {
            break;
        }
    }

    (
        r1.expect("grpc relay send task result must be set"),
        r2.expect("grpc relay recv task result must be set"),
    )
}

pub(crate) struct GrpcTunnel {
    pub(crate) service_name: String,
    pub(crate) tls_sni: String,
    pub(crate) response_future: ResponseFuture,
    pub(crate) send_stream: h2::SendStream<Bytes>,
}

pub(crate) async fn open_grpc_tunnel(
    upstream: Arc<Upstream>,
    pool: Arc<GrpcPool>,
) -> Result<GrpcTunnel> {
    use crate::vmess::validator::Transport;

    let (service_name, tls_sni, request_uri) = match &upstream.transport {
        Transport::Grpc {
            service_name,
            tls_sni,
            request_uri,
        } => (service_name.clone(), tls_sni.clone(), request_uri.clone()),
        _ => return Err(anyhow!("open_grpc_tunnel called on non-gRPC upstream")),
    };

    let mut send_request = pool.get_or_create(&upstream.addr, &tls_sni).await?;

    let request = http::Request::builder()
        .method("POST")
        .uri(request_uri)
        .header("content-type", "application/grpc")
        .header("user-agent", "grpc-go/1.48.0")
        .header("te", "trailers")
        .body(())
        .map_err(|e| anyhow!("build request: {}", e))?;

    if std::future::poll_fn(|cx| send_request.poll_ready(cx))
        .await
        .is_err()
    {
        tracing::debug!(
            "cached H2 connection dead for {} -- reconnecting",
            upstream.addr
        );
        pool.evict(&upstream.addr, &tls_sni);
        send_request = pool.get_or_create(&upstream.addr, &tls_sni).await?;
        std::future::poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .map_err(|e| anyhow!("h2 not ready after reconnect: {}", e))?;
    }

    let (response_future, send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| anyhow!("send_request: {}", e))?;

    Ok(GrpcTunnel {
        service_name,
        tls_sni,
        response_future,
        send_stream,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::transport::grpc::{
        decode_gun_payload, grpc_to_raw, raw_to_grpc, read_varint, varint_size, write_varint,
    };
    use bytes::{Buf, BufMut, BytesMut};

    // ── varint helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_varint_roundtrip() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            300,
            16383,
            16384,
            65535,
            65536,
            1 << 21,
            u32::MAX as u64,
        ] {
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
                    if data_end <= 5 + outer_len {
                        Some(data_start..data_end)
                    } else {
                        None
                    }
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
        tokio::spawn(async move {
            let _ = conn.await;
        });

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
        std::future::poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .unwrap();
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

        assert_eq!(
            server_got, payload,
            "server could not decode client gun-lite frames"
        );
        assert_eq!(
            client_got, payload,
            "client could not decode server gun-lite response"
        );
    }

    // ── prost / tonic gRPC compatibility ──────────────────────────────────────

    /// Wire message `Hunk { bytes data = 1; }` — the gun-lite protobuf schema.
    /// Derived so that prost can encode/decode it for compatibility checks.
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct HunkMsg {
        #[prost(bytes = "bytes", tag = "1")]
        data: Bytes,
    }

    /// `encode_grpc_frame` must produce a valid standard gRPC frame whose
    /// protobuf payload prost can decode into `HunkMsg { data: <original> }`.
    #[test]
    fn test_prost_compat_encode() {
        use prost::Message as _;

        let payload = b"gun-lite encodes as standard gRPC protobuf";
        let frame = encode_grpc_frame(payload);

        // Strip the 5-byte gRPC prefix; what remains is a protobuf-encoded HunkMsg.
        let outer_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
        let hunk = HunkMsg::decode(&frame[5..5 + outer_len])
            .expect("prost must decode gun-lite protobuf payload");
        assert_eq!(hunk.data.as_ref(), payload as &[u8]);
    }

    /// A prost-encoded `HunkMsg` must be decodable by our hand-rolled `decode_gun_payload`.
    #[test]
    fn test_prost_compat_decode() {
        use prost::Message as _;

        let payload = b"prost-encoded HunkMsg is gun-lite compatible";
        let hunk = HunkMsg {
            data: Bytes::copy_from_slice(payload),
        };
        let mut proto = BytesMut::new();
        hunk.encode(&mut proto).unwrap();

        let decoded = decode_gun_payload(&proto)
            .expect("decode_gun_payload must handle prost-encoded HunkMsg");
        assert_eq!(decoded, payload as &[u8]);
    }

    /// Full integration: raw-h2 gun-lite client ↔ real tonic gRPC server (h2c, no TLS).
    ///
    /// Flow:
    ///   bytes ─raw_to_grpc──► h2c ──► tonic EchoSvc (prost decode / re-encode)
    ///         ◄─grpc_to_raw─  h2c ◄──────────────────────────────────────────┘
    ///
    /// Verifies two-way wire compatibility between our hand-rolled gun-lite
    /// framing and a real tonic gRPC server using the ProstCodec.

    #[tokio::test]
    async fn test_tonic_server_compat() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        use tokio_stream::wrappers::TcpListenerStream;
        use tonic::codec::ProstCodec;
        use tonic::server::Grpc;
        use tonic::{Request, Response, Status, Streaming};

        // Sink: the tonic server sends back whatever it decoded from our frames.
        let (result_tx, result_rx) = oneshot::channel::<Vec<u8>>();
        let result_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(result_tx)));

        // ── Tonic bidirectional-streaming echo service ─────────────────────────
        //
        // Implements tower::Service<Request<BoxBody>> so that tonic's Server
        // can route requests to it.  Internally it uses tonic::server::Grpc
        // with ProstCodec to decode gun-lite frames into HunkMsg values, then
        // echoes the concatenated payload back as a single HunkMsg response.
        #[derive(Clone)]
        struct EchoSvc {
            tx: std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
        }

        impl tonic::server::NamedService for EchoSvc {
            const NAME: &'static str = "TestService";
        }

        impl tower::Service<http::Request<tonic::body::BoxBody>> for EchoSvc {
            type Response = http::Response<tonic::body::BoxBody>;
            type Error = std::convert::Infallible;
            type Future = Pin<
                Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
            >;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
                let tx = self.tx.clone();
                Box::pin(async move {
                    let codec = ProstCodec::<HunkMsg, HunkMsg>::default();
                    let mut grpc = Grpc::new(codec);

                    // Inner handler: collect all HunkMsg chunks, echo them back.
                    let handler = tower::service_fn(move |req: Request<Streaming<HunkMsg>>| {
                        let tx = tx.clone();
                        async move {
                            let mut stream = req.into_inner();
                            let mut all: Vec<u8> = Vec::new();
                            while let Some(h) = stream.message().await? {
                                all.extend_from_slice(&h.data);
                            }
                            if let Some(s) = tx.lock().unwrap().take() {
                                let _ = s.send(all.clone());
                            }
                            let echo = HunkMsg {
                                data: Bytes::copy_from_slice(&all),
                            };
                            let out = tokio_stream::iter(vec![Ok::<_, Status>(echo)]);
                            Ok::<_, Status>(Response::new(out))
                        }
                    });

                    Ok(grpc.streaming(handler, req).await)
                })
            }
        }

        // ── Start tonic server on an OS-assigned port (h2c, no TLS) ───────────
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let svc = EchoSvc { tx: result_tx };
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("tonic server error");
        });
        tokio::task::yield_now().await;

        // ── Connect with a plain h2c client (mirrors relay_grpc, but no TLS) ──
        let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let (mut send_req, h2_conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // ── Send gRPC POST request with gun-lite framing ───────────────────────
        std::future::poll_fn(|cx| send_req.poll_ready(cx))
            .await
            .unwrap();
        let req = http::Request::builder()
            .method("POST")
            .uri("/TestService/Tun")
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-go/1.48.0")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let (resp_fut, send_stream) = send_req.send_request(req, false).unwrap();

        // raw_to_grpc: pipe raw bytes through gun-lite encoding to the tonic server.
        let (inbound_r, mut inbound_w) = tokio::io::duplex(64 * 1024);
        let t_send = tokio::spawn(async move { raw_to_grpc(inbound_r, send_stream).await });

        let payload = b"hello from gun-lite h2 client to tonic gRPC server";
        inbound_w.write_all(payload).await.unwrap();
        drop(inbound_w); // EOF → raw_to_grpc sends H2 EOS

        // ── Receive tonic response ─────────────────────────────────────────────
        let response = resp_fut.await.unwrap();
        assert_eq!(response.status(), 200);

        // grpc_to_raw: decode tonic's gRPC response frames back to raw bytes.
        let (mut out_r, out_w) = tokio::io::duplex(64 * 1024);
        let t_recv = tokio::spawn(async move { grpc_to_raw(response.into_body(), out_w).await });

        let mut client_got = Vec::new();
        out_r.read_to_end(&mut client_got).await.unwrap();

        t_send.await.unwrap().unwrap();
        t_recv.await.unwrap().unwrap();
        let server_got = result_rx
            .await
            .expect("tonic server must report decoded payload");

        assert_eq!(
            server_got, payload as &[u8],
            "tonic decoded our gun-lite frames correctly"
        );
        assert_eq!(
            client_got, payload as &[u8],
            "grpc_to_raw decoded tonic's gRPC response correctly"
        );
    }
}
