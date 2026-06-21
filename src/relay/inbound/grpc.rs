/// VMess+gRPC h2c inbound listener.
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::{self, SendResponse};
use h2::RecvStream;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::relay::activity::{idle_check_interval, RelayActivity};
use crate::relay::core;
use crate::relay::inbound::{Inbound, InboundContext, InboundFuture};
use crate::relay::outbound;
use crate::relay::runtime::RelayRuntime;
use crate::relay::transport::grpc as grpc_transport;
use crate::vmess::validator::Transport;

pub struct GrpcInbound {
    pub service_name: String,
}

const H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl Inbound for GrpcInbound {
    fn run(self: Box<Self>, ctx: InboundContext) -> InboundFuture {
        Box::pin(async move { run(ctx.addr, self.service_name, ctx.runtime).await })
    }
}

/// Start the gRPC h2c relay listener.
pub async fn run(addr: SocketAddr, service_name: String, runtime: RelayRuntime) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        "gRPC h2c relay listening on {} (service={})",
        addr,
        service_name
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("gRPC accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        let service_name = service_name.clone();
        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, peer_addr, service_name, runtime).await {
                tracing::debug!("gRPC H2 connection error ({}): {}", peer_addr, e);
            }
        });
    }
}

async fn serve_conn(
    stream: TcpStream,
    peer_addr: SocketAddr,
    service_name: String,
    runtime: RelayRuntime,
) -> Result<()> {
    let mut h2 = timeout(H2_HANDSHAKE_TIMEOUT, server::handshake(stream)).await??;

    while let Some(request) = h2.accept().await {
        let (request, respond) = request?;
        let runtime = runtime.clone();
        let service_name = service_name.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond, peer_addr, service_name, runtime).await
            {
                tracing::debug!("gRPC stream error ({}): {}", peer_addr, e);
            }
        });
    }

    Ok(())
}

async fn handle_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer_addr: SocketAddr,
    service_name: String,
    runtime: RelayRuntime,
) -> Result<()> {
    if let Err(response) = validate_request(&request, &service_name) {
        respond.send_response(response, true)?;
        return Ok(());
    }

    let (request_parts, request_body) = request.into_parts();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .map_err(|e| anyhow!("build gRPC response: {}", e))?;
    let send_stream = respond.send_response(response, false)?;

    relay_request(request_body, send_stream, peer_addr, runtime).await?;

    tracing::debug!(
        "{} gRPC stream {} closed",
        peer_addr,
        request_parts.uri.path()
    );
    Ok(())
}

async fn relay_request(
    request_body: RecvStream,
    mut response_stream: h2::SendStream<Bytes>,
    peer_addr: SocketAddr,
    runtime: RelayRuntime,
) -> Result<()> {
    let mut reader = grpc_transport::GrpcFrameReader::new(request_body);
    let (cached_frames, auth_id) =
        match timeout(core::AUTH_READ_TIMEOUT, read_initial_auth(&mut reader)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::debug!("{} failed to read gRPC auth id: {}", peer_addr, e);
                drain_grpc_request(reader).await;
                let _ =
                    grpc_transport::send_grpc_data(&mut response_stream, Bytes::new(), true).await;
                return Ok(());
            }
            Err(_) => {
                tracing::debug!("{} timed out reading gRPC auth id", peer_addr);
                drain_grpc_request(reader).await;
                let _ =
                    grpc_transport::send_grpc_data(&mut response_stream, Bytes::new(), true).await;
                return Ok(());
            }
        };

    let upstream = {
        let validator = runtime.validator.read().await;
        validator.match_auth_id(&auth_id)
    };

    let Some(upstream) = upstream else {
        tracing::debug!("{} auth failed on gRPC inbound", peer_addr);
        drain_grpc_request(reader).await;
        let _ = grpc_transport::send_grpc_data(&mut response_stream, Bytes::new(), true).await;
        return Ok(());
    };

    match &upstream.transport {
        Transport::Grpc { .. } => {
            relay_grpc_to_grpc_fast(
                reader,
                cached_frames,
                response_stream,
                upstream,
                peer_addr,
                runtime,
            )
            .await
        }
        _ => {
            relay_grpc_via_core(
                reader,
                cached_frames,
                response_stream,
                upstream,
                auth_id,
                peer_addr,
                runtime,
            )
            .await
        }
    }
}

async fn drain_grpc_request(mut reader: grpc_transport::GrpcFrameReader) {
    let drain_len = rand::random_range(64usize..512);

    let _ = timeout(Duration::from_secs(5), async move {
        let mut drained = 0usize;
        while drained < drain_len {
            match reader.next_frame().await {
                Ok(Some(frame)) => {
                    if let Some(data) = grpc_transport::decode_grpc_frame_data(&frame) {
                        drained += data.len();
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    })
    .await;
}

async fn read_initial_auth(
    reader: &mut grpc_transport::GrpcFrameReader,
) -> Result<(Vec<Bytes>, [u8; 16])> {
    let mut cached_frames = Vec::new();
    let mut initial_raw = Vec::new();

    while initial_raw.len() < 16 {
        let Some(frame) = reader.next_frame().await? else {
            return Err(anyhow!("gRPC stream ended before VMess auth id"));
        };
        if let Some(data) = grpc_transport::decode_grpc_frame_data(&frame) {
            initial_raw.extend_from_slice(data);
        }
        cached_frames.push(frame);
    }

    let auth_id: [u8; 16] = initial_raw[..16].try_into().unwrap();
    Ok((cached_frames, auth_id))
}

async fn relay_grpc_to_grpc_fast(
    reader: grpc_transport::GrpcFrameReader,
    cached_frames: Vec<Bytes>,
    response_stream: h2::SendStream<Bytes>,
    upstream: std::sync::Arc<crate::vmess::validator::Upstream>,
    peer_addr: SocketAddr,
    runtime: RelayRuntime,
) -> Result<()> {
    let outbound::grpc::GrpcTunnel {
        service_name,
        tls_sni,
        response_future,
        mut send_stream,
    } = outbound::grpc::open_grpc_tunnel(upstream.clone(), runtime.grpc_pool.clone()).await?;

    let idle_timeout = *runtime.relay_idle_timeout.read().await;
    let activity = idle_timeout.map(|_| RelayActivity::new());

    for frame in cached_frames {
        grpc_transport::send_grpc_data(&mut send_stream, frame, false).await?;
        if let Some(activity) = &activity {
            activity.mark();
        }
    }

    let upstream_addr = upstream.addr.clone();
    let tls_sni2 = tls_sni.clone();
    let pool = runtime.grpc_pool.clone();
    let t1_activity = activity.clone();
    let t1 = tokio::spawn(async move {
        let result =
            grpc_transport::grpc_frames_to_grpc_with_activity(reader, send_stream, t1_activity)
                .await;
        if let Err(error) = &result {
            if grpc_transport::is_grpc_connection_error(error) {
                pool.evict(&upstream_addr, &tls_sni2);
            } else {
                tracing::debug!(
                    "{} -> {} [grpc/fast sni={}] request stream ended without evicting pool: {}",
                    peer_addr,
                    upstream_addr,
                    tls_sni2,
                    error
                );
            }
        }
        result
    });

    let (response, t1) = outbound::grpc::await_grpc_response_headers(
        response_future,
        t1,
        runtime.grpc_pool.clone(),
        upstream.addr.clone(),
        tls_sni.clone(),
        peer_addr,
        "grpc/fast",
    )
    .await?;
    tracing::info!(
        "{} -> {} [grpc/{}/fast sni={}] relaying",
        peer_addr,
        upstream.addr,
        service_name,
        tls_sni,
    );
    let t2_activity = activity.clone();
    let t2 = tokio::spawn(async move {
        grpc_transport::grpc_frames_to_grpc_with_activity(
            grpc_transport::GrpcFrameReader::new(response.into_body()),
            response_stream,
            t2_activity,
        )
        .await
    });

    let (r1, r2) = wait_grpc_fast_relay(
        t1,
        t2,
        GrpcFastRelayWaitContext {
            activity,
            idle_timeout,
            upstream_addr: upstream.addr.clone(),
            tls_sni: tls_sni.clone(),
            peer: peer_addr,
        },
    )
    .await;
    let _ = r1
        .map_err(|e| tracing::debug!("grpc fast relay t1 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc fast relay t1: {}", e)));
    let _ = r2
        .map_err(|e| tracing::debug!("grpc fast relay t2 join: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("grpc fast relay t2: {}", e)));

    Ok(())
}

struct GrpcFastRelayWaitContext {
    activity: Option<RelayActivity>,
    idle_timeout: Option<Duration>,
    upstream_addr: String,
    tls_sni: String,
    peer: SocketAddr,
}

async fn wait_grpc_fast_relay(
    t1: tokio::task::JoinHandle<Result<()>>,
    t2: tokio::task::JoinHandle<Result<()>>,
    ctx: GrpcFastRelayWaitContext,
) -> (
    std::result::Result<Result<()>, tokio::task::JoinError>,
    std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    let GrpcFastRelayWaitContext {
        activity,
        idle_timeout,
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
                        "{} -> {} [grpc/fast sni={}] idle timeout after {:.2}s",
                        peer,
                        upstream_addr,
                        tls_sni,
                        idle_for.as_secs_f64()
                    );
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
        r1.expect("grpc fast relay send task result must be set"),
        r2.expect("grpc fast relay recv task result must be set"),
    )
}

async fn relay_grpc_via_core(
    mut reader: grpc_transport::GrpcFrameReader,
    cached_frames: Vec<Bytes>,
    response_stream: h2::SendStream<Bytes>,
    upstream: std::sync::Arc<crate::vmess::validator::Upstream>,
    auth_id: [u8; 16],
    peer_addr: SocketAddr,
    runtime: RelayRuntime,
) -> Result<()> {
    let upstream_addr = upstream.addr.clone();
    tracing::debug!(
        "{} -> {} [grpc-in/core] starting relay",
        peer_addr,
        upstream_addr
    );

    let (inbound_write, inbound_read) = tokio::io::duplex(64 * 1024);
    let (outbound_read, outbound_write) = tokio::io::duplex(64 * 1024);
    let stream = SplitDuplex {
        reader: inbound_read,
        writer: outbound_write,
    };

    let mut decode_task = tokio::spawn(async move {
        let mut inbound_write = inbound_write;
        let mut skip = 16usize;
        for frame in cached_frames {
            if let Some(data) = grpc_transport::decode_grpc_frame_data(&frame) {
                let data = skip_auth_id_bytes(data, &mut skip);
                if !data.is_empty() {
                    tokio::io::AsyncWriteExt::write_all(&mut inbound_write, data).await?;
                }
            }
        }
        while let Some(frame) = reader.next_frame().await? {
            if let Some(data) = grpc_transport::decode_grpc_frame_data(&frame) {
                let data = skip_auth_id_bytes(data, &mut skip);
                if !data.is_empty() {
                    tokio::io::AsyncWriteExt::write_all(&mut inbound_write, data).await?;
                }
            }
        }
        tracing::debug!(
            "{} [grpc-in/core] request stream ended; forwarding TCP write half-close",
            peer_addr
        );
        Ok(())
    });

    let relay_upstream_addr = upstream.addr.clone();
    let mut relay_task = tokio::spawn(async move {
        let result =
            core::relay_authenticated_stream(stream, peer_addr, runtime, upstream, auth_id).await;
        if let Err(e) = &result {
            tracing::debug!("gRPC inbound relay error ({}): {}", peer_addr, e);
        }
        tracing::debug!(
            "{} -> {} [grpc-in/core] relay task ended",
            peer_addr,
            relay_upstream_addr
        );
        result
    });

    let encode_task = grpc_transport::raw_to_grpc(outbound_read, response_stream);
    tokio::pin!(encode_task);

    let result = tokio::select! {
        decode_result = &mut decode_task => {
            match decode_result_to_result(decode_result, peer_addr) {
                Ok(()) => {
                    tokio::select! {
                        encode_result = &mut encode_task => {
                            relay_task.abort();
                            await_relay_result(relay_task).await;
                            encode_result
                        }
                        relay_result = &mut relay_task => {
                            match relay_result_to_result(relay_result, peer_addr) {
                                Ok(()) => encode_task.await,
                                Err(e) => Err(e),
                            }
                        }
                    }
                }
                Err(e) => {
                    relay_task.abort();
                    await_relay_result(relay_task).await;
                    return Err(e);
                }
            }
        }
        encode_result = &mut encode_task => {
            decode_task.abort();
            relay_task.abort();
            await_decode_result(decode_task, peer_addr).await;
            await_relay_result(relay_task).await;
            encode_result
        }
        relay_result = &mut relay_task => {
            let relay_result = relay_result_to_result(relay_result, peer_addr);
            decode_task.abort();
            await_decode_result(decode_task, peer_addr).await;
            match relay_result {
                Ok(()) => encode_task.await,
                Err(e) => Err(e),
            }
        }
    };

    match &result {
        Ok(()) => tracing::debug!(
            "{} -> {} [grpc-in/core] response stream ended",
            peer_addr,
            upstream_addr
        ),
        Err(e) => tracing::debug!(
            "{} -> {} [grpc-in/core] response stream error: {}",
            peer_addr,
            upstream_addr,
            e
        ),
    }

    result
}

fn decode_result_to_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    peer_addr: SocketAddr,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            tracing::debug!("gRPC inbound decode error ({}): {}", peer_addr, e);
            Err(e)
        }
        Err(e) => Err(anyhow!("gRPC inbound decode join error: {}", e)),
    }
}

async fn await_decode_result(task: tokio::task::JoinHandle<Result<()>>, peer_addr: SocketAddr) {
    let _ = decode_result_to_result(task.await, peer_addr);
}

fn relay_result_to_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    peer_addr: SocketAddr,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            tracing::debug!("gRPC inbound relay error ({}): {}", peer_addr, e);
            Err(e)
        }
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(anyhow!("gRPC inbound relay join error: {}", e)),
    }
}

async fn await_relay_result(task: tokio::task::JoinHandle<Result<()>>) {
    let _ = task
        .await
        .map_err(|e| tracing::debug!("gRPC inbound relay join error: {}", e))
        .and_then(|r| r.map_err(|e| tracing::debug!("gRPC inbound relay error: {}", e)));
}

fn skip_auth_id_bytes<'a>(data: &'a [u8], skip: &mut usize) -> &'a [u8] {
    let n = (*skip).min(data.len());
    *skip -= n;
    &data[n..]
}

fn validate_request(
    request: &Request<RecvStream>,
    service_name: &str,
) -> std::result::Result<(), Response<()>> {
    if request.method() != http::Method::POST {
        return Err(simple_response(StatusCode::METHOD_NOT_ALLOWED));
    }

    let expected_path = format!("/{}/Tun", service_name);
    if request.uri().path() != expected_path {
        return Err(simple_response(StatusCode::NOT_FOUND));
    }

    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("application/grpc") {
        return Err(simple_response(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }

    Ok(())
}

fn simple_response(status: StatusCode) -> Response<()> {
    Response::builder().status(status).body(()).unwrap()
}

struct SplitDuplex {
    reader: DuplexStream,
    writer: DuplexStream,
}

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

impl AsyncRead for SplitDuplex {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for SplitDuplex {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
