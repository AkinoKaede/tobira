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
use tokio::task::JoinHandle;
use tokio::time::timeout;

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
const INITIAL_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

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
    response_stream: h2::SendStream<Bytes>,
    peer_addr: SocketAddr,
    runtime: RelayRuntime,
) -> Result<()> {
    let mut reader = grpc_transport::GrpcFrameReader::new(request_body);
    let (cached_frames, auth_id) =
        timeout(INITIAL_AUTH_TIMEOUT, read_initial_auth(&mut reader)).await??;

    let upstream = {
        let validator = runtime.validator.read().await;
        validator.match_auth_id(&auth_id)
    };

    let Some(upstream) = upstream else {
        tracing::debug!("{} auth failed on gRPC inbound", peer_addr);
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

    for frame in cached_frames {
        grpc_transport::send_grpc_data(&mut send_stream, frame, false).await?;
    }

    let upstream_addr = upstream.addr.clone();
    let tls_sni2 = tls_sni.clone();
    let pool = runtime.grpc_pool.clone();
    let t1 = tokio::spawn(async move {
        let result = grpc_transport::grpc_frames_to_grpc(reader, send_stream).await;
        if result.is_err() {
            pool.evict(&upstream_addr, &tls_sni2);
        }
        result
    });

    let response = match response_future.await {
        Ok(response) => response,
        Err(e) => {
            runtime.grpc_pool.evict(&upstream.addr, &tls_sni);
            t1.abort();
            let _ = t1.await;
            return Err(anyhow!("response headers: {}", e));
        }
    };
    tracing::info!(
        "{} -> {} [grpc/{}/fast sni={}] relaying",
        peer_addr,
        upstream.addr,
        service_name,
        tls_sni,
    );
    let t2 = tokio::spawn(async move {
        grpc_transport::grpc_frames_to_grpc(
            grpc_transport::GrpcFrameReader::new(response.into_body()),
            response_stream,
        )
        .await
    });

    grpc_transport::relay_until_one_side_finishes("grpc fast relay", t1, t2).await;

    Ok(())
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
    let (inbound_write, inbound_read) = tokio::io::duplex(64 * 1024);
    let (outbound_read, outbound_write) = tokio::io::duplex(64 * 1024);
    let stream = SplitDuplex {
        reader: inbound_read,
        writer: outbound_write,
    };

    let decode_task = tokio::spawn(async move {
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
        Ok(())
    });

    let relay_task = tokio::spawn(async move {
        core::relay_authenticated_stream(stream, peer_addr, runtime, upstream, auth_id).await
    });

    let encode_task =
        tokio::spawn(
            async move { grpc_transport::raw_to_grpc(outbound_read, response_stream).await },
        );

    relay_grpc_via_core_until_one_side_finishes(peer_addr, decode_task, relay_task, encode_task)
        .await
}

async fn relay_grpc_via_core_until_one_side_finishes(
    peer_addr: SocketAddr,
    mut decode_task: JoinHandle<Result<()>>,
    mut relay_task: JoinHandle<Result<()>>,
    mut encode_task: JoinHandle<Result<()>>,
) -> Result<()> {
    tokio::select! {
        result = &mut decode_task => {
            let result = bridge_task_result(peer_addr, "decode", result);
            relay_task.abort();
            encode_task.abort();
            log_aborted_bridge_task(peer_addr, "relay", relay_task.await);
            log_aborted_bridge_task(peer_addr, "encode", encode_task.await);
            result
        }
        result = &mut relay_task => {
            let result = bridge_task_result(peer_addr, "relay", result);
            decode_task.abort();
            encode_task.abort();
            log_aborted_bridge_task(peer_addr, "decode", decode_task.await);
            log_aborted_bridge_task(peer_addr, "encode", encode_task.await);
            result
        }
        result = &mut encode_task => {
            let result = bridge_task_result(peer_addr, "encode", result);
            decode_task.abort();
            relay_task.abort();
            log_aborted_bridge_task(peer_addr, "decode", decode_task.await);
            log_aborted_bridge_task(peer_addr, "relay", relay_task.await);
            result
        }
    }
}

fn bridge_task_result(
    peer_addr: SocketAddr,
    direction: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => {
            tracing::debug!(%peer_addr, direction, "gRPC-to-TCP bridge side finished");
            Ok(())
        }
        Ok(Err(e)) => {
            tracing::debug!(%peer_addr, direction, "gRPC-to-TCP bridge side error: {}", e);
            Err(e)
        }
        Err(e) if e.is_cancelled() => {
            tracing::debug!(%peer_addr, direction, "gRPC-to-TCP bridge side cancelled");
            Ok(())
        }
        Err(e) => Err(anyhow!(
            "gRPC-to-TCP bridge {direction} task join error: {e}"
        )),
    }
}

fn log_aborted_bridge_task(
    peer_addr: SocketAddr,
    direction: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => tracing::debug!(
            %peer_addr,
            direction,
            "gRPC-to-TCP bridge side finished during shutdown"
        ),
        Ok(Err(e)) => tracing::debug!(
            %peer_addr,
            direction,
            "gRPC-to-TCP bridge side error during shutdown: {}",
            e
        ),
        Err(e) if e.is_cancelled() => tracing::debug!(
            %peer_addr,
            direction,
            "gRPC-to-TCP bridge side aborted after another side finished"
        ),
        Err(e) => tracing::debug!(
            %peer_addr,
            direction,
            "gRPC-to-TCP bridge side join error during shutdown: {}",
            e
        ),
    }
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
