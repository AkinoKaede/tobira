/// VMess+gRPC h2c inbound listener.
use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::{self, SendResponse};
use h2::RecvStream;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

use crate::relay::core;
use crate::relay::inbound::{Inbound, InboundContext, InboundFuture};
use crate::relay::runtime::RelayRuntime;
use crate::relay::transport::grpc as grpc_transport;

pub struct GrpcInbound {
    pub service_name: String,
}

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
    let mut h2 = server::handshake(stream).await?;

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
    let (inbound_write, inbound_read) = tokio::io::duplex(64 * 1024);
    let (outbound_read, outbound_write) = tokio::io::duplex(64 * 1024);
    let stream = SplitDuplex {
        reader: inbound_read,
        writer: outbound_write,
    };

    tokio::spawn(async move {
        if let Err(e) = grpc_transport::grpc_to_raw(request_body, inbound_write).await {
            tracing::debug!("gRPC inbound decode error ({}): {}", peer_addr, e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = core::handle_stream(stream, peer_addr, runtime).await {
            tracing::debug!("gRPC inbound relay error ({}): {}", peer_addr, e);
        }
    });

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .map_err(|e| anyhow!("build gRPC response: {}", e))?;
    let send_stream = respond.send_response(response, false)?;
    grpc_transport::raw_to_grpc(outbound_read, send_stream).await?;

    tracing::debug!(
        "{} gRPC stream {} closed",
        peer_addr,
        request_parts.uri.path()
    );
    Ok(())
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
