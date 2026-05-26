/// VMess+TCP inbound listener.
///
/// Accepts TCP connections, reads the first 16 bytes (Auth ID), looks up the
/// matching upstream in the validator, then relays the connection.
///
/// On auth failure: drain a random amount of data before closing (prevents
/// timing-based fingerprinting).
use anyhow::Result;
use tokio_tfo::TfoListener;

use crate::relay::core;
use crate::relay::inbound::{Inbound, InboundContext, InboundFuture};
use crate::relay::runtime::RelayRuntime;

pub struct TcpInbound;

impl Inbound for TcpInbound {
    fn run(self: Box<Self>, ctx: InboundContext) -> InboundFuture {
        Box::pin(async move { run(ctx.addr, ctx.runtime).await })
    }
}

/// Start the TCP relay listener.
///
/// `runtime`: shared relay resources.
pub async fn run(addr: std::net::SocketAddr, runtime: RelayRuntime) -> Result<()> {
    let listener = TfoListener::bind(addr).await?;
    tracing::info!("relay listening on {}", addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {}", e);
                continue;
            }
        };
        tracing::debug!("accepted connection from {}", peer_addr);

        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer_addr, runtime).await {
                tracing::debug!("connection error ({}): {}", peer_addr, e);
            }
        });
    }
}

async fn handle_conn(
    stream: tokio_tfo::TfoStream,
    peer_addr: std::net::SocketAddr,
    runtime: RelayRuntime,
) -> Result<()> {
    core::handle_stream(stream, peer_addr, runtime).await
}
