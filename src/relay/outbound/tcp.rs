/// TCP outbound relay.
///
/// Connects to the upstream via TCP (with TCP Fast Open), writes the
/// initial buffered bytes (the auth ID that was already read), then performs
/// bidirectional copy between inbound and upstream.
use std::sync::Arc;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio_tfo::TfoStream;

use crate::relay::outbound::{InboundStream, Outbound, OutboundContext, OutboundFuture};
use crate::vmess::validator::Upstream;

pub struct TcpOutbound;

impl Outbound for TcpOutbound {
    fn relay(
        self: Box<Self>,
        inbound: Box<dyn InboundStream>,
        ctx: OutboundContext,
    ) -> OutboundFuture {
        Box::pin(async move { relay_tcp(inbound, ctx.upstream, ctx.auth_id, ctx.peer).await })
    }
}

async fn relay_tcp(
    mut inbound: impl InboundStream,
    upstream: Arc<Upstream>,
    auth_id: [u8; 16],
    peer: std::net::SocketAddr,
) -> Result<()> {
    // Connect to upstream
    tracing::info!("{} → {} [tcp] connecting", peer, upstream.addr);
    let mut outbound = TfoStream::connect(upstream.parsed_addr).await?;
    tracing::debug!("{} → {} [tcp] connected", peer, upstream.addr);

    // Write the initial buffered bytes (auth ID + any peeked bytes)
    outbound.write_all(&auth_id).await?;

    // Bidirectional copy
    let started = std::time::Instant::now();
    let (up, down) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    tracing::info!(
        "{} → {} [tcp] closed (↑{} ↓{} B, {:.2}s)",
        peer,
        upstream.addr,
        up,
        down,
        started.elapsed().as_secs_f64(),
    );

    Ok(())
}
