/// TCP outbound relay.
///
/// Connects to the upstream via TCP (with TCP Fast Open), writes the
/// initial buffered bytes (the auth ID that was already read), then performs
/// bidirectional copy between inbound and upstream.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_tfo::TfoStream;

use crate::relay::activity::copy_bidirectional_with_idle_timeout;
use crate::relay::outbound::{InboundStream, Outbound, OutboundContext, OutboundFuture};
use crate::vmess::validator::Upstream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TcpOutbound;

impl Outbound for TcpOutbound {
    fn relay(
        self: Box<Self>,
        inbound: Box<dyn InboundStream>,
        ctx: OutboundContext,
    ) -> OutboundFuture {
        Box::pin(async move {
            let idle_timeout = *ctx.runtime.relay_idle_timeout.read().await;
            relay_tcp(inbound, ctx.upstream, ctx.auth_id, ctx.peer, idle_timeout).await
        })
    }
}

async fn relay_tcp(
    mut inbound: impl InboundStream,
    upstream: Arc<Upstream>,
    auth_id: [u8; 16],
    peer: std::net::SocketAddr,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    // Connect to upstream
    tracing::info!("{} → {} [tcp] connecting", peer, upstream.addr);
    let mut outbound = timeout(CONNECT_TIMEOUT, TfoStream::connect(upstream.parsed_addr))
        .await
        .map_err(|_| anyhow!("connect timeout: {}", upstream.addr))??;
    outbound.set_nodelay(true)?;
    tracing::debug!("{} → {} [tcp] connected", peer, upstream.addr);

    // Write the initial buffered bytes (auth ID + any peeked bytes)
    timeout(INITIAL_WRITE_TIMEOUT, outbound.write_all(&auth_id))
        .await
        .map_err(|_| anyhow!("initial write timeout: {}", upstream.addr))??;

    // Bidirectional copy
    let started = std::time::Instant::now();
    let (up, down) = if let Some(idle_timeout) = idle_timeout {
        match copy_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, idle_timeout).await
        {
            Ok(counts) => counts,
            Err(e) => {
                tracing::debug!(
                    "{} -> {} [tcp] idle/error closing relay: {}",
                    peer,
                    upstream.addr,
                    e
                );
                return Err(e);
            }
        }
    } else {
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?
    };
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
