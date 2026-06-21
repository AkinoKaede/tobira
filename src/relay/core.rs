/// Shared VMess inbound routing.
///
/// Reads the VMess Auth ID from an inbound byte stream, selects the configured
/// upstream, then relays the stream to either TCP or gRPC outbound transport.
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::timeout;

use crate::buf as buf_pool;
use crate::relay::outbound::{self, OutboundContext};
use crate::relay::runtime::RelayRuntime;
use crate::vmess::validator::Upstream;

const AUTH_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn handle_stream<S>(
    mut stream: S,
    peer_addr: std::net::SocketAddr,
    runtime: RelayRuntime,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read the first 16 bytes (VMess Auth ID)
    let mut auth_id = [0u8; 16];
    timeout(AUTH_READ_TIMEOUT, stream.read_exact(&mut auth_id)).await??;

    // Lookup upstream
    let upstream = {
        let v = runtime.validator.read().await;
        v.match_auth_id(&auth_id)
    };

    let upstream = match upstream {
        Some(u) => u,
        None => {
            // Auth failed — drain random bytes to prevent timing attacks
            tracing::debug!("{} auth failed — draining and closing", peer_addr);
            drain_and_close(stream).await;
            return Ok(());
        }
    };

    relay_authenticated_stream(stream, peer_addr, runtime, upstream, auth_id).await
}

pub(crate) async fn relay_authenticated_stream<S>(
    stream: S,
    peer_addr: std::net::SocketAddr,
    runtime: RelayRuntime,
    upstream: Arc<Upstream>,
    auth_id: [u8; 16],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let outbound = outbound::from_transport(&upstream.transport);
    let ctx = OutboundContext {
        upstream,
        auth_id,
        peer: peer_addr,
        runtime,
    };
    outbound.relay(Box::new(stream), ctx).await?;
    Ok(())
}

/// Drain a random number of bytes from `stream` then close it.
/// This makes auth-failure behavior indistinguishable from a legitimate (but
/// slow) connection to an observer measuring response time.
async fn drain_and_close<S>(mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use bytes::BufMut;

    let drain_len = rand::random_range(64usize..512);
    let mut buf = buf_pool::get(drain_len);
    // `read_buf` writes through `BufMut` into the pooled buffer's spare
    // capacity, so it doesn't need to be zero-initialized first.
    // Cap at `drain_len` so the read length isn't influenced by the pool's
    // size class (preserves timing-defense semantics).
    let mut limited = (&mut buf).limit(drain_len);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_buf(&mut limited),
    )
    .await;
    buf_pool::put(buf);
}
