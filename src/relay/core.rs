/// Shared VMess inbound routing.
///
/// Reads the VMess Auth ID from an inbound byte stream, selects the configured
/// upstream, then relays the stream to either TCP or gRPC outbound transport.
use anyhow::Result;
use bytes::Bytes;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::buf as buf_pool;
use crate::relay::outbound::{self, OutboundContext};
use crate::relay::runtime::RelayRuntime;

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
    stream.read_exact(&mut auth_id).await?;

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

    let initial_data = Bytes::copy_from_slice(&auth_id);

    let outbound = outbound::from_transport(&upstream.transport);
    let ctx = OutboundContext {
        upstream,
        initial_data,
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
    let drain_len = rand::thread_rng().gen_range(64usize..512);
    let mut buf = buf_pool::get(drain_len);
    buf.resize(drain_len, 0);
    // Best-effort read; ignore errors
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    buf_pool::put(buf);
}
