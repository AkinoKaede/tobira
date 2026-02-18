/// TCP outbound relay.
///
/// Connects to the upstream via TCP (with optional TCP Fast Open), writes the
/// initial buffered bytes (the auth ID that was already read), then performs
/// bidirectional copy between inbound and upstream.
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio_tfo::TfoStream;

use crate::vmess::validator::Upstream;

pub async fn relay_tcp(
    mut inbound: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    upstream: Arc<Upstream>,
    initial_data: Bytes,
) -> Result<()> {
    // Connect to upstream
    let addr: std::net::SocketAddr = upstream.addr.parse()?;
    let mut outbound = TfoStream::connect(addr).await?;

    // Write the initial buffered bytes (auth ID + any peeked bytes)
    outbound.write_all(&initial_data).await?;

    // Bidirectional copy
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;

    Ok(())
}
