/// VMess+TCP inbound listener.
///
/// Accepts TCP connections, reads the first 16 bytes (Auth ID), looks up the
/// matching upstream in the validator, then relays the connection.
///
/// On auth failure: drain a random amount of data before closing (prevents
/// timing-based fingerprinting).
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use tokio_tfo::TfoListener;

use crate::buf as buf_pool;
use crate::relay::{outbound_grpc, outbound_tcp};
use crate::vmess::validator::{Transport, Validator};

/// Start the relay listener.
///
/// `validator`: shared, hot-reloadable routing table.
/// `grpc_pool`: shared gRPC connection pool.
pub async fn run(
    addr: std::net::SocketAddr,
    validator: Arc<RwLock<Validator>>,
    grpc_pool: Arc<outbound_grpc::GrpcPool>,
) -> Result<()> {
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

        let validator = validator.clone();
        let grpc_pool = grpc_pool.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer_addr, validator, grpc_pool).await {
                tracing::debug!("connection error ({}): {}", peer_addr, e);
            }
        });
    }
}

async fn handle_conn(
    mut stream: tokio_tfo::TfoStream,
    peer_addr: std::net::SocketAddr,
    validator: Arc<RwLock<Validator>>,
    grpc_pool: Arc<outbound_grpc::GrpcPool>,
) -> Result<()> {
    // Read the first 16 bytes (VMess Auth ID)
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await?;

    // Lookup upstream
    let upstream = {
        let v = validator.read().await;
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

    match &upstream.transport {
        Transport::Tcp => {
            outbound_tcp::relay_tcp(stream, upstream, initial_data, peer_addr).await?;
        }
        Transport::Grpc { .. } => {
            outbound_grpc::relay_grpc(stream, upstream, grpc_pool, initial_data, peer_addr).await?;
        }
    }

    Ok(())
}

/// Drain a random number of bytes from `stream` then close it.
/// This makes auth-failure behavior indistinguishable from a legitimate (but
/// slow) connection to an observer measuring response time.
async fn drain_and_close(mut stream: tokio_tfo::TfoStream) {
    let drain_len = rand::thread_rng().gen_range(64usize..512);
    let mut buf = buf_pool::get(drain_len);
    buf.resize(drain_len, 0);
    // Best-effort read; ignore errors
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    buf_pool::put(buf);
}
