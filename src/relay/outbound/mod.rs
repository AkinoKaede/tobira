use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay::runtime::RelayRuntime;
use crate::vmess::validator::Transport;
use crate::vmess::validator::Upstream;

pub mod grpc;
pub mod tcp;

pub trait InboundStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> InboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type OutboundFuture = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

pub struct OutboundContext {
    pub upstream: Arc<Upstream>,
    /// The 16-byte VMess Auth ID already consumed from the inbound stream.
    /// Passed by value to avoid a heap copy on every connection.
    pub auth_id: [u8; 16],
    pub peer: SocketAddr,
    pub runtime: RelayRuntime,
}

pub trait Outbound: Send + 'static {
    fn relay(
        self: Box<Self>,
        inbound: Box<dyn InboundStream>,
        ctx: OutboundContext,
    ) -> OutboundFuture;
}

pub fn from_transport(transport: &Transport) -> Box<dyn Outbound> {
    match transport {
        Transport::Tcp => Box::new(tcp::TcpOutbound),
        Transport::Grpc { .. } => Box::new(grpc::GrpcOutbound),
    }
}
