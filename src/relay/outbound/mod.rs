use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
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
    pub initial_data: Bytes,
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
