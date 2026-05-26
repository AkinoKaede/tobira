use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::Result;

use crate::config::{RelayConfig, RelayNetwork};
use crate::relay::runtime::RelayRuntime;

pub type InboundFuture = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

#[derive(Clone)]
pub struct InboundContext {
    pub addr: SocketAddr,
    pub runtime: RelayRuntime,
}

pub trait Inbound: Send + 'static {
    fn run(self: Box<Self>, ctx: InboundContext) -> InboundFuture;
}

pub mod grpc;
pub mod tcp;

pub fn from_config(config: &RelayConfig) -> Box<dyn Inbound> {
    match config.network {
        RelayNetwork::Tcp => Box::new(tcp::TcpInbound),
        RelayNetwork::Grpc => Box::new(grpc::GrpcInbound {
            service_name: config.service_name.clone(),
        }),
    }
}
