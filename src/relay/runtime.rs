use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::relay::transport::grpc::GrpcPool;
use crate::vmess::validator::Validator;

#[derive(Clone)]
pub struct RelayRuntime {
    pub validator: Arc<RwLock<Validator>>,
    pub grpc_pool: Arc<GrpcPool>,
    pub relay_idle_timeout: Arc<RwLock<Option<Duration>>>,
}

impl RelayRuntime {
    pub fn new(
        validator: Arc<RwLock<Validator>>,
        grpc_pool: Arc<GrpcPool>,
        relay_idle_timeout: Option<Duration>,
    ) -> Self {
        Self {
            validator,
            grpc_pool,
            relay_idle_timeout: Arc::new(RwLock::new(relay_idle_timeout)),
        }
    }

    pub async fn set_relay_idle_timeout(&self, relay_idle_timeout: Option<Duration>) {
        *self.relay_idle_timeout.write().await = relay_idle_timeout;
    }
}
