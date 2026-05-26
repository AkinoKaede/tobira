use std::sync::Arc;

use tokio::sync::RwLock;

use crate::relay::transport::grpc::GrpcPool;
use crate::vmess::validator::Validator;

#[derive(Clone)]
pub struct RelayRuntime {
    pub validator: Arc<RwLock<Validator>>,
    pub grpc_pool: Arc<GrpcPool>,
}

impl RelayRuntime {
    pub fn new(validator: Arc<RwLock<Validator>>, grpc_pool: Arc<GrpcPool>) -> Self {
        Self {
            validator,
            grpc_pool,
        }
    }
}
