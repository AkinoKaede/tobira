/// Subscription manager — fetches, caches, and processes VMess subscriptions.
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

use crate::config::{SubscriptionConfig, SubscriptionSource};
use crate::subscription::parser::{self, VMessNode};
use crate::subscription::process::apply_pipeline;
use crate::vmess::validator::{Transport, Upstream, Validator};

// ──────────────────────────────────────────────────────────────────────────────
// Cache
// ──────────────────────────────────────────────────────────────────────────────

type CacheMap = HashMap<String, Vec<VMessNode>>;

fn load_cache(path: &str) -> CacheMap {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_cache(path: &str, cache: &CacheMap) {
    if let Ok(s) = serde_json::to_string(cache) {
        let _ = std::fs::write(path, s);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Fetch
// ──────────────────────────────────────────────────────────────────────────────

async fn fetch_source(source: &SubscriptionSource) -> Result<Vec<VMessNode>> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30));

    if let Some(ua) = &source.user_agent {
        builder = builder.user_agent(ua.as_str());
    }

    let client = builder.build()?;
    let resp = client.get(&source.url).send().await?;

    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {}", resp.status()));
    }

    let body = resp.text().await?;
    let raw_nodes = parser::parse_subscription(&body);
    let nodes = apply_pipeline(raw_nodes, &source.process);
    Ok(nodes)
}

// ──────────────────────────────────────────────────────────────────────────────
// Manager
// ──────────────────────────────────────────────────────────────────────────────

/// Shared subscription manager state.
pub struct SubscriptionManager {
    config: SubscriptionConfig,
    /// All nodes from all sources, keyed by source name.
    nodes_by_source: Arc<RwLock<HashMap<String, Vec<VMessNode>>>>,
    /// Flat list of all nodes (for HTTP subscription output).
    all_nodes: Arc<RwLock<Vec<VMessNode>>>,
}

impl SubscriptionManager {
    pub fn new(config: SubscriptionConfig) -> Self {
        Self {
            config,
            nodes_by_source: Arc::new(RwLock::new(HashMap::new())),
            all_nodes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Fetch all subscription sources, apply pipelines, update the shared state.
    /// Falls back to cached data when a source fails.
    pub async fn reload(&self) -> Result<()> {
        let cache_path = self.config.cache_file.as_deref();
        let mut cache: CacheMap = cache_path.map(load_cache).unwrap_or_default();

        let mut new_source_map: HashMap<String, Vec<VMessNode>> = HashMap::new();

        for source in &self.config.sources {
            match fetch_source(source).await {
                Ok(nodes) => {
                    tracing::info!(
                        "fetched {} nodes from source {:?}",
                        nodes.len(),
                        source.name
                    );
                    cache.insert(source.name.clone(), nodes.clone());
                    new_source_map.insert(source.name.clone(), nodes);
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to fetch source {:?}: {} — using cache",
                        source.name,
                        e
                    );
                    if let Some(cached) = cache.get(&source.name) {
                        new_source_map.insert(source.name.clone(), cached.clone());
                    }
                }
            }
        }

        // Persist cache
        if let Some(path) = cache_path {
            save_cache(path, &cache);
        }

        // Update shared state
        let all: Vec<VMessNode> =
            new_source_map.values().flat_map(|v| v.iter().cloned()).collect();

        {
            let mut nodes_by_source = self.nodes_by_source.write().await;
            *nodes_by_source = new_source_map;
        }
        {
            let mut all_nodes = self.all_nodes.write().await;
            *all_nodes = all;
        }

        Ok(())
    }

    /// Build a new `Validator` from all currently loaded nodes.
    ///
    /// Each node's UUID is paired with an upstream derived from its server/port/transport.
    pub async fn build_validator(&self) -> Result<Validator> {
        let nodes = self.all_nodes.read().await;
        let mut pairs: Vec<(String, Arc<Upstream>)> = Vec::new();

        for node in nodes.iter() {
            let transport = node_transport(node);
            let addr = format!("{}:{}", node.server, node.port);
            let upstream = Arc::new(Upstream {
                addr,
                transport,
                tcp_fast_open: false,
            });
            pairs.push((node.uuid.clone(), upstream));
        }

        Validator::new(pairs)
    }

    /// Return a clone of all currently loaded nodes.
    pub async fn all_nodes(&self) -> Vec<VMessNode> {
        self.all_nodes.read().await.clone()
    }
}

fn node_transport(node: &VMessNode) -> Transport {
    if node.network == "grpc" {
        Transport::Grpc {
            service_name: node.grpc_service_name.clone().unwrap_or_default(),
            tls_sni: node.sni.clone(),
        }
    } else {
        Transport::Tcp
    }
}
