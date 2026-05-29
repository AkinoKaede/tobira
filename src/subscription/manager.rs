/// Subscription manager — fetches, caches, and processes VMess subscriptions.
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

use crate::config::{SubscriptionConfig, SubscriptionSource};
use crate::subscription::parser::{self, VMessNode};
use crate::subscription::process::{apply_pipeline, deduplicate_nodes};
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
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));

    builder = builder.user_agent(source.user_agent.as_str());

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
    /// Wrapped in `Arc` so readers can take a snapshot with a single refcount bump
    /// instead of cloning the entire `Vec`.
    all_nodes: Arc<RwLock<Arc<Vec<VMessNode>>>>,
}

impl SubscriptionManager {
    pub fn new(config: SubscriptionConfig) -> Self {
        Self {
            config,
            nodes_by_source: Arc::new(RwLock::new(HashMap::new())),
            all_nodes: Arc::new(RwLock::new(Arc::new(Vec::new()))),
        }
    }

    /// Fetch all subscription sources, apply pipelines, update the shared state.
    /// Falls back to cached data when a source fails.
    pub async fn reload(&self) -> Result<()> {
        let cache_path = self.config.cache_file.as_deref();
        let mut cache: CacheMap = cache_path.map(load_cache).unwrap_or_default();

        let mut new_source_map: HashMap<String, Vec<VMessNode>> = HashMap::new();

        for source in &self.config.sources {
            // Hoist the Arc<str> creation out of the per-node loop so each node
            // assignment is just a refcount bump instead of a string allocation.
            let source_name: Arc<str> = Arc::from(source.name.as_str());
            match fetch_source(source).await {
                Ok(mut nodes) => {
                    for node in &mut nodes {
                        node.source = source_name.clone();
                    }
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
                        let mut nodes = cached.clone();
                        for node in &mut nodes {
                            node.source = source_name.clone();
                        }
                        new_source_map.insert(source.name.clone(), nodes);
                    }
                }
            }
        }

        // Persist cache
        if let Some(path) = cache_path {
            save_cache(path, &cache);
        }

        // Update shared state — iterate over sources in config order to get deterministic
        // ordering for first/last deduplication strategies.
        let all: Vec<VMessNode> = self
            .config
            .sources
            .iter()
            .flat_map(|s| {
                new_source_map
                    .get(&s.name)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[])
                    .iter()
                    .cloned()
            })
            .collect();
        let all = deduplicate_nodes(all, &self.config.deduplication);

        {
            let mut nodes_by_source = self.nodes_by_source.write().await;
            *nodes_by_source = new_source_map;
        }
        {
            let mut all_nodes = self.all_nodes.write().await;
            *all_nodes = Arc::new(all);
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
            let addr = format!("{}:{}", node.server, node.port);
            let parsed_addr: std::net::SocketAddr = addr.parse()?;
            let transport = node_transport(node, parsed_addr.port())?;
            let upstream = Arc::new(Upstream {
                addr,
                parsed_addr,
                transport,
                tcp_fast_open: false,
            });
            pairs.push((node.uuid.clone(), upstream));
        }

        Validator::new(pairs)
    }

    /// Return a snapshot of all currently loaded nodes.
    ///
    /// Returns an `Arc<Vec<VMessNode>>` so callers share the underlying data;
    /// the lock is only held for the duration of a single `Arc::clone`.
    pub async fn all_nodes(&self) -> Arc<Vec<VMessNode>> {
        self.all_nodes.read().await.clone()
    }
}

fn node_transport(node: &VMessNode, port: u16) -> Result<Transport> {
    if node.network == "grpc" {
        let service_name = node.grpc_service_name.clone().unwrap_or_default();
        let tls_sni = node.sni.clone();
        let request_uri = format!("https://{}:{}/{}/Tun", tls_sni, port, service_name)
            .parse()
            .map_err(|e| anyhow!("build gRPC request URI: {}", e))?;
        Ok(Transport::Grpc {
            service_name,
            tls_sni,
            request_uri,
        })
    } else {
        Ok(Transport::Tcp)
    }
}
