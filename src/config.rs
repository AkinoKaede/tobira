use anyhow::Result;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub relay: RelayConfig,
    pub http: HttpConfig,
    pub subscription: SubscriptionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    #[allow(dead_code)]
    pub tcp_fast_open: bool,
    #[serde(default = "default_true")]
    #[allow(dead_code)]
    pub anti_replay: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpConfig {
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<HttpUser>,
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,
}

/// An HTTP Basic Auth user with optional output restrictions.
/// `outputs = None` means access to all outputs.
/// `outputs = Some([...])` means access to only the named outputs.
#[derive(Debug, Deserialize, Clone)]
pub struct HttpUser {
    pub username: String,
    pub password: String,
    pub outputs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub security: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionConfig {
    pub cache_file: Option<String>,
    #[serde(default)]
    pub sources: Vec<SubscriptionSource>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionSource {
    pub name: String,
    pub url: String,
    pub user_agent: Option<String>,
    #[serde(default)]
    pub process: Vec<ProcessStep>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProcessStep {
    Rename {
        rules: Vec<[String; 2]>,
    },
    Filter {
        patterns: Vec<String>,
    },
    Exclude {
        patterns: Vec<String>,
    },
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
