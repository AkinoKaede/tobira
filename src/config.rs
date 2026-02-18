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
    #[serde(default)]
    pub process: Vec<ProcessStep>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionConfig {
    pub cache_file: Option<String>,
    /// Automatic subscription update interval in seconds.
    /// Periodically re-fetches all subscription sources without re-reading the config file.
    /// 0 or absent disables the timer.
    #[serde(default)]
    pub update_interval: u64,
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

/// A single step in the subscription processing pipeline.
///
/// Selection: a node is "selected" if it matches `filter` (by name) AND `filter_source`
/// (by subscription source). An empty list means "match all".
/// If `invert` is true, the selection is inverted.
///
/// Actions applied to selected nodes:
/// - `remove = true`  → remove the selected nodes from the list entirely
/// - `rename`         → apply regex rename rules to the node's name
/// - `remove_emoji`   → strip emoji characters from the node's name
/// - `override_security` → replace the node's security field
///
/// Example (TOML):
/// ```toml
/// process = [
///   { filter_source = ["free_sub"], remove = true },
///   { filter = ["(?i)expired"], remove = true },
///   { remove_emoji = true, rename = [["^US ", "美国 "]] },
///   { override_security = "aes-128-gcm" },
/// ]
/// ```
#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct ProcessStep {
    #[serde(default)]
    pub filter: Vec<String>,
    #[serde(default)]
    pub filter_source: Vec<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub remove: bool,
    #[serde(default)]
    pub rename: Vec<[String; 2]>,
    #[serde(default)]
    pub remove_emoji: bool,
    #[serde(default)]
    pub override_security: Option<String>,
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
