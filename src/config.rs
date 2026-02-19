use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Tracing filter string, e.g. "info", "debug", "tobira=debug,h2=warn".
    /// Overridden by the RUST_LOG environment variable.
    /// Defaults to "info" if absent.
    #[serde(default = "default::log_level")]
    pub log_level: String,
    pub relay: RelayConfig,
    pub http: HttpConfig,
    pub subscription: SubscriptionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    #[serde(default = "default::relay::listen")]
    pub listen: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpConfig {
    #[serde(default = "default::http::listen")]
    pub listen: String,
    #[serde(default = "default::http::port")]
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

mod default {
    pub fn log_level() -> String {
        "info".to_string()
    }

    pub mod relay {
        /// Dual-stack wildcard: accepts both IPv4 and IPv6 connections on Linux
        /// (requires net.ipv6.bindv6only = 0, which is the kernel default).
        /// Bracketed so that `format!("{}:{}", listen, port)` produces `[::]:port`.
        pub fn listen() -> String {
            "[::]".to_string()
        }
    }

    pub mod http {
        pub fn listen() -> String {
            "[::]".to_string()
        }

        pub fn port() -> u16 {
            8080
        }
    }
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
