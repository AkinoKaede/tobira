use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RelayNetwork {
    Tcp,
    Grpc,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Tracing filter string, e.g. "info", "debug", "tobira=debug,h2=warn".
    /// Overridden by the RUST_LOG environment variable.
    /// Defaults to "info" if absent.
    #[serde(default = "default::log_level")]
    pub log_level: String,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub subscription: SubscriptionConfig,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct RelayConfig {
    #[serde(default = "default::relay::listen")]
    pub listen: String,
    #[serde(default = "default::relay::port")]
    pub port: u16,
    #[serde(default = "default::relay::network")]
    pub network: RelayNetwork,
    #[serde(default = "default::relay::service_name")]
    pub service_name: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
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
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub process: Vec<ProcessStep>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct SubscriptionConfig {
    pub cache_file: Option<String>,
    /// Automatic subscription update interval in seconds.
    /// Periodically re-fetches all subscription sources without re-reading the config file.
    /// 0 or absent disables the timer.
    #[serde(default)]
    pub update_interval: u64,
    #[serde(default)]
    pub sources: Vec<SubscriptionSource>,
    /// Deduplication strategy for nodes with the same name across all sources.
    /// - `"rename"` (default): keep all, append " (1)", " (2)" suffixes
    /// - `"first"`:  keep the first occurrence
    /// - `"last"`:   keep the last occurrence
    /// - `"prefer_ipv4"`:            IPv4 > Domain > IPv6
    /// - `"prefer_ipv6"`:            IPv6 > Domain > IPv4
    /// - `"prefer_domain_then_ipv4"`: Domain > IPv4 > IPv6
    /// - `"prefer_domain_then_ipv6"`: Domain > IPv6 > IPv4
    #[serde(default = "default::deduplication")]
    pub deduplication: String,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            cache_file: None,
            update_interval: 0,
            sources: Vec::new(),
            deduplication: default::deduplication(),
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: default::relay::listen(),
            port: default::relay::port(),
            network: default::relay::network(),
            service_name: default::relay::service_name(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: default::http::listen(),
            port: default::http::port(),
            users: Vec::new(),
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionSource {
    pub name: String,
    pub url: String,
    #[serde(default = "default::subscription::user_agent")]
    pub user_agent: String,
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

    pub fn deduplication() -> String {
        "rename".to_string()
    }

    pub mod subscription {
        pub fn user_agent() -> String {
            concat!(
                "tobira/",
                env!("CARGO_PKG_VERSION_MAJOR"),
                ".",
                env!("CARGO_PKG_VERSION_MINOR"),
                " (like dae/1.0) (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)"
            )
            .to_string()
        }
    }

    pub mod relay {
        /// Dual-stack wildcard: accepts both IPv4 and IPv6 connections on Linux
        /// (requires net.ipv6.bindv6only = 0, which is the kernel default).
        /// Bracketed so that `format!("{}:{}", listen, port)` produces `[::]:port`.
        pub fn listen() -> String {
            "[::]".to_string()
        }

        pub fn port() -> u16 {
            10808
        }

        pub fn network() -> super::super::RelayNetwork {
            super::super::RelayNetwork::Tcp
        }

        pub fn service_name() -> String {
            "GunService".to_string()
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

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parse_defaults_for_omitted_listen_and_http_port() {
        let text = r#"
[relay]
port = 12204

[http]

[subscription]
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(cfg.relay.listen, "[::]");
        assert_eq!(cfg.relay.port, 12204);
        assert_eq!(cfg.relay.network, super::RelayNetwork::Tcp);
        assert_eq!(cfg.relay.service_name, "GunService");
        assert_eq!(cfg.http.listen, "[::]");
        assert_eq!(cfg.http.port, 8080);
    }

    #[test]
    fn parse_defaults_when_sections_omitted() {
        let text = r#"
[subscription]
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(cfg.relay.listen, "[::]");
        assert_eq!(cfg.relay.port, 10808);
        assert_eq!(cfg.relay.network, super::RelayNetwork::Tcp);
        assert_eq!(cfg.relay.service_name, "GunService");
        assert_eq!(cfg.http.listen, "[::]");
        assert_eq!(cfg.http.port, 8080);
        assert_eq!(cfg.subscription.update_interval, 0);
        assert!(cfg.subscription.sources.is_empty());
    }

    #[test]
    fn parse_grpc_relay_network_with_default_service_name() {
        let text = r#"
[relay]
network = "grpc"
port = 1443
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(cfg.relay.network, super::RelayNetwork::Grpc);
        assert_eq!(cfg.relay.port, 1443);
        assert_eq!(cfg.relay.service_name, "GunService");
    }

    #[test]
    fn output_rejects_transport_overrides() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 10808
network = "grpc"
tls = true
"#;
        let err = toml::from_str::<Config>(text).expect_err("output transport is relay-scoped");
        let message = err.to_string();
        assert!(message.contains("unknown field"));
    }
}
