use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RelayNetwork {
    Tcp,
    Grpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketEncoding {
    #[default]
    Default,
    PacketAddr,
    Xudp,
}

impl PacketEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::PacketAddr => "packetaddr",
            Self::Xudp => "xudp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "" | "default" | "none" => Some(Self::Default),
            "packetaddr" | "packet_addr" | "packet-addr" => Some(Self::PacketAddr),
            "xudp" => Some(Self::Xudp),
            _ => None,
        }
    }
}

impl Serialize for PacketEncoding {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PacketEncoding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(
                "packet_encoding must be one of \"\", \"none\", \"packetaddr\", or \"xudp\"",
            )
        })
    }
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
    /// Relay idle timeout in seconds. 0 disables idle reaping.
    #[serde(default)]
    pub idle_timeout: u64,
    /// Cached outbound gRPC H2 connection idle timeout in seconds.
    /// 0 disables idle pruning of cached gRPC connections.
    #[serde(default)]
    pub grpc_pool_idle_timeout: u64,
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
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
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
            idle_timeout: 0,
            grpc_pool_idle_timeout: 0,
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

#[derive(Debug, Clone)]
pub struct SubscriptionSource {
    pub name: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub user_agent: String,
    pub process: Vec<ProcessStep>,
}

impl<'de> Deserialize<'de> for SubscriptionSource {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawSubscriptionSource {
            name: String,
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default = "default::subscription::user_agent")]
            user_agent: String,
            #[serde(default)]
            process: Vec<ProcessStep>,
        }

        let raw = RawSubscriptionSource::deserialize(deserializer)?;
        let url = raw.url.filter(|s| !s.trim().is_empty());
        let path = raw.path.filter(|s| !s.trim().is_empty());

        match (url.is_some(), path.is_some()) {
            (true, false) | (false, true) => Ok(Self {
                name: raw.name,
                url,
                path,
                user_agent: raw.user_agent,
                process: raw.process,
            }),
            (true, true) => Err(serde::de::Error::custom(
                "subscription source must set only one of `url` or `path`",
            )),
            (false, false) => Err(serde::de::Error::custom(
                "subscription source must set either `url` or `path`",
            )),
        }
    }
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
/// - `packet_encoding` → replace the node's packet encoding (`""`, `"none"`, `"packetaddr"`, `"xudp"`)
///
/// Example (TOML):
/// ```toml
/// process = [
///   { filter_source = ["free_sub"], remove = true },
///   { filter = ["(?i)expired"], remove = true },
///   { remove_emoji = true, rename = [["^US ", "美国 "]] },
///   { override_security = "aes-128-gcm" },
///   { packet_encoding = "xudp" },
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
    #[serde(default, alias = "packetencoding", alias = "packet-encoding")]
    pub packet_encoding: Option<PacketEncoding>,
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
    let mut config: Config = toml::from_str(&content)?;
    resolve_local_source_paths(&mut config, path);
    Ok(config)
}

fn resolve_local_source_paths(config: &mut Config, config_path: &str) {
    let config_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));

    for source in &mut config.subscription.sources {
        let Some(path) = &mut source.path else {
            continue;
        };

        let source_path = Path::new(path);
        if source_path.is_absolute() {
            continue;
        }

        *path = config_dir.join(source_path).to_string_lossy().into_owned();
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{load, Config};

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
        assert_eq!(cfg.relay.idle_timeout, 0);
        assert_eq!(cfg.relay.grpc_pool_idle_timeout, 0);
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
        assert_eq!(cfg.relay.grpc_pool_idle_timeout, 0);
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
        assert_eq!(cfg.relay.idle_timeout, 0);
        assert_eq!(cfg.relay.grpc_pool_idle_timeout, 0);
    }

    #[test]
    fn parse_relay_timeouts() {
        let text = r#"
[relay]
idle_timeout = 300
grpc_pool_idle_timeout = 60
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(cfg.relay.idle_timeout, 300);
        assert_eq!(cfg.relay.grpc_pool_idle_timeout, 60);
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

    #[test]
    fn output_parses_skip_cert_verify() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 443
skip-cert-verify = true
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert!(cfg.http.outputs[0].skip_cert_verify);
    }

    #[test]
    fn output_process_parses_packet_encoding() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 443

[[http.outputs.process]]
packet_encoding = "packetaddr"
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(
            cfg.http.outputs[0].process[0].packet_encoding,
            Some(super::PacketEncoding::PacketAddr)
        );
    }

    #[test]
    fn output_process_accepts_packetencoding_alias() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 443

[[http.outputs.process]]
packetencoding = "xudp"
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(
            cfg.http.outputs[0].process[0].packet_encoding,
            Some(super::PacketEncoding::Xudp)
        );
    }

    #[test]
    fn output_process_parses_packet_encoding_none() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 443

[[http.outputs.process]]
packet_encoding = "none"
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(
            cfg.http.outputs[0].process[0].packet_encoding,
            Some(super::PacketEncoding::Default)
        );
    }

    #[test]
    fn output_process_rejects_unknown_packet_encoding() {
        let text = r#"
[[http.outputs]]
name = "main"
host = "relay.example.com"
port = 443

[[http.outputs.process]]
packet_encoding = "bad"
"#;
        let err = toml::from_str::<Config>(text).expect_err("invalid packet_encoding");
        assert!(err.to_string().contains("packet_encoding must be one of"));
    }

    #[test]
    fn subscription_source_accepts_url_or_path() {
        let text = r#"
[[subscription.sources]]
name = "remote"
url = "https://example.com/sub"

[[subscription.sources]]
name = "local"
path = "/tmp/sub.txt"
"#;
        let cfg: Config = toml::from_str(text).expect("config should parse");
        assert_eq!(
            cfg.subscription.sources[0].url.as_deref(),
            Some("https://example.com/sub")
        );
        assert_eq!(
            cfg.subscription.sources[1].path.as_deref(),
            Some("/tmp/sub.txt")
        );
    }

    #[test]
    fn subscription_source_rejects_missing_location() {
        let text = r#"
[[subscription.sources]]
name = "broken"
"#;
        let err = toml::from_str::<Config>(text).expect_err("source location is required");
        assert!(err
            .to_string()
            .contains("subscription source must set either `url` or `path`"));
    }

    #[test]
    fn subscription_source_rejects_multiple_locations() {
        let text = r#"
[[subscription.sources]]
name = "broken"
url = "https://example.com/sub"
path = "/tmp/sub.txt"
"#;
        let err = toml::from_str::<Config>(text).expect_err("source location must be unique");
        assert!(err
            .to_string()
            .contains("subscription source must set only one of `url` or `path`"));
    }

    #[test]
    fn load_resolves_relative_subscription_path_from_config_dir() {
        let dir = temp_config_dir("relative-source-path");
        std::fs::create_dir_all(&dir).expect("create temp config dir");
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[[subscription.sources]]
name = "local"
path = "subs/local.txt"
"#,
        )
        .expect("write config");

        let cfg = load(config_path.to_str().expect("utf-8 config path")).expect("load config");

        assert_eq!(
            cfg.subscription.sources[0].path.as_deref(),
            Some(
                dir.join("subs/local.txt")
                    .to_str()
                    .expect("utf-8 source path")
            )
        );

        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_keeps_absolute_subscription_path() {
        let dir = temp_config_dir("absolute-source-path");
        std::fs::create_dir_all(&dir).expect("create temp config dir");
        let config_path = dir.join("config.toml");
        let source_path = dir.join("local.txt");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[subscription.sources]]
name = "local"
path = "{}"
"#,
                source_path.to_string_lossy()
            ),
        )
        .expect("write config");

        let cfg = load(config_path.to_str().expect("utf-8 config path")).expect("load config");

        assert_eq!(
            cfg.subscription.sources[0].path.as_deref(),
            Some(source_path.to_str().expect("utf-8 source path"))
        );

        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn temp_config_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("tobira-{name}-{}-{nanos}", std::process::id()))
    }
}
