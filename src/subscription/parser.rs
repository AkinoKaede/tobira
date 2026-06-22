/// VMess node parsed from a subscription link.
///
/// Supports three link formats (ported from yori's link_vmess.go):
///   1. `vmess://base64(json)` — v2rayN JSON format
///   2. `vmess://uuid@host:port?params` — URL format
///   3. `vmess://base64(method:uuid@host:port)?params` — Shadowrocket format
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::PacketEncoding;

/// A parsed VMess proxy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMessNode {
    pub name: String,
    /// Subscription source name this node came from.
    #[serde(default = "empty_source")]
    pub source: Arc<str>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u32,
    /// Encryption algorithm: "aes-128-gcm", "chacha20-poly1305", "none", "auto", etc.
    pub security: String,
    /// Transport layer: "tcp", "ws", "grpc", "http", etc.
    pub network: String,
    pub tls: bool,
    pub sni: String,
    pub grpc_service_name: Option<String>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
}

fn empty_source() -> Arc<str> {
    Arc::from("")
}

// ──────────────────────────────────────────────────────────────────────────────
// StringOrInt — JSON field that can be a string or integer
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct StringOrInt(i64);

impl<'de> Deserialize<'de> for StringOrInt {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StringOrInt;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "an integer or a string representation of an integer")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StringOrInt(v))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StringOrInt(v as i64))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                if v.is_empty() {
                    return Ok(StringOrInt(0));
                }
                v.parse::<i64>()
                    .map(StringOrInt)
                    .map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_any(Visitor)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// v2rayN JSON format
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct V2rayNJson {
    #[serde(default)]
    #[allow(dead_code)]
    v: StringOrInt,
    #[serde(default)]
    ps: String,
    #[serde(default)]
    add: String,
    #[serde(default)]
    port: StringOrInt,
    #[serde(default)]
    id: String,
    #[serde(default)]
    aid: StringOrInt,
    #[serde(default)]
    net: String,
    #[serde(rename = "type", default)]
    #[allow(dead_code)]
    type_: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    scy: String,
    #[serde(default, rename = "packetEncoding", alias = "packetencoding")]
    packet_encoding: PacketEncoding,
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a `vmess://` link into a `VMessNode`.
/// Returns `Err` if the link is malformed or not a VMess link.
pub fn parse_vmess_link(link: &str) -> Result<VMessNode> {
    let link = link.trim();
    if !link.starts_with("vmess://") {
        return Err(anyhow!("not a vmess link"));
    }

    // Try URL parse first to detect format
    let parsed = Url::parse(link).map_err(|e| anyhow!("url parse: {}", e))?;

    if parsed.username().is_empty() {
        if parsed.query().is_some() {
            return parse_shadowrocket_format(link, &parsed);
        }
        parse_base64_json(link)
    } else {
        parse_url_format(&parsed)
    }
}

/// Parse a raw subscription body (newline-separated or base64 of newline-separated).
/// Returns only the successfully parsed VMess nodes; silently skips other protocols.
pub fn parse_subscription(body: &str) -> Vec<VMessNode> {
    // Try to base64-decode the whole body first (standard subscription format)
    let text = try_base64_decode(body.trim()).unwrap_or_else(|| body.to_string());

    tracing::debug!("parse_subscription: {} lines", text.lines().count());

    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("vmess://") {
                match parse_vmess_link(line) {
                    Ok(node) => Some(node),
                    Err(e) => {
                        tracing::debug!("skipped vmess link: {}: {:?}", e, line);
                        None
                    }
                }
            } else {
                None
            }
        })
        .collect()
}

fn try_base64_decode(s: &str) -> Option<String> {
    // Try various base64 encodings: standard/URL-safe, with/without padding.
    // Some subscription servers emit wrong padding (e.g. one `=` where two are
    // required); stripping all `=` and using NO_PAD engines handles that case.
    let s_stripped = s.trim_end_matches('=');
    macro_rules! try_decode {
        ($engine:expr, $data:expr) => {
            if let Ok(bytes) = $engine.decode($data.as_bytes()) {
                if let Ok(decoded) = String::from_utf8(bytes) {
                    return Some(decoded);
                }
            }
        };
    }
    try_decode!(general_purpose::STANDARD, s);
    try_decode!(general_purpose::STANDARD_NO_PAD, s_stripped);
    try_decode!(general_purpose::URL_SAFE, s);
    try_decode!(general_purpose::URL_SAFE_NO_PAD, s_stripped);
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Format 1: vmess://base64(json)
// ──────────────────────────────────────────────────────────────────────────────

fn parse_base64_json(link: &str) -> Result<VMessNode> {
    let encoded = &link["vmess://".len()..];
    let json_bytes = try_base64_decode(encoded)
        .ok_or_else(|| anyhow!("failed to base64-decode vmess payload"))?;
    let opts: V2rayNJson =
        serde_json::from_str(&json_bytes).map_err(|e| anyhow!("parse vmess json: {}", e))?;
    build_node(opts)
}

// ──────────────────────────────────────────────────────────────────────────────
// Format 2: vmess://uuid@host:port?params
// ──────────────────────────────────────────────────────────────────────────────

fn parse_url_format(u: &Url) -> Result<VMessNode> {
    let query: std::collections::HashMap<_, _> = u.query_pairs().collect();
    let opts = V2rayNJson {
        id: u.username().to_string(),
        add: u.host_str().unwrap_or("").to_string(),
        port: u.port().map(|p| StringOrInt(p as i64)).unwrap_or_default(),
        ps: query
            .get("remarks")
            .or_else(|| query.get("ps"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| u.fragment().unwrap_or("").to_string()),
        aid: StringOrInt(query.get("aid").and_then(|v| v.parse().ok()).unwrap_or(0)),
        // Standard URL format uses "type" for transport; fall back to legacy "net"
        net: query
            .get("type")
            .or_else(|| query.get("net"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "tcp".to_string()),
        type_: String::new(),
        host: query.get("host").map(|v| v.to_string()).unwrap_or_default(),
        // Standard URL format uses "path"; gRPC may also use "serviceName"
        path: query
            .get("path")
            .or_else(|| query.get("serviceName"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        // Standard URL format uses "security" (value "tls"); fall back to legacy "tls"
        tls: query
            .get("security")
            .or_else(|| query.get("tls"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        sni: query.get("sni").map(|v| v.to_string()).unwrap_or_default(),
        // Standard URL format may use "encryption"; fall back to legacy "scy"
        scy: query
            .get("encryption")
            .or_else(|| query.get("scy"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        packet_encoding: query
            .get("packetEncoding")
            .or_else(|| query.get("packetencoding"))
            .and_then(|v| PacketEncoding::parse(v))
            .unwrap_or_default(),
        ..Default::default()
    };
    build_node(opts)
}

// ──────────────────────────────────────────────────────────────────────────────
// Format 3: vmess://base64(method:uuid@host:port)?params
// ──────────────────────────────────────────────────────────────────────────────

fn parse_shadowrocket_format(link: &str, u: &Url) -> Result<VMessNode> {
    let encoded = link["vmess://".len()..]
        .split_once('?')
        .map(|(payload, _)| payload)
        .unwrap_or_else(|| u.path());
    let decoded = try_base64_decode(encoded)
        .ok_or_else(|| anyhow!("failed to base64-decode shadowrocket payload"))?;
    let (security, authority) = decoded
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid shadowrocket payload"))?;
    let parsed = Url::parse(&format!("vmess://{}", authority))
        .map_err(|e| anyhow!("shadowrocket payload url parse: {}", e))?;
    let query: std::collections::HashMap<_, _> = u.query_pairs().collect();
    let network = query
        .get("obfs")
        .or_else(|| query.get("type"))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "tcp".to_string());
    let opts = V2rayNJson {
        id: parsed.username().to_string(),
        add: parsed.host_str().unwrap_or("").to_string(),
        port: parsed
            .port()
            .map(|p| StringOrInt(p as i64))
            .unwrap_or_default(),
        ps: query
            .get("remarks")
            .or_else(|| query.get("ps"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| u.fragment().unwrap_or("").to_string()),
        aid: StringOrInt(
            query
                .get("alterId")
                .or_else(|| query.get("aid"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        ),
        net: network,
        path: query
            .get("path")
            .or_else(|| query.get("serviceName"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        tls: query
            .get("tls")
            .or_else(|| query.get("security"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        sni: query
            .get("peer")
            .or_else(|| query.get("obfsParam"))
            .or_else(|| query.get("sni"))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        scy: security.to_string(),
        ..Default::default()
    };

    let mut node = build_node(opts)?;
    node.packet_encoding = parse_shadowrocket_udp(query.get("udp").map(|v| v.as_ref()));
    Ok(node)
}

fn parse_shadowrocket_udp(value: Option<&str>) -> PacketEncoding {
    match value {
        Some("2") => PacketEncoding::PacketAddr,
        Some("3") => PacketEncoding::Xudp,
        _ => PacketEncoding::Default,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Common builder
// ──────────────────────────────────────────────────────────────────────────────

fn build_node(opts: V2rayNJson) -> Result<VMessNode> {
    let port = opts.port.0;
    if port <= 0 || port > 65535 {
        return Err(anyhow!("invalid port: {}", port));
    }
    if opts.add.is_empty() {
        return Err(anyhow!("missing server address"));
    }
    if opts.id.is_empty() {
        return Err(anyhow!("missing UUID"));
    }

    let tls_enabled = matches!(opts.tls.as_str(), "tls" | "true" | "1");
    let network = if opts.net.is_empty() {
        "tcp".to_string()
    } else {
        opts.net.to_lowercase()
    };
    let security = if opts.scy.is_empty() {
        "auto".to_string()
    } else {
        opts.scy.clone()
    };

    let sni = if !opts.sni.is_empty() {
        opts.sni.clone()
    } else if !opts.host.is_empty() {
        opts.host.clone()
    } else {
        opts.add.clone()
    };

    let grpc_service_name = if network == "grpc" {
        Some(opts.path.clone())
    } else {
        None
    };
    let ws_path = if network == "ws" {
        Some(opts.path.clone())
    } else {
        None
    };
    let ws_host = if network == "ws" && !opts.host.is_empty() {
        Some(opts.host.clone())
    } else {
        None
    };

    Ok(VMessNode {
        name: opts.ps,
        source: empty_source(),
        server: opts.add,
        port: port as u16,
        uuid: opts.id,
        alter_id: opts.aid.0.max(0) as u32,
        security,
        network,
        tls: tls_enabled,
        sni,
        grpc_service_name,
        ws_path,
        ws_host,
        packet_encoding: opts.packet_encoding,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn shadowrocket_payload(authority: &str) -> String {
        general_purpose::STANDARD.encode(authority)
    }

    #[test]
    fn test_parse_v2rayn_json_format() {
        // Create a v2rayN base64-encoded JSON link
        let json = r#"{"v":"2","ps":"test","add":"node.example","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"node.example","scy":"aes-128-gcm"}"#;
        let encoded = general_purpose::STANDARD.encode(json);
        let link = format!("vmess://{}", encoded);

        let node = parse_vmess_link(&link).unwrap();
        assert_eq!(node.name, "test");
        assert_eq!(node.server, "node.example");
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(node.security, "aes-128-gcm");
        assert!(node.tls);
    }

    #[test]
    fn test_parse_v2rayn_json_int_port() {
        // Port as integer in JSON
        let json = r#"{"ps":"test","add":"192.0.2.20","port":8080,"id":"550e8400-e29b-41d4-a716-446655440000","aid":0,"net":"ws","path":"/test","host":"","tls":"","scy":""}"#;
        let encoded = general_purpose::STANDARD.encode(json);
        let link = format!("vmess://{}", encoded);

        let node = parse_vmess_link(&link).unwrap();
        assert_eq!(node.port, 8080);
        assert_eq!(node.network, "ws");
        assert_eq!(node.ws_path, Some("/test".to_string()));
    }

    #[test]
    fn test_parse_url_format() {
        // Legacy format: net= and tls= (still supported)
        let link = "vmess://550e8400-e29b-41d4-a716-446655440000@proxy.example:443?net=grpc&path=test&tls=tls&sni=proxy.example&ps=test";

        let node = parse_vmess_link(link).unwrap();
        assert_eq!(node.server, "proxy.example");
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(node.network, "grpc");
        assert_eq!(node.grpc_service_name, Some("test".to_string()));
        assert!(node.tls);
    }

    #[test]
    fn test_parse_url_format_standard() {
        // Standard format: type= and security= (qv2ray/v2ray spec)
        let link = "vmess://44efe52b-e143-46b5-a9e7-aadbfd77eb9c@ws.example:6939?type=ws&security=tls&host=ws.example&path=%2Ftest#test";

        let node = parse_vmess_link(link).unwrap();
        assert_eq!(node.server, "ws.example");
        assert_eq!(node.port, 6939);
        assert_eq!(node.uuid, "44efe52b-e143-46b5-a9e7-aadbfd77eb9c");
        assert_eq!(node.network, "ws");
        assert!(node.tls);
        assert_eq!(node.ws_path, Some("/test".to_string()));
        assert_eq!(node.ws_host, Some("ws.example".to_string()));
        assert_eq!(node.name, "test");
    }

    #[test]
    fn test_parse_url_format_grpc_service_name() {
        // gRPC with serviceName= (standard) and type= and security=
        let link = "vmess://550e8400-e29b-41d4-a716-446655440000@grpc.example:443?type=grpc&security=tls&sni=grpc.example&serviceName=test#test";

        let node = parse_vmess_link(link).unwrap();
        assert_eq!(node.network, "grpc");
        assert!(node.tls);
        assert_eq!(node.grpc_service_name, Some("test".to_string()));
        assert_eq!(node.sni, "grpc.example");
        assert_eq!(node.name, "test");
    }

    #[test]
    fn test_parse_url_format_packet_encoding() {
        let link = "vmess://550e8400-e29b-41d4-a716-446655440000@proxy.example:443?type=grpc&security=tls&serviceName=test&packetEncoding=packetaddr#test";

        let node = parse_vmess_link(link).unwrap();
        assert_eq!(node.packet_encoding, PacketEncoding::PacketAddr);
    }

    #[test]
    fn test_parse_shadowrocket_format() {
        let payload =
            shadowrocket_payload("auto:550e8400-e29b-41d4-a716-446655440000@192.0.2.10:50443");
        let link = format!(
            "vmess://{}?path=test&remarks=test&obfsParam=proxy.example&obfs=grpc&tls=1&peer=proxy.example&udp=3&alterId=0",
            payload
        );

        let node = parse_vmess_link(&link).unwrap();
        assert_eq!(node.name, "test");
        assert_eq!(node.server, "192.0.2.10");
        assert_eq!(node.port, 50443);
        assert_eq!(node.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(node.security, "auto");
        assert_eq!(node.network, "grpc");
        assert!(node.tls);
        assert_eq!(node.grpc_service_name, Some("test".to_string()));
        assert_eq!(node.sni, "proxy.example");
        assert_eq!(node.alter_id, 0);
        assert_eq!(node.packet_encoding, PacketEncoding::Xudp);
    }

    #[test]
    fn test_parse_shadowrocket_udp_packetaddr() {
        let payload =
            shadowrocket_payload("auto:550e8400-e29b-41d4-a716-446655440000@192.0.2.10:50443");
        let link = format!(
            "vmess://{}?remarks=test&obfs=grpc&tls=1&udp=2&alterId=0",
            payload
        );

        let node = parse_vmess_link(&link).unwrap();
        assert_eq!(node.packet_encoding, PacketEncoding::PacketAddr);
    }

    #[test]
    fn test_parse_grpc_transport() {
        let json = r#"{"ps":"test","add":"grpc.example","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"grpc","path":"test","tls":"tls","sni":"grpc.example","scy":"auto"}"#;
        let encoded = general_purpose::STANDARD.encode(json);
        let link = format!("vmess://{}", encoded);

        let node = parse_vmess_link(&link).unwrap();
        assert_eq!(node.network, "grpc");
        assert_eq!(node.grpc_service_name, Some("test".to_string()));
        assert!(node.tls);
        assert_eq!(node.sni, "grpc.example");
    }

    #[test]
    fn test_parse_subscription_mixed_protocols() {
        let json = r#"{"v":"2","ps":"test","add":"192.0.2.30","port":"1234","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","net":"tcp","type":"","host":"","path":"","tls":"","sni":"","scy":"auto"}"#;
        let vmess_link = format!("vmess://{}", general_purpose::STANDARD.encode(json));
        let links = [
            "ss://invalid-not-vmess",
            vmess_link.as_str(),
            "trojan://not-vmess@host:443",
        ];
        let body = links.join("\n");
        let nodes = parse_subscription(&body);
        // Only the vmess:// link should parse successfully
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "test");
    }

    #[test]
    fn test_non_vmess_link_rejected() {
        assert!(parse_vmess_link("ss://something").is_err());
        assert!(parse_vmess_link("trojan://something").is_err());
    }
}
