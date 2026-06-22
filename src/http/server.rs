/// HTTP subscription server.
///
/// Endpoints:
///   GET /sub                  — all outputs, format auto-selected from User-Agent
///   GET /sub/base64           — all outputs in v2rayN format (base64 envelope)
///   GET /sub/v2rayn           — same
///   GET /sub/standard         — same outputs in raw VMess URL format
///   GET /sub/url              — compatibility alias of `/sub/standard`
///   GET /sub/shadowrocket     — same outputs in Shadowrocket VMess format (base64 envelope)
///   GET /sub/<name>           — specific named output, format auto-selected from User-Agent
///   GET /sub/<name>/base64    — specific named output in v2rayN format (base64 envelope)
///   GET /sub/<name>/v2rayn    — specific named output
///   GET /sub/<name>/standard  — specific named output in raw VMess URL format
///   GET /sub/<name>/url       — compatibility alias of `/sub/<name>/standard`
///   GET /sub/<name>/shadowrocket — specific named output in Shadowrocket VMess format (base64 envelope)
///
/// Basic Auth:
///   - `[[http.users]]` with optional `outputs` field restricts per-user access.
///   - No users configured → anonymous access to all outputs.
///   - Constant-time comparison prevents timing attacks.
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use url::Url;

use crate::config::{HttpUser, OutputConfig, PacketEncoding, RelayNetwork};
use crate::subscription::parser::VMessNode;
use crate::subscription::process::apply_pipeline;

const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

// ──────────────────────────────────────────────────────────────────────────────
// Shared state
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HttpState {
    pub users: Vec<HttpUser>,
    pub outputs: Vec<RenderedOutput>,
}

#[derive(Clone)]
pub struct RenderedOutput {
    pub name: String,
    v2rayn_links: Vec<String>,
    standard_links: Vec<String>,
    shadowrocket_links: Vec<String>,
}

impl HttpState {
    pub fn new(
        users: Vec<HttpUser>,
        outputs: Vec<OutputConfig>,
        nodes: &[VMessNode],
        relay_network: RelayNetwork,
        relay_service_name: &str,
    ) -> Self {
        let outputs = outputs
            .iter()
            .map(|output| render_output(output, nodes, relay_network, relay_service_name))
            .collect();
        Self { users, outputs }
    }
}

pub type SharedState = Arc<RwLock<HttpState>>;

// ──────────────────────────────────────────────────────────────────────────────
// Server entry point
// ──────────────────────────────────────────────────────────────────────────────

pub async fn run(addr: SocketAddr, state: SharedState) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HTTP server listening on {}", addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("HTTP accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, service_fn(move |req| handle(req, state.clone())))
                .await
            {
                tracing::debug!("HTTP connection error: {}", e);
            }
        });
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Request handler
// ──────────────────────────────────────────────────────────────────────────────

async fn handle(
    req: Request<hyper::body::Incoming>,
    state: SharedState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(dispatch(req, state).await)
}

async fn dispatch(
    req: Request<hyper::body::Incoming>,
    state: SharedState,
) -> Response<Full<Bytes>> {
    let s = state.read().await.clone();

    // Authenticate
    let user = match authenticate(req.headers(), &s.users) {
        Some(u) => u,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", r#"Basic realm="Subscription""#)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from("Unauthorized")))
                .unwrap();
        }
    };

    // Route
    let path = req.uri().path();
    match route(path) {
        Route::AllOutputs(fmt) => {
            build_subscription_response(&s, user, None, fmt.resolve(req.headers()))
        }
        Route::NamedOutput(name, fmt) => {
            build_subscription_response(&s, user, Some(&name), fmt.resolve(req.headers()))
        }
        Route::NotFound => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Routing
// ──────────────────────────────────────────────────────────────────────────────

/// VMess link format returned by the subscription endpoint.
#[derive(Debug, Clone, Copy, PartialEq)]
enum LinkFormat {
    /// `vmess://base64(json)` — v2rayN JSON format (default)
    V2rayN,
    /// `vmess://uuid@host:port?params` — URL format
    Standard,
    /// `vmess://base64(security:uuid@host:port)?params` — Shadowrocket format
    Shadowrocket,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RequestedFormat {
    Auto,
    Explicit(LinkFormat),
}

impl RequestedFormat {
    fn resolve(self, headers: &http::HeaderMap) -> LinkFormat {
        match self {
            Self::Auto => link_format_for_user_agent(headers),
            Self::Explicit(format) => format,
        }
    }
}

enum Route {
    AllOutputs(RequestedFormat),
    NamedOutput(String, RequestedFormat),
    NotFound,
}

fn route(path: &str) -> Route {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match parts.as_slice() {
        ["sub"] => Route::AllOutputs(RequestedFormat::Auto),
        ["sub", "base64"] | ["sub", "v2rayn"] => {
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::V2rayN))
        }
        ["sub", "standard"] | ["sub", "url"] => {
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::Standard))
        }
        ["sub", "shadowrocket"] => {
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::Shadowrocket))
        }
        ["sub", name, "base64"] | ["sub", name, "v2rayn"] => Route::NamedOutput(
            name.to_string(),
            RequestedFormat::Explicit(LinkFormat::V2rayN),
        ),
        ["sub", name, "standard"] | ["sub", name, "url"] => Route::NamedOutput(
            name.to_string(),
            RequestedFormat::Explicit(LinkFormat::Standard),
        ),
        ["sub", name, "shadowrocket"] => Route::NamedOutput(
            name.to_string(),
            RequestedFormat::Explicit(LinkFormat::Shadowrocket),
        ),
        ["sub", name] => Route::NamedOutput(name.to_string(), RequestedFormat::Auto),
        _ => Route::NotFound,
    }
}

fn link_format_for_user_agent(headers: &http::HeaderMap) -> LinkFormat {
    let Some(user_agent) = headers.get(http::header::USER_AGENT) else {
        return LinkFormat::V2rayN;
    };
    let Ok(user_agent) = user_agent.to_str() else {
        return LinkFormat::V2rayN;
    };
    let user_agent = user_agent.to_ascii_lowercase();
    if user_agent.contains("shadowrocket") {
        LinkFormat::Shadowrocket
    } else {
        LinkFormat::V2rayN
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Authentication
// ──────────────────────────────────────────────────────────────────────────────

/// Returns the authenticated `HttpUser`, or `None` if auth fails.
/// If no users are configured, returns a default anonymous user.
fn authenticate<'a>(headers: &http::HeaderMap, users: &'a [HttpUser]) -> Option<&'a HttpUser> {
    static ANON: std::sync::OnceLock<HttpUser> = std::sync::OnceLock::new();
    let anon = ANON.get_or_init(|| HttpUser {
        username: String::new(),
        password: String::new(),
        outputs: None,
    });

    if users.is_empty() {
        return Some(anon);
    }

    let (username, password) = extract_basic_auth(headers)?;

    // Constant-time comparison for all users (prevents timing attacks)
    let mut matched: Option<&HttpUser> = None;
    for user in users {
        let un_ok = username
            .as_bytes()
            .ct_eq(user.username.as_bytes())
            .unwrap_u8()
            == 1;
        let pw_ok = password
            .as_bytes()
            .ct_eq(user.password.as_bytes())
            .unwrap_u8()
            == 1;
        if un_ok && pw_ok && matched.is_none() {
            matched = Some(user);
        }
    }
    matched
}

fn extract_basic_auth(headers: &http::HeaderMap) -> Option<(String, String)> {
    let header = headers.get("Authorization")?;
    let value = header.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Subscription response builder
// ──────────────────────────────────────────────────────────────────────────────

fn build_subscription_response(
    state: &HttpState,
    user: &HttpUser,
    output_name: Option<&str>,
    format: LinkFormat,
) -> Response<Full<Bytes>> {
    // Determine which outputs this user can access
    let allowed_outputs: Vec<&RenderedOutput> = state
        .outputs
        .iter()
        .filter(|o| {
            // Check output-name filter from the URL
            if let Some(name) = output_name {
                if o.name != name {
                    return false;
                }
            }
            // Check per-user output restriction
            if let Some(user_outputs) = &user.outputs {
                return user_outputs.iter().any(|n| n == &o.name);
            }
            true
        })
        .collect();

    if allowed_outputs.is_empty() {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("no matching outputs")))
            .unwrap();
    }

    let links = allowed_outputs
        .iter()
        .flat_map(|output| match format {
            LinkFormat::V2rayN => output.v2rayn_links.iter(),
            LinkFormat::Standard => output.standard_links.iter(),
            LinkFormat::Shadowrocket => output.shadowrocket_links.iter(),
        })
        .map(String::as_str)
        .collect::<Vec<_>>();

    let content = links.join("\n");
    let body = match format {
        LinkFormat::V2rayN | LinkFormat::Shadowrocket => {
            general_purpose::STANDARD.encode(content.as_bytes())
        }
        LinkFormat::Standard => content,
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header(
            "Subscription-Userinfo",
            "upload=0; download=0; total=0; expire=0",
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn render_output(
    output: &OutputConfig,
    nodes: &[VMessNode],
    relay_network: RelayNetwork,
    relay_service_name: &str,
) -> RenderedOutput {
    let processed = apply_pipeline(nodes.to_vec(), &output.process);
    let v2rayn_links = processed
        .iter()
        .map(|node| build_vmess_json_link(node, output, relay_network, relay_service_name))
        .collect();
    let standard_links = processed
        .iter()
        .map(|node| build_vmess_url_link(node, output, relay_network, relay_service_name))
        .collect();
    let shadowrocket_links = processed
        .iter()
        .map(|node| build_shadowrocket_link(node, output, relay_network, relay_service_name))
        .collect();

    RenderedOutput {
        name: output.name.clone(),
        v2rayn_links,
        standard_links,
        shadowrocket_links,
    }
}

/// Build a `vmess://base64(json)` link (v2rayN format) rewritten to `output`.
///
/// The VMess encryption algorithm (`scy`) is preserved so clients can communicate
/// with the upstream through the relay's transparent forwarding.
fn build_vmess_json_link(
    node: &VMessNode,
    output: &OutputConfig,
    network: RelayNetwork,
    service_name: &str,
) -> String {
    let is_grpc = network == RelayNetwork::Grpc;
    let tls = if is_grpc { "tls" } else { "" };
    let sni = if is_grpc {
        output.sni.as_deref().unwrap_or("")
    } else {
        ""
    };
    let json = serde_json::json!({
        "v": "2",
        "ps": node.name,
        "add": output.host,
        "port": output.port.to_string(),
        "id": node.uuid,
        "aid": node.alter_id.to_string(),
        "net": if is_grpc { "grpc" } else { "tcp" },
        "type": "none",
        "host": "",
        "path": if is_grpc { service_name } else { "" },
        "tls": tls,
        "sni": sni,
        "scy": node.security,
    });
    let mut json = json;
    if is_grpc && output.skip_cert_verify {
        json["insecure"] = serde_json::Value::String("1".to_string());
    }

    let encoded = general_purpose::STANDARD.encode(json.to_string().as_bytes());
    format!("vmess://{}", encoded)
}

/// Build a `vmess://uuid@host:port?params#name` link (URL format) rewritten to `output`.
fn build_vmess_url_link(
    node: &VMessNode,
    output: &OutputConfig,
    network: RelayNetwork,
    service_name: &str,
) -> String {
    let host = format_url_host(&output.host);
    let base = format!("vmess://{}@{}:{}", node.uuid, host, output.port);
    let mut url = Url::parse(&base).expect("vmess URL is always valid");
    {
        let mut q = url.query_pairs_mut();
        if network == RelayNetwork::Grpc {
            q.append_pair("type", "grpc");
            q.append_pair("serviceName", service_name);
        } else {
            q.append_pair("type", "tcp");
        }
        q.append_pair(
            "security",
            if network == RelayNetwork::Grpc {
                "tls"
            } else {
                "none"
            },
        );
        if network == RelayNetwork::Grpc {
            if let Some(sni) = &output.sni {
                q.append_pair("sni", sni);
            }
        }
        q.append_pair("encryption", &node.security);
    }

    if !node.name.is_empty() {
        url.set_fragment(Some(&node.name));
    }

    url.to_string()
}

/// Build a Shadowrocket VMess link rewritten to `output`.
fn build_shadowrocket_link(
    node: &VMessNode,
    output: &OutputConfig,
    network: RelayNetwork,
    service_name: &str,
) -> String {
    let host = format_url_host(&output.host);
    let payload = format!("{}:{}@{}:{}", node.security, node.uuid, host, output.port);
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let is_grpc = network == RelayNetwork::Grpc;
    let mut query = url::form_urlencoded::Serializer::new(String::new());

    if is_grpc {
        query.append_pair("path", service_name);
    }
    if !node.name.is_empty() {
        query.append_pair("remarks", &node.name);
    }
    if is_grpc {
        let sni = output.sni.as_deref().unwrap_or(&output.host);
        query.append_pair("obfsParam", sni);
        query.append_pair("obfs", "grpc");
        query.append_pair("tls", "1");
        query.append_pair("peer", sni);
    } else {
        query.append_pair("obfs", "tcp");
        query.append_pair("tls", "0");
    }
    query.append_pair("udp", shadowrocket_udp(node.packet_encoding));
    query.append_pair("alterId", &node.alter_id.to_string());

    format!("vmess://{}?{}", encoded, query.finish())
}

fn shadowrocket_udp(packet_encoding: PacketEncoding) -> &'static str {
    match packet_encoding {
        PacketEncoding::Default => "1",
        PacketEncoding::PacketAddr => "2",
        PacketEncoding::Xudp => "3",
    }
}

fn format_url_host(host: &str) -> String {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", trimmed)
    } else {
        host.to_string()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node(uuid: &str, name: &str) -> VMessNode {
        VMessNode {
            name: name.to_string(),
            source: Arc::from(""),
            server: "origin.example.com".to_string(),
            port: 9000,
            uuid: uuid.to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            network: "tcp".to_string(),
            tls: false,
            sni: "origin.example.com".to_string(),
            grpc_service_name: None,
            ws_path: None,
            ws_host: None,
            packet_encoding: PacketEncoding::Default,
        }
    }

    fn test_output(name: &str, host: &str, port: u16) -> OutputConfig {
        OutputConfig {
            name: name.to_string(),
            host: host.to_string(),
            port,
            sni: None,
            skip_cert_verify: false,
            process: vec![],
        }
    }

    fn make_state(
        users: Vec<HttpUser>,
        outputs: Vec<OutputConfig>,
        nodes: Vec<VMessNode>,
    ) -> HttpState {
        HttpState::new(users, outputs, &nodes, RelayNetwork::Tcp, "GunService")
    }

    // ── build_vmess_json_link ──

    #[test]
    fn test_build_vmess_link_rewrites_addr_and_port() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "My Node");
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_json_link(&node, &output, RelayNetwork::Tcp, "GunService");
        assert!(link.starts_with("vmess://"));

        // Decode and verify
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["add"], "relay.example.com");
        assert_eq!(json["port"], "10808");
        assert_eq!(json["id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(json["ps"], "My Node");
    }

    #[test]
    fn test_build_vmess_link_override_security() {
        // Security override is applied via the process pipeline (SetSecurity step)
        // before build_vmess_json_link is called — test that node.security is used as-is.
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        node.security = "aes-128-gcm".to_string(); // already set by pipeline
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_json_link(&node, &output, RelayNetwork::Tcp, "GunService");
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["scy"], "aes-128-gcm");
    }

    #[test]
    fn test_build_vmess_link_preserves_original_security() {
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        node.security = "chacha20-poly1305".to_string();
        let output = test_output("main", "relay.example.com", 10808); // no security override

        let link = build_vmess_json_link(&node, &output, RelayNetwork::Tcp, "GunService");
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["scy"], "chacha20-poly1305");
    }

    // ── build_vmess_url_link ──

    #[test]
    fn test_build_vmess_url_link_always_tcp() {
        // Even if the original node uses gRPC/WS, a TCP relay output is TCP+no-TLS.
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "My Node");
        node.network = "grpc".to_string();
        node.tls = true;
        node.grpc_service_name = Some("GunService".to_string());
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");
        assert!(link
            .starts_with("vmess://550e8400-e29b-41d4-a716-446655440000@relay.example.com:10808?"));
        assert!(link.contains("type=tcp"));
        assert!(link.contains("security=none"));
        assert!(!link.contains("grpc"));
        assert!(!link.contains("tls=tls"));
        assert!(!link.contains("security=tls"));
    }

    #[test]
    fn test_build_vmess_url_link_preserves_encryption() {
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        node.security = "aes-128-gcm".to_string();
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");
        assert!(link.contains("encryption=aes-128-gcm"));
    }

    #[test]
    fn test_build_vmess_url_link_fragment() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "My Node");
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");
        assert!(link.contains("#My%20Node") || link.contains("#My Node"));
    }

    #[test]
    fn test_build_vmess_url_link_brackets_ipv6_host() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        let output = test_output("main", "2001:db8::1", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");

        assert!(
            link.starts_with("vmess://550e8400-e29b-41d4-a716-446655440000@[2001:db8::1]:10808?")
        );
    }

    #[test]
    fn test_build_vmess_url_link_preserves_bracketed_ipv6_host() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        let output = test_output("main", "[2001:db8::1]", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");

        assert!(
            link.starts_with("vmess://550e8400-e29b-41d4-a716-446655440000@[2001:db8::1]:10808?")
        );
    }

    #[test]
    fn test_build_vmess_url_link_follows_grpc_relay() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        let mut output = test_output("main", "relay.example.com", 443);
        output.sni = Some("relay.example.com".to_string());

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Grpc, "TunSvc");
        assert!(link.contains("type=grpc"));
        assert!(link.contains("security=tls"));
        assert!(link.contains("serviceName=TunSvc"));
        assert!(link.contains("sni=relay.example.com"));
    }

    #[test]
    fn test_build_vmess_url_link_omits_packet_encoding() {
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        node.packet_encoding = PacketEncoding::Xudp;
        let output = test_output("main", "relay.example.com", 10808);

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Tcp, "GunService");

        assert!(!link.contains("packetEncoding"));
        assert!(!link.contains("packet_encoding"));
    }

    #[test]
    fn test_build_vmess_json_link_emits_skip_cert_verify_for_grpc() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        let mut output = test_output("main", "relay.example.com", 443);
        output.skip_cert_verify = true;

        let link = build_vmess_json_link(&node, &output, RelayNetwork::Grpc, "GunService");
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["tls"], "tls");
        assert_eq!(json["insecure"], "1");
    }

    #[test]
    fn test_build_vmess_json_link_omits_packet_encoding() {
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        node.packet_encoding = PacketEncoding::PacketAddr;
        let output = test_output("main", "relay.example.com", 443);

        let link = build_vmess_json_link(&node, &output, RelayNetwork::Grpc, "GunService");
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert!(json.get("packetEncoding").is_none());
        assert!(json.get("packet_encoding").is_none());
    }

    #[test]
    fn test_build_vmess_url_link_omits_skip_cert_verify_for_grpc() {
        let node = test_node("550e8400-e29b-41d4-a716-446655440000", "Node");
        let mut output = test_output("main", "relay.example.com", 443);
        output.skip_cert_verify = true;

        let link = build_vmess_url_link(&node, &output, RelayNetwork::Grpc, "GunService");

        assert!(link.contains("security=tls"));
        assert!(!link.contains("insecure"));
        assert!(!link.contains("allowInsecure"));
    }

    // ── build_shadowrocket_link ──

    #[test]
    fn test_build_shadowrocket_link_follows_grpc_relay_and_packet_encoding() {
        let mut node = test_node("550e8400-e29b-41d4-a716-446655440000", "My Node");
        node.packet_encoding = PacketEncoding::Xudp;
        let mut output = test_output("main", "relay.example.com", 443);
        output.sni = Some("sni.example.com".to_string());

        let link = build_shadowrocket_link(&node, &output, RelayNetwork::Grpc, "TunSvc");
        let parsed = Url::parse(&link).unwrap();
        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(parsed.host_str().unwrap())
            .unwrap();
        let payload = String::from_utf8(payload).unwrap();
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();

        assert_eq!(
            payload,
            "auto:550e8400-e29b-41d4-a716-446655440000@relay.example.com:443"
        );
        assert_eq!(query.get("path").map(|v| v.as_ref()), Some("TunSvc"));
        assert_eq!(query.get("remarks").map(|v| v.as_ref()), Some("My Node"));
        assert_eq!(query.get("obfs").map(|v| v.as_ref()), Some("grpc"));
        assert_eq!(query.get("tls").map(|v| v.as_ref()), Some("1"));
        assert_eq!(
            query.get("peer").map(|v| v.as_ref()),
            Some("sni.example.com")
        );
        assert_eq!(
            query.get("obfsParam").map(|v| v.as_ref()),
            Some("sni.example.com")
        );
        assert_eq!(query.get("udp").map(|v| v.as_ref()), Some("3"));
        assert_eq!(query.get("alterId").map(|v| v.as_ref()), Some("0"));
    }

    // ── route ──

    #[test]
    fn test_route_all_outputs() {
        assert!(matches!(
            route("/sub"),
            Route::AllOutputs(RequestedFormat::Auto)
        ));
        assert!(matches!(
            route("/sub/base64"),
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::V2rayN))
        ));
        assert!(matches!(
            route("/sub/v2rayn"),
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::V2rayN))
        ));
        assert!(matches!(
            route("/sub/standard"),
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::Standard))
        ));
        assert!(matches!(
            route("/sub/url"),
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::Standard))
        ));
        assert!(matches!(
            route("/sub/shadowrocket"),
            Route::AllOutputs(RequestedFormat::Explicit(LinkFormat::Shadowrocket))
        ));
    }

    #[test]
    fn test_route_named_output() {
        assert!(
            matches!(route("/sub/main"), Route::NamedOutput(ref n, RequestedFormat::Auto) if n == "main")
        );
        assert!(
            matches!(route("/sub/backup/base64"), Route::NamedOutput(ref n, RequestedFormat::Explicit(LinkFormat::V2rayN)) if n == "backup")
        );
        assert!(
            matches!(route("/sub/main/v2rayn"), Route::NamedOutput(ref n, RequestedFormat::Explicit(LinkFormat::V2rayN)) if n == "main")
        );
        assert!(
            matches!(route("/sub/main/standard"), Route::NamedOutput(ref n, RequestedFormat::Explicit(LinkFormat::Standard)) if n == "main")
        );
        assert!(
            matches!(route("/sub/main/url"), Route::NamedOutput(ref n, RequestedFormat::Explicit(LinkFormat::Standard)) if n == "main")
        );
        assert!(
            matches!(route("/sub/main/shadowrocket"), Route::NamedOutput(ref n, RequestedFormat::Explicit(LinkFormat::Shadowrocket)) if n == "main")
        );
    }

    #[test]
    fn test_route_not_found() {
        assert!(matches!(route("/"), Route::NotFound));
        assert!(matches!(route("/other"), Route::NotFound));
    }

    // ── authenticate ──

    fn make_auth_headers(username: &str, password: &str) -> http::HeaderMap {
        let creds = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", creds).parse().unwrap(),
        );
        headers
    }

    fn make_user_agent_headers(user_agent: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::USER_AGENT, user_agent.parse().unwrap());
        headers
    }

    #[test]
    fn test_auto_format_defaults_to_v2rayn() {
        let headers = http::HeaderMap::new();
        assert_eq!(link_format_for_user_agent(&headers), LinkFormat::V2rayN);
    }

    #[test]
    fn test_auto_format_uses_v2rayn_for_v2rayn_user_agent() {
        let headers = make_user_agent_headers("v2rayN/6.0");
        assert_eq!(link_format_for_user_agent(&headers), LinkFormat::V2rayN);
    }

    #[test]
    fn test_auto_format_uses_v2rayn_for_v2rayng_user_agent() {
        let headers = make_user_agent_headers("v2rayNG/version");
        assert_eq!(link_format_for_user_agent(&headers), LinkFormat::V2rayN);
    }

    #[test]
    fn test_auto_format_uses_shadowrocket_for_shadowrocket_user_agent() {
        let headers = make_user_agent_headers(
            "Shadowrocket/3319 CFNetwork/3860.600.21 Darwin/25.5.0 arm64",
        );
        assert_eq!(
            link_format_for_user_agent(&headers),
            LinkFormat::Shadowrocket
        );
    }

    #[test]
    fn test_extract_basic_auth_valid() {
        let headers = make_auth_headers("alice", "secret");
        let (user, pass) = extract_basic_auth(&headers).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn test_extract_basic_auth_missing() {
        let headers = http::HeaderMap::new();
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_authenticate_valid_user() {
        let users = vec![HttpUser {
            username: "alice".to_string(),
            password: "secret".to_string(),
            outputs: None,
        }];
        let headers = make_auth_headers("alice", "secret");
        assert!(authenticate(&headers, &users).is_some());
    }

    #[test]
    fn test_authenticate_wrong_password() {
        let users = vec![HttpUser {
            username: "alice".to_string(),
            password: "secret".to_string(),
            outputs: None,
        }];
        let headers = make_auth_headers("alice", "wrong");
        assert!(authenticate(&headers, &users).is_none());
    }

    #[test]
    fn test_authenticate_no_users_anon_access() {
        let headers = http::HeaderMap::new();
        let result = authenticate(&headers, &[]);
        assert!(result.is_some());
    }

    // ── build_subscription_response ──

    #[test]
    fn test_subscription_response_rewrite() {
        let nodes = vec![test_node(
            "550e8400-e29b-41d4-a716-446655440000",
            "TestNode",
        )];
        let outputs = vec![test_output("main", "relay.example.com", 10808)];
        let state = make_state(vec![], outputs, nodes);
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(&state, &anon_user, None, LinkFormat::V2rayN);
        assert_eq!(resp.status(), StatusCode::OK);

        // Decode response body
        use http_body_util::BodyExt;
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        let decoded_body = general_purpose::STANDARD.decode(&body).unwrap();
        let content = String::from_utf8(decoded_body).unwrap();

        // Parse the vmess link
        let link = content.trim();
        assert!(link.starts_with("vmess://"));
        let encoded = &link["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["add"], "relay.example.com");
        assert_eq!(json["port"], "10808");
    }

    #[test]
    fn test_subscription_user_output_filter() {
        let nodes = vec![test_node("550e8400-e29b-41d4-a716-446655440000", "Node1")];
        let outputs = vec![
            test_output("main", "relay1.example.com", 10808),
            test_output("backup", "relay2.example.com", 10809),
        ];
        let user_restricted = HttpUser {
            username: "alice".to_string(),
            password: "secret".to_string(),
            outputs: Some(vec!["main".to_string()]),
        };
        let state = make_state(vec![user_restricted.clone()], outputs, nodes);

        let resp = build_subscription_response(&state, &user_restricted, None, LinkFormat::V2rayN);
        assert_eq!(resp.status(), StatusCode::OK);

        use http_body_util::BodyExt;
        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        let decoded_body = general_purpose::STANDARD.decode(&body).unwrap();
        let content = String::from_utf8(decoded_body).unwrap();

        // Should only contain links for "main" output
        for line in content.lines() {
            if let Some(encoded) = line.strip_prefix("vmess://") {
                let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
                let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
                assert_eq!(json["add"], "relay1.example.com");
            }
        }
    }

    #[test]
    fn test_subscription_no_outputs_returns_not_found() {
        let state = make_state(vec![], vec![], vec![]);
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(&state, &anon_user, None, LinkFormat::V2rayN);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_subscription_named_output_not_found() {
        let nodes = vec![test_node("550e8400-e29b-41d4-a716-446655440000", "Node")];
        let outputs = vec![test_output("main", "relay.example.com", 10808)];
        let state = make_state(vec![], outputs, nodes);
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(
            &state,
            &anon_user,
            Some("nonexistent"),
            LinkFormat::V2rayN,
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_subscription_output_process_pipeline() {
        use crate::config::ProcessStep;
        use http_body_util::BodyExt;

        let nodes = vec![
            test_node("550e8400-e29b-41d4-a716-446655440000", "Premium US"),
            test_node("550e8400-e29b-41d4-a716-446655440001", "Free HK"),
        ];
        let mut output = test_output("main", "relay.example.com", 10808);
        output.process = vec![
            // Remove non-Premium nodes
            ProcessStep {
                filter: vec!["Premium".to_string()],
                invert: true,
                remove: true,
                ..Default::default()
            },
            // Rename and override security on remaining nodes
            ProcessStep {
                rename: vec![["Premium ".to_string(), "".to_string()]],
                override_security: Some("aes-128-gcm".to_string()),
                ..Default::default()
            },
        ];
        let state = make_state(vec![], vec![output], nodes);
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(&state, &anon_user, None, LinkFormat::V2rayN);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        let decoded_body = general_purpose::STANDARD.decode(&body).unwrap();
        let content = String::from_utf8(decoded_body).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // Only 1 node passes the filter (Premium US)
        assert_eq!(lines.len(), 1);

        let encoded = &lines[0]["vmess://".len()..];
        let json_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(json["ps"], "US"); // renamed: "Premium US" → "US"
        assert_eq!(json["scy"], "aes-128-gcm"); // security set by pipeline
        assert_eq!(json["add"], "relay.example.com");
    }

    #[test]
    fn test_subscription_url_format() {
        use http_body_util::BodyExt;

        let nodes = vec![test_node("550e8400-e29b-41d4-a716-446655440000", "My Node")];
        let outputs = vec![test_output("main", "relay.example.com", 10808)];
        let state = make_state(vec![], outputs, nodes);
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(&state, &anon_user, None, LinkFormat::Standard);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        let content = String::from_utf8(body.to_vec()).unwrap();
        let link = content.trim();

        assert!(link
            .starts_with("vmess://550e8400-e29b-41d4-a716-446655440000@relay.example.com:10808?"));
        assert!(link.contains("type=tcp"));
        assert!(link.contains("security=none"));
        assert!(link.contains("encryption=auto"));
        assert!(!link.contains("grpc"));
        assert!(!link.contains("ws"));
    }

    #[test]
    fn test_subscription_shadowrocket_format() {
        use crate::config::ProcessStep;
        use http_body_util::BodyExt;

        let nodes = vec![test_node("550e8400-e29b-41d4-a716-446655440000", "My Node")];
        let mut output = test_output("main", "relay.example.com", 443);
        output.sni = Some("sni.example.com".to_string());
        output.process = vec![ProcessStep {
            packet_encoding: Some(PacketEncoding::PacketAddr),
            ..Default::default()
        }];
        let state = HttpState::new(vec![], vec![output], &nodes, RelayNetwork::Grpc, "TunSvc");
        let anon_user = HttpUser {
            username: "".to_string(),
            password: "".to_string(),
            outputs: None,
        };

        let resp = build_subscription_response(&state, &anon_user, None, LinkFormat::Shadowrocket);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { resp.into_body().collect().await.unwrap().to_bytes() });
        let decoded_body = general_purpose::STANDARD.decode(&body).unwrap();
        let content = String::from_utf8(decoded_body).unwrap();
        let parsed = Url::parse(content.trim()).unwrap();
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().collect();

        assert_eq!(query.get("obfs").map(|v| v.as_ref()), Some("grpc"));
        assert_eq!(query.get("tls").map(|v| v.as_ref()), Some("1"));
        assert_eq!(query.get("path").map(|v| v.as_ref()), Some("TunSvc"));
        assert_eq!(
            query.get("peer").map(|v| v.as_ref()),
            Some("sni.example.com")
        );
        assert_eq!(query.get("udp").map(|v| v.as_ref()), Some("2"));
    }
}
