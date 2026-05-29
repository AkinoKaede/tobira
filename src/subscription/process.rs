/// Subscription processing pipeline.
///
/// Applies a sequence of `ProcessStep`s to a list of nodes.
/// Each step selects a subset of nodes (by name/source regex, optionally inverted),
/// then either removes or transforms the selected nodes.
use std::collections::HashMap;

use crate::config::ProcessStep;
use crate::subscription::parser::VMessNode;
use regex::Regex;

struct CompiledStep {
    filter_compiled: Vec<Regex>,
    filter_source_compiled: Vec<Regex>,
    rename_compiled: Vec<(Regex, String)>,
    remove_emoji: bool,
    override_security: Option<String>,
    remove: bool,
    invert: bool,
}

impl CompiledStep {
    fn from_step(step: &ProcessStep) -> Self {
        Self {
            filter_compiled: compile_patterns(&step.filter),
            filter_source_compiled: compile_patterns(&step.filter_source),
            rename_compiled: step
                .rename
                .iter()
                .filter_map(|[pat, repl]| {
                    Regex::new(pat)
                        .map_err(|e| tracing::warn!("invalid rename regex {:?}: {}", pat, e))
                        .ok()
                        .map(|re| (re, repl.clone()))
                })
                .collect(),
            remove_emoji: step.remove_emoji,
            override_security: step.override_security.clone(),
            remove: step.remove,
            invert: step.invert,
        }
    }
}

/// Apply a processing pipeline to a list of nodes.
/// Steps are executed in order. Regexes are compiled once per step.
pub fn apply_pipeline(mut nodes: Vec<VMessNode>, steps: &[ProcessStep]) -> Vec<VMessNode> {
    for step in steps {
        let compiled = CompiledStep::from_step(step);
        nodes = apply_step(nodes, &compiled);
    }
    nodes
}

fn apply_step(nodes: Vec<VMessNode>, compiled: &CompiledStep) -> Vec<VMessNode> {
    let name_pats = &compiled.filter_compiled;
    let source_pats = &compiled.filter_source_compiled;
    let invert = compiled.invert;

    // A node is "selected" if it matches both name and source patterns.
    // Empty pattern lists match all nodes.
    let is_selected = move |node: &VMessNode| {
        let name_ok = name_pats.is_empty() || name_pats.iter().any(|re| re.is_match(&node.name));
        let source_ok =
            source_pats.is_empty() || source_pats.iter().any(|re| re.is_match(&node.source));
        let matched = name_ok && source_ok;
        if invert {
            !matched
        } else {
            matched
        }
    };

    if compiled.remove {
        return nodes.into_iter().filter(|n| !is_selected(n)).collect();
    }

    let rename_rules = &compiled.rename_compiled;
    let remove_emoji = compiled.remove_emoji;
    let override_security = &compiled.override_security;

    nodes
        .into_iter()
        .map(move |mut node| {
            if is_selected(&node) {
                for (re, repl) in rename_rules {
                    node.name = re.replace_all(&node.name, repl.as_str()).into_owned();
                }
                if remove_emoji {
                    node.name = strip_emoji(&node.name);
                }
                if let Some(ref sec) = override_security {
                    node.security = sec.clone();
                }
            }
            node
        })
        .collect()
}

fn compile_patterns(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| {
            Regex::new(p)
                .map_err(|e| tracing::warn!("invalid regex pattern {:?}: {}", p, e))
                .ok()
        })
        .collect()
}

fn strip_emoji(s: &str) -> String {
    s.chars().filter(|&c| !is_emoji(c)).collect()
}

fn is_emoji(r: char) -> bool {
    let r = r as u32;
    (0x1F600..=0x1F64F).contains(&r)  // Emoticons
    || (0x1F300..=0x1F5FF).contains(&r) // Misc Symbols and Pictographs
    || (0x1F680..=0x1F6FF).contains(&r) // Transport and Map
    || (0x1F1E0..=0x1F1FF).contains(&r) // Regional indicators (flags)
    || (0x2600..=0x26FF).contains(&r)   // Misc symbols
    || (0x2700..=0x27BF).contains(&r)   // Dingbats
    || (0xFE00..=0xFE0F).contains(&r)   // Variation Selectors
    || (0x1F900..=0x1F9FF).contains(&r) // Supplemental Symbols and Pictographs
    || (0x1FA70..=0x1FAFF).contains(&r) // Symbols and Pictographs Extended-A
}

// ──────────────────────────────────────────────────────────────────────────────
// Deduplication
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum AddressType {
    Domain,
    Ipv4,
    Ipv6,
    Unknown,
}

fn get_address_type(address: &str) -> AddressType {
    if address.is_empty() {
        return AddressType::Unknown;
    }
    if address.parse::<std::net::Ipv4Addr>().is_ok() {
        return AddressType::Ipv4;
    }
    if address.parse::<std::net::Ipv6Addr>().is_ok() {
        return AddressType::Ipv6;
    }
    AddressType::Domain
}

fn get_address_priority(addr_type: &AddressType, strategy: &str) -> i32 {
    match strategy {
        "prefer_ipv4" => match addr_type {
            AddressType::Ipv4 => 3,
            AddressType::Domain => 2,
            AddressType::Ipv6 => 1,
            AddressType::Unknown => 0,
        },
        "prefer_ipv6" => match addr_type {
            AddressType::Ipv6 => 3,
            AddressType::Domain => 2,
            AddressType::Ipv4 => 1,
            AddressType::Unknown => 0,
        },
        "prefer_domain_then_ipv4" => match addr_type {
            AddressType::Domain => 3,
            AddressType::Ipv4 => 2,
            AddressType::Ipv6 => 1,
            AddressType::Unknown => 0,
        },
        "prefer_domain_then_ipv6" => match addr_type {
            AddressType::Domain => 3,
            AddressType::Ipv6 => 2,
            AddressType::Ipv4 => 1,
            AddressType::Unknown => 0,
        },
        _ => 0,
    }
}

/// Deduplicate nodes by name according to the given strategy.
///
/// - `""` or `"rename"` (default): keep all, append " (1)", " (2)" suffixes to duplicates
/// - `"first"`:                    keep the first occurrence of each name
/// - `"last"`:                     keep the last occurrence of each name
/// - `"prefer_ipv4"`:              IPv4 > Domain > IPv6
/// - `"prefer_ipv6"`:              IPv6 > Domain > IPv4
/// - `"prefer_domain_then_ipv4"`:  Domain > IPv4 > IPv6
/// - `"prefer_domain_then_ipv6"`:  Domain > IPv6 > IPv4
pub fn deduplicate_nodes(nodes: Vec<VMessNode>, strategy: &str) -> Vec<VMessNode> {
    if strategy.is_empty() || strategy == "rename" {
        let mut seen: HashMap<String, usize> = HashMap::new();
        return nodes
            .into_iter()
            .map(|mut node| {
                let tag = node.name.clone();
                if let Some(count) = seen.get_mut(&tag) {
                    *count += 1;
                    node.name = format!("{} ({})", tag, count);
                } else {
                    seen.insert(tag, 0);
                }
                node
            })
            .collect();
    }

    // For other strategies: keep only one node per name.
    // First pass: collect indices for each name.
    let mut name_indices: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, node) in nodes.iter().enumerate() {
        name_indices.entry(node.name.clone()).or_default().push(i);
    }

    // Determine which index to keep for each name.
    let mut keep: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for indices in name_indices.values() {
        if indices.len() == 1 {
            keep.insert(indices[0]);
            continue;
        }
        let selected = match strategy {
            "first" => indices[0],
            "last" => *indices.last().unwrap(),
            _ => {
                // Priority-based: pick the node whose server address best matches the strategy.
                let mut best_idx = indices[0];
                let mut best_priority = -1i32;
                for &idx in indices {
                    let addr_type = get_address_type(&nodes[idx].server);
                    let priority = get_address_priority(&addr_type, strategy);
                    if priority > best_priority {
                        best_priority = priority;
                        best_idx = idx;
                    }
                }
                best_idx
            }
        };
        keep.insert(selected);
    }

    // Preserve original order.
    nodes
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep.contains(i))
        .map(|(_, node)| node)
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_node(name: &str) -> VMessNode {
        VMessNode {
            name: name.to_string(),
            source: Arc::from(""),
            server: "1.2.3.4".to_string(),
            port: 443,
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            network: "tcp".to_string(),
            tls: false,
            sni: String::new(),
            grpc_service_name: None,
            ws_path: None,
            ws_host: None,
        }
    }

    fn make_node_with_source(name: &str, source: &str) -> VMessNode {
        VMessNode {
            source: Arc::from(source),
            ..make_node(name)
        }
    }

    // ── rename ──

    #[test]
    fn test_rename_all_nodes() {
        let nodes = vec![make_node("US Node 1"), make_node("HK Node 2")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                rename: vec![["^US (.*)$".to_string(), "United States $1".to_string()]],
                ..Default::default()
            }],
        );
        assert_eq!(result[0].name, "United States Node 1");
        assert_eq!(result[1].name, "HK Node 2");
    }

    #[test]
    fn test_rename_only_selected() {
        let nodes = vec![make_node("US Node"), make_node("HK Node")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter: vec!["^US".to_string()],
                rename: vec![["^US ".to_string(), "America-".to_string()]],
                ..Default::default()
            }],
        );
        assert_eq!(result[0].name, "America-Node");
        assert_eq!(result[1].name, "HK Node"); // unselected → unchanged
    }

    #[test]
    fn test_rename_multiple_rules() {
        let nodes = vec![make_node("US Server")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                rename: vec![
                    ["US".to_string(), "America".to_string()],
                    ["Server".to_string(), "Node".to_string()],
                ],
                ..Default::default()
            }],
        );
        assert_eq!(result[0].name, "America Node");
    }

    // ── remove ──

    #[test]
    fn test_remove_by_name_filter() {
        let nodes = vec![
            make_node("Expired US"),
            make_node("Active HK"),
            make_node("Expired SG"),
        ];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter: vec![".*Expired.*".to_string()],
                remove: true,
                ..Default::default()
            }],
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Active HK");
    }

    #[test]
    fn test_remove_inverted_keeps_only_matching() {
        // Remove non-Premium (invert=true removes non-matching)
        let nodes = vec![
            make_node("Premium US"),
            make_node("Free HK"),
            make_node("Premium HK"),
        ];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter: vec![".*[Pp]remium.*".to_string()],
                invert: true,
                remove: true,
                ..Default::default()
            }],
        );
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.name.contains("Premium")));
    }

    #[test]
    fn test_remove_by_source() {
        let nodes = vec![
            make_node_with_source("Node A", "premium_sub"),
            make_node_with_source("Node B", "free_sub"),
            make_node_with_source("Node C", "premium_sub"),
        ];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter_source: vec!["free_sub".to_string()],
                remove: true,
                ..Default::default()
            }],
        );
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.source.as_ref() == "premium_sub"));
    }

    #[test]
    fn test_filter_source_keep_only_matching() {
        // Keep only premium_sub nodes (remove nodes NOT from premium_sub)
        let nodes = vec![
            make_node_with_source("Node A", "premium_sub"),
            make_node_with_source("Node B", "free_sub"),
            make_node_with_source("Node C", "premium_sub"),
        ];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter_source: vec!["premium_sub".to_string()],
                invert: true,
                remove: true,
                ..Default::default()
            }],
        );
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.source.as_ref() == "premium_sub"));
    }

    // ── remove_emoji ──

    #[test]
    fn test_remove_emoji_strips_emoji() {
        let nodes = vec![make_node("🇺🇸 US Node"), make_node("🇭🇰 HK Node")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                remove_emoji: true,
                ..Default::default()
            }],
        );
        assert_eq!(result[0].name, " US Node");
        assert_eq!(result[1].name, " HK Node");
    }

    #[test]
    fn test_remove_emoji_only_on_selected() {
        let nodes = vec![make_node("🇺🇸 US Node"), make_node("🇭🇰 HK Node")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter: vec!["^🇺🇸".to_string()],
                remove_emoji: true,
                ..Default::default()
            }],
        );
        assert_eq!(result[0].name, " US Node"); // emoji removed
        assert_eq!(result[1].name, "🇭🇰 HK Node"); // unchanged
    }

    // ── override_security ──

    #[test]
    fn test_override_security_all() {
        let nodes = vec![make_node("Node A"), make_node("Node B")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                override_security: Some("aes-128-gcm".to_string()),
                ..Default::default()
            }],
        );
        assert!(result.iter().all(|n| n.security == "aes-128-gcm"));
    }

    #[test]
    fn test_override_security_only_selected() {
        let nodes = vec![make_node("US Node"), make_node("HK Node")];
        let result = apply_pipeline(
            nodes,
            &[ProcessStep {
                filter: vec!["^US".to_string()],
                override_security: Some("none".to_string()),
                ..Default::default()
            }],
        );
        assert_eq!(result[0].security, "none");
        assert_eq!(result[1].security, "auto"); // unchanged
    }

    // ── empty / no-op ──

    #[test]
    fn test_empty_pipeline() {
        let nodes = vec![make_node("Node A"), make_node("Node B")];
        let result = apply_pipeline(nodes.clone(), &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_empty_step_is_noop() {
        let nodes = vec![make_node("Node A"), make_node("Node B")];
        let result = apply_pipeline(nodes, &[ProcessStep::default()]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "Node A");
    }

    // ── deduplicate_nodes ──

    fn make_node_with_server(name: &str, server: &str) -> VMessNode {
        VMessNode {
            server: server.to_string(),
            ..make_node(name)
        }
    }

    #[test]
    fn test_dedup_rename_appends_suffixes() {
        let nodes = vec![
            make_node_with_server("node", "1.1.1.1"),
            make_node_with_server("node", "2.2.2.2"),
            make_node_with_server("node", "3.3.3.3"),
        ];
        let result = deduplicate_nodes(nodes, "rename");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "node");
        assert_eq!(result[1].name, "node (1)");
        assert_eq!(result[2].name, "node (2)");
    }

    #[test]
    fn test_dedup_empty_strategy_is_rename() {
        let nodes = vec![
            make_node_with_server("node", "1.1.1.1"),
            make_node_with_server("node", "2.2.2.2"),
        ];
        let result = deduplicate_nodes(nodes, "");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "node");
        assert_eq!(result[1].name, "node (1)");
    }

    #[test]
    fn test_dedup_first_keeps_first_occurrence() {
        let nodes = vec![
            make_node_with_server("node", "1.1.1.1"),
            make_node_with_server("node", "2.2.2.2"),
            make_node_with_server("node", "3.3.3.3"),
        ];
        let result = deduplicate_nodes(nodes, "first");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "1.1.1.1");
    }

    #[test]
    fn test_dedup_last_keeps_last_occurrence() {
        let nodes = vec![
            make_node_with_server("node", "1.1.1.1"),
            make_node_with_server("node", "2.2.2.2"),
            make_node_with_server("node", "3.3.3.3"),
        ];
        let result = deduplicate_nodes(nodes, "last");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "3.3.3.3");
    }

    #[test]
    fn test_dedup_prefer_ipv4() {
        let nodes = vec![
            make_node_with_server("node", "example.com"),
            make_node_with_server("node", "192.168.1.1"),
            make_node_with_server("node", "2001:db8::1"),
        ];
        let result = deduplicate_nodes(nodes, "prefer_ipv4");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "192.168.1.1");
    }

    #[test]
    fn test_dedup_prefer_ipv6() {
        let nodes = vec![
            make_node_with_server("node", "192.168.1.1"),
            make_node_with_server("node", "example.com"),
            make_node_with_server("node", "2001:db8::1"),
        ];
        let result = deduplicate_nodes(nodes, "prefer_ipv6");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "2001:db8::1");
    }

    #[test]
    fn test_dedup_prefer_domain_then_ipv4() {
        let nodes = vec![
            make_node_with_server("node", "192.168.1.1"),
            make_node_with_server("node", "2001:db8::1"),
            make_node_with_server("node", "example.com"),
        ];
        let result = deduplicate_nodes(nodes, "prefer_domain_then_ipv4");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "example.com");
    }

    #[test]
    fn test_dedup_prefer_domain_then_ipv6() {
        let nodes = vec![
            make_node_with_server("node", "192.168.1.1"),
            make_node_with_server("node", "2001:db8::1"),
            make_node_with_server("node", "example.com"),
        ];
        let result = deduplicate_nodes(nodes, "prefer_domain_then_ipv6");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "example.com");
    }

    #[test]
    fn test_dedup_mixed_names_first() {
        let nodes = vec![
            make_node_with_server("node1", "1.1.1.1"),
            make_node_with_server("node2", "2.2.2.2"),
            make_node_with_server("node1", "example.com"),
        ];
        let result = deduplicate_nodes(nodes, "first");
        assert_eq!(result.len(), 2);
        let node1 = result.iter().find(|n| n.name == "node1").unwrap();
        assert_eq!(node1.server, "1.1.1.1");
        assert!(result.iter().any(|n| n.name == "node2"));
    }

    #[test]
    fn test_dedup_no_duplicates_unchanged() {
        let nodes = vec![
            make_node_with_server("node1", "1.1.1.1"),
            make_node_with_server("node2", "2.2.2.2"),
        ];
        let result = deduplicate_nodes(nodes, "first");
        assert_eq!(result.len(), 2);
    }

    // ── get_address_type ──

    #[test]
    fn test_get_address_type() {
        assert_eq!(get_address_type(""), AddressType::Unknown);
        assert_eq!(get_address_type("example.com"), AddressType::Domain);
        assert_eq!(get_address_type("192.168.1.1"), AddressType::Ipv4);
        assert_eq!(get_address_type("2001:db8::1"), AddressType::Ipv6);
        assert_eq!(get_address_type("::1"), AddressType::Ipv6);
    }

    // ── get_address_priority ──

    #[test]
    fn test_get_address_priority_prefer_ipv4() {
        assert_eq!(get_address_priority(&AddressType::Ipv4, "prefer_ipv4"), 3);
        assert_eq!(get_address_priority(&AddressType::Domain, "prefer_ipv4"), 2);
        assert_eq!(get_address_priority(&AddressType::Ipv6, "prefer_ipv4"), 1);
    }

    #[test]
    fn test_get_address_priority_prefer_ipv6() {
        assert_eq!(get_address_priority(&AddressType::Ipv6, "prefer_ipv6"), 3);
        assert_eq!(get_address_priority(&AddressType::Domain, "prefer_ipv6"), 2);
        assert_eq!(get_address_priority(&AddressType::Ipv4, "prefer_ipv6"), 1);
    }

    // ── combined pipeline ──

    #[test]
    fn test_combined_pipeline() {
        let nodes = vec![
            make_node_with_source("Premium US East", "sub_a"),
            make_node_with_source("Free HK", "sub_b"),
            make_node_with_source("Premium HK West", "sub_a"),
            make_node_with_source("Expired US", "sub_a"),
        ];
        let steps = vec![
            // Keep only sub_a nodes
            ProcessStep {
                filter_source: vec!["sub_a".to_string()],
                invert: true,
                remove: true,
                ..Default::default()
            },
            // Remove Expired nodes
            ProcessStep {
                filter: vec![".*Expired.*".to_string()],
                remove: true,
                ..Default::default()
            },
            // Strip "Premium " prefix and set security
            ProcessStep {
                rename: vec![["Premium ".to_string(), "".to_string()]],
                override_security: Some("none".to_string()),
                ..Default::default()
            },
        ];
        let result = apply_pipeline(nodes, &steps);
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|n| n.name == "US East"));
        assert!(result.iter().any(|n| n.name == "HK West"));
        assert!(result.iter().all(|n| n.security == "none"));
    }
}
