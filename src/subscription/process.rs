/// Subscription processing pipeline.
///
/// Applies a sequence of `ProcessStep`s to a list of nodes.
/// Each step selects a subset of nodes (by name/source regex, optionally inverted),
/// then either removes or transforms the selected nodes.
use crate::config::ProcessStep;
use crate::subscription::parser::VMessNode;
use regex::Regex;

/// Apply a processing pipeline to a list of nodes.
/// Steps are executed in order.
pub fn apply_pipeline(mut nodes: Vec<VMessNode>, steps: &[ProcessStep]) -> Vec<VMessNode> {
    for step in steps {
        nodes = apply_step(nodes, step);
    }
    nodes
}

fn apply_step(nodes: Vec<VMessNode>, step: &ProcessStep) -> Vec<VMessNode> {
    let name_pats = compile_patterns(&step.filter);
    let source_pats = compile_patterns(&step.filter_source);
    let invert = step.invert;

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

    if step.remove {
        return nodes.into_iter().filter(|n| !is_selected(n)).collect();
    }

    // Clone values needed inside the map closure.
    let rename_rules: Vec<(Regex, String)> = step
        .rename
        .iter()
        .filter_map(|[pat, repl]| {
            Regex::new(pat)
                .map_err(|e| tracing::warn!("invalid rename regex {:?}: {}", pat, e))
                .ok()
                .map(|re| (re, repl.clone()))
        })
        .collect();
    let remove_emoji = step.remove_emoji;
    let override_security = step.override_security.clone();

    nodes
        .into_iter()
        .map(move |mut node| {
            if is_selected(&node) {
                for (re, repl) in &rename_rules {
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
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str) -> VMessNode {
        VMessNode {
            name: name.to_string(),
            source: String::new(),
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
            source: source.to_string(),
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
        assert!(result.iter().all(|n| n.source == "premium_sub"));
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
        assert!(result.iter().all(|n| n.source == "premium_sub"));
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
