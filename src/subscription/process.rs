/// Subscription processing pipeline.
///
/// Applies a sequence of `ProcessStep`s to a list of nodes.
/// Non-VMess nodes are filtered out automatically before this pipeline runs.
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
    match step {
        ProcessStep::Rename { rules } => apply_rename(nodes, rules),
        ProcessStep::Filter { patterns } => apply_filter(nodes, patterns),
        ProcessStep::Exclude { patterns } => apply_exclude(nodes, patterns),
    }
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

fn apply_rename(mut nodes: Vec<VMessNode>, rules: &[[String; 2]]) -> Vec<VMessNode> {
    let compiled: Vec<(Regex, &str)> = rules
        .iter()
        .filter_map(|[pat, repl]| {
            Regex::new(pat)
                .map_err(|e| tracing::warn!("invalid rename regex {:?}: {}", pat, e))
                .ok()
                .map(|re| (re, repl.as_str()))
        })
        .collect();

    for node in &mut nodes {
        for (re, repl) in &compiled {
            let new_name = re.replace_all(&node.name, *repl).into_owned();
            node.name = new_name;
        }
    }
    nodes
}

fn apply_filter(nodes: Vec<VMessNode>, patterns: &[String]) -> Vec<VMessNode> {
    if patterns.is_empty() {
        return nodes;
    }
    let regexes = compile_patterns(patterns);
    nodes
        .into_iter()
        .filter(|n| regexes.iter().any(|re| re.is_match(&n.name)))
        .collect()
}

fn apply_exclude(nodes: Vec<VMessNode>, patterns: &[String]) -> Vec<VMessNode> {
    if patterns.is_empty() {
        return nodes;
    }
    let regexes = compile_patterns(patterns);
    nodes
        .into_iter()
        .filter(|n| !regexes.iter().any(|re| re.is_match(&n.name)))
        .collect()
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

    #[test]
    fn test_rename_basic() {
        let nodes = vec![make_node("US Node 1"), make_node("HK Node 2")];
        let rules = vec![
            ["^US (.*)$".to_string(), "United States $1".to_string()],
        ];
        let result = apply_rename(nodes, &rules);
        assert_eq!(result[0].name, "United States Node 1");
        assert_eq!(result[1].name, "HK Node 2"); // unchanged
    }

    #[test]
    fn test_rename_multiple_rules() {
        let nodes = vec![make_node("US Server")];
        let rules = vec![
            ["US".to_string(), "America".to_string()],
            ["Server".to_string(), "Node".to_string()],
        ];
        let result = apply_rename(nodes, &rules);
        assert_eq!(result[0].name, "America Node");
    }

    #[test]
    fn test_filter_keeps_matching() {
        let nodes = vec![
            make_node("Premium US"),
            make_node("Free HK"),
            make_node("Premium HK"),
        ];
        let step = ProcessStep::Filter {
            patterns: vec![".*[Pp]remium.*".to_string()],
        };
        let result = apply_pipeline(nodes, &[step]);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.name.contains("Premium")));
    }

    #[test]
    fn test_exclude_removes_matching() {
        let nodes = vec![
            make_node("Expired US"),
            make_node("Active HK"),
            make_node("Expired SG"),
        ];
        let step = ProcessStep::Exclude {
            patterns: vec![".*Expired.*".to_string()],
        };
        let result = apply_pipeline(nodes, &[step]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Active HK");
    }

    #[test]
    fn test_empty_pipeline() {
        let nodes = vec![make_node("Node A"), make_node("Node B")];
        let result = apply_pipeline(nodes.clone(), &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_empty_patterns() {
        let nodes = vec![make_node("Node A"), make_node("Node B")];
        let step = ProcessStep::Filter { patterns: vec![] };
        let result = apply_pipeline(nodes, &[step]);
        // Empty filter keeps all
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_combined_pipeline() {
        let nodes = vec![
            make_node("Premium US East"),
            make_node("Free HK"),
            make_node("Premium HK West"),
            make_node("Expired US"),
        ];
        let steps = vec![
            ProcessStep::Filter {
                patterns: vec![".*[Pp]remium.*".to_string()],
            },
            ProcessStep::Exclude {
                patterns: vec![".*Expired.*".to_string()],
            },
            ProcessStep::Rename {
                rules: vec![["Premium ".to_string(), "".to_string()]],
            },
        ];
        let result = apply_pipeline(nodes, &steps);
        assert_eq!(result.len(), 2);
        // Renamed to remove "Premium "
        assert!(result.iter().any(|n| n.name == "US East"));
        assert!(result.iter().any(|n| n.name == "HK West"));
    }
}
