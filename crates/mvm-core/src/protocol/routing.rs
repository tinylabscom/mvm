use std::collections::HashSet;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// A routing table for a gateway pool's instances.
/// Maps inbound traffic (by port, path prefix, or source) to target worker instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingTable {
    pub routes: Vec<Route>,
}

/// A single routing rule: match inbound traffic and forward to a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    #[serde(default)]
    pub name: String,
    pub match_rule: MatchRule,
    pub target: RouteTarget,
}

/// Criteria for matching inbound traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub source_cidr: Option<String>,
}

/// Target for matched traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTarget {
    pub pool_id: String,
    #[serde(default)]
    pub instance_selector: InstanceSelector,
    #[serde(default)]
    pub target_port: Option<u16>,
}

/// Strategy for selecting an instance within the target pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceSelector {
    #[default]
    Any,
    ByIp(String),
    LeastConnections,
}

impl RoutingTable {
    pub fn from_json(json: &str) -> Result<Self> {
        let table: Self = serde_json::from_str(json)?;
        table.validate()?;
        Ok(table)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen_ports: HashSet<u16> = HashSet::new();

        for (i, route) in self.routes.iter().enumerate() {
            if route.match_rule.port.is_none()
                && route.match_rule.path_prefix.is_none()
                && route.match_rule.source_cidr.is_none()
            {
                bail!(
                    "Route {} ({}) has no match criteria — at least one of port, path_prefix, or source_cidr must be set",
                    i,
                    route.name,
                );
            }

            if let Some(port) = route.match_rule.port
                && !seen_ports.insert(port)
            {
                bail!(
                    "Route {} ({}) has duplicate port {}: another route already matches this port",
                    i,
                    route.name,
                    port,
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_table_serde_roundtrip() {
        let table = RoutingTable {
            routes: vec![
                Route {
                    name: "slack-webhook".to_string(),
                    match_rule: MatchRule {
                        port: Some(8080),
                        path_prefix: Some("/webhook/slack".to_string()),
                        source_cidr: None,
                    },
                    target: RouteTarget {
                        pool_id: "workers".to_string(),
                        instance_selector: InstanceSelector::Any,
                        target_port: Some(8080),
                    },
                },
                Route {
                    name: "telegram-bot".to_string(),
                    match_rule: MatchRule {
                        port: Some(8443),
                        path_prefix: None,
                        source_cidr: Some("149.154.160.0/20".to_string()),
                    },
                    target: RouteTarget {
                        pool_id: "workers".to_string(),
                        instance_selector: InstanceSelector::ByIp("10.240.3.5".to_string()),
                        target_port: None,
                    },
                },
            ],
        };

        let json = table.to_json().unwrap();
        let parsed = RoutingTable::from_json(&json).unwrap();
        assert_eq!(parsed.routes.len(), 2);
        assert_eq!(parsed.routes[0].name, "slack-webhook");
        assert_eq!(parsed.routes[0].match_rule.port, Some(8080));
        assert_eq!(parsed.routes[1].target.pool_id, "workers");
    }

    #[test]
    fn test_empty_routing_table() {
        let table = RoutingTable::default();
        assert!(table.validate().is_ok());
        let json = table.to_json().unwrap();
        let parsed = RoutingTable::from_json(&json).unwrap();
        assert!(parsed.routes.is_empty());
    }

    #[test]
    fn test_validation_rejects_empty_match() {
        let table = RoutingTable {
            routes: vec![Route {
                name: "bad-route".to_string(),
                match_rule: MatchRule {
                    port: None,
                    path_prefix: None,
                    source_cidr: None,
                },
                target: RouteTarget {
                    pool_id: "workers".to_string(),
                    instance_selector: InstanceSelector::Any,
                    target_port: None,
                },
            }],
        };
        let err = table.validate().unwrap_err();
        assert!(err.to_string().contains("no match criteria"));
    }

    #[test]
    fn test_validation_rejects_duplicate_port() {
        let table = RoutingTable {
            routes: vec![
                Route {
                    name: "first".to_string(),
                    match_rule: MatchRule {
                        port: Some(8080),
                        path_prefix: None,
                        source_cidr: None,
                    },
                    target: RouteTarget {
                        pool_id: "workers".to_string(),
                        instance_selector: InstanceSelector::Any,
                        target_port: None,
                    },
                },
                Route {
                    name: "second".to_string(),
                    match_rule: MatchRule {
                        port: Some(8080),
                        path_prefix: None,
                        source_cidr: None,
                    },
                    target: RouteTarget {
                        pool_id: "other".to_string(),
                        instance_selector: InstanceSelector::Any,
                        target_port: None,
                    },
                },
            ],
        };
        let err = table.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate port 8080"));
    }

    #[test]
    fn test_instance_selector_serde() {
        let variants = vec![
            (InstanceSelector::Any, "\"any\""),
            (
                InstanceSelector::ByIp("10.0.0.1".to_string()),
                "{\"by_ip\":\"10.0.0.1\"}",
            ),
            (InstanceSelector::LeastConnections, "\"least_connections\""),
        ];

        for (selector, expected) in &variants {
            let json = serde_json::to_string(selector).unwrap();
            assert_eq!(&json, expected);
            let parsed: InstanceSelector = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, selector);
        }
    }

    #[test]
    fn test_instance_selector_default_is_any() {
        assert_eq!(InstanceSelector::default(), InstanceSelector::Any);
    }

    #[test]
    fn test_route_with_path_prefix_only() {
        let table = RoutingTable {
            routes: vec![Route {
                name: "api".to_string(),
                match_rule: MatchRule {
                    port: None,
                    path_prefix: Some("/api/v1".to_string()),
                    source_cidr: None,
                },
                target: RouteTarget {
                    pool_id: "workers".to_string(),
                    instance_selector: InstanceSelector::LeastConnections,
                    target_port: Some(3000),
                },
            }],
        };
        assert!(table.validate().is_ok());
    }

    #[test]
    fn test_route_with_source_cidr_only() {
        let table = RoutingTable {
            routes: vec![Route {
                name: "trusted".to_string(),
                match_rule: MatchRule {
                    port: None,
                    path_prefix: None,
                    source_cidr: Some("10.0.0.0/8".to_string()),
                },
                target: RouteTarget {
                    pool_id: "internal".to_string(),
                    instance_selector: InstanceSelector::Any,
                    target_port: None,
                },
            }],
        };
        assert!(table.validate().is_ok());
    }

    #[test]
    fn test_backward_compat_no_routing_table() {
        let json = r#"{"routes": []}"#;
        let parsed: RoutingTable = serde_json::from_str(json).unwrap();
        assert!(parsed.routes.is_empty());
    }
}
