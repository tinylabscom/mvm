use serde::{Deserialize, Serialize};

use crate::instance::InstanceState;
use crate::node::{NodeInfo, NodeStats};
use crate::pool::{
    DesiredCounts, InstanceResources, RegistryArtifact, Role, RuntimePolicy, SecretScope,
    SleepPolicyConfig, UpdateStrategy,
};
use crate::routing::RoutingTable;
use crate::signing::SignedPayload;
use crate::tenant::TenantQuota;

// ============================================================================
// Desired state schema (pushed by coordinator)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredState {
    pub schema_version: u32,
    pub node_id: String,
    pub tenants: Vec<DesiredTenant>,
    #[serde(default)]
    pub prune_unknown_tenants: bool,
    #[serde(default)]
    pub prune_unknown_pools: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredTenant {
    pub tenant_id: String,
    pub network: DesiredTenantNetwork,
    pub quotas: TenantQuota,
    #[serde(default)]
    pub secrets_hash: Option<String>,
    pub pools: Vec<DesiredPool>,
    /// Preferred regions for scheduling this tenant's instances.
    /// The scheduler scores nodes in these regions higher during placement.
    #[serde(default)]
    pub preferred_regions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredTenantNetwork {
    pub tenant_net_id: u16,
    pub ipv4_subnet: String,
}

/// Maximum desired instances per pool per state.
pub const MAX_DESIRED_PER_STATE: u32 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredPool {
    pub pool_id: String,
    pub flake_ref: String,
    pub profile: String,
    #[serde(default)]
    pub role: Role,
    pub instance_resources: InstanceResources,
    pub desired_counts: DesiredCounts,
    #[serde(default)]
    pub runtime_policy: RuntimePolicy,
    #[serde(default = "default_seccomp")]
    pub seccomp_policy: String,
    #[serde(default = "default_compression")]
    pub snapshot_compression: String,
    #[serde(default)]
    pub routing_table: Option<RoutingTable>,
    #[serde(default)]
    pub secret_scopes: Vec<SecretScope>,
    #[serde(default)]
    pub sleep_policy: Option<SleepPolicyConfig>,
    /// Default update strategy for rollouts (rolling or canary).
    /// When set, the agent uses this instead of the deploy config default.
    #[serde(default)]
    pub default_update_strategy: Option<UpdateStrategy>,
    /// Pre-built artifacts to pull from the template registry.
    /// When set, the agent downloads artifacts from S3 instead of running
    /// a local Nix build. Falls back to local build if the pull fails.
    #[serde(default)]
    pub registry_artifact: Option<RegistryArtifact>,
}

fn default_seccomp() -> String {
    "baseline".to_string()
}

fn default_compression() -> String {
    "none".to_string()
}

// ============================================================================
// Reconcile report
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub tenants_created: Vec<String>,
    pub tenants_pruned: Vec<String>,
    pub pools_created: Vec<String>,
    pub instances_created: u32,
    pub instances_started: u32,
    pub instances_warmed: u32,
    pub instances_slept: u32,
    pub instances_stopped: u32,
    #[serde(default)]
    pub instances_deferred: u32,
    pub errors: Vec<String>,
}

// ============================================================================
// Typed message protocol (QUIC API)
// ============================================================================

/// Strongly typed request sent over QUIC streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRequest {
    /// Push a new desired state for reconciliation (unsigned, dev mode only).
    Reconcile(DesiredState),
    /// Push a signed desired state for reconciliation (production mode).
    ReconcileSigned(SignedPayload),
    /// Query node capabilities and identity.
    NodeInfo,
    /// Query aggregate node statistics.
    NodeStats,
    /// List all tenants on this node.
    TenantList,
    /// List instances for a specific tenant (optionally filtered by pool).
    InstanceList {
        tenant_id: String,
        pool_id: Option<String>,
    },
    /// Urgently wake a sleeping instance.
    WakeInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
    },
    /// Perform an imperative lifecycle action on a specific instance.
    InstanceAction {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        action: InstanceAction,
    },
    /// Forward a sandbox operation (filesystem, exec, logs) to the guest agent.
    SandboxAction {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        request: serde_json::Value,
    },
}

/// Imperative lifecycle action for a single instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstanceAction {
    Start,
    Stop,
    Sleep,
    Wake,
    Warm,
    Destroy,
}

/// Strongly typed response returned over QUIC streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResponse {
    /// Result of a reconcile pass.
    ReconcileResult(ReconcileReport),
    /// Node info.
    NodeInfo(NodeInfo),
    /// Aggregate node stats.
    NodeStats(NodeStats),
    /// List of tenant IDs.
    TenantList(Vec<String>),
    /// List of instance states.
    InstanceList(Vec<InstanceState>),
    /// Result of a wake operation.
    WakeResult { success: bool },
    /// Result of an imperative instance action.
    InstanceActionResult {
        success: bool,
        new_status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Result of a sandbox operation (filesystem, exec, logs).
    SandboxResult {
        success: bool,
        response: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Error response.
    Error { code: u16, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_request_serde() {
        let req = AgentRequest::NodeInfo;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::NodeInfo));
    }

    #[test]
    fn test_agent_response_error() {
        let resp = AgentResponse::Error {
            code: 404,
            message: "not found".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Error { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message, "not found");
            }
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_desired_state_serde() {
        let ds = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };
        let json = serde_json::to_string(&ds).unwrap();
        let parsed: DesiredState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.node_id, "node-1");
    }

    #[test]
    fn test_reconcile_report_default() {
        let report = ReconcileReport::default();
        assert!(report.tenants_created.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.instances_created, 0);
    }

    #[test]
    fn test_instance_action_serde_all_variants() {
        let actions = vec![
            InstanceAction::Start,
            InstanceAction::Stop,
            InstanceAction::Sleep,
            InstanceAction::Wake,
            InstanceAction::Warm,
            InstanceAction::Destroy,
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: InstanceAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn test_instance_action_request_serde() {
        let req = AgentRequest::InstanceAction {
            tenant_id: "t1".to_string(),
            pool_id: "p1".to_string(),
            instance_id: "i1".to_string(),
            action: InstanceAction::Wake,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::InstanceAction {
                tenant_id,
                pool_id,
                instance_id,
                action,
            } => {
                assert_eq!(tenant_id, "t1");
                assert_eq!(pool_id, "p1");
                assert_eq!(instance_id, "i1");
                assert_eq!(action, InstanceAction::Wake);
            }
            _ => panic!("Expected InstanceAction variant"),
        }
    }

    #[test]
    fn test_instance_action_result_success() {
        let resp = AgentResponse::InstanceActionResult {
            success: true,
            new_status: "running".to_string(),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error"));
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::InstanceActionResult {
                success,
                new_status,
                error,
            } => {
                assert!(success);
                assert_eq!(new_status, "running");
                assert!(error.is_none());
            }
            _ => panic!("Expected InstanceActionResult variant"),
        }
    }

    #[test]
    fn test_sandbox_action_serde_roundtrip() {
        let req = AgentRequest::SandboxAction {
            tenant_id: "t1".to_string(),
            pool_id: "p1".to_string(),
            instance_id: "i1".to_string(),
            request: serde_json::json!({"type": "Ping"}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::SandboxAction {
                tenant_id,
                pool_id,
                instance_id,
                request,
            } => {
                assert_eq!(tenant_id, "t1");
                assert_eq!(pool_id, "p1");
                assert_eq!(instance_id, "i1");
                assert_eq!(request.get("type").and_then(|t| t.as_str()), Some("Ping"));
            }
            _ => panic!("Expected SandboxAction variant"),
        }
    }

    #[test]
    fn test_sandbox_result_success_roundtrip() {
        let resp = AgentResponse::SandboxResult {
            success: true,
            response: serde_json::json!({"type": "Pong"}),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error"));
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::SandboxResult {
                success,
                response,
                error,
            } => {
                assert!(success);
                assert_eq!(response.get("type").and_then(|t| t.as_str()), Some("Pong"));
                assert!(error.is_none());
            }
            _ => panic!("Expected SandboxResult variant"),
        }
    }

    #[test]
    fn test_sandbox_result_failure_roundtrip() {
        let resp = AgentResponse::SandboxResult {
            success: false,
            response: serde_json::Value::Null,
            error: Some("proxy_error: socket not found".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::SandboxResult { success, error, .. } => {
                assert!(!success);
                assert_eq!(error.as_deref(), Some("proxy_error: socket not found"));
            }
            _ => panic!("Expected SandboxResult variant"),
        }
    }

    #[test]
    fn test_instance_action_result_failure() {
        let resp = AgentResponse::InstanceActionResult {
            success: false,
            new_status: "stopped".to_string(),
            error: Some("Instance not found".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::InstanceActionResult {
                success,
                new_status,
                error,
            } => {
                assert!(!success);
                assert_eq!(new_status, "stopped");
                assert_eq!(error.as_deref(), Some("Instance not found"));
            }
            _ => panic!("Expected InstanceActionResult variant"),
        }
    }

    #[test]
    fn test_desired_pool_backward_compat_no_new_fields() {
        // Old JSON without default_update_strategy should still parse
        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": "github:org/repo",
            "profile": "minimal",
            "instance_resources": {"vcpus": 2, "mem_mib": 1024},
            "desired_counts": {"running": 3, "warm": 1, "sleeping": 0}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.pool_id, "gateways");
        assert!(parsed.default_update_strategy.is_none());
        assert!(parsed.sleep_policy.is_none());
    }

    #[test]
    fn test_desired_pool_with_update_strategy() {
        use crate::pool::UpdateStrategy;

        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 1, "mem_mib": 512},
            "desired_counts": {"running": 1, "warm": 0, "sleeping": 0},
            "default_update_strategy": {"type": "canary", "canary_count": 2, "canary_duration_secs": 600, "success_threshold": 0.99}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        let strategy = parsed.default_update_strategy.unwrap();
        match strategy {
            UpdateStrategy::Canary(c) => {
                assert_eq!(c.canary_count, 2);
                assert_eq!(c.canary_duration_secs, 600);
                assert!((c.success_threshold - 0.99).abs() < 0.001);
            }
            _ => panic!("Expected Canary strategy"),
        }
    }

    #[test]
    fn test_desired_pool_update_strategy_roundtrip() {
        use crate::pool::{RollingUpdateStrategy, UpdateStrategy};

        let pool = DesiredPool {
            pool_id: "workers".to_string(),
            flake_ref: ".".to_string(),
            profile: "minimal".to_string(),
            role: Role::Worker,
            instance_resources: InstanceResources {
                vcpus: 1,
                mem_mib: 512,
                data_disk_mib: 0,
            },
            desired_counts: DesiredCounts {
                running: 1,
                warm: 0,
                sleeping: 0,
            },
            runtime_policy: RuntimePolicy::default(),
            seccomp_policy: "baseline".to_string(),
            snapshot_compression: "none".to_string(),
            routing_table: None,
            secret_scopes: vec![],
            sleep_policy: None,
            default_update_strategy: Some(UpdateStrategy::Rolling(RollingUpdateStrategy {
                max_unavailable: 3,
                max_surge: 2,
                health_check_timeout_secs: 90,
            })),
            registry_artifact: None,
        };
        let json = serde_json::to_string(&pool).unwrap();
        let parsed: DesiredPool = serde_json::from_str(&json).unwrap();
        let strategy = parsed.default_update_strategy.unwrap();
        match strategy {
            UpdateStrategy::Rolling(r) => {
                assert_eq!(r.max_unavailable, 3);
                assert_eq!(r.max_surge, 2);
                assert_eq!(r.health_check_timeout_secs, 90);
            }
            _ => panic!("Expected Rolling strategy"),
        }
    }

    #[test]
    fn test_desired_tenant_backward_compat_no_preferred_regions() {
        // Old JSON without preferred_regions should still parse
        let json = r#"{
            "tenant_id": "acme",
            "network": {"tenant_net_id": 1, "ipv4_subnet": "10.240.1.0/24"},
            "quotas": {"max_vcpus": 16, "max_mem_mib": 32768, "max_running": 8, "max_warm": 4, "max_pools": 4, "max_instances_per_pool": 16, "max_disk_gib": 100},
            "pools": []
        }"#;
        let parsed: DesiredTenant = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.tenant_id, "acme");
        assert!(parsed.preferred_regions.is_empty());
    }

    #[test]
    fn test_desired_tenant_with_preferred_regions() {
        let json = r#"{
            "tenant_id": "acme",
            "network": {"tenant_net_id": 1, "ipv4_subnet": "10.240.1.0/24"},
            "quotas": {"max_vcpus": 16, "max_mem_mib": 32768, "max_running": 8, "max_warm": 4, "max_pools": 4, "max_instances_per_pool": 16, "max_disk_gib": 100},
            "pools": [],
            "preferred_regions": ["us-east-1", "eu-west-1"]
        }"#;
        let parsed: DesiredTenant = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.preferred_regions, vec!["us-east-1", "eu-west-1"]);
    }

    #[test]
    fn test_desired_tenant_preferred_regions_roundtrip() {
        let tenant = DesiredTenant {
            tenant_id: "acme".to_string(),
            network: DesiredTenantNetwork {
                tenant_net_id: 5,
                ipv4_subnet: "10.240.5.0/24".to_string(),
            },
            quotas: TenantQuota::default(),
            secrets_hash: None,
            pools: vec![],
            preferred_regions: vec!["us-west-2".to_string(), "ap-southeast-1".to_string()],
        };
        let json = serde_json::to_string(&tenant).unwrap();
        let parsed: DesiredTenant = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.preferred_regions.len(), 2);
        assert_eq!(parsed.preferred_regions[0], "us-west-2");
        assert_eq!(parsed.preferred_regions[1], "ap-southeast-1");
    }

    #[test]
    fn test_desired_pool_backward_compat_no_registry_artifact() {
        // Old JSON without registry_artifact should still parse
        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": "github:org/repo",
            "profile": "minimal",
            "instance_resources": {"vcpus": 2, "mem_mib": 1024},
            "desired_counts": {"running": 3, "warm": 1, "sleeping": 0}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.pool_id, "gateways");
        assert!(parsed.registry_artifact.is_none());
    }

    #[test]
    fn test_desired_pool_with_registry_artifact() {
        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 1, "mem_mib": 512},
            "desired_counts": {"running": 1, "warm": 0, "sleeping": 0},
            "registry_artifact": {"template_id": "hello", "revision": "abc123"}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        let ra = parsed.registry_artifact.unwrap();
        assert_eq!(ra.template_id, "hello");
        assert_eq!(ra.revision.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_desired_pool_registry_artifact_no_revision() {
        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 1, "mem_mib": 512},
            "desired_counts": {"running": 1, "warm": 0, "sleeping": 0},
            "registry_artifact": {"template_id": "openclaw"}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        let ra = parsed.registry_artifact.unwrap();
        assert_eq!(ra.template_id, "openclaw");
        assert!(ra.revision.is_none());
    }

    #[test]
    fn test_desired_pool_registry_artifact_roundtrip() {
        use crate::pool::{RegistryArtifact, RollingUpdateStrategy, UpdateStrategy};

        let pool = DesiredPool {
            pool_id: "workers".to_string(),
            flake_ref: ".".to_string(),
            profile: "minimal".to_string(),
            role: Role::Worker,
            instance_resources: InstanceResources {
                vcpus: 1,
                mem_mib: 512,
                data_disk_mib: 0,
            },
            desired_counts: DesiredCounts {
                running: 1,
                warm: 0,
                sleeping: 0,
            },
            runtime_policy: RuntimePolicy::default(),
            seccomp_policy: "baseline".to_string(),
            snapshot_compression: "none".to_string(),
            routing_table: None,
            secret_scopes: vec![],
            sleep_policy: None,
            default_update_strategy: Some(
                UpdateStrategy::Rolling(RollingUpdateStrategy::default()),
            ),
            registry_artifact: Some(RegistryArtifact {
                template_id: "hello".to_string(),
                revision: Some("rev-abc123".to_string()),
            }),
        };
        let json = serde_json::to_string(&pool).unwrap();
        let parsed: DesiredPool = serde_json::from_str(&json).unwrap();
        let ra = parsed.registry_artifact.unwrap();
        assert_eq!(ra.template_id, "hello");
        assert_eq!(ra.revision.as_deref(), Some("rev-abc123"));
    }
}
