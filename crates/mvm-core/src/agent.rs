use serde::{Deserialize, Serialize};

use crate::instance::InstanceState;
use crate::node::{NodeInfo, NodeStats};
use crate::pool::{
    DesiredCounts, InstanceResources, Role, RuntimePolicy, SecretScope, SleepPolicyConfig,
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
}
