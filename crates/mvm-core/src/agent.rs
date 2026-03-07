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
// Deployment control types
// ============================================================================

/// Deployment phase for rollout state tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    NotStarted,
    CanaryEvaluation,
    RollingUpdate,
    Paused,
    Complete,
    RolledBack,
    Failed,
}

// ============================================================================
// Batch operation types
// ============================================================================

/// Single item in a batch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchActionItem {
    pub tenant_id: String,
    pub pool_id: String,
    pub instance_id: String,
    pub action: InstanceAction,
}

/// Pool-level action types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PoolActionType {
    StartAll,
    StopAll,
    WarmAll,
    DestroyAll {
        wipe_volumes: bool,
    },
    ScaleTo {
        running: u32,
        warm: u32,
        sleeping: u32,
    },
}

/// Result for a single item in a batch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchActionItemResult {
    pub tenant_id: String,
    pub pool_id: String,
    pub instance_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Monitoring and observability types
// ============================================================================

/// Health status for a single instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceHealthReport {
    pub tenant_id: String,
    pub pool_id: String,
    pub instance_id: String,
    pub status: InstanceState,
    pub healthy: bool,
    pub integration_health: Vec<IntegrationHealthSummary>,
    pub probe_results: Vec<ProbeResultSummary>,
    pub idle_metrics: crate::idle_metrics::IdleMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_health_check_at: Option<String>,
}

/// Integration health summary (from guest integrations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationHealthSummary {
    pub name: String,
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Probe result summary (from guest probes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultSummary {
    pub name: String,
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Single reconciliation history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileHistoryEntry {
    pub timestamp: String,
    pub duration_ms: u64,
    pub report: ReconcileReport,
}

/// Tenant state in state dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStateDump {
    pub tenant_id: String,
    pub pools: Vec<PoolStateDump>,
}

/// Pool state in state dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStateDump {
    pub pool_id: String,
    pub instances: Vec<InstanceState>,
    pub desired_counts: DesiredCounts,
}

/// Content for StateDump response (boxed to reduce enum size).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDumpContent {
    pub node_info: NodeInfo,
    pub node_stats: NodeStats,
    #[serde(default)]
    pub metrics: Option<crate::observability::metrics::MetricsSnapshot>,
    #[serde(default)]
    pub audit_log: Option<Vec<crate::audit::AuditEntry>>,
    pub tenants: Vec<TenantStateDump>,
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
    /// Query the status of an ongoing deployment/rollout for a pool.
    DeploymentStatus { tenant_id: String, pool_id: String },
    /// Pause an ongoing deployment/rollout.
    PauseDeployment { tenant_id: String, pool_id: String },
    /// Resume a paused deployment/rollout.
    ResumeDeployment { tenant_id: String, pool_id: String },
    /// Rollback a deployment to the previous revision.
    RollbackDeployment {
        tenant_id: String,
        pool_id: String,
        #[serde(default)]
        target_revision: Option<String>,
    },
    /// Perform the same action on multiple instances at once.
    BatchInstanceAction { actions: Vec<BatchActionItem> },
    /// Perform pool-level operations (affect all instances in pool).
    PoolAction {
        tenant_id: String,
        pool_id: String,
        action: PoolActionType,
    },
    /// Query current metrics snapshot.
    GetMetrics,
    /// Retrieve recent audit log entries for a tenant.
    GetAuditLog {
        tenant_id: String,
        #[serde(default)]
        last_n: Option<u32>,
        #[serde(default)]
        since: Option<String>,
    },
    /// Get detailed health status for instances.
    GetHealthStatus {
        #[serde(default)]
        tenant_id: Option<String>,
        #[serde(default)]
        pool_id: Option<String>,
    },
    /// Retrieve reconciliation history.
    GetReconcileHistory {
        #[serde(default)]
        last_n: Option<u32>,
    },
    /// Force an immediate reconciliation pass (debug/troubleshooting).
    ForceReconcile { dry_run: bool },
    /// Export complete node state for debugging.
    DumpState {
        include_metrics: bool,
        include_audit_log: bool,
    },
    /// Hot reload secrets without restarting instances.
    UpdateSecrets {
        tenant_id: String,
        secrets_hash: String,
        force_reload: bool,
    },
    /// Update config drive for instances in a pool.
    UpdateConfig {
        tenant_id: String,
        pool_id: String,
        config_version: u64,
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
    /// Deployment status with rollout progress.
    DeploymentStatus {
        pool_id: String,
        current_revision: String,
        #[serde(default)]
        target_revision: Option<String>,
        strategy: UpdateStrategy,
        phase: DeploymentPhase,
        instances_updated: u32,
        instances_pending: u32,
        #[serde(default)]
        canary_health: Option<f64>,
        paused: bool,
        errors: Vec<String>,
    },
    /// Result of pause/resume/rollback operations.
    DeploymentControlResult {
        success: bool,
        pool_id: String,
        new_phase: String,
        message: String,
    },
    /// Result of batch instance operations.
    BatchActionResult {
        results: Vec<BatchActionItemResult>,
        total: u32,
        succeeded: u32,
        failed: u32,
    },
    /// Result of pool-level action.
    PoolActionResult {
        success: bool,
        pool_id: String,
        instances_affected: u32,
        errors: Vec<String>,
    },
    /// Metrics snapshot.
    Metrics(crate::observability::metrics::MetricsSnapshot),
    /// Audit log entries.
    AuditLog {
        entries: Vec<crate::audit::AuditEntry>,
        total_count: u32,
    },
    /// Health status report for instances.
    HealthStatus {
        instances: Vec<InstanceHealthReport>,
        unhealthy_count: u32,
        degraded_count: u32,
    },
    /// Reconciliation history.
    ReconcileHistory { runs: Vec<ReconcileHistoryEntry> },
    /// Complete node state dump (boxed due to size).
    StateDump(Box<StateDumpContent>),
    /// Result of secrets update.
    SecretsUpdateResult {
        success: bool,
        tenant_id: String,
        instances_reloaded: u32,
        errors: Vec<String>,
    },
    /// Result of config update.
    ConfigUpdateResult {
        success: bool,
        pool_id: String,
        instances_updated: u32,
        errors: Vec<String>,
    },
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

    // ========================================================================
    // Tests for new protocol extensions
    // ========================================================================

    #[test]
    fn test_deployment_phase_serde_all_variants() {
        let phases = vec![
            DeploymentPhase::NotStarted,
            DeploymentPhase::CanaryEvaluation,
            DeploymentPhase::RollingUpdate,
            DeploymentPhase::Paused,
            DeploymentPhase::Complete,
            DeploymentPhase::RolledBack,
            DeploymentPhase::Failed,
        ];
        for phase in phases {
            let json = serde_json::to_string(&phase).unwrap();
            let parsed: DeploymentPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, phase);
        }
    }

    #[test]
    fn test_batch_action_item_serde() {
        let item = BatchActionItem {
            tenant_id: "t1".to_string(),
            pool_id: "p1".to_string(),
            instance_id: "i1".to_string(),
            action: InstanceAction::Start,
        };
        let json = serde_json::to_string(&item).unwrap();
        let parsed: BatchActionItem = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tenant_id, "t1");
        assert_eq!(parsed.pool_id, "p1");
        assert_eq!(parsed.instance_id, "i1");
        assert_eq!(parsed.action, InstanceAction::Start);
    }

    #[test]
    fn test_pool_action_type_serde_all_variants() {
        let actions = vec![
            PoolActionType::StartAll,
            PoolActionType::StopAll,
            PoolActionType::WarmAll,
            PoolActionType::DestroyAll { wipe_volumes: true },
            PoolActionType::ScaleTo {
                running: 3,
                warm: 1,
                sleeping: 0,
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: PoolActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn test_agent_request_deployment_status() {
        let req = AgentRequest::DeploymentStatus {
            tenant_id: "acme".to_string(),
            pool_id: "gateways".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::DeploymentStatus { tenant_id, pool_id } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(pool_id, "gateways");
            }
            _ => panic!("Expected DeploymentStatus variant"),
        }
    }

    #[test]
    fn test_agent_request_pause_deployment() {
        let req = AgentRequest::PauseDeployment {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::PauseDeployment { .. }));
    }

    #[test]
    fn test_agent_request_resume_deployment() {
        let req = AgentRequest::ResumeDeployment {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::ResumeDeployment { .. }));
    }

    #[test]
    fn test_agent_request_rollback_deployment() {
        let req = AgentRequest::RollbackDeployment {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            target_revision: Some("rev-abc123".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::RollbackDeployment {
                target_revision, ..
            } => {
                assert_eq!(target_revision.as_deref(), Some("rev-abc123"));
            }
            _ => panic!("Expected RollbackDeployment variant"),
        }
    }

    #[test]
    fn test_agent_request_batch_instance_action() {
        let req = AgentRequest::BatchInstanceAction {
            actions: vec![
                BatchActionItem {
                    tenant_id: "t1".to_string(),
                    pool_id: "p1".to_string(),
                    instance_id: "i1".to_string(),
                    action: InstanceAction::Start,
                },
                BatchActionItem {
                    tenant_id: "t1".to_string(),
                    pool_id: "p1".to_string(),
                    instance_id: "i2".to_string(),
                    action: InstanceAction::Stop,
                },
            ],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::BatchInstanceAction { actions } => {
                assert_eq!(actions.len(), 2);
                assert_eq!(actions[0].instance_id, "i1");
                assert_eq!(actions[1].instance_id, "i2");
            }
            _ => panic!("Expected BatchInstanceAction variant"),
        }
    }

    #[test]
    fn test_agent_request_pool_action() {
        let req = AgentRequest::PoolAction {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            action: PoolActionType::StartAll,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::PoolAction { action, .. } => {
                assert_eq!(action, PoolActionType::StartAll);
            }
            _ => panic!("Expected PoolAction variant"),
        }
    }

    #[test]
    fn test_agent_request_get_metrics() {
        let req = AgentRequest::GetMetrics;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::GetMetrics));
    }

    #[test]
    fn test_agent_request_get_audit_log() {
        let req = AgentRequest::GetAuditLog {
            tenant_id: "acme".to_string(),
            last_n: Some(10),
            since: Some("2025-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::GetAuditLog {
                tenant_id,
                last_n,
                since,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(last_n, Some(10));
                assert_eq!(since.as_deref(), Some("2025-01-01T00:00:00Z"));
            }
            _ => panic!("Expected GetAuditLog variant"),
        }
    }

    #[test]
    fn test_agent_request_get_health_status() {
        let req = AgentRequest::GetHealthStatus {
            tenant_id: Some("acme".to_string()),
            pool_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::GetHealthStatus { tenant_id, pool_id } => {
                assert_eq!(tenant_id.as_deref(), Some("acme"));
                assert!(pool_id.is_none());
            }
            _ => panic!("Expected GetHealthStatus variant"),
        }
    }

    #[test]
    fn test_agent_request_get_reconcile_history() {
        let req = AgentRequest::GetReconcileHistory { last_n: Some(5) };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::GetReconcileHistory { last_n } => {
                assert_eq!(last_n, Some(5));
            }
            _ => panic!("Expected GetReconcileHistory variant"),
        }
    }

    #[test]
    fn test_agent_request_force_reconcile() {
        let req = AgentRequest::ForceReconcile { dry_run: true };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::ForceReconcile { dry_run } => {
                assert!(dry_run);
            }
            _ => panic!("Expected ForceReconcile variant"),
        }
    }

    #[test]
    fn test_agent_request_dump_state() {
        let req = AgentRequest::DumpState {
            include_metrics: true,
            include_audit_log: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::DumpState {
                include_metrics,
                include_audit_log,
            } => {
                assert!(include_metrics);
                assert!(!include_audit_log);
            }
            _ => panic!("Expected DumpState variant"),
        }
    }

    #[test]
    fn test_agent_request_update_secrets() {
        let req = AgentRequest::UpdateSecrets {
            tenant_id: "acme".to_string(),
            secrets_hash: "sha256:abc123".to_string(),
            force_reload: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::UpdateSecrets {
                tenant_id,
                secrets_hash,
                force_reload,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(secrets_hash, "sha256:abc123");
                assert!(!force_reload);
            }
            _ => panic!("Expected UpdateSecrets variant"),
        }
    }

    #[test]
    fn test_agent_request_update_config() {
        let req = AgentRequest::UpdateConfig {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            config_version: 42,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::UpdateConfig {
                tenant_id,
                pool_id,
                config_version,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(pool_id, "workers");
                assert_eq!(config_version, 42);
            }
            _ => panic!("Expected UpdateConfig variant"),
        }
    }

    #[test]
    fn test_agent_response_deployment_status() {
        use crate::pool::{RollingUpdateStrategy, UpdateStrategy};

        let resp = AgentResponse::DeploymentStatus {
            pool_id: "workers".to_string(),
            current_revision: "rev-old".to_string(),
            target_revision: Some("rev-new".to_string()),
            strategy: UpdateStrategy::Rolling(RollingUpdateStrategy::default()),
            phase: DeploymentPhase::RollingUpdate,
            instances_updated: 5,
            instances_pending: 3,
            canary_health: None,
            paused: false,
            errors: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::DeploymentStatus {
                pool_id,
                current_revision,
                phase,
                ..
            } => {
                assert_eq!(pool_id, "workers");
                assert_eq!(current_revision, "rev-old");
                assert_eq!(phase, DeploymentPhase::RollingUpdate);
            }
            _ => panic!("Expected DeploymentStatus variant"),
        }
    }

    #[test]
    fn test_agent_response_deployment_control_result() {
        let resp = AgentResponse::DeploymentControlResult {
            success: true,
            pool_id: "workers".to_string(),
            new_phase: "paused".to_string(),
            message: "Deployment paused successfully".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::DeploymentControlResult {
                success, pool_id, ..
            } => {
                assert!(success);
                assert_eq!(pool_id, "workers");
            }
            _ => panic!("Expected DeploymentControlResult variant"),
        }
    }

    #[test]
    fn test_agent_response_batch_action_result() {
        let resp = AgentResponse::BatchActionResult {
            results: vec![
                BatchActionItemResult {
                    tenant_id: "t1".to_string(),
                    pool_id: "p1".to_string(),
                    instance_id: "i1".to_string(),
                    success: true,
                    new_status: Some("running".to_string()),
                    error: None,
                },
                BatchActionItemResult {
                    tenant_id: "t1".to_string(),
                    pool_id: "p1".to_string(),
                    instance_id: "i2".to_string(),
                    success: false,
                    new_status: None,
                    error: Some("Instance not found".to_string()),
                },
            ],
            total: 2,
            succeeded: 1,
            failed: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::BatchActionResult {
                results,
                total,
                succeeded,
                failed,
            } => {
                assert_eq!(total, 2);
                assert_eq!(succeeded, 1);
                assert_eq!(failed, 1);
                assert_eq!(results.len(), 2);
                assert!(results[0].success);
                assert!(!results[1].success);
            }
            _ => panic!("Expected BatchActionResult variant"),
        }
    }

    #[test]
    fn test_agent_response_pool_action_result() {
        let resp = AgentResponse::PoolActionResult {
            success: true,
            pool_id: "workers".to_string(),
            instances_affected: 5,
            errors: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::PoolActionResult {
                success,
                pool_id,
                instances_affected,
                ..
            } => {
                assert!(success);
                assert_eq!(pool_id, "workers");
                assert_eq!(instances_affected, 5);
            }
            _ => panic!("Expected PoolActionResult variant"),
        }
    }

    #[test]
    fn test_agent_response_metrics() {
        use crate::observability::metrics::MetricsSnapshot;

        let snapshot = MetricsSnapshot {
            requests_total: 100,
            requests_reconcile: 10,
            requests_node_info: 5,
            requests_node_stats: 3,
            requests_tenant_list: 2,
            requests_instance_list: 15,
            requests_wake: 8,
            requests_rate_limited: 1,
            requests_failed: 2,
            reconcile_runs: 10,
            reconcile_errors: 0,
            reconcile_duration_ms: 500,
            instances_created: 20,
            instances_started: 18,
            instances_stopped: 10,
            instances_slept: 5,
            instances_woken: 8,
            instances_destroyed: 2,
            instances_deferred: 3,
            connections_accepted: 50,
            connections_rejected: 1,
        };
        let resp = AgentResponse::Metrics(snapshot);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Metrics(s) => {
                assert_eq!(s.requests_total, 100);
                assert_eq!(s.reconcile_runs, 10);
                assert_eq!(s.instances_created, 20);
            }
            _ => panic!("Expected Metrics variant"),
        }
    }

    #[test]
    fn test_agent_response_audit_log() {
        use crate::audit::{AuditAction, AuditEntry};

        let resp = AgentResponse::AuditLog {
            entries: vec![AuditEntry {
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                tenant_id: "acme".to_string(),
                pool_id: Some("workers".to_string()),
                instance_id: Some("i-001".to_string()),
                action: AuditAction::InstanceStarted,
                detail: Some("pid=12345".to_string()),
                threats: vec![],
                gate_decision: None,
                frame_sequence: None,
            }],
            total_count: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::AuditLog {
                entries,
                total_count,
            } => {
                assert_eq!(total_count, 1);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].tenant_id, "acme");
            }
            _ => panic!("Expected AuditLog variant"),
        }
    }

    #[test]
    fn test_agent_response_secrets_update_result() {
        let resp = AgentResponse::SecretsUpdateResult {
            success: true,
            tenant_id: "acme".to_string(),
            instances_reloaded: 10,
            errors: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::SecretsUpdateResult {
                success,
                tenant_id,
                instances_reloaded,
                ..
            } => {
                assert!(success);
                assert_eq!(tenant_id, "acme");
                assert_eq!(instances_reloaded, 10);
            }
            _ => panic!("Expected SecretsUpdateResult variant"),
        }
    }

    #[test]
    fn test_agent_response_config_update_result() {
        let resp = AgentResponse::ConfigUpdateResult {
            success: true,
            pool_id: "workers".to_string(),
            instances_updated: 5,
            errors: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::ConfigUpdateResult {
                success,
                pool_id,
                instances_updated,
                ..
            } => {
                assert!(success);
                assert_eq!(pool_id, "workers");
                assert_eq!(instances_updated, 5);
            }
            _ => panic!("Expected ConfigUpdateResult variant"),
        }
    }
}
