use serde::{Deserialize, Serialize};

use crate::instance::InstanceState;
use crate::node::{NodeInfo, NodeStats};
use crate::pool::{
    AttestedDeployment, DesiredCounts, InstanceResources, RegistryArtifact, Role, RuntimePolicy,
    SecretScope, SleepPolicyConfig, UpdateStrategy,
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
    /// Monotonic sequence number from the coordinator's event log.
    /// Agents use this to track which state version they last applied,
    /// enabling incremental sync via `SyncEvents { since }`.
    #[serde(default)]
    pub sequence: u64,
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
    /// Attested deployment bundle to fetch from mvmd before this pool boots.
    /// Unlike `registry_artifact`, a failed fetch is terminal for this
    /// desired revision and must not fall back to a local build.
    #[serde(default)]
    pub attested_deployment: Option<AttestedDeployment>,
    /// Distributed-volume mounts attached to every instance of this pool.
    ///
    /// Schema evolution: `#[serde(default)]` keeps the old-coordinator →
    /// new-agent direction parsing (missing field ⇒ no mounts). The
    /// reverse direction (new coordinator sending `mounts` to an old
    /// agent) fails closed on `deny_unknown_fields`; rolling that out is
    /// governed by `DesiredState::schema_version`, matching how prior
    /// `DesiredPool` field additions were sequenced.
    #[serde(default)]
    pub mounts: Vec<DesiredMount>,
}

fn default_seccomp() -> String {
    "baseline".to_string()
}

fn default_compression() -> String {
    "none".to_string()
}

/// A distributed-volume mount (S3/NFS/FUSE-backed bucket) attached to
/// every instance of a pool.
///
/// Part of the signed desired-state contract. The coordinator resolves a
/// tenant bucket into this shape; agents reconcile it via the hostd
/// `MountVolume` / `UnmountVolume` verbs.
///
/// This is deliberately a separate type from the IR `Mount`
/// (`mvm-contract::ir::workload`) — the IR describes a single workload's
/// authored intent, while this describes coordinator-resolved fleet
/// state pushed to agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredMount {
    /// Coordinator-scoped bucket identifier this mount materializes.
    pub bucket_id: String,
    /// Backing provider (e.g. "s3", "nfs", "local-virtiofs").
    ///
    /// Deliberately an open string rather than an enum, mirroring the
    /// `MountSource::External { provider, .. }` precedent in the IR:
    /// new providers plug in without a core-schema edit. An unknown
    /// provider is rejected at mount time, never silently defaulted.
    pub provider: String,
    /// Provider-schema-owned configuration. The desired-state layer
    /// does not interpret it; the provider validates it at mount time.
    pub config: serde_json::Value,
    /// Absolute guest path the volume is mounted at.
    pub target: String,
    /// Read-only vs read-write attachment for each instance.
    pub mode: DesiredMountMode,
    /// Monotonic mount-config generation. The coordinator bumps it on
    /// any change to this mount (config, mode, access_mode, …); agents
    /// remount when their applied generation is behind.
    pub generation: u64,
    /// Concurrency contract across instances (see [`MountAccessMode`]).
    ///
    /// Defaults to [`MountAccessMode::Rox`]: read-only-many is the only
    /// mode that is safe on every provider without write coordination,
    /// so writers must opt in explicitly.
    #[serde(default)]
    pub access_mode: MountAccessMode,
}

/// Read-only vs read-write for a [`DesiredMount`].
///
/// Mirrors (rather than reuses) the IR `MountMode`
/// (`mvm-contract::ir::workload`) so the signed desired-state schema
/// stays self-contained; the wire values (`"ro"` / `"rw"`) are
/// identical by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredMountMode {
    /// Read-only attachment.
    Ro,
    /// Read-write attachment.
    Rw,
}

/// Concurrency/access contract for a [`DesiredMount`] across the
/// instances of a pool (Kubernetes PV-style semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountAccessMode {
    /// Read-write by at most one instance at a time.
    Rwo,
    /// Read-only by many instances. The default: the only mode that is
    /// safe on every provider without write coordination — writers must
    /// opt in explicitly via `Rwo`/`Rwx`.
    #[default]
    Rox,
    /// Read-write by many instances (requires a provider that
    /// coordinates concurrent writers, e.g. NFS).
    Rwx,
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
// Host-services delegation types
// ============================================================================

/// Query for the mvmd-delegated `host.cost.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantCostQuery {
    /// Tenant the caller wants aggregated spend for. The agent must refuse any
    /// mismatch against the authenticated workload tenant.
    pub requested_tenant_id: String,
}

/// Successful result for the mvmd-delegated `host.cost.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantCostResult {
    pub report: crate::protocol::host_cost::CostReport,
}

/// Query for the mvmd-delegated `host.catalog.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantCatalogQuery {
    /// Tenant the caller wants the service catalog for. The agent must refuse
    /// any mismatch against the authenticated workload tenant.
    pub requested_tenant_id: String,
    /// Optional caller-provided idempotency/replay key for delegated calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Query for the mvmd-delegated `host.peers.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantPeersQuery {
    /// Tenant the caller wants peer data for.
    pub requested_tenant_id: String,
    /// Optional caller-provided idempotency/replay key for delegated calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional label selector forwarded to the mvmd gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
}

/// Query for the mvmd-delegated `host.config.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigQuery {
    /// Tenant the caller wants config data for.
    pub requested_tenant_id: String,
    /// Optional caller-provided idempotency/replay key for delegated calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Tenant config key to read.
    pub key: String,
}

/// Query for the mvmd-delegated `host.rate_budget.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantRateBudgetQuery {
    /// Tenant the caller wants rate-budget data for.
    pub requested_tenant_id: String,
    /// Optional caller-provided idempotency/replay key for delegated calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Service id whose effective rate budget should be returned.
    pub service: String,
}

/// Successful result for the mvmd-delegated `host.catalog.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantCatalogResult {
    pub tenant_id: String,
    pub services: Vec<serde_json::Value>,
}

/// Successful result for the mvmd-delegated `host.peers.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantPeersResult {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
    pub peers: Vec<serde_json::Value>,
}

/// Successful result for the mvmd-delegated `host.config.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigResult {
    pub tenant_id: String,
    pub key: String,
    pub value: serde_json::Value,
}

/// Successful result for the mvmd-delegated `host.rate_budget.v1::tenant` verb.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantRateBudgetResult {
    pub tenant_id: String,
    pub service: String,
    pub effective_requests_per_second: u32,
    pub effective_burst: u32,
    pub source: String,
    pub limits: Vec<serde_json::Value>,
}

// ============================================================================
// Typed message protocol (QUIC API)
// ============================================================================

// ============================================================================
// Egress-secrets delivery payload (gateway → agent, instance-start path)
// ============================================================================
//
// The fleet controller (mvmd's gateway) owns the tenant-secrets vault
// (Postgres). The agent — the node where the VM and its substitution
// endpoint actually run — has no line to that vault. These types are the
// one-directional gateway→agent delivery of a VM's *pre-resolved* egress
// secret catalog plus the *decrypted* values, carried over the existing
// mTLS-protected QUIC control channel at instance start.
//
// Split by sensitivity: `EgressSecretBinding` is non-secret catalog metadata
// (safe to log); `EgressSecretValue` carries decrypted material and therefore
// gets a hand-written redacting `Debug`. `EgressSecretsPayload` bundles both
// and rides `InstanceAction::Start` / `StartInstanceWithBlockVolumes` as an
// optional, back-compatible field.

/// Non-secret catalog entry describing one egress secret the VM is allowed to
/// use: its logical `name`, the destinations it may be sent to, and the auth
/// scheme. Contains no secret material and is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSecretBinding {
    /// Logical name the guest references (e.g. `"stripe_api_key"`).
    pub name: String,
    /// Destinations this secret may be substituted into (host/URL globs).
    pub allowed_destinations: Vec<String>,
    /// Auth scheme this secret satisfies (e.g. `"bearer"`, `"basic"`).
    pub auth_type: String,
}

/// Secret-bearing resolved value for one egress secret, keyed by `name` to a
/// base64-encoded decrypted value.
///
/// `value_b64` holds decrypted secret material, so this type has a
/// hand-written [`Debug`] that redacts the value — mirroring the redaction of
/// `value_b64` in the substitution wire response. The value MUST NOT appear in
/// logs, panics, or `{:?}` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSecretValue {
    /// Logical name matching an [`EgressSecretBinding::name`].
    pub name: String,
    /// Base64-encoded decrypted secret value. Redacted in `Debug`.
    pub value_b64: String,
}

// allow(secret-debug): hand-written Debug below redacts `value_b64`; only the
// non-secret `name` is printed.
impl std::fmt::Debug for EgressSecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressSecretValue")
            .field("name", &self.name)
            .field("value_b64", &"[REDACTED]")
            .finish()
    }
}

/// A VM's fully-resolved egress-secret bundle: the non-secret catalog
/// (`bindings`) plus the decrypted `values`. Delivered gateway→agent on the
/// instance-start path. `Debug` is derived; the secret `values` redact
/// themselves via [`EgressSecretValue`]'s hand-written `Debug`.
// allow(secret-debug): nested EgressSecretValue implements redacting Debug;
// the payload-level test below proves decrypted values never appear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSecretsPayload {
    /// Non-secret catalog: what the VM may egress and where.
    pub bindings: Vec<EgressSecretBinding>,
    /// Secret-bearing decrypted values, redacted in `Debug`.
    pub values: Vec<EgressSecretValue>,
}

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
    ///
    /// When `action` is [`InstanceAction::Start`], the fleet controller
    /// (mvmd's gateway) may attach `egress_secrets`: the VM's pre-resolved
    /// egress-secret catalog plus decrypted values. See
    /// [`EgressSecretsPayload`] for why this rides the start path. The field
    /// is `#[serde(default)]` so pre-existing callers (and any non-`Start`
    /// action) serialize and deserialize byte-for-byte as before.
    InstanceAction {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        action: InstanceAction,
        /// Optional gateway→agent delivery of resolved egress secrets for a
        /// `Start`. `None` = today's behavior (no secrets delivered inline).
        #[serde(default)]
        egress_secrets: Option<EgressSecretsPayload>,
    },
    /// Start an instance with fleet-resolved encrypted block volumes.
    StartInstanceWithBlockVolumes {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        #[serde(default)]
        workspace_id: Option<String>,
        volumes: Vec<crate::instance::BlockVolumeAttach>,
        /// Optional gateway→agent delivery of resolved egress secrets,
        /// delivered alongside the block volumes at instance start. `None` =
        /// today's behavior. See [`EgressSecretsPayload`].
        #[serde(default)]
        egress_secrets: Option<EgressSecretsPayload>,
    },
    /// Refresh the same fenced leases before their UTC expiry.
    RenewBlockVolumeLeases {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        volumes: Vec<crate::instance::BlockVolumeAttach>,
    },
    /// Read one bounded ciphertext chunk from a fenced, detached volume image.
    ReadBlockVolumeChunk {
        tenant_id: String,
        pool_id: String,
        volume: crate::instance::BlockVolumeTransfer,
        offset: u64,
        max_bytes: u32,
    },
    /// Create private restore staging for an exact encrypted image.
    BeginBlockVolumeRestore {
        tenant_id: String,
        pool_id: String,
        restore: crate::instance::BlockVolumeRestore,
    },
    /// Append one verified ciphertext chunk to restore staging.
    WriteBlockVolumeRestoreChunk {
        tenant_id: String,
        pool_id: String,
        transfer_id: String,
        chunk: crate::instance::BlockVolumeChunk,
    },
    /// Verify, fsync, and atomically publish a staged encrypted image.
    CommitBlockVolumeRestore {
        tenant_id: String,
        pool_id: String,
        transfer_id: String,
    },
    /// Idempotently discard private restore staging.
    AbortBlockVolumeRestore {
        tenant_id: String,
        pool_id: String,
        transfer_id: String,
    },
    /// Forward a sandbox operation (filesystem, exec, logs) to the guest agent.
    SandboxAction {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        request: serde_json::Value,
    },
    /// Query tenant-aggregated spend for the calling workload's tenant.
    HostCostTenantQuery {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        query: TenantCostQuery,
    },
    /// Query tenant service catalog for the calling workload's tenant.
    HostCatalogTenantQuery {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        query: TenantCatalogQuery,
    },
    /// Query tenant peer metadata for the calling workload's tenant.
    HostPeersTenantQuery {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        query: TenantPeersQuery,
    },
    /// Query one tenant config key for the calling workload's tenant.
    HostConfigTenantQuery {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        query: TenantConfigQuery,
    },
    /// Query effective rate budget for a service in the calling workload's tenant.
    HostRateBudgetTenantQuery {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        query: TenantRateBudgetQuery,
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
    /// Request incremental state events since a given sequence number.
    ///
    /// Returns events with sequence > `since`. If the event log has been
    /// truncated past the requested sequence, the coordinator responds with
    /// a full `DesiredState` instead.
    SyncEvents { since: u64 },
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
    /// A bounded encrypted-image chunk returned to the gateway.
    BlockVolumeChunk(crate::instance::BlockVolumeChunk),
    /// Progress or completion of a worker-side image restore.
    BlockVolumeTransferResult {
        success: bool,
        next_offset: u64,
        complete: bool,
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
    /// Successful result of a `HostCostTenantQuery`.
    HostCostTenantResult(TenantCostResult),
    /// Successful result of a `HostCatalogTenantQuery`.
    HostCatalogTenantResult(TenantCatalogResult),
    /// Successful result of a `HostPeersTenantQuery`.
    HostPeersTenantResult(TenantPeersResult),
    /// Successful result of a `HostConfigTenantQuery`.
    HostConfigTenantResult(TenantConfigResult),
    /// Successful result of a `HostRateBudgetTenantQuery`.
    HostRateBudgetTenantResult(TenantRateBudgetResult),
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
    Metrics(Box<crate::observability::metrics::MetricsSnapshot>),
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
    /// Incremental state events in response to `SyncEvents`.
    SyncEventsResult {
        /// Events with sequence > the requested `since` value.
        events: Vec<serde_json::Value>,
        /// Current sequence number at the coordinator.
        current_sequence: u64,
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
    fn test_host_cost_tenant_query_roundtrips() {
        let req = AgentRequest::HostCostTenantQuery {
            tenant_id: "tenant-a".to_string(),
            pool_id: "pool-a".to_string(),
            instance_id: "vm-a".to_string(),
            query: TenantCostQuery {
                requested_tenant_id: "tenant-a".to_string(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::HostCostTenantQuery {
                tenant_id,
                pool_id,
                instance_id,
                query,
            } => {
                assert_eq!(tenant_id, "tenant-a");
                assert_eq!(pool_id, "pool-a");
                assert_eq!(instance_id, "vm-a");
                assert_eq!(query.requested_tenant_id, "tenant-a");
            }
            other => panic!("Expected HostCostTenantQuery, got {other:?}"),
        }
    }

    #[test]
    fn test_host_cost_tenant_result_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "HostCostTenantResult": {
                "report": { "spent_micros_usd": 42 },
                "unexpected": true
            }
        });
        let err = serde_json::from_value::<AgentResponse>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_delegated_host_services_requests_roundtrip() {
        let requests = vec![
            AgentRequest::HostCatalogTenantQuery {
                tenant_id: "tenant-a".to_string(),
                pool_id: "pool-a".to_string(),
                instance_id: "vm-a".to_string(),
                query: TenantCatalogQuery {
                    requested_tenant_id: "tenant-a".to_string(),
                    request_id: Some("req-catalog".to_string()),
                },
            },
            AgentRequest::HostPeersTenantQuery {
                tenant_id: "tenant-a".to_string(),
                pool_id: "pool-a".to_string(),
                instance_id: "vm-a".to_string(),
                query: TenantPeersQuery {
                    requested_tenant_id: "tenant-a".to_string(),
                    request_id: Some("req-peers".to_string()),
                    label_selector: Some("region=us-east-1".to_string()),
                },
            },
            AgentRequest::HostConfigTenantQuery {
                tenant_id: "tenant-a".to_string(),
                pool_id: "pool-a".to_string(),
                instance_id: "vm-a".to_string(),
                query: TenantConfigQuery {
                    requested_tenant_id: "tenant-a".to_string(),
                    request_id: Some("req-config".to_string()),
                    key: "max_vcpus".to_string(),
                },
            },
            AgentRequest::HostRateBudgetTenantQuery {
                tenant_id: "tenant-a".to_string(),
                pool_id: "pool-a".to_string(),
                instance_id: "vm-a".to_string(),
                query: TenantRateBudgetQuery {
                    requested_tenant_id: "tenant-a".to_string(),
                    request_id: Some("req-rate".to_string()),
                    service: "svc-a".to_string(),
                },
            },
        ];

        for request in requests {
            let json = serde_json::to_value(&request).unwrap();
            let parsed: AgentRequest = serde_json::from_value(json.clone())
                .unwrap_or_else(|err| panic!("failed to parse delegated request {json}: {err}"));
            assert_eq!(serde_json::to_value(parsed).unwrap(), json);
        }
    }

    #[test]
    fn test_delegated_host_services_responses_roundtrip() {
        let responses = vec![
            AgentResponse::HostCatalogTenantResult(TenantCatalogResult {
                tenant_id: "tenant-a".to_string(),
                services: vec![serde_json::json!({"service_id": "svc-a"})],
            }),
            AgentResponse::HostPeersTenantResult(TenantPeersResult {
                tenant_id: "tenant-a".to_string(),
                label_selector: Some("region=us-east-1".to_string()),
                peers: vec![serde_json::json!({"peer_region_id": "us-east-1"})],
            }),
            AgentResponse::HostConfigTenantResult(TenantConfigResult {
                tenant_id: "tenant-a".to_string(),
                key: "max_vcpus".to_string(),
                value: serde_json::json!(8),
            }),
            AgentResponse::HostRateBudgetTenantResult(TenantRateBudgetResult {
                tenant_id: "tenant-a".to_string(),
                service: "svc-a".to_string(),
                effective_requests_per_second: 10,
                effective_burst: 20,
                source: "tenant_default".to_string(),
                limits: vec![serde_json::json!({"scope": "tenant"})],
            }),
        ];

        for response in responses {
            let json = serde_json::to_value(&response).unwrap();
            let parsed: AgentResponse = serde_json::from_value(json.clone())
                .unwrap_or_else(|err| panic!("failed to parse delegated response {json}: {err}"));
            assert_eq!(serde_json::to_value(parsed).unwrap(), json);
        }
    }

    #[test]
    fn test_delegated_host_services_reject_unknown_fields() {
        for bad in [
            serde_json::json!({
                "HostCatalogTenantQuery": {
                    "tenant_id": "tenant-a",
                    "pool_id": "pool-a",
                    "instance_id": "vm-a",
                    "query": {
                        "requested_tenant_id": "tenant-a",
                        "unexpected": true
                    }
                }
            }),
            serde_json::json!({
                "HostPeersTenantResult": {
                    "tenant_id": "tenant-a",
                    "peers": [],
                    "unexpected": true
                }
            }),
            serde_json::json!({
                "HostRateBudgetTenantResult": {
                    "tenant_id": "tenant-a",
                    "service": "svc-a",
                    "effective_requests_per_second": 10,
                    "effective_burst": 20,
                    "source": "tenant_default",
                    "limits": [],
                    "unexpected": true
                }
            }),
        ] {
            let request_err = serde_json::from_value::<AgentRequest>(bad.clone());
            let response_err = serde_json::from_value::<AgentResponse>(bad);
            assert!(
                [request_err.err(), response_err.err()]
                    .into_iter()
                    .flatten()
                    .any(|err| err.to_string().contains("unknown field"))
            );
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
            sequence: 0,
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
            egress_secrets: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::InstanceAction {
                tenant_id,
                pool_id,
                instance_id,
                action,
                ..
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
            attested_deployment: None,
            mounts: vec![],
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
        assert!(parsed.attested_deployment.is_none());
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
            attested_deployment: None,
            mounts: vec![],
        };
        let json = serde_json::to_string(&pool).unwrap();
        let parsed: DesiredPool = serde_json::from_str(&json).unwrap();
        let ra = parsed.registry_artifact.unwrap();
        assert_eq!(ra.template_id, "hello");
        assert_eq!(ra.revision.as_deref(), Some("rev-abc123"));
    }

    // ========================================================================
    // Tests for distributed-volume mounts
    // ========================================================================

    /// Old coordinator → new agent: a `DesiredPool` payload that predates
    /// the `mounts` field must still parse (`#[serde(default)]` ⇒ empty).
    ///
    /// The reverse direction (new coordinator sending `mounts` to an old
    /// agent) fails closed on that agent's `deny_unknown_fields` — that
    /// rollout is governed by `DesiredState::schema_version`, matching how
    /// prior `DesiredPool` field additions were sequenced.
    #[test]
    fn test_desired_pool_backward_compat_no_mounts() {
        let json = r#"{
            "pool_id": "gateways",
            "flake_ref": "github:org/repo",
            "profile": "minimal",
            "instance_resources": {"vcpus": 2, "mem_mib": 1024},
            "desired_counts": {"running": 3, "warm": 1, "sleeping": 0}
        }"#;
        let parsed: DesiredPool = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.pool_id, "gateways");
        assert!(parsed.mounts.is_empty());
    }

    #[test]
    fn test_desired_pool_mounts_roundtrip() {
        let mount = DesiredMount {
            bucket_id: "bkt-artifacts".to_string(),
            provider: "s3".to_string(),
            config: serde_json::json!({
                "endpoint": "https://s3.example.com",
                "bucket": "acme-artifacts",
                "region": "us-east-1"
            }),
            target: "/mnt/artifacts".to_string(),
            mode: DesiredMountMode::Rw,
            generation: 7,
            access_mode: MountAccessMode::Rwx,
        };
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
            default_update_strategy: None,
            registry_artifact: None,
            attested_deployment: None,
            mounts: vec![mount.clone()],
        };
        let json = serde_json::to_string(&pool).unwrap();
        let parsed: DesiredPool = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mounts.len(), 1);
        assert_eq!(parsed.mounts[0], mount);
    }

    #[test]
    fn test_desired_mount_parses_from_json() {
        let json = r#"{
            "bucket_id": "bkt-shared",
            "provider": "nfs",
            "config": {"server": "10.240.0.9", "export": "/exports/shared"},
            "target": "/mnt/shared",
            "mode": "ro",
            "generation": 1
        }"#;
        let parsed: DesiredMount = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.bucket_id, "bkt-shared");
        assert_eq!(parsed.provider, "nfs");
        assert_eq!(parsed.target, "/mnt/shared");
        assert_eq!(parsed.mode, DesiredMountMode::Ro);
        assert_eq!(parsed.generation, 1);
        // access_mode omitted ⇒ defaults to read-only-many.
        assert_eq!(parsed.access_mode, MountAccessMode::Rox);
    }

    #[test]
    fn test_desired_mount_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "bucket_id": "bkt-shared",
            "provider": "s3",
            "config": {},
            "target": "/mnt/shared",
            "mode": "ro",
            "generation": 1,
            "unexpected": true
        });
        let err = serde_json::from_value::<DesiredMount>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_mount_access_mode_default_is_rox() {
        assert_eq!(MountAccessMode::default(), MountAccessMode::Rox);
    }

    #[test]
    fn test_mount_enums_wire_values() {
        // Pin the wire values: mode mirrors the IR MountMode ("ro"/"rw");
        // access_mode is snake_case of the K8s-style variants.
        assert_eq!(
            serde_json::to_string(&DesiredMountMode::Ro).unwrap(),
            "\"ro\""
        );
        assert_eq!(
            serde_json::to_string(&DesiredMountMode::Rw).unwrap(),
            "\"rw\""
        );
        assert_eq!(
            serde_json::to_string(&MountAccessMode::Rwo).unwrap(),
            "\"rwo\""
        );
        assert_eq!(
            serde_json::to_string(&MountAccessMode::Rox).unwrap(),
            "\"rox\""
        );
        assert_eq!(
            serde_json::to_string(&MountAccessMode::Rwx).unwrap(),
            "\"rwx\""
        );
        for mode in [DesiredMountMode::Ro, DesiredMountMode::Rw] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: DesiredMountMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
        for access in [
            MountAccessMode::Rwo,
            MountAccessMode::Rox,
            MountAccessMode::Rwx,
        ] {
            let json = serde_json::to_string(&access).unwrap();
            let parsed: MountAccessMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, access);
        }
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
            build_image_duration_ms: 0,
            vm_start_duration_ms: 0,
            vsock_handshake_rtt_ms: 0,
            vsock_egress_packets_total: 0,
            vsock_egress_bytes_total: 0,
            vsock_egress_events_total: 0,
            dev_image_verify_ok: 0,
            dev_image_verify_sig_invalid: 0,
            dev_image_verify_digest_mismatch: 0,
            dev_image_verify_version_skew: 0,
            dev_image_verify_revoked: 0,
            dev_image_verify_expired: 0,
            dev_image_verify_network: 0,
            dev_image_verify_duration_ms: 0,
            audit_cmd_total: 0,
            audit_lifecycle_total: 0,
            audit_secret_total: 0,
            audit_flow_total: 0,
            audit_plan_total: 0,
            audit_policy_total: 0,
            audit_key_total: 0,
            audit_host_total: 0,
            audit_audit_total: 0,
            audit_dns_total: 0,
            audit_icmp_total: 0,
            audit_workload_audit_total: 0,
        };
        let resp = AgentResponse::Metrics(Box::new(snapshot));
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
                authorizer_principal: None,
                authorization_reason: None,
                authorization_ticket_ref: None,
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

    // ==========================================================================
    // Comprehensive round-trip tests for all protocol variants
    // ==========================================================================

    /// Build one instance of every `AgentRequest` variant to ensure full coverage.
    fn all_request_variants() -> Vec<AgentRequest> {
        vec![
            AgentRequest::Reconcile(DesiredState {
                schema_version: 1,
                node_id: "n1".to_string(),
                tenants: vec![],
                prune_unknown_tenants: false,
                prune_unknown_pools: false,
                sequence: 0,
            }),
            AgentRequest::ReconcileSigned(SignedPayload {
                payload: b"{}".to_vec(),
                signature: b"abcd".to_vec(),
                signer_id: "1234".to_string(),
            }),
            AgentRequest::NodeInfo,
            AgentRequest::NodeStats,
            AgentRequest::TenantList,
            AgentRequest::InstanceList {
                tenant_id: "t1".to_string(),
                pool_id: Some("p1".to_string()),
            },
            AgentRequest::InstanceList {
                tenant_id: "t1".to_string(),
                pool_id: None,
            },
            AgentRequest::WakeInstance {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
            },
            AgentRequest::InstanceAction {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                action: InstanceAction::Start,
                egress_secrets: None,
            },
            AgentRequest::StartInstanceWithBlockVolumes {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                workspace_id: Some("ws1".to_string()),
                volumes: vec![crate::instance::BlockVolumeAttach {
                    org_id: "org1".to_string(),
                    workspace_id: "ws1".to_string(),
                    volume_id: "vol1".to_string(),
                    guest_path: "/data".to_string(),
                    read_only: false,
                    encrypted: true,
                    size_mib: 1024,
                    initialize_if_missing: false,
                    fencing_token: 1,
                    lease_expires_at: "2026-08-02T12:00:00Z".to_string(),
                    data_key_version: 1,
                }],
                egress_secrets: None,
            },
            AgentRequest::RenewBlockVolumeLeases {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                volumes: vec![crate::instance::BlockVolumeAttach {
                    org_id: "org1".to_string(),
                    workspace_id: "ws1".to_string(),
                    volume_id: "vol1".to_string(),
                    guest_path: "/data".to_string(),
                    read_only: false,
                    encrypted: true,
                    size_mib: 1024,
                    initialize_if_missing: false,
                    fencing_token: 1,
                    lease_expires_at: "2026-08-02T12:01:00Z".to_string(),
                    data_key_version: 1,
                }],
            },
            AgentRequest::ReadBlockVolumeChunk {
                tenant_id: "t1".into(),
                pool_id: "p1".into(),
                volume: crate::instance::BlockVolumeTransfer {
                    org_id: "org1".into(),
                    workspace_id: "ws1".into(),
                    volume_id: "vol1".into(),
                    fencing_token: 2,
                    data_key_version: 1,
                },
                offset: 0,
                max_bytes: 1024,
            },
            AgentRequest::BeginBlockVolumeRestore {
                tenant_id: "t1".into(),
                pool_id: "p1".into(),
                restore: crate::instance::BlockVolumeRestore {
                    transfer_id: "restore1".into(),
                    volume: crate::instance::BlockVolumeTransfer {
                        org_id: "org1".into(),
                        workspace_id: "ws1".into(),
                        volume_id: "vol1".into(),
                        fencing_token: 3,
                        data_key_version: 1,
                    },
                    expected_size: 2,
                    expected_sha256: "ab".repeat(32),
                },
            },
            AgentRequest::WriteBlockVolumeRestoreChunk {
                tenant_id: "t1".into(),
                pool_id: "p1".into(),
                transfer_id: "restore1".into(),
                chunk: crate::instance::BlockVolumeChunk {
                    offset: 0,
                    total_size: 2,
                    sha256: "ab".repeat(32),
                    data_hex: "00ff".into(),
                    eof: true,
                },
            },
            AgentRequest::CommitBlockVolumeRestore {
                tenant_id: "t1".into(),
                pool_id: "p1".into(),
                transfer_id: "restore1".into(),
            },
            AgentRequest::AbortBlockVolumeRestore {
                tenant_id: "t1".into(),
                pool_id: "p1".into(),
                transfer_id: "restore1".into(),
            },
            AgentRequest::SandboxAction {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                request: serde_json::json!({"type": "Ping"}),
            },
            AgentRequest::HostCostTenantQuery {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                query: TenantCostQuery {
                    requested_tenant_id: "t1".to_string(),
                },
            },
            AgentRequest::HostCatalogTenantQuery {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                query: TenantCatalogQuery {
                    requested_tenant_id: "t1".to_string(),
                    request_id: Some("req-catalog".to_string()),
                },
            },
            AgentRequest::HostPeersTenantQuery {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                query: TenantPeersQuery {
                    requested_tenant_id: "t1".to_string(),
                    request_id: Some("req-peers".to_string()),
                    label_selector: Some("region=us-east-1".to_string()),
                },
            },
            AgentRequest::HostConfigTenantQuery {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                query: TenantConfigQuery {
                    requested_tenant_id: "t1".to_string(),
                    request_id: Some("req-config".to_string()),
                    key: "max_vcpus".to_string(),
                },
            },
            AgentRequest::HostRateBudgetTenantQuery {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                query: TenantRateBudgetQuery {
                    requested_tenant_id: "t1".to_string(),
                    request_id: Some("req-rate".to_string()),
                    service: "svc-a".to_string(),
                },
            },
            AgentRequest::DeploymentStatus {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
            },
            AgentRequest::PauseDeployment {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
            },
            AgentRequest::ResumeDeployment {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
            },
            AgentRequest::RollbackDeployment {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                target_revision: Some("rev-abc".to_string()),
            },
            AgentRequest::BatchInstanceAction {
                actions: vec![BatchActionItem {
                    tenant_id: "t1".to_string(),
                    pool_id: "p1".to_string(),
                    instance_id: "i1".to_string(),
                    action: InstanceAction::Stop,
                }],
            },
            AgentRequest::PoolAction {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                action: PoolActionType::StartAll,
            },
            AgentRequest::GetMetrics,
            AgentRequest::GetAuditLog {
                tenant_id: "t1".to_string(),
                last_n: Some(10),
                since: None,
            },
            AgentRequest::GetHealthStatus {
                tenant_id: Some("t1".to_string()),
                pool_id: None,
            },
            AgentRequest::GetReconcileHistory { last_n: Some(5) },
            AgentRequest::ForceReconcile { dry_run: true },
            AgentRequest::DumpState {
                include_metrics: true,
                include_audit_log: false,
            },
            AgentRequest::UpdateSecrets {
                tenant_id: "t1".to_string(),
                secrets_hash: "sha256:abc".to_string(),
                force_reload: false,
            },
            AgentRequest::UpdateConfig {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                config_version: 42,
            },
            AgentRequest::SyncEvents { since: 42 },
        ]
    }

    fn sample_egress_secrets() -> EgressSecretsPayload {
        EgressSecretsPayload {
            bindings: vec![EgressSecretBinding {
                name: "stripe_api_key".to_string(),
                allowed_destinations: vec!["api.stripe.com".to_string()],
                auth_type: "bearer".to_string(),
            }],
            values: vec![EgressSecretValue {
                name: "stripe_api_key".to_string(),
                value_b64: "c2stbGl2ZS1TVVBFUlNFQ1JFVA==".to_string(),
            }],
        }
    }

    /// `InstanceAction` round-trips with and without an `egress_secrets` payload.
    #[test]
    fn test_instance_action_egress_secrets_round_trip() {
        for egress_secrets in [None, Some(sample_egress_secrets())] {
            let req = AgentRequest::InstanceAction {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                action: InstanceAction::Start,
                egress_secrets: egress_secrets.clone(),
            };
            let json = serde_json::to_string(&req).expect("serialize");
            let back: AgentRequest = serde_json::from_str(&json).expect("deserialize");
            match back {
                AgentRequest::InstanceAction {
                    egress_secrets: got,
                    action,
                    ..
                } => {
                    assert_eq!(action, InstanceAction::Start);
                    assert_eq!(got, egress_secrets);
                }
                other => panic!("expected InstanceAction, got {other:?}"),
            }
        }
    }

    /// `StartInstanceWithBlockVolumes` round-trips with and without egress secrets.
    #[test]
    fn test_start_with_block_volumes_egress_secrets_round_trip() {
        for egress_secrets in [None, Some(sample_egress_secrets())] {
            let req = AgentRequest::StartInstanceWithBlockVolumes {
                tenant_id: "t1".to_string(),
                pool_id: "p1".to_string(),
                instance_id: "i1".to_string(),
                workspace_id: None,
                volumes: vec![],
                egress_secrets: egress_secrets.clone(),
            };
            let json = serde_json::to_string(&req).expect("serialize");
            let back: AgentRequest = serde_json::from_str(&json).expect("deserialize");
            match back {
                AgentRequest::StartInstanceWithBlockVolumes {
                    egress_secrets: got,
                    ..
                } => assert_eq!(got, egress_secrets),
                other => panic!("expected StartInstanceWithBlockVolumes, got {other:?}"),
            }
        }
    }

    /// An old-format payload without the `egress_secrets` key must deserialize
    /// to `None`, preserving byte-for-byte back-compat with existing callers.
    #[test]
    fn test_egress_secrets_absent_defaults_to_none() {
        // JSON produced before the field existed (no `egress_secrets` key).
        let old_instance_action = r#"{
            "InstanceAction": {
                "tenant_id": "t1",
                "pool_id": "p1",
                "instance_id": "i1",
                "action": "Start"
            }
        }"#;
        match serde_json::from_str::<AgentRequest>(old_instance_action).expect("deserialize old") {
            AgentRequest::InstanceAction { egress_secrets, .. } => {
                assert!(egress_secrets.is_none())
            }
            other => panic!("expected InstanceAction, got {other:?}"),
        }

        let old_start = r#"{
            "StartInstanceWithBlockVolumes": {
                "tenant_id": "t1",
                "pool_id": "p1",
                "instance_id": "i1",
                "volumes": []
            }
        }"#;
        match serde_json::from_str::<AgentRequest>(old_start).expect("deserialize old") {
            AgentRequest::StartInstanceWithBlockVolumes {
                egress_secrets,
                workspace_id,
                ..
            } => {
                assert!(egress_secrets.is_none());
                assert!(workspace_id.is_none());
            }
            other => panic!("expected StartInstanceWithBlockVolumes, got {other:?}"),
        }
    }

    /// The decrypted secret value must never appear in `Debug` output.
    #[test]
    fn test_egress_secret_value_debug_redacts() {
        let secret = "c2stbGl2ZS1TVVBFUlNFQ1JFVA==";
        let payload = sample_egress_secrets();
        assert_eq!(payload.values[0].value_b64, secret);

        // Direct value Debug.
        let value_dbg = format!("{:?}", payload.values[0]);
        assert!(!value_dbg.contains(secret), "value leaked: {value_dbg}");
        assert!(value_dbg.contains("[REDACTED]"));
        assert!(value_dbg.contains("stripe_api_key")); // non-secret name kept

        // Nested through the payload and the request that carries it.
        let payload_dbg = format!("{payload:?}");
        assert!(!payload_dbg.contains(secret), "value leaked: {payload_dbg}");

        let req = AgentRequest::InstanceAction {
            tenant_id: "t1".to_string(),
            pool_id: "p1".to_string(),
            instance_id: "i1".to_string(),
            action: InstanceAction::Start,
            egress_secrets: Some(payload),
        };
        let req_dbg = format!("{req:?}");
        assert!(
            !req_dbg.contains(secret),
            "value leaked via request: {req_dbg}"
        );
    }

    /// Every `AgentRequest` variant must survive a JSON round-trip.
    #[test]
    fn test_all_agent_request_variants_round_trip() {
        for (i, req) in all_request_variants().into_iter().enumerate() {
            let json = serde_json::to_value(&req).unwrap_or_else(|e| {
                panic!("Failed to serialize AgentRequest variant #{}: {}", i, e)
            });
            let _back: AgentRequest = serde_json::from_value(json.clone()).unwrap_or_else(|e| {
                panic!(
                    "Failed to deserialize AgentRequest variant #{}: {} -- json: {}",
                    i, e, json
                )
            });
        }
    }

    fn test_node_info() -> NodeInfo {
        NodeInfo {
            node_id: "node-1".to_string(),
            hostname: "host".to_string(),
            arch: "aarch64".to_string(),
            total_vcpus: 8,
            total_mem_mib: 16384,
            vm_status: Some("running".to_string()),
            firecracker_version: Some("1.5.0".to_string()),
            jailer_available: true,
            cgroup_v2: true,
            attestation_provider: "none".to_string(),
        }
    }

    /// Build one instance of every `AgentResponse` variant to ensure full coverage.
    fn all_response_variants() -> Vec<AgentResponse> {
        vec![
            AgentResponse::ReconcileResult(ReconcileReport::default()),
            AgentResponse::NodeInfo(test_node_info()),
            AgentResponse::NodeStats(NodeStats::default()),
            AgentResponse::TenantList(vec!["t1".to_string()]),
            AgentResponse::InstanceList(vec![]),
            AgentResponse::WakeResult { success: true },
            AgentResponse::InstanceActionResult {
                success: true,
                new_status: "running".to_string(),
                error: None,
            },
            AgentResponse::BlockVolumeChunk(crate::instance::BlockVolumeChunk {
                offset: 0,
                total_size: 1,
                sha256: "ab".repeat(32),
                data_hex: "00".into(),
                eof: true,
            }),
            AgentResponse::BlockVolumeTransferResult {
                success: true,
                next_offset: 1,
                complete: true,
                error: None,
            },
            AgentResponse::SandboxResult {
                success: true,
                response: serde_json::json!({"type": "Pong"}),
                error: None,
            },
            AgentResponse::HostCostTenantResult(TenantCostResult {
                report: crate::protocol::host_cost::CostReport {
                    spent_micros_usd: 42,
                },
            }),
            AgentResponse::HostCatalogTenantResult(TenantCatalogResult {
                tenant_id: "t1".to_string(),
                services: vec![serde_json::json!({"service_id": "svc-a"})],
            }),
            AgentResponse::HostPeersTenantResult(TenantPeersResult {
                tenant_id: "t1".to_string(),
                label_selector: None,
                peers: vec![serde_json::json!({"peer_region_id": "us-east-1"})],
            }),
            AgentResponse::HostConfigTenantResult(TenantConfigResult {
                tenant_id: "t1".to_string(),
                key: "max_vcpus".to_string(),
                value: serde_json::json!(8),
            }),
            AgentResponse::HostRateBudgetTenantResult(TenantRateBudgetResult {
                tenant_id: "t1".to_string(),
                service: "svc-a".to_string(),
                effective_requests_per_second: 10,
                effective_burst: 20,
                source: "tenant_default".to_string(),
                limits: vec![],
            }),
            AgentResponse::Error {
                code: 500,
                message: "internal error".to_string(),
            },
            AgentResponse::DeploymentStatus {
                pool_id: "p1".to_string(),
                current_revision: "rev-1".to_string(),
                target_revision: None,
                strategy: Default::default(),
                phase: DeploymentPhase::Complete,
                instances_updated: 3,
                instances_pending: 0,
                canary_health: None,
                paused: false,
                errors: vec![],
            },
            AgentResponse::DeploymentControlResult {
                success: true,
                pool_id: "p1".to_string(),
                new_phase: "paused".to_string(),
                message: "ok".to_string(),
            },
            AgentResponse::BatchActionResult {
                results: vec![],
                total: 0,
                succeeded: 0,
                failed: 0,
            },
            AgentResponse::PoolActionResult {
                success: true,
                pool_id: "p1".to_string(),
                instances_affected: 5,
                errors: vec![],
            },
            AgentResponse::Metrics(Box::new(crate::observability::metrics::global().snapshot())),
            AgentResponse::AuditLog {
                entries: vec![],
                total_count: 0,
            },
            AgentResponse::HealthStatus {
                instances: vec![],
                unhealthy_count: 0,
                degraded_count: 0,
            },
            AgentResponse::ReconcileHistory { runs: vec![] },
            AgentResponse::StateDump(Box::new(StateDumpContent {
                node_info: test_node_info(),
                node_stats: NodeStats::default(),
                metrics: None,
                audit_log: None,
                tenants: vec![],
            })),
            AgentResponse::SecretsUpdateResult {
                success: true,
                tenant_id: "t1".to_string(),
                instances_reloaded: 0,
                errors: vec![],
            },
            AgentResponse::ConfigUpdateResult {
                success: true,
                pool_id: "p1".to_string(),
                instances_updated: 0,
                errors: vec![],
            },
            AgentResponse::SyncEventsResult {
                events: vec![serde_json::json!({"type": "TenantAdded", "tenant_id": "acme"})],
                current_sequence: 5,
            },
        ]
    }

    /// Every `AgentResponse` variant must survive a JSON round-trip.
    #[test]
    fn test_all_agent_response_variants_round_trip() {
        for (i, resp) in all_response_variants().into_iter().enumerate() {
            let json = serde_json::to_value(&resp).unwrap_or_else(|e| {
                panic!("Failed to serialize AgentResponse variant #{}: {}", i, e)
            });
            let _back: AgentResponse = serde_json::from_value(json.clone()).unwrap_or_else(|e| {
                panic!(
                    "Failed to deserialize AgentResponse variant #{}: {} -- json: {}",
                    i, e, json
                )
            });
        }
    }

    /// All `PoolActionType` variants must round-trip through JSON.
    #[test]
    fn test_pool_action_type_all_variants_round_trip() {
        let variants = vec![
            PoolActionType::StartAll,
            PoolActionType::StopAll,
            PoolActionType::WarmAll,
            PoolActionType::DestroyAll { wipe_volumes: true },
            PoolActionType::ScaleTo {
                running: 3,
                warm: 1,
                sleeping: 2,
            },
        ];
        for v in &variants {
            let json = serde_json::to_value(v).unwrap();
            let back: PoolActionType = serde_json::from_value(json).unwrap();
            assert_eq!(*v, back);
        }
    }
}
