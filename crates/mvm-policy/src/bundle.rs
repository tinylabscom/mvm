//! `PolicyBundle` — the policy half of plan 37 §10.

use std::collections::BTreeMap;

use mvm_plan::TenantId;
use serde::{Deserialize, Serialize};

use crate::policies::{
    ArtifactPolicy, AuditPolicy, EgressPolicy, KeyPolicy, NetworkPolicy, PiiPolicy, ToolPolicy,
};

/// Wire-format version. Same fail-closed semantics as
/// `mvm-plan::SCHEMA_VERSION` — older verifiers reject unknown
/// future bundle versions before any per-field deserialisation.
pub const SCHEMA_VERSION: u32 = 1;

/// Stable identifier for a `PolicyBundle`. Audit entries reference
/// `(bundle_id, bundle_version)` alongside the plan's
/// `(plan_id, plan_version)` so a runbook can answer "which policy
/// was in force when this audit entry was written?" in O(1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(pub String);

/// A bundle of every policy a workload boots under. Resolved from a
/// `PolicyRef` on `ExecutionPlan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema_version: u32,
    pub bundle_id: PolicyId,
    /// Monotonic per-`bundle_id` revision counter.
    pub bundle_version: u32,

    pub network: NetworkPolicy,
    pub egress: EgressPolicy,
    pub pii: PiiPolicy,
    pub tool: ToolPolicy,
    pub artifact: ArtifactPolicy,
    pub keys: KeyPolicy,
    pub audit: AuditPolicy,

    /// Per-tenant overlays. Resolved by composing the bundle's
    /// base policy with the matching tenant overlay (overlay wins
    /// on conflict). Empty map means no per-tenant variation.
    pub tenant_overlays: BTreeMap<TenantId, TenantOverlay>,
}

/// Per-tenant overlay. Each field is optional — `None` means
/// "inherit from the bundle base"; `Some(_)` overrides.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantOverlay {
    pub network: Option<NetworkPolicy>,
    pub egress: Option<EgressPolicy>,
    pub pii: Option<PiiPolicy>,
    pub tool: Option<ToolPolicy>,
    pub artifact: Option<ArtifactPolicy>,
    pub keys: Option<KeyPolicy>,
    pub audit: Option<AuditPolicy>,
}
