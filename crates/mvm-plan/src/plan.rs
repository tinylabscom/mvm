//! `ExecutionPlan` — the cornerstone type of plan 37 §3.3.
//!
//! Every workload mvm runs is launched from one of these. The plan
//! is signed by mvmd (or a developer key in dev mode) and the
//! supervisor refuses unsigned plans outside dev mode. Every audit
//! entry the supervisor emits references `(plan_id, plan_version)`
//! so a runbook can answer "what plan was this workload running at
//! the moment of incident?" in O(1) without re-deriving from logs.

use serde::{Deserialize, Serialize};

use crate::types::{
    ArtifactPolicy, AttestationRequirement, AuditLabels, FsPolicyRef, KeyRotationSpec, PlanId,
    PolicyRef, PostRunLifecycle, ReleasePin, Resources, RuntimeProfileRef, SecretBinding,
    SignedImageRef, TenantId, WorkloadId,
};

/// Wire-format version. Bump when fields change in a way older
/// verifiers can't ignore. Older verifiers must fail closed on
/// unknown schema versions rather than silently skipping unknown
/// fields — the schema_version field is consulted before any
/// per-field deserialisation.
pub const SCHEMA_VERSION: u32 = 1;

/// Typed contract for one workload's execution.
///
/// Plan 37 §3.3. The fields here are the rubric — `enforce_*`
/// in `mvm-runtime/src/enforce.rs` (Wave 1.5) walks the plan
/// field-by-field and rejects any plan that doesn't satisfy
/// the corresponding §5 row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// Wire-format version. See [`SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Stable plan identifier. Audit entries reference this verbatim.
    pub plan_id: PlanId,

    /// Monotonic per-`plan_id` revision counter. Bumped each time
    /// mvmd publishes a revised plan with the same id (eg. policy
    /// changes). The supervisor logs both id+version on every
    /// audit entry so "which version of the plan was running" is
    /// answerable from audit alone.
    pub plan_version: u32,

    pub tenant: TenantId,
    pub workload: WorkloadId,

    /// Which backend / runtime profile this workload runs on.
    /// Resolved by `BackendRegistry` (plan 37 §3.1).
    pub runtime_profile: RuntimeProfileRef,

    /// Signed image to boot. SHA-256 + cosign bundle reference;
    /// resolved by `mvm-security::image_verify` (plan 36).
    pub image: SignedImageRef,

    pub resources: Resources,

    /// Network policy reference. Wave 2 wires this to
    /// `mvm-policy::EgressPolicy` (L7 + PII rules) via the
    /// supervisor's `EgressProxy`.
    pub network_policy: PolicyRef,

    /// Filesystem policy reference. Resolved per Wave 2.
    pub fs_policy: FsPolicyRef,

    pub secrets: Vec<SecretBinding>,

    /// L7 egress + PII rules. Wave 2 differentiator. The same kind
    /// of `PolicyRef` as `network_policy` so the resolver is shared,
    /// but kept separate here so an audit entry can show "egress
    /// allowed, pii redacted" as orthogonal facts.
    pub egress_policy: PolicyRef,

    /// Tool-call policy (which tools the model is allowed to invoke
    /// over the supervisor's vsock RPC). Wave 2.
    pub tool_policy: PolicyRef,

    pub artifact_policy: ArtifactPolicy,

    /// Free-form audit labels copied verbatim into every audit entry
    /// generated for this plan. Usually carries tenant-meaningful
    /// metadata (`workflow_id`, `request_id`).
    pub audit_labels: AuditLabels,

    pub key_rotation: KeyRotationSpec,
    pub attestation: AttestationRequirement,

    /// Optional release pin. mvmd sets this to enforce
    /// "this workload runs at exactly v0.X.Y of mvm/mvmd."
    pub release_pin: Option<ReleasePin>,

    pub post_run: PostRunLifecycle,
}
