//! `ExecutionPlan` — the cornerstone workload-launch type.
//!
//! Every workload mvm runs is launched from one of these. The plan
//! is signed by mvmd (or a developer key in dev mode) and the
//! supervisor refuses unsigned plans outside dev mode. Every audit
//! entry the supervisor emits references `(plan_id, plan_version)`
//! so a runbook can answer "what plan was this workload running at
//! the moment of incident?" in O(1) without re-deriving from logs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::plan::bundle::PlanArtifact;
use crate::plan::types::{
    AdmissionProfile, ArtifactPolicy, AttestationRequirement, AuditLabels, DepsVolumeBinding,
    FsPolicyRef, HostShareGrant, KeyRotationSpec, Nonce, PlanId, PolicyRef, PostRunLifecycle,
    ReleasePin, Resources, RuntimeProfileRef, SecretBinding, SignedImageRef, TenantId, WorkloadId,
};

/// Wire-format version. Bump when fields change in a way older
/// verifiers can't ignore. Older verifiers must fail closed on
/// unknown schema versions rather than silently skipping unknown
/// fields — the schema_version field is consulted before any
/// per-field deserialisation.
///
/// Bumped 1 → 2 with the addition of `valid_from` / `valid_until` /
/// `nonce`. Older verifiers will reject v2 plans with
/// `UnsupportedSchema`; this is the correct fail-closed behavior —
/// they can't enforce the validity window they don't understand.
///
/// Bumped 2 → 3 with the addition of `bundle: Option<PlanArtifact>` —
/// the supervisor's admit path re-verifies the pinned bundle archive
/// before backend dispatch (claim 9 fully load-bearing at launch, not
/// just at fetch). Older verifiers will reject v3 plans with
/// `UnsupportedSchema` because they don't know how to re-verify
/// the binding.
///
/// Bumped 3 → 4 with the addition of intent-bound
/// `admission_profile`: older verifiers do not know how to check
/// that seccomp, network, tool, secret-release, and audit controls
/// were resolved under one profile, so they must reject rather than
/// silently ignore the binding.
///
/// Bumped 4 → 5 with the addition of `shares` (user host-fs grants):
/// an older verifier doesn't know to enforce that the launch config's
/// volumes are a subset of the admitted grants (claim 1 / claim 8), so
/// it must reject rather than admit a plan whose shares it can't check.
pub const SCHEMA_VERSION: u32 = 5;

/// Typed contract for one workload's execution.
///
/// The fields here are the rubric — `enforce_*` in `mvm/src/enforce.rs`
/// walks the plan field-by-field and rejects any plan that doesn't
/// satisfy the corresponding enforcement row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Resolved by `BackendRegistry`.
    pub runtime_profile: RuntimeProfileRef,

    /// Signed image to boot. SHA-256 + cosign bundle reference;
    /// resolved by `mvm-security::image_verify`.
    pub image: SignedImageRef,

    pub resources: Resources,

    /// Intent-bound profile resolved before admission. This binds the
    /// workload purpose to the concrete seccomp tier, policy refs,
    /// secret-release posture, and audit taxonomy the runtime must
    /// enforce for this boot.
    pub admission_profile: AdmissionProfile,

    /// Network policy reference. Wired to `mvm-policy::EgressPolicy`
    /// (L7 + PII rules) via the supervisor's `EgressProxy`.
    pub network_policy: PolicyRef,

    /// Filesystem policy reference.
    pub fs_policy: FsPolicyRef,

    pub secrets: Vec<SecretBinding>,

    /// L7 egress + PII rules. The same kind of `PolicyRef` as
    /// `network_policy` so the resolver is shared, but kept separate
    /// here so an audit entry can show "egress allowed, pii redacted"
    /// as orthogonal facts.
    pub egress_policy: PolicyRef,

    /// Per-destination egress redaction policy. Rides inline in the signed plan
    /// — like `secrets` — so the per-VM substitution endpoint gets it at spawn
    /// without resolving the bundle. Default = the all-off curated baseline (no
    /// per-destination entropy/name redaction).
    #[serde(default)]
    pub redaction: crate::policy::RedactionPolicy,

    /// Tool-call policy (which tools the model is allowed to invoke
    /// over the supervisor's vsock RPC).
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

    /// Plan validity window — start. The supervisor refuses to admit
    /// a plan before `valid_from`.
    pub valid_from: DateTime<Utc>,

    /// Plan validity window — end. The supervisor refuses to admit
    /// a plan at or after `valid_until`. Without this bound, signed
    /// plans are forever-valid and replayable.
    pub valid_until: DateTime<Utc>,

    /// Per-plan nonce for replay protection. The supervisor maintains
    /// a seen-nonce ledger keyed by signer; an admission attempt with
    /// a previously-seen nonce for the same signer is refused. The
    /// ledger self-prunes once `valid_until` passes for a stored
    /// nonce.
    pub nonce: Nonce,

    /// Optional pin to a content-addressed `.mvmpkg` bundle. When
    /// present, the supervisor's admit path re-runs
    /// [`crate::plan::bundle::read_and_verify_bundle`] against the
    /// resolved archive bytes, then compares the resulting
    /// `bundle_sha256` + `manifest_sig` + `key_id` against the
    /// pinned values here. Any mismatch refuses the admission —
    /// claim 9 is load-bearing at launch, not just at fetch.
    ///
    /// `None` (the default) means the plan is not pinned to a
    /// bundle; the admit path skips the bundle re-verify step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<PlanArtifact>,

    /// Optional pin to an application-dependencies volume sealed
    /// by `mvm_sdk::compile::deps_audit::seal_volume`. When present,
    /// the supervisor's admit path re-runs `verify_sealed_volume`
    /// against `~/.mvm/volumes/deps/<volume_hash>/`, then compares
    /// the derived volume hash + manifest sha against the pinned
    /// values here. Any mismatch refuses admission (claim 9).
    ///
    /// `None` (the default) means the plan has no deps volume; the
    /// admit path skips this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deps_volume: Option<DepsVolumeBinding>,

    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`):
    /// directory shares and disk images the workload is admitted to
    /// mount. Empty for the common no-volume case. The admit path
    /// asserts the launch config's volumes are a subset of this list
    /// (claim 1 / claim 8) and emits it to the chain-signed audit log;
    /// the Vz supervisor's future per-attach gate reads it to refuse
    /// any share the plan didn't name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<HostShareGrant>,
}
