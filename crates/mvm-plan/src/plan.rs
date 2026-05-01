//! `ExecutionPlan` — the typed, signed contract every workload runs from.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::refs::{
    ArtifactPolicy, AttestationRequirement, FsPolicyRef, KeyRotationSpec, PolicyRef,
    PostRunLifecycle, ReleasePin, RuntimeProfileRef, SecretBinding, SignedImageRef,
};

/// Stable identifier for a single plan submission. ULID-shape via UUIDv7 for
/// time-ordered uniqueness; we just emit the canonical UUID string form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

impl PlanId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for PlanId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable identifier for a logical workload (the thing being run, distinct
/// from a single execution of it). Free-form short string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub String);

/// Tenant identifier — matches `TenantConfig::tenant_id` in
/// `mvm_core::domain::tenant`. Plans bind to the existing tenant model
/// by string id; the supervisor resolves to the full `TenantConfig`
/// at admission.
pub type TenantId = String;

/// Resource caps applied to a workload at admission. Hard limits — the
/// supervisor refuses to launch a plan whose resources are oversubscribed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpus: u8,
    pub memory_mib: u32,
    pub disk_mib: u32,
    /// Wall-clock cap; plan is terminated and audited on expiry.
    pub timeout_secs: u32,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cpus: 1,
            memory_mib: 512,
            disk_mib: 1024,
            timeout_secs: 3600,
        }
    }
}

/// Decorated execution plan — whitepaper §3.3.
///
/// Unsigned form. Wrap in `SignedExecutionPlan` before submission; the
/// supervisor refuses unsigned plans outside dev mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub plan_id: PlanId,
    pub plan_version: u32,

    pub tenant: TenantId,
    pub workload: WorkloadId,

    pub runtime_profile: RuntimeProfileRef,
    pub image: SignedImageRef,
    pub resources: Resources,

    pub network_policy: PolicyRef,
    pub fs_policy: FsPolicyRef,
    pub egress_policy: PolicyRef,
    pub tool_policy: PolicyRef,

    pub secrets: Vec<SecretBinding>,
    pub artifact_policy: ArtifactPolicy,
    pub key_rotation: KeyRotationSpec,
    pub attestation: AttestationRequirement,
    pub release_pin: Option<ReleasePin>,
    pub post_run: PostRunLifecycle,

    pub audit_labels: BTreeMap<String, String>,

    /// Plan validity window — admission refuses plans before `valid_from`,
    /// after `valid_until`, or whose `nonce` has been seen before. Closes
    /// the replay-of-old-signed-plan vector flagged in plan 37 Addendum
    /// G4.
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// Random per-plan nonce; the supervisor maintains a seen-nonce set
    /// per signing key bounded by `valid_until` purge.
    pub nonce: [u8; 16],
}

impl ExecutionPlan {
    /// Canonical bytes for signing — JSON with sorted keys. Stability
    /// matters because the signature is over these bytes, so any
    /// non-canonical re-encoding would break verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        // serde_json by default emits in struct-declaration order which is
        // stable here. We use to_vec rather than to_string + as_bytes to
        // avoid an extra allocation.
        serde_json::to_vec(self)
    }
}
