//! `*Ref` and `*Spec` types referenced from `ExecutionPlan`.
//!
//! Most fields here are opaque newtype wrappers so plan 37's later
//! waves can introduce real resolvers without churning the wire
//! format. Every type carries `#[serde(deny_unknown_fields)]` so
//! adding a field is a fail-closed schema bump for older verifiers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable identifier for an `ExecutionPlan` instance. Plan 37 §3.3
/// specifies a ULID; we keep the type opaque so the constructor can
/// switch generators (UUIDv7, snowflake, etc.) without touching the
/// wire format. Audit entries reference this id verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub String);

/// Reference to a runtime profile (Firecracker / Apple Container /
/// MicrovmNix / Lima / containerd). Plan 37 §3.1's open
/// `BackendRegistry` resolves the name to a backend factory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeProfileRef(pub String);

/// Reference to a signed image. Mirrors plan 36's `ArtifactDigest`
/// shape: SHA-256 of the rootfs + name. The `cosign_bundle` field
/// is the path or URL to the cosign keyless bundle that
/// `mvm-security::image_verify` validates against; in dev mode the
/// resolver may stub this to `None` and accept the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedImageRef {
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Cosign-keyless `.bundle` reference. Path on disk or URL
    /// resolvable by the supervisor. Stub in dev.
    pub cosign_bundle: Option<String>,
}

/// Resource budget. Hard caps; the supervisor refuses to start a VM
/// that would exceed the host's available capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpus: u32,
    pub mem_mib: u64,
    pub disk_mib: u64,
    pub timeouts: TimeoutSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutSpec {
    /// Max wall-clock for kernel boot + initramfs + minimal-init.
    pub boot_secs: u32,
    /// Max wall-clock for the workload itself. 0 = unbounded (only
    /// permitted for sleep-waking instances; supervisor enforces).
    pub exec_secs: u32,
}

/// Opaque pointer to a policy bundle. Wave 2 introduces the real
/// `mvm-policy::PolicyBundle` resolver; until then this is a name
/// the supervisor's `Noop` resolver maps to a default-deny / open
/// stance per its bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FsPolicyRef(pub String);

/// A secret binding from a name (visible inside the guest) to its
/// source (resolved by the supervisor's `KeystoreReleaser` per Wave 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// Name as the workload sees it (e.g. env var name or
    /// /run/mvm-secrets/<name> file).
    pub name: String,
    pub source: SecretSource,
}

/// Where a secret comes from. Plan 37 §25 lists pluggable providers
/// (Vault, AWS SM, GCP SM); Wave 3 adds the per-run attestation-gated
/// release. The `Static` variant is a compile-time literal for tests
/// only — `mvmctl plan validate --prod` rejects plans that contain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SecretSource {
    /// Test-only literal. Refused by `--prod` validation.
    Static { value: String },
    /// Per-run release from the supervisor's keystore. The address
    /// resolves to a SecretId at the supervisor.
    Keystore { address: String },
    /// External provider (Vault, AWS SM, etc.). The provider URL +
    /// path are opaque to mvm-plan; resolved by `KeystoreReleaser`.
    External { provider: String, path: String },
}

/// Artifact-capture policy for the run. `capture_paths` are guest-side
/// directories the supervisor's `ArtifactCollector` (Wave 3) sweeps
/// post-run; `retention_days` controls the cleanup sweeper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationSpec {
    /// 0 = no rotation required; supervisor warns but accepts.
    pub interval_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequirement {
    pub mode: AttestationMode,
}

/// Plan 37 §14 attestation modes. Wave 3 introduces real TPM2 / SEV
/// providers; the `Noop` mode lets every plan launch without
/// attestation (today's behaviour) for backwards compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    /// No attestation. Stub. mvmctl warns; mvmd may refuse.
    Noop,
    /// TPM2 EK + AK quote. Supervisor's `KeystoreReleaser` gates
    /// secret release on a successful quote.
    Tpm2,
    /// AMD SEV-SNP report. Provider lands in Wave 6.
    SevSnp,
    /// Intel TDX quote. Provider lands in Wave 6.
    Tdx,
}

/// Plan 37 §11 release pinning: the workload runs at a specific
/// release of mvm/mvmd. Mismatch is grounds for refusal at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePin {
    pub release_id: String,
}

/// Plan 37 §27 lifecycle directives. The supervisor's plan state
/// machine consults these on workload exit / idle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostRunLifecycle {
    /// Tear down the VM on workload exit (one-shot semantics).
    pub destroy_on_exit: bool,
    /// Snapshot the VM after `idle_secs` of inactivity (sleep-wake).
    pub snapshot_on_idle: bool,
    /// Idle window before snapshot. Ignored if `snapshot_on_idle`
    /// is false. 0 = immediate.
    pub idle_secs: u32,
}

/// Convenience — the audit-labels alias the type uses. Free-form
/// `key: value` annotations the supervisor copies into every audit
/// entry generated for this plan.
pub type AuditLabels = BTreeMap<String, String>;
