//! Reference and spec types embedded in `ExecutionPlan`.
//!
//! These are intentionally thin scaffolds. The shape is stable; the
//! resolvers (which turn a `PolicyRef` into an effective set of rules,
//! a `SignedImageRef` into a verified disk artifact, etc.) live in
//! `mvm-policy`, `mvm-supervisor`, and `mvm-security` and are out of
//! scope for this crate. Per plan 37 Wave 1: ship the types now so
//! every downstream component can depend on a stable plan shape, fill
//! in resolvers in subsequent waves.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A reference to a runtime profile (kernel + image variant + boot
/// configuration) by digest. The supervisor resolves this against the
/// signed image catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfileRef {
    pub name: String,
    /// SHA-256 of the resolved profile artifact.
    pub digest: [u8; 32],
}

/// A signed image reference: content digest + cosign signature bundle
/// hash. `mvm-security::image_verify` is the resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedImageRef {
    pub name: String,
    /// SHA-256 of the image rootfs (or composite manifest).
    pub digest: [u8; 32],
    /// SHA-256 of the cosign signature bundle authenticating `digest`.
    pub signature_bundle_digest: [u8; 32],
}

/// Reference to a `PolicyBundle` slot in `mvm-policy`. The bundle itself
/// is signed and addressed by digest; pinning the digest in the plan
/// prevents silent policy mutation between admission and execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// Stable bundle id (e.g. `"egress/default"`).
    pub bundle_id: String,
    /// Monotonic version of the named bundle.
    pub bundle_version: u32,
    /// SHA-256 of the canonical bundle bytes — pin against silent
    /// mutation.
    pub digest: [u8; 32],
}

impl PolicyRef {
    /// Sentinel "no policy" — used by dev-mode plans before policy
    /// bundles are authored.
    pub fn none() -> Self {
        Self {
            bundle_id: "none".to_string(),
            bundle_version: 0,
            digest: [0u8; 32],
        }
    }
}

/// Filesystem / volume policy reference. Distinct from `PolicyRef`
/// because filesystem policies declare allowed shares and read/write
/// scopes, which the supervisor enforces via virtiofs / dm-verity
/// rather than via the egress proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsPolicyRef {
    pub bundle_id: String,
    pub bundle_version: u32,
    pub digest: [u8; 32],
}

impl FsPolicyRef {
    pub fn none() -> Self {
        Self {
            bundle_id: "none".to_string(),
            bundle_version: 0,
            digest: [0u8; 32],
        }
    }
}

/// A secret the workload may request at runtime. The supervisor's
/// `KeystoreReleaser` is the resolver and gates release on plan
/// authority + (optionally) attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// Opaque reference resolved by the secret provider; not the
    /// secret itself.
    pub secret_ref: String,
    /// What the workload may do with it (read-only handle, env var,
    /// signed-token issuance).
    pub mode: SecretMode,
    /// Per-grant lifetime; the supervisor revokes on plan stop / fail
    /// / expiry regardless.
    pub max_lifetime_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretMode {
    /// Materialize as an env var inside the guest.
    Env,
    /// Mount at a virtiofs path.
    File,
    /// Issue a short-lived signed token derived from the secret.
    Token,
}

/// What the supervisor does with workload outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    /// Where in the guest the supervisor scrapes outputs from.
    pub capture_path: String,
    /// How long captured artifacts are retained host-side.
    #[serde(with = "duration_secs")]
    pub retention: Duration,
    /// Whether captured artifacts are encrypted at rest with the
    /// per-tenant DEK.
    pub encrypt_at_rest: bool,
    /// Whether captured artifacts are signed by the supervisor's
    /// audit key.
    pub sign: bool,
}

impl Default for ArtifactPolicy {
    fn default() -> Self {
        Self {
            capture_path: "/artifacts".to_string(),
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            encrypt_at_rest: true,
            sign: false,
        }
    }
}

/// When and how the supervisor rotates workload secrets / identity
/// material during a plan's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum KeyRotationSpec {
    /// No rotation; secrets are static for the plan's lifetime.
    #[default]
    None,
    /// Rotate on every supervisor-initiated workload restart.
    OnRestart,
    /// Rotate on a fixed schedule.
    Periodic { interval_secs: u32 },
}

/// What the supervisor must verify before releasing sensitive secrets
/// for this plan.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "tier", deny_unknown_fields)]
pub enum AttestationRequirement {
    /// No attestation required; suitable for non-sensitive workloads.
    #[default]
    None,
    /// Plan declares an expected workload measurement; supervisor
    /// must verify the running guest matches.
    Measured { measurement: [u8; 32] },
    /// Plan requires a hardware-rooted confidential-computing
    /// attestation. Vendors marked here as `Tpm2` ship today; SEV-SNP
    /// and TDX are scaffolded `unimplemented!()` providers — plans
    /// requiring them are refused at admission until the providers
    /// land. Whitepaper §14.
    Confidential { vendor: ConfidentialVendor },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialVendor {
    Tpm2,
    SevSnp,
    Tdx,
}

/// Pin a plan to a specific signed release bundle so the supervisor
/// refuses to launch when live image / policy / runtime-profile
/// digests diverge from the pinned set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePin {
    pub release_id: String,
    pub image_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub runtime_profile_digest: [u8; 32],
}

/// What the supervisor does when the workload exits / crashes / times
/// out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum PostRunLifecycle {
    /// Tear down immediately and reclaim resources.
    #[default]
    Destroy,
    /// Snapshot to disk (encrypted with per-tenant DEK) for later
    /// resume; then tear down the live VM.
    Snapshot,
    /// Keep the VM warm; the supervisor may suspend it on idle.
    KeepWarm,
}

mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

// `valid_from` / `valid_until` use `chrono::DateTime<Utc>` directly;
// callers should depend on `chrono` themselves to construct those.
