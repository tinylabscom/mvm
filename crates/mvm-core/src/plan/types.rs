//! `*Ref` and `*Spec` types referenced from `ExecutionPlan`.
//!
//! Most fields here are opaque newtype wrappers so later resolvers
//! can be introduced without churning the wire format. Every type
//! carries `#[serde(deny_unknown_fields)]` so
//! adding a field is a fail-closed schema bump for older verifiers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable identifier for an `ExecutionPlan` instance. Currently a
/// ULID; we keep the type opaque so the constructor can switch
/// generators (UUIDv7, snowflake, etc.) without touching the wire
/// format. Audit entries reference this id verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub String);

/// Reference to a runtime profile (Firecracker / libkrun / Vz / QEMU).
/// The open `BackendRegistry` resolves the name to a backend factory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeProfileRef(pub String);

/// Reference to a signed image. SHA-256 of the rootfs + name. The
/// `cosign_bundle` field
/// is the path or URL to the cosign keyless bundle that
/// `mvm-core::crypto::image_verify` validates against; in dev mode the
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
    /// False iff the sealed image declares no workload entrypoint.
    /// Defaults to true (every legacy plan + every dev image), and is
    /// skip-serialized when true so existing signed-plan fixtures stay
    /// byte-identical (the field is inside the signed payload). The
    /// supervisor refuses a plan whose image asserts entrypoint_present ==
    /// false — admission-time defense in depth behind the SDK's compile
    /// gate.
    #[serde(
        default = "default_entrypoint_present",
        skip_serializing_if = "is_entrypoint_present"
    )]
    pub entrypoint_present: bool,
}

fn default_entrypoint_present() -> bool {
    true
}

fn is_entrypoint_present(v: &bool) -> bool {
    *v
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

/// Opaque pointer to a policy bundle. Until the real
/// `mvm-core::policy::PolicyBundle` resolver lands, this is a name the
/// supervisor's `Noop` resolver maps to a default-deny / open stance
/// per its bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FsPolicyRef(pub String);

/// Purpose label bound into the signed plan at admission time.
///
/// This is intentionally separate from [`WorkloadId`]: many workloads
/// can share the same security posture because they have the same
/// purpose (`code:execute`, `agent:web-research`, `deploy:publish`,
/// etc.). Resolvers use the intent to pick a concrete admission
/// profile before the backend boots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadIntent(pub String);

/// Seccomp tier name as it appears in a signed `ExecutionPlan`.
///
/// The concrete filter lives in `mvm-core::crypto`; keeping this enum
/// in `mvm-core::plan` keeps the selected tier a typed, auditable plan
/// field decoupled from the filter impl.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanSeccompTier {
    Essential,
    Minimal,
    #[default]
    Standard,
    Network,
    Unrestricted,
}

impl std::fmt::Display for PlanSeccompTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Essential => write!(f, "essential"),
            Self::Minimal => write!(f, "minimal"),
            Self::Standard => write!(f, "standard"),
            Self::Network => write!(f, "network"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
}

impl std::str::FromStr for PlanSeccompTier {
    type Err = PlanSeccompTierParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "essential" => Ok(Self::Essential),
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "network" => Ok(Self::Network),
            "unrestricted" => Ok(Self::Unrestricted),
            _ => Err(PlanSeccompTierParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "unknown seccomp tier {value:?} (expected: essential, minimal, standard, network, unrestricted)"
)]
pub struct PlanSeccompTierParseError {
    pub value: String,
}

/// How a profile permits secrets to become visible to the workload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReleasePolicy {
    /// No secrets may be released.
    #[default]
    None,
    /// Secrets listed in `ExecutionPlan.secrets` may be released
    /// after plan signature, validity, replay, and policy checks pass.
    PlanBound,
    /// Secrets require the plan checks plus the plan's attestation
    /// requirement before release.
    AttestationBound,
}

/// Event naming and required labels for plan-bound audit output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTaxonomy {
    /// Prefix for events produced under this profile. Examples:
    /// `execution.code`, `agent.web`, `deploy.release`.
    pub event_prefix: String,
    /// Labels that must be copied into audit output for this profile.
    pub required_labels: Vec<String>,
}

/// Fully resolved admission controls for a signed plan.
///
/// This is the binding between a plan's declared purpose and the
/// concrete enforcement surfaces the runtime must use. The separate
/// top-level `network_policy`, `egress_policy`, `tool_policy`, and
/// `secrets` fields remain for backwards-compatible consumers; this
/// profile records why those refs were selected and which taxonomy
/// audit should use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProfile {
    pub id: String,
    pub intent: WorkloadIntent,
    pub seccomp_tier: PlanSeccompTier,
    pub network_policy: PolicyRef,
    pub fs_policy: FsPolicyRef,
    pub egress_policy: PolicyRef,
    pub tool_policy: PolicyRef,
    pub secret_release: SecretReleasePolicy,
    pub audit: AuditTaxonomy,
}

impl AdmissionProfile {
    /// Construct the local default profile used by legacy fixtures
    /// and direct local boots. This records the selected seccomp tier
    /// while leaving every policy ref at `local-default`.
    pub fn local_default(intent: impl Into<String>, seccomp_tier: PlanSeccompTier) -> Self {
        let intent = intent.into();
        let policy = PolicyRef("local-default".to_string());
        let fs_policy = FsPolicyRef("local-default".to_string());
        Self {
            id: format!("{intent}:{seccomp_tier}"),
            intent: WorkloadIntent(intent.clone()),
            seccomp_tier,
            network_policy: policy.clone(),
            fs_policy,
            egress_policy: policy.clone(),
            tool_policy: policy,
            secret_release: SecretReleasePolicy::None,
            audit: AuditTaxonomy {
                event_prefix: intent.replace(':', "."),
                required_labels: vec![
                    "intent".to_string(),
                    "admission_profile".to_string(),
                    "seccomp_tier".to_string(),
                ],
            },
        }
    }
}

/// Workload variant — `Dev` is the development sandbox (carries the
/// dev guest agent's RCE-by-design Exec handler, accepts looser
/// policies), `Prod` is the production posture (no dev primitives,
/// strict policy gates). The `L7EgressProxy` consults this at
/// construction time to refuse plain-HTTP egress for `Prod`.
///
/// Mirrors `passthru.variant` from Nix-side `mkGuest`. The supervisor
/// resolves it from the workload's `SignedImageRef.name` suffix or
/// from the policy bundle's bound variant; `audit::AuditEntry::variant`
/// records this for every entry, so the value flows through the audit
/// chain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    Dev,
    Prod,
}

impl Variant {
    /// True iff this variant carries production-strict policy
    /// requirements (no dev RCE primitives, no plain-HTTP egress,
    /// verity-required rootfs, etc.).
    pub fn is_prod(self) -> bool {
        matches!(self, Variant::Prod)
    }
}

/// A secret binding from a name (visible inside the guest) to its
/// source (resolved by the supervisor's `KeystoreReleaser`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// Name as the workload sees it (e.g. env var name or
    /// /run/mvm-secrets/<name> file).
    pub name: String,
    pub source: SecretSource,
}

/// Where a secret comes from. Pluggable providers (Vault, AWS SM,
/// GCP SM) plus per-run attestation-gated release. The `Static`
/// variant is a compile-time literal for tests only — `mvmctl plan
/// validate --prod` rejects plans that contain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SecretSource {
    /// Test-only literal. Refused by `--prod` validation.
    Static { value: String },
    /// Per-run release from the supervisor's keystore. The address
    /// resolves to a SecretId at the supervisor.
    Keystore { address: String },
    /// External provider (Vault, AWS SM, etc.). The provider URL +
    /// path are opaque to mvm-core::plan; resolved by `KeystoreReleaser`.
    External { provider: String, path: String },
}

/// Artifact-capture policy for the run. `capture_paths` are guest-side
/// directories the supervisor's `ArtifactCollector` sweeps post-run;
/// `retention_days` controls the cleanup sweeper.
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

/// Attestation modes. Real TPM2 / SEV providers land later; the
/// `Noop` mode lets every plan launch without attestation (today's
/// behaviour) for backwards compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    /// No attestation. Stub. mvmctl warns; mvmd may refuse.
    Noop,
    /// TPM2 EK + AK quote. Supervisor's `KeystoreReleaser` gates
    /// secret release on a successful quote.
    Tpm2,
    /// AMD SEV-SNP report. Provider not yet implemented.
    SevSnp,
    /// Intel TDX quote. Provider not yet implemented.
    Tdx,
}

/// Release pinning: the workload runs at a specific release of
/// mvm/mvmd. Mismatch is grounds for refusal at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePin {
    pub release_id: String,
}

/// Lifecycle directives. The supervisor's plan state machine
/// consults these on workload exit / idle.
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

/// Per-plan replay-protection nonce. 16 random bytes, generated by
/// the plan signer. The supervisor's `NonceStore` (see
/// `crate::plan::validity`) refuses a second admission with the same
/// nonce for the same signer until the plan's `valid_until`
/// passes.
///
/// Wire format: 32-character lowercase hex string. Stored as a
/// string rather than `[u8; 16]` so JSON readers can eyeball it;
/// the type guarantees length and case via `from_hex` / `from_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Nonce(String);

impl Nonce {
    /// Construct from 16 raw bytes. Always lowercases the hex.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut s = String::with_capacity(32);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        Self(s)
    }

    /// Construct from a hex string. Returns `Err` if the input is not
    /// exactly 32 lowercase hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, NonceParseError> {
        if hex.len() != 32 {
            return Err(NonceParseError::WrongLength { len: hex.len() });
        }
        for c in hex.chars() {
            if !matches!(c, '0'..='9' | 'a'..='f') {
                return Err(NonceParseError::NonHex { ch: c });
            }
        }
        Ok(Self(hex.to_string()))
    }

    /// 32-character lowercase-hex view.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Nonce {
    type Error = NonceParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_hex(&s)
    }
}

impl From<Nonce> for String {
    fn from(n: Nonce) -> Self {
        n.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceParseError {
    #[error("nonce hex must be exactly 32 chars, got {len}")]
    WrongLength { len: usize },
    #[error("nonce hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// Pin from an `ExecutionPlan` to an application-dependencies volume.
///
/// Backs security claim 9. When a workload mounts a deps volume at
/// `/app/.venv` (Python) or
/// `/app/node_modules` (Node), the plan binds the on-disk volume's
/// deterministic hashes here so the supervisor's admission gate can
/// re-verify them before launch.
///
/// Two hashes are pinned:
///
/// 1. **`volume_hash`** — the canonical
///    `sha256(content_sha256 || canonical(meta.json))` produced by
///    `mvm_sdk::compile::deps_audit::seal_volume`. This is the value
///    used as the volume directory name on disk
///    (`~/.mvm/volumes/deps/<volume_hash>/`).
/// 2. **`manifest_sha256`** — the SHA-256 of the canonical
///    `meta.json` bytes. Pinned separately so an attacker who
///    re-derives a volume hash for tampered content (which they
///    can't, modulo a SHA-256 break) still fails the second check.
///    Belt-and-suspenders against future hash-derivation changes.
///
/// Both are 64-character lowercase hex strings. The
/// `TryFrom<String>` impl rejects shorter/longer/uppercase/non-hex
/// inputs so a forged plan can't sneak a malformed pin past the
/// envelope's `deny_unknown_fields` gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsVolumeBinding {
    /// Lowercase hex SHA-256, 64 chars. The volume directory name
    /// on disk under `~/.mvm/volumes/deps/`.
    #[serde(deserialize_with = "deserialize_sha256_hex")]
    pub volume_hash: String,
    /// Lowercase hex SHA-256, 64 chars. The hash of the canonical
    /// `meta.json` bytes inside the volume.
    #[serde(deserialize_with = "deserialize_sha256_hex")]
    pub manifest_sha256: String,
}

impl DepsVolumeBinding {
    /// Construct a binding. Returns `Err` if either hash is not
    /// 64 lowercase hex characters.
    pub fn new(
        volume_hash: impl Into<String>,
        manifest_sha256: impl Into<String>,
    ) -> Result<Self, DepsVolumeBindingError> {
        let volume_hash = validate_sha256_hex(volume_hash.into())?;
        let manifest_sha256 = validate_sha256_hex(manifest_sha256.into())?;
        Ok(Self {
            volume_hash,
            manifest_sha256,
        })
    }
}

/// Validation error for [`DepsVolumeBinding`] hash fields. Surfaces
/// through the `TryFrom<String>` impl on each field so a malformed
/// pin is rejected at serde deserialise time, before the supervisor
/// inspects the plan.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DepsVolumeBindingError {
    #[error("deps-volume hash must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    #[error("deps-volume hash must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

fn validate_sha256_hex(s: String) -> Result<String, DepsVolumeBindingError> {
    if s.len() != 64 {
        return Err(DepsVolumeBindingError::WrongLength { len: s.len() });
    }
    for c in s.chars() {
        if !matches!(c, '0'..='9' | 'a'..='f') {
            return Err(DepsVolumeBindingError::NonHex { ch: c });
        }
    }
    Ok(s)
}

fn deserialize_sha256_hex<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    validate_sha256_hex(s).map_err(serde::de::Error::custom)
}

/// Whether a [`HostShareGrant`] is a live directory share (virtio-fs)
/// or a disk image (virtio-blk).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareKind {
    DirShare,
    Disk,
}

/// A host-filesystem grant recorded in — and signed with — the
/// `ExecutionPlan`: one user `--volume` directory share or disk image.
///
/// Claim 1 ("no host-fs access from a guest beyond explicit shares") +
/// claim 8. Today user volumes attach as a host-side launch detail; this
/// binding makes each an *admitted, signed, audited* grant so the Vz
/// supervisor's future "refuse a share the admitted plan didn't name"
/// gate can allow them, and every admission emits the list to the
/// chain-signed audit log. `deny_unknown_fields` + the
/// absolute-path check keep a forged plan from smuggling a grant past
/// the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostShareGrant {
    /// Coordination tag/id the backend assigns (`uvol{idx}`) — the
    /// virtio-fs tag or virtio-blk device id.
    pub tag: String,
    /// Resolved (canonical) host path shared/attached. The CLI pins the
    /// symlink-resolved path here (TOCTOU-safe).
    pub host_path: String,
    /// Absolute guest mount point.
    #[serde(deserialize_with = "deserialize_abs_path")]
    pub guest_path: String,
    pub kind: ShareKind,
    pub read_only: bool,
    /// Disk-only: in-guest encryption requested. Always false for a
    /// directory share.
    #[serde(default)]
    pub encrypted: bool,
}

/// Reject a non-absolute or empty guest path at deserialize time.
fn deserialize_abs_path<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    if !s.starts_with('/') {
        return Err(serde::de::Error::custom(format!(
            "guest_path must be absolute (start with '/'), got {s:?}"
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod host_share_grant_tests {
    use super::*;

    fn sample() -> HostShareGrant {
        HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/host/src".into(),
            guest_path: "/work2".into(),
            kind: ShareKind::DirShare,
            read_only: true,
            encrypted: false,
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let g = sample();
        let json = serde_json::to_string(&g).unwrap();
        // snake_case for the kind discriminant.
        assert!(json.contains("\"dir_share\""), "{json}");
        let back: HostShareGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn disk_kind_serializes_snake_case() {
        let json = serde_json::to_string(&ShareKind::Disk).unwrap();
        assert_eq!(json, "\"disk\"");
    }

    #[test]
    fn rejects_relative_guest_path() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"work2",
            "kind":"dir_share","read_only":false}"#;
        let err = serde_json::from_str::<HostShareGrant>(json).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"/g",
            "kind":"disk","read_only":false,"bogus":1}"#;
        assert!(serde_json::from_str::<HostShareGrant>(json).is_err());
    }

    #[test]
    fn encrypted_defaults_false_when_absent() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"/g",
            "kind":"disk","read_only":false}"#;
        let g: HostShareGrant = serde_json::from_str(json).unwrap();
        assert!(!g.encrypted);
    }
}

#[cfg(test)]
mod signed_image_ref_tests {
    use super::*;

    /// Byte-identity guard: a default-true `entrypoint_present` must
    /// NOT serialize, so every existing
    /// signed-plan fixture (which never carried the field) hashes the
    /// same bytes and its Ed25519 signature stays valid.
    #[test]
    fn serde_omits_entrypoint_present_when_true() {
        let r = SignedImageRef {
            name: "img".into(),
            sha256: "a".repeat(64),
            cosign_bundle: None,
            entrypoint_present: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("entrypoint_present"),
            "default-true field leaked into wire: {json}"
        );

        // A plan JSON without the key round-trips to true (default).
        let back: SignedImageRef =
            serde_json::from_str(r#"{"name":"img","sha256":"deadbeef","cosign_bundle":null}"#)
                .unwrap();
        assert!(back.entrypoint_present);
    }

    /// The guard field is serialized only when false — the one case the
    /// supervisor's admission gate must see on the wire.
    #[test]
    fn serde_emits_entrypoint_present_when_false() {
        let r = SignedImageRef {
            name: "img".into(),
            sha256: "a".repeat(64),
            cosign_bundle: None,
            entrypoint_present: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"entrypoint_present\":false"), "{json}");
        let back: SignedImageRef = serde_json::from_str(&json).unwrap();
        assert!(!back.entrypoint_present);
    }
}
