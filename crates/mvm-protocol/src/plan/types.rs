//! `*Ref` and `*Spec` types referenced from `ExecutionPlan`.
//!
//! Most fields here are opaque newtype wrappers so later resolvers
//! can be introduced without churning the wire format. Every type
//! carries `#[serde(deny_unknown_fields)]` so
//! adding a field is a fail-closed schema bump for older verifiers.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// How a workload reaches the network. Closed by default: the guest gets no
/// virtio-net device and can reach nothing until networking is explicitly
/// requested. [`HostVsockProxy`](NetworkMode::HostVsockProxy) is the brokered,
/// no-NIC transport — egress and ingress are mediated by host brokers over
/// vsock, and the `network_policy` allowlist still gates which endpoints are
/// reachable. Carried in the signed `ExecutionPlan` so the transport is part of
/// the admitted contract, not a host-wide setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No guest NIC, no broker — the workload cannot reach the network.
    #[default]
    None,
    /// No guest NIC; egress and ingress are mediated by host brokers over vsock.
    HostVsockProxy,
    /// No guest NIC; the guest gets a point-to-point `mvm0` **TUN** interface
    /// and raw IP packets are framed over dedicated vsock connections to the
    /// host gateway, which applies policy before anything reaches host
    /// networking.
    ///
    /// A compatibility mode for workloads that need a real IP stack. It is
    /// never selected implicitly — the presence of an egress rule does not
    /// imply it — and there is no fallback between it and the other modes.
    /// It trades the socket-aware path's connection intent and owned-cleartext
    /// substitution for IP-stack fidelity; see
    /// `specs/adrs/036-l3-tun-over-vsock.md` §"Capability difference".
    L3Vsock,
}

impl NetworkMode {
    /// Stable wire/CLI spelling. Matches the serde representation, so the
    /// CLI parser and the plan cannot drift apart.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostVsockProxy => "host_vsock_proxy",
            Self::L3Vsock => "l3_vsock",
        }
    }

    /// Whether this mode carries the L3 tunnel.
    pub fn is_l3_vsock(&self) -> bool {
        matches!(self, Self::L3Vsock)
    }
}

/// How much ICMP an L3 workload may exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3IcmpPolicy {
    /// No ICMP at all.
    Deny,
    /// Error and control messages only — enough for path-MTU discovery.
    ErrorsOnly,
    /// Errors plus echo to admitted destinations.
    #[default]
    EchoAndErrors,
}

/// One declared ingress mapping: a host listener forwarding into the guest.
///
/// `"tcp"` and `"udp"` are both declarable; anything else is refused at
/// admission rather than accepted and ignored, so a workload never believes
/// it is reachable on a port nothing is listening for. Whether a declared
/// mapping is *served* is a property of the selected forwarding backend and
/// is reported through its capabilities, not decided here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L3IngressMapping {
    /// `"tcp"` or `"udp"`. Any other value is refused at admission.
    pub proto: String,
    /// Host address the listener binds. `0.0.0.0` is a wildcard exposure.
    pub host_addr: String,
    pub host_port: u16,
    /// Guest port packets are delivered to.
    pub guest_port: u16,
}

/// The L3-tunnel half of a workload's admitted networking contract.
///
/// Present only when [`NetworkMode::L3Vsock`] is selected; admission refuses
/// an `l3_vsock` plan that carries no spec, and refuses a spec on a plan whose
/// mode is something else. Every field is part of the signed contract, so the
/// transport's shape is admitted rather than host-chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L3NetworkSpec {
    /// Wire-protocol major version the plan admits. Version 1 today.
    pub protocol_version: u8,
    /// Negotiated feature bits. Version 1 grants none.
    #[serde(default)]
    pub features: u32,
    /// MTU assigned to the guest interface.
    pub mtu: u16,
    /// Data queues to open. Version 1 admits exactly one.
    pub queue_count: u16,
    /// CIDR the host allocates the machine's point-to-point /30 from. `None`
    /// means the host default pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_pool: Option<String>,
    /// Private ranges this workload may reach. Empty — the default — denies
    /// every RFC1918 destination. `MANDATORY_DENY_RANGES` is unconditional
    /// and cannot be opened here.
    #[serde(default)]
    pub admitted_private_cidrs: Vec<String>,
    #[serde(default)]
    pub icmp: L3IcmpPolicy,
    /// Whether IP fragments are carried. Version 1 admits `false` only;
    /// reassembly is an unbounded-state sink.
    #[serde(default)]
    pub allow_fragments: bool,
    /// Declared ingress mappings. Anything not listed here is never
    /// reachable from outside.
    #[serde(default)]
    pub ingress: Vec<L3IngressMapping>,
    /// Cap on concurrent flows for this machine.
    pub max_flows: u32,
    /// Cap on live DNS bindings for this machine.
    pub max_dns_bindings: u32,
    /// Revision counter for the networking rules. Flows and DNS bindings
    /// from a superseded epoch never apply.
    #[serde(default)]
    pub policy_epoch: u64,
}

impl L3NetworkSpec {
    /// The version-1 shape with conservative defaults: one queue, MTU 1500,
    /// no fragments, no private ranges, no ingress.
    pub fn v1() -> Self {
        Self {
            protocol_version: 1,
            features: 0,
            mtu: 1500,
            queue_count: 1,
            address_pool: None,
            admitted_private_cidrs: Vec::new(),
            icmp: L3IcmpPolicy::default(),
            allow_fragments: false,
            ingress: Vec::new(),
            max_flows: 4096,
            max_dns_bindings: 1024,
            policy_epoch: 0,
        }
    }
}

/// How the workload image was specified — the source the deterministic build
/// pipeline consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// An OCI image reference.
    Oci,
    /// A bundled Nix template.
    NixTemplate,
    /// A Nix flake output (`.#app`).
    NixFlake,
    /// A local repo/project with detected Nix metadata.
    LocalProject,
}

/// Content-addressed digests (hex sha256) of the artifacts a build produced,
/// recorded so a launch is traceable to exact bytes. `None` = not applicable to
/// this workload (e.g. no initramfs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigests {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mvm_init: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_base: Option<String>,
}

/// Provenance of a workload build: what input was consumed, pinned how, by which
/// builder, producing which artifacts. Recorded in the signed plan so a launch
/// is traceable end-to-end to deterministic inputs and outputs. The build
/// pipeline populates it; absence (`None` on the plan) means provenance was not
/// recorded for this workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProvenance {
    /// Which kind of source produced this image.
    pub input_kind: InputKind,
    /// The supplied reference: OCI ref, flake ref, template name, or local
    /// project path.
    pub input_ref: String,
    /// Pin of the input: image manifest digest, `flake.lock` hash, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_digest: Option<String>,
    /// Identity/fingerprint of the builder VM that produced the artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    /// Content-addressed digests of the produced artifacts.
    #[serde(default)]
    pub artifacts: ArtifactDigests,
}

/// Stable identifier for an `ExecutionPlan` instance. Synthesis derives it
/// as the content-address of the plan body — `sha256:<64 lowercase hex>` over
/// every load-bearing field except the id itself — so a run is addressable and
/// hash-linkable by digest. The type stays an opaque `String` newtype: the
/// derivation lives in `mvm-core` (which owns the hashing crates), and this
/// no_std DTO crate only carries the value across the wire. Audit entries
/// reference this id verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub String);

/// Reference to a runtime profile (Firecracker / libkrun / HVF / QEMU).
/// The open `BackendRegistry` resolves the name to a backend factory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeProfileRef(pub String);

/// The execution environment a workload is admitted to boot *in*, as opposed to
/// the image it boots. Content-addressed like [`SignedImageRef`].
///
/// This exists because the image digest alone does not determine how the
/// workload is confined. The same signed image, booted on a kernel built for a
/// different job, gets a different security posture — a kernel with
/// `CONFIG_USER_NS` enabled lets the guest enter a user namespace as uid 0,
/// which the workload kernel deliberately prevents. Without the kernel in the
/// plan, that difference is invisible: identical plan, identical image,
/// identical digests, and a posture decided by whatever the host had cached.
///
/// Pinning it makes the mismatch refusable at admission instead of silent at
/// boot. The struct (rather than a bare digest) is so the rest of the
/// environment — initrd, runtime overlay, seccomp tier — can be added without
/// another plan field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRef {
    /// Lowercase hex SHA-256 of the kernel image this workload boots.
    pub kernel_sha256: String,
}

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

impl core::fmt::Display for PlanSeccompTier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Essential => write!(f, "essential"),
            Self::Minimal => write!(f, "minimal"),
            Self::Standard => write!(f, "standard"),
            Self::Network => write!(f, "network"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
}

impl core::str::FromStr for PlanSeccompTier {
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
    /// `/run/mvm-secrets/<name>` file).
    pub name: String,
    pub source: SecretSource,
}

/// Where a secret comes from. Pluggable providers (Vault, AWS SM,
/// GCP SM) plus per-run attestation-gated release. A secret's raw
/// value never appears in a plan — only a reference the supervisor's
/// `KeystoreReleaser` resolves at admission; the plan (persisted to
/// `plan.json`) carries no plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SecretSource {
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

impl core::fmt::Display for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
/// binding makes each an *admitted, signed, audited* grant so a future
/// supervisor-side "refuse a share the admitted plan didn't name"
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

#[cfg(test)]
mod network_mode_tests {
    use super::*;

    #[test]
    fn default_is_closed_none() {
        assert_eq!(NetworkMode::default(), NetworkMode::None);
    }

    #[test]
    fn serde_uses_snake_case_tokens() {
        assert_eq!(
            serde_json::to_string(&NetworkMode::HostVsockProxy).unwrap(),
            "\"host_vsock_proxy\""
        );
        assert_eq!(
            serde_json::from_str::<NetworkMode>("\"none\"").unwrap(),
            NetworkMode::None
        );
    }
}

#[cfg(test)]
mod build_provenance_tests {
    use super::*;

    #[test]
    fn input_kind_uses_snake_case_tokens() {
        assert_eq!(
            serde_json::to_string(&InputKind::NixFlake).unwrap(),
            "\"nix_flake\""
        );
        assert_eq!(
            serde_json::from_str::<InputKind>("\"local_project\"").unwrap(),
            InputKind::LocalProject
        );
    }

    #[test]
    fn provenance_round_trips_with_digests() {
        let prov = BuildProvenance {
            input_kind: InputKind::Oci,
            input_ref: "docker.io/library/alpine@sha256:abc".to_string(),
            lock_digest: Some("sha256:manifest".to_string()),
            builder_id: Some("builder-hvf-01".to_string()),
            artifacts: ArtifactDigests {
                kernel: Some("k".repeat(64)),
                rootfs: Some("r".repeat(64)),
                mvm_init: Some("i".repeat(64)),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&prov).unwrap();
        let back: BuildProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, prov);
    }

    #[test]
    fn absent_artifact_digests_are_omitted_not_null() {
        let digests = ArtifactDigests {
            kernel: Some("k".repeat(64)),
            ..Default::default()
        };
        let json = serde_json::to_string(&digests).unwrap();
        assert!(json.contains("kernel"));
        assert!(
            !json.contains("initramfs"),
            "absent digests omitted: {json}"
        );
    }
}
