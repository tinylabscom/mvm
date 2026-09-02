//! `ExecutionPlan` synthesis from a resolved [`SynthesisInput`].
//!
//! Turns an already-resolved launch shape (name, backend, image digest,
//! cpus, memory, volumes, secrets, policy refs, etc.) into a typed
//! [`crate::plan::ExecutionPlan`] the supervisor can verify, audit, and gate
//! on. This is the pure, side-effect-free core of signed-plan admission
//! (claim 8): the caller resolves CLI/API args into a `SynthesisInput`, this
//! builds the unsigned plan, and the caller signs + admits it. Living in
//! `mvm-core` (beside the plan types) lets every driver — the CLI, and the
//! `mvm-client` local backend once the boot seam lands — synthesize through
//! one contract.
//!
//! ## What lives here
//!
//! - [`synthesize_plan`] — the one entry point. Takes a borrowed
//!   `SynthesisInput` and produces an `ExecutionPlan` ready to sign.
//! - Internal helpers for resource budgets and validity windows.
//!
//! ## What does NOT live here
//!
//! - **Signing.** The `signer` module owns it — `synthesize_plan`
//!   builds the unsigned plan; the caller signs.
//! - **Backend dispatch.** The supervisor wires `BackendLauncher`;
//!   this module is plan-shape-only, no I/O.
//! - **Policy resolution.** The `policy_resolver` turns the plan's
//!   `PolicyRef` fields into concrete supervisor components.
//!
//! ## Field source map (plan field → CLI input)
//!
//! | Plan field | Where it comes from |
//! |---|---|
//! | `plan_id` | content-address of the finished plan (all load-bearing fields except the id itself) |
//! | `plan_version` | always 1 for synthesized plans; the revision counter under the stable `(tenant, workload)` identity (mvmd revisions get higher numbers) |
//! | `tenant` | `--tenant` flag or default `"local"` |
//! | `workload` | derived from `--name` or flake ref leaf |
//! | `runtime_profile` | hypervisor flag mapped to a profile name |
//! | `image` | computed lazily from rootfs SHA-256 (filled by caller after build) |
//! | `resources` | `--cpus`, `--memory`, `--ttl` |
//! | `*_policy` / `fs_policy` | `"local-default"` (resolver maps to Noops) |
//! | `valid_from`/`valid_until` | now + 10 min window |
//! | `nonce` | fresh 128 bits from `SysRng` per invocation |
//! | `stream_retention` | caller-supplied; `Persist` unless a driver opts the run out of a durable transcript |
//! | everything else | conservative defaults (no attestation, destroy-on-exit, etc.) |

use crate::plan::{
    AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, AuditLabels,
    AuditTaxonomy, CallerCommitment, DepsVolumeBinding, EnvironmentRef, ExecutionPlan, FsPolicyRef,
    IngressMapping, KeyRotationSpec, NetworkMode, Nonce, PlanId, PlanSeccompTier, PolicyRef,
    PostRunLifecycle, Resources, RuntimeProfileRef, SCHEMA_VERSION, SecretBinding,
    SecretReleasePolicy, SignedImageRef, StreamRetention, TenantId, TimeoutSpec, WorkloadId,
    WorkloadIntent,
};
use anyhow::Result;
use chrono::{Duration, Utc};
use mvm_contract::builder::BuilderError;
use rand::Rng;
use std::collections::BTreeMap;

/// Default tenant for single-host runs. The "one guest = one
/// workload" model means the tenant boundary is the host itself unless
/// mvmd's multi-tenant control plane is wired in.
pub const DEFAULT_TENANT: &str = "local";

/// Default policy name resolved by the policy_resolver to a Noop
/// component-slot set. Production deployments override via the
/// supervisor's policy bundle.
pub const DEFAULT_POLICY_REF: &str = "local-default";

/// Default intent for direct `mvmctl up` boots. Higher-level callers
/// can pass a more specific purpose such as `code:execute` or
/// `agent:web-research` once their API has that context.
pub const DEFAULT_INTENT: &str = "vm:boot";

/// Default audit event prefix for direct VM boots.
pub const DEFAULT_AUDIT_EVENT_PREFIX: &str = "vm.boot";

/// Plan validity window from `now`. 10 minutes is long enough that
/// boot + signature verification + state machine walk finishes well
/// within the window; short enough that a captured plan can't be
/// replayed hours later.
pub const VALIDITY_WINDOW_MINUTES: i64 = 10;

/// Caller-supplied input. We take a struct rather than the 10
/// individual fields the workspace clippy `too_many_arguments` lint
/// would otherwise force into a refactor anyway.
#[derive(Debug, Clone)]
pub struct SynthesisInput<'a> {
    /// VM name (post-validation). Synthesized plans use this verbatim
    /// as the `WorkloadId`.
    pub vm_name: &'a str,
    /// Optional tenant override. `None` → `DEFAULT_TENANT`.
    pub tenant: Option<&'a str>,
    /// Resolved runtime profile (`firecracker` / `libkrun` / `hvf` / `qemu`).
    pub backend_name: &'a str,
    /// Image reference for `SignedImageRef`. `sha256` is the
    /// lowercase-hex digest of the rootfs (computed by `mvm-core::crypto::
    /// image_verify::sha256_file` or upstream Nix).
    pub image_name: &'a str,
    pub image_sha256: &'a str,
    /// Lowercase-hex SHA-256 of the kernel this workload boots, pinning the
    /// environment into the signed plan. `None` = the caller resolved no kernel
    /// (a backend that supplies its own bundled one), and the plan pins none.
    pub kernel_sha256: Option<&'a str>,
    pub image_cosign_bundle: Option<&'a str>,
    /// Purpose this run is admitted for. `None` means
    /// `DEFAULT_INTENT`.
    pub intent: Option<&'a str>,
    /// Seccomp tier resolved by the caller before admission. This is
    /// mirrored into `ExecutionPlan.admission_profile` so audit can
    /// prove which filter tier the boot was bound to.
    pub seccomp_tier: PlanSeccompTier,
    /// Policy refs selected by the caller. `None` falls back to
    /// `DEFAULT_POLICY_REF`. Keeping refs in the synthesis input
    /// lets intent profiles bind to live policy bundles without a
    /// later mutation step.
    pub network_policy_ref: Option<&'a str>,
    pub fs_policy_ref: Option<&'a str>,
    pub egress_policy_ref: Option<&'a str>,
    pub tool_policy_ref: Option<&'a str>,
    /// Whether any secret can be released under this profile.
    pub secret_release: SecretReleasePolicy,
    /// Secret refs lowered into plan-visible bindings.
    pub secrets: Vec<SecretBinding>,
    /// Optional audit event prefix override. `None` derives from the
    /// intent.
    pub audit_event_prefix: Option<&'a str>,
    /// How this workload reaches the network. Part of the signed contract:
    /// the transport is admitted, never a host-side default the guest
    /// discovers at boot. `Default` is the closed mode.
    pub network_mode: NetworkMode,
    /// Exact host listeners and guest-loopback targets admitted for ingress.
    pub ingress: Vec<IngressMapping>,
    /// What this workload asks to be permitted to consume. `None` = it
    /// declares none. Resolved across the caller's declaration surfaces before
    /// it gets here; admission checks it against the host's ceiling — which is
    /// not in this struct, because the ceiling's whole purpose is to come from
    /// somewhere the requester cannot write.
    pub grants: Option<mvm_contract::grants::Grants>,
    /// vCPU count.
    pub cpus: u32,
    /// Memory budget in MiB.
    pub mem_mib: u64,
    /// Disk budget in MiB. 0 = no explicit cap (supervisor falls back
    /// to whatever the image carries).
    pub disk_mib: u64,
    /// Boot-timeout seconds. Conservative default 60s on capable hosts.
    pub boot_timeout_secs: u32,
    /// Whether the post-run lifecycle should destroy the VM on exit.
    /// True for one-shot CLI workloads; false for daemon-shape services.
    pub destroy_on_exit: bool,
    /// Optional pin to a content-addressed `.mvmpkg` bundle. When
    /// set, the synthesised plan carries the pin and the supervisor's
    /// admit path re-verifies the archive against this triple before
    /// backend dispatch. Populating it from `mvmctl up` flags is the
    /// next step.
    pub bundle_pin: Option<crate::plan::bundle::PlanArtifact>,
    /// Optional pin to an application-dependencies volume sealed by
    /// `mvm_sdk::compile::deps_audit::seal_volume`. Populated by
    /// `mvmctl up`'s deps-install path when the workload declares
    /// `App.dependencies = Dependencies::Python | Dependencies::Node`;
    /// absent when `Dependencies::None` / no `--from-workload-ir` flag
    /// is set. The supervisor's admit path re-runs
    /// `verify_sealed_volume` against the pinned `volume_hash` +
    /// `manifest_sha256` before backend dispatch (security claim 9).
    pub deps_volume: Option<DepsVolumeBinding>,
    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`) to bake
    /// into the signed plan + audit log (claim 1 / claim 8). Empty for
    /// the common no-volume case.
    pub shares: Vec<crate::plan::HostShareGrant>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// Default (all-off) preserves the curated-only baseline.
    pub redaction: crate::policy::RedactionPolicy,
    /// Per-destination reversible replacement. Default (disabled) preserves the
    /// current one-way-only behavior.
    pub reversible_replacement: crate::policy::ReversibleReplacementPolicy,
    /// Caller-supplied audit labels merged into the synthesized plan's
    /// `audit_labels`. They serialize inside the signed payload and are
    /// inherited by every chain-signed audit entry. The profile-derived keys
    /// (intent / admission_profile / seccomp_tier) take precedence — caller
    /// labels cannot override them. Key format is caller-defined
    /// (unconstrained); supervisor-injected per-event extras are applied
    /// separately at audit-emit time and do not modify the plan's stored labels.
    pub audit_labels: AuditLabels,
    /// Opaque 32-byte caller commitment bound into the plan identity and
    /// signature. `None` keeps the legacy plan bytes unchanged.
    pub caller_commitment: Option<CallerCommitment>,
    /// Per-workload agent verb allow-list threaded verbatim into the plan.
    /// `None` preserves the current class/profile-gate-only behavior.
    pub agent_verbs: Option<Vec<crate::plan::VerbId>>,
    /// Host services this workload is authorized to call over the broker
    /// channel, threaded verbatim into the plan. Empty (the common case) means
    /// the workload calls none: the broker answers `NotBound` and the launch
    /// path attaches no SDK sidecar. The same list also carries the input-plane
    /// grant (`mvm_contract::stream::INPUT_GRANT_SERVICE`) — no dedicated field
    /// was needed, since `mvm_contract::stream::grants_input` reads this list.
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// Verified optional extensions admitted for this exact workload. Empty
    /// keeps extension resolution out of ordinary launch.
    pub extensions: Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>,
    /// Inbound stream edges this workload is fed by. Empty (the default) means
    /// no other workload writes its stdin.
    pub stream_edges: Vec<mvm_contract::stream::StreamEdge>,
    /// Whether this workload's captured output is kept after the run.
    /// [`StreamRetention::Persist`] (the default) writes an encrypted,
    /// hash-chained transcript sealed at exit; `Ephemeral` fans the output out
    /// live and keeps nothing. Admitted rather than flagged so an absent
    /// transcript is attributable to a signed decision.
    pub stream_retention: StreamRetention,
    /// Runtime attestation required by the signed plan. Ordinary launch
    /// callers use `Noop`; assurance controllers may select a hardware mode
    /// only from operator-owned configuration.
    pub attestation_mode: AttestationMode,
}

impl<'a> SynthesisInput<'a> {
    /// Start building a [`SynthesisInput`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> SynthesisInputBuilder<'a> {
        SynthesisInputBuilder::new()
    }
}

/// Builder for [`SynthesisInput`]. Required fields are checked by
/// [`SynthesisInputBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct SynthesisInputBuilder<'a> {
    vm_name: Option<&'a str>,
    tenant: Option<&'a str>,
    backend_name: Option<&'a str>,
    image_name: Option<&'a str>,
    image_sha256: Option<&'a str>,
    kernel_sha256: Option<&'a str>,
    image_cosign_bundle: Option<&'a str>,
    intent: Option<&'a str>,
    seccomp_tier: Option<PlanSeccompTier>,
    network_policy_ref: Option<&'a str>,
    fs_policy_ref: Option<&'a str>,
    egress_policy_ref: Option<&'a str>,
    tool_policy_ref: Option<&'a str>,
    secret_release: Option<SecretReleasePolicy>,
    secrets: Option<Vec<SecretBinding>>,
    audit_event_prefix: Option<&'a str>,
    network_mode: Option<NetworkMode>,
    ingress: Option<Vec<IngressMapping>>,
    grants: Option<mvm_contract::grants::Grants>,
    cpus: Option<u32>,
    mem_mib: Option<u64>,
    disk_mib: Option<u64>,
    boot_timeout_secs: Option<u32>,
    destroy_on_exit: Option<bool>,
    bundle_pin: Option<crate::plan::bundle::PlanArtifact>,
    deps_volume: Option<DepsVolumeBinding>,
    shares: Option<Vec<crate::plan::HostShareGrant>>,
    redaction: Option<crate::policy::RedactionPolicy>,
    reversible_replacement: Option<crate::policy::ReversibleReplacementPolicy>,
    audit_labels: Option<AuditLabels>,
    caller_commitment: Option<CallerCommitment>,
    agent_verbs: Option<Vec<crate::plan::VerbId>>,
    services: Option<Vec<mvm_contract::protocol::broker::ServiceId>>,
    extensions: Option<Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>>,
    stream_edges: Option<Vec<mvm_contract::stream::StreamEdge>>,
    stream_retention: Option<StreamRetention>,
    attestation_mode: Option<AttestationMode>,
}

impl<'a> SynthesisInputBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vm_name: None,
            tenant: None,
            backend_name: None,
            image_name: None,
            image_sha256: None,
            kernel_sha256: None,
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: None,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: None,
            secrets: None,
            audit_event_prefix: None,
            network_mode: None,
            ingress: None,
            grants: None,
            cpus: None,
            mem_mib: None,
            disk_mib: None,
            boot_timeout_secs: None,
            destroy_on_exit: None,
            bundle_pin: None,
            deps_volume: None,
            shares: None,
            redaction: None,
            reversible_replacement: None,
            audit_labels: None,
            caller_commitment: None,
            agent_verbs: None,
            services: None,
            extensions: None,
            stream_edges: None,
            stream_retention: None,
            attestation_mode: None,
        }
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `tenant`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tenant(mut self, tenant: impl Into<Option<&'a str>>) -> Self {
        self.tenant = tenant.into();
        self
    }

    /// Set `backend_name`.
    #[must_use]
    pub fn backend_name(mut self, backend_name: &'a str) -> Self {
        self.backend_name = Some(backend_name);
        self
    }

    /// Set `image_name`.
    #[must_use]
    pub fn image_name(mut self, image_name: &'a str) -> Self {
        self.image_name = Some(image_name);
        self
    }

    /// Set `image_sha256`.
    #[must_use]
    pub fn image_sha256(mut self, image_sha256: &'a str) -> Self {
        self.image_sha256 = Some(image_sha256);
        self
    }

    /// Set `kernel_sha256`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn kernel_sha256(mut self, kernel_sha256: impl Into<Option<&'a str>>) -> Self {
        self.kernel_sha256 = kernel_sha256.into();
        self
    }

    /// Set `image_cosign_bundle`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn image_cosign_bundle(mut self, image_cosign_bundle: impl Into<Option<&'a str>>) -> Self {
        self.image_cosign_bundle = image_cosign_bundle.into();
        self
    }

    /// Set `intent`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn intent(mut self, intent: impl Into<Option<&'a str>>) -> Self {
        self.intent = intent.into();
        self
    }

    /// Set `seccomp_tier`.
    #[must_use]
    pub fn seccomp_tier(mut self, seccomp_tier: PlanSeccompTier) -> Self {
        self.seccomp_tier = Some(seccomp_tier);
        self
    }

    /// Set `network_policy_ref`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn network_policy_ref(mut self, network_policy_ref: impl Into<Option<&'a str>>) -> Self {
        self.network_policy_ref = network_policy_ref.into();
        self
    }

    /// Set `fs_policy_ref`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn fs_policy_ref(mut self, fs_policy_ref: impl Into<Option<&'a str>>) -> Self {
        self.fs_policy_ref = fs_policy_ref.into();
        self
    }

    /// Set `egress_policy_ref`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn egress_policy_ref(mut self, egress_policy_ref: impl Into<Option<&'a str>>) -> Self {
        self.egress_policy_ref = egress_policy_ref.into();
        self
    }

    /// Set `tool_policy_ref`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tool_policy_ref(mut self, tool_policy_ref: impl Into<Option<&'a str>>) -> Self {
        self.tool_policy_ref = tool_policy_ref.into();
        self
    }

    /// Set `secret_release`.
    #[must_use]
    pub fn secret_release(mut self, secret_release: SecretReleasePolicy) -> Self {
        self.secret_release = Some(secret_release);
        self
    }

    /// Set `secrets`.
    #[must_use]
    pub fn secrets(mut self, secrets: Vec<SecretBinding>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Set `audit_event_prefix`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn audit_event_prefix(mut self, audit_event_prefix: impl Into<Option<&'a str>>) -> Self {
        self.audit_event_prefix = audit_event_prefix.into();
        self
    }

    /// Set `network_mode`.
    #[must_use]
    pub fn network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = Some(network_mode);
        self
    }

    /// Set the admitted ingress mappings.
    #[must_use]
    pub fn ingress(mut self, ingress: Vec<IngressMapping>) -> Self {
        self.ingress = Some(ingress);
        self
    }

    /// Set `grants`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn grants(mut self, grants: impl Into<Option<mvm_contract::grants::Grants>>) -> Self {
        self.grants = grants.into();
        self
    }

    /// Set `cpus`.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Set `mem_mib`.
    #[must_use]
    pub fn mem_mib(mut self, mem_mib: u64) -> Self {
        self.mem_mib = Some(mem_mib);
        self
    }

    /// Set `disk_mib`.
    #[must_use]
    pub fn disk_mib(mut self, disk_mib: u64) -> Self {
        self.disk_mib = Some(disk_mib);
        self
    }

    /// Set `boot_timeout_secs`.
    #[must_use]
    pub fn boot_timeout_secs(mut self, boot_timeout_secs: u32) -> Self {
        self.boot_timeout_secs = Some(boot_timeout_secs);
        self
    }

    /// Set `destroy_on_exit`.
    #[must_use]
    pub fn destroy_on_exit(mut self, destroy_on_exit: bool) -> Self {
        self.destroy_on_exit = Some(destroy_on_exit);
        self
    }

    /// Set `bundle_pin`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn bundle_pin(
        mut self,
        bundle_pin: impl Into<Option<crate::plan::bundle::PlanArtifact>>,
    ) -> Self {
        self.bundle_pin = bundle_pin.into();
        self
    }

    /// Set `deps_volume`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn deps_volume(mut self, deps_volume: impl Into<Option<DepsVolumeBinding>>) -> Self {
        self.deps_volume = deps_volume.into();
        self
    }

    /// Set `shares`.
    #[must_use]
    pub fn shares(mut self, shares: Vec<crate::plan::HostShareGrant>) -> Self {
        self.shares = Some(shares);
        self
    }

    /// Set `redaction`.
    #[must_use]
    pub fn redaction(mut self, redaction: crate::policy::RedactionPolicy) -> Self {
        self.redaction = Some(redaction);
        self
    }

    /// Set `reversible_replacement`.
    #[must_use]
    pub fn reversible_replacement(
        mut self,
        reversible_replacement: crate::policy::ReversibleReplacementPolicy,
    ) -> Self {
        self.reversible_replacement = Some(reversible_replacement);
        self
    }

    /// Set `audit_labels`.
    #[must_use]
    pub fn audit_labels(mut self, audit_labels: AuditLabels) -> Self {
        self.audit_labels = Some(audit_labels);
        self
    }

    /// Set the optional opaque caller commitment.
    #[must_use]
    pub fn caller_commitment(
        mut self,
        caller_commitment: impl Into<Option<CallerCommitment>>,
    ) -> Self {
        self.caller_commitment = caller_commitment.into();
        self
    }

    /// Set `agent_verbs`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn agent_verbs(mut self, agent_verbs: impl Into<Option<Vec<crate::plan::VerbId>>>) -> Self {
        self.agent_verbs = agent_verbs.into();
        self
    }

    /// Set `services`.
    #[must_use]
    pub fn services(mut self, services: Vec<mvm_contract::protocol::broker::ServiceId>) -> Self {
        self.services = Some(services);
        self
    }

    /// Set verified optional extension bindings.
    #[must_use]
    pub fn extensions(
        mut self,
        extensions: Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>,
    ) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Set `stream_edges`.
    #[must_use]
    pub fn stream_edges(mut self, stream_edges: Vec<mvm_contract::stream::StreamEdge>) -> Self {
        self.stream_edges = Some(stream_edges);
        self
    }

    /// Set `stream_retention`.
    #[must_use]
    pub fn stream_retention(mut self, stream_retention: StreamRetention) -> Self {
        self.stream_retention = Some(stream_retention);
        self
    }

    /// Set the runtime attestation mode signed into the execution plan.
    #[must_use]
    pub fn attestation_mode(mut self, attestation_mode: AttestationMode) -> Self {
        self.attestation_mode = Some(attestation_mode);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<SynthesisInput<'a>, BuilderError> {
        Ok(SynthesisInput {
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("SynthesisInput", "vm_name"))?,
            tenant: self.tenant,
            backend_name: self
                .backend_name
                .ok_or(BuilderError::missing("SynthesisInput", "backend_name"))?,
            image_name: self
                .image_name
                .ok_or(BuilderError::missing("SynthesisInput", "image_name"))?,
            image_sha256: self
                .image_sha256
                .ok_or(BuilderError::missing("SynthesisInput", "image_sha256"))?,
            kernel_sha256: self.kernel_sha256,
            image_cosign_bundle: self.image_cosign_bundle,
            intent: self.intent,
            seccomp_tier: self
                .seccomp_tier
                .ok_or(BuilderError::missing("SynthesisInput", "seccomp_tier"))?,
            network_policy_ref: self.network_policy_ref,
            fs_policy_ref: self.fs_policy_ref,
            egress_policy_ref: self.egress_policy_ref,
            tool_policy_ref: self.tool_policy_ref,
            secret_release: self
                .secret_release
                .ok_or(BuilderError::missing("SynthesisInput", "secret_release"))?,
            secrets: self
                .secrets
                .ok_or(BuilderError::missing("SynthesisInput", "secrets"))?,
            audit_event_prefix: self.audit_event_prefix,
            network_mode: self
                .network_mode
                .ok_or(BuilderError::missing("SynthesisInput", "network_mode"))?,
            ingress: self.ingress.unwrap_or_default(),
            grants: self.grants,
            cpus: self
                .cpus
                .ok_or(BuilderError::missing("SynthesisInput", "cpus"))?,
            mem_mib: self
                .mem_mib
                .ok_or(BuilderError::missing("SynthesisInput", "mem_mib"))?,
            disk_mib: self
                .disk_mib
                .ok_or(BuilderError::missing("SynthesisInput", "disk_mib"))?,
            boot_timeout_secs: self
                .boot_timeout_secs
                .ok_or(BuilderError::missing("SynthesisInput", "boot_timeout_secs"))?,
            destroy_on_exit: self
                .destroy_on_exit
                .ok_or(BuilderError::missing("SynthesisInput", "destroy_on_exit"))?,
            bundle_pin: self.bundle_pin,
            deps_volume: self.deps_volume,
            shares: self
                .shares
                .ok_or(BuilderError::missing("SynthesisInput", "shares"))?,
            redaction: self
                .redaction
                .ok_or(BuilderError::missing("SynthesisInput", "redaction"))?,
            reversible_replacement: self.reversible_replacement.ok_or(BuilderError::missing(
                "SynthesisInput",
                "reversible_replacement",
            ))?,
            audit_labels: self
                .audit_labels
                .ok_or(BuilderError::missing("SynthesisInput", "audit_labels"))?,
            caller_commitment: self.caller_commitment,
            agent_verbs: self.agent_verbs,
            services: self
                .services
                .ok_or(BuilderError::missing("SynthesisInput", "services"))?,
            extensions: self.extensions.unwrap_or_default(),
            stream_edges: self
                .stream_edges
                .ok_or(BuilderError::missing("SynthesisInput", "stream_edges"))?,
            stream_retention: self
                .stream_retention
                .ok_or(BuilderError::missing("SynthesisInput", "stream_retention"))?,
            attestation_mode: self.attestation_mode.unwrap_or(AttestationMode::Noop),
        })
    }
}

impl<'a> Default for SynthesisInputBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an unsigned `ExecutionPlan` from CLI-shaped input.
///
/// Generates a fresh `nonce` (128 random bits) per invocation and
/// derives `plan_id` as the content-address of the finished plan (see
/// [`crate::plan::compute_plan_id`]); the validity window starts at the
/// call site's `now()` and lasts `VALIDITY_WINDOW_MINUTES`. The caller
/// signs the returned plan via [`crate::plan::sign_plan`] before passing
/// it to the supervisor — the signature covers the derived id.
pub fn synthesize_plan(input: &SynthesisInput<'_>) -> Result<ExecutionPlan> {
    let nonce = fresh_nonce();
    let now = Utc::now();

    let tenant_str = input.tenant.unwrap_or(DEFAULT_TENANT);
    if tenant_str.is_empty() {
        anyhow::bail!("tenant must not be empty");
    }
    if input.vm_name.is_empty() {
        anyhow::bail!("vm_name must not be empty");
    }
    if input.image_sha256.len() != 64 {
        anyhow::bail!(
            "image_sha256 must be a 64-character lowercase hex digest, got {} chars",
            input.image_sha256.len()
        );
    }
    if let Some(kernel) = input.kernel_sha256
        && kernel.len() != 64
    {
        anyhow::bail!(
            "kernel_sha256 must be a 64-character lowercase hex digest, got {} chars",
            kernel.len()
        );
    }
    let intent = input.intent.unwrap_or(DEFAULT_INTENT);
    if intent.is_empty() {
        anyhow::bail!("intent must not be empty");
    }

    let network_policy = policy_ref(input.network_policy_ref);
    let fs_policy = fs_policy_ref(input.fs_policy_ref);
    let egress_policy = policy_ref(input.egress_policy_ref);
    let tool_policy = policy_ref(input.tool_policy_ref);
    let admission_profile = admission_profile(
        input,
        intent,
        &network_policy,
        &fs_policy,
        &egress_policy,
        &tool_policy,
    );
    let mut audit_labels = audit_labels_for_profile(&admission_profile);
    // Caller labels fill additional keys; profile-derived keys stay authoritative.
    for (k, v) in &input.audit_labels {
        audit_labels.entry(k.clone()).or_insert_with(|| v.clone());
    }

    let resources = Resources {
        cpus: input.cpus.max(1),
        mem_mib: input.mem_mib.max(64),
        disk_mib: input.disk_mib,
        timeouts: TimeoutSpec {
            boot_secs: input.boot_timeout_secs.max(1),
            // The wall-clock bound has one author — the grant. This is its
            // projection into the plan's older encoding, and the only write of
            // the field anywhere; admission refuses a plan whose two encodings
            // disagree rather than choosing between them.
            exec_secs: mvm_contract::grants::projection::exec_secs_from_grants(
                input
                    .grants
                    .as_ref()
                    .unwrap_or(&mvm_contract::grants::Grants::default()),
            ),
        },
    };

    let image = SignedImageRef {
        name: input.image_name.to_string(),
        sha256: input.image_sha256.to_string(),
        cosign_bundle: input.image_cosign_bundle.map(str::to_string),
        // The CLI only ever synthesizes plans for images that carry an
        // entrypoint (the SDK's compile gate refuses to produce one
        // without). The supervisor's admission gate rejects
        // entrypoint_present == false as defense in depth.
        entrypoint_present: true,
    };

    let environment = input.kernel_sha256.map(|kernel_sha256| EnvironmentRef {
        kernel_sha256: kernel_sha256.to_string(),
    });

    let mut plan = ExecutionPlan {
        environment,
        build_provenance: Default::default(),
        snapshot_at: Default::default(),
        network_mode: input.network_mode,
        network_limits: Default::default(),
        ingress: input.ingress.clone(),
        schema_version: SCHEMA_VERSION,
        // Placeholder — overwritten below with the content-address once every
        // load-bearing field is set. The derivation excludes `plan_id`, so this
        // seed value never influences the result.
        plan_id: PlanId(String::new()),
        plan_version: 1,
        tenant: TenantId(tenant_str.to_string()),
        workload: WorkloadId(input.vm_name.to_string()),
        runtime_profile: RuntimeProfileRef(input.backend_name.to_string()),
        image,
        resources,
        grants: input.grants.clone(),
        admission_profile,
        network_policy,
        fs_policy,
        secrets: input.secrets.clone(),
        egress_policy,
        redaction: input.redaction.clone(),
        reversible_replacement: input.reversible_replacement.clone(),
        tool_policy,
        artifact_policy: ArtifactPolicy {
            capture_paths: Vec::new(),
            retention_days: 0,
        },
        caller_commitment: input.caller_commitment.clone(),
        audit_labels,
        key_rotation: KeyRotationSpec { interval_days: 0 },
        attestation: AttestationRequirement {
            mode: input.attestation_mode.clone(),
        },
        release_pin: None,
        post_run: PostRunLifecycle {
            destroy_on_exit: input.destroy_on_exit,
            snapshot_on_idle: false,
            idle_secs: 0,
        },
        valid_from: now,
        valid_until: now + Duration::minutes(VALIDITY_WINDOW_MINUTES),
        nonce,
        agent_verbs: input.agent_verbs.clone(),
        bundle: input.bundle_pin.clone(),
        // Populated by the caller when an `mvmctl up --from-workload-ir
        // <path>` invocation drove `install_app_deps` to a sealed
        // volume. `None` preserves claim 8 (the supervisor's
        // deps-volume gate is skipped).
        deps_volume: input.deps_volume.clone(),
        shares: input.shares.clone(),
        services: input.services.clone(),
        extensions: input.extensions.clone(),
        stream_edges: input.stream_edges.clone(),
        stream_retention: input.stream_retention,
        sdk_uses_sidecar: true,
    };

    plan.validate_ingress()?;

    // Content-address the finished plan. The fresh nonce makes this unique per
    // synthesis; the signature the caller applies next covers the derived id.
    plan.plan_id = crate::plan::compute_plan_id(&plan);
    Ok(plan)
}

/// Generate a fresh 128-bit nonce from `SysRng`. `crate::plan::Nonce`
/// wraps a 32-character lowercase hex string (i.e., 16 bytes = 128
/// bits) — match that here so the wire format roundtrips.
fn fresh_nonce() -> Nonce {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    Nonce::from_bytes(bytes)
}

fn policy_ref(value: Option<&str>) -> PolicyRef {
    PolicyRef(value.unwrap_or(DEFAULT_POLICY_REF).to_string())
}

fn fs_policy_ref(value: Option<&str>) -> FsPolicyRef {
    FsPolicyRef(value.unwrap_or(DEFAULT_POLICY_REF).to_string())
}

fn admission_profile(
    input: &SynthesisInput<'_>,
    intent: &str,
    network_policy: &PolicyRef,
    fs_policy: &FsPolicyRef,
    egress_policy: &PolicyRef,
    tool_policy: &PolicyRef,
) -> AdmissionProfile {
    let profile_id = format!("{intent}:{}", input.seccomp_tier);
    let event_prefix = input
        .audit_event_prefix
        .map(str::to_string)
        .unwrap_or_else(|| event_prefix_for_intent(intent));
    AdmissionProfile {
        id: profile_id,
        intent: WorkloadIntent(intent.to_string()),
        seccomp_tier: input.seccomp_tier,
        network_policy: network_policy.clone(),
        fs_policy: fs_policy.clone(),
        egress_policy: egress_policy.clone(),
        tool_policy: tool_policy.clone(),
        secret_release: input.secret_release,
        audit: AuditTaxonomy {
            event_prefix,
            required_labels: vec![
                "intent".to_string(),
                "admission_profile".to_string(),
                "seccomp_tier".to_string(),
            ],
        },
    }
}

fn event_prefix_for_intent(intent: &str) -> String {
    match intent {
        DEFAULT_INTENT => DEFAULT_AUDIT_EVENT_PREFIX.to_string(),
        "code:execute" => "execution.code".to_string(),
        "agent:web-research" => "agent.web".to_string(),
        "deploy:publish" => "deploy.release".to_string(),
        other => other.replace(':', "."),
    }
}

fn audit_labels_for_profile(profile: &AdmissionProfile) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("intent".to_string(), profile.intent.0.clone()),
        ("admission_profile".to_string(), profile.id.clone()),
        ("seccomp_tier".to_string(), profile.seccomp_tier.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(vm_name: &str) -> SynthesisInput<'_> {
        SynthesisInput {
            grants: None,
            kernel_sha256: None,
            network_mode: NetworkMode::default(),
            ingress: Vec::new(),
            vm_name,
            tenant: None,
            backend_name: "firecracker",
            image_name: "myimage",
            image_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: None,
            cpus: 2,
            mem_mib: 512,
            disk_mib: 0,
            boot_timeout_secs: 60,
            destroy_on_exit: false,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: crate::policy::RedactionPolicy::default(),
            reversible_replacement: crate::policy::ReversibleReplacementPolicy::default(),
            caller_commitment: None,
            audit_labels: Default::default(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
            stream_retention: Default::default(),
            attestation_mode: AttestationMode::Noop,
        }
    }

    #[test]
    fn carries_cli_resource_overrides() {
        let mut inp = input("myvm");
        inp.cpus = 4;
        inp.mem_mib = 2048;
        inp.boot_timeout_secs = 120;
        inp.grants = Some(mvm_contract::grants::Grants {
            wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: core::num::NonZeroU32::new(600).expect("nonzero"),
            }),
            ..Default::default()
        });
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.cpus, 4);
        assert_eq!(plan.resources.mem_mib, 2048);
        assert_eq!(plan.resources.timeouts.boot_secs, 120);
        assert_eq!(plan.resources.timeouts.exec_secs, 600);
    }

    #[test]
    fn rejects_a_kernel_digest_that_is_not_sha256_length() {
        let mut inp = input("myvm");
        let kernel = "a".repeat(63);
        inp.kernel_sha256 = Some(&kernel);

        let err = synthesize_plan(&inp).expect_err("short kernel digests must be refused");
        assert!(err.to_string().contains("kernel_sha256"));
    }

    #[test]
    fn defaults_tenant_to_local() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.tenant.0, DEFAULT_TENANT);
    }

    #[test]
    fn honors_explicit_tenant_override() {
        let mut inp = input("myvm");
        inp.tenant = Some("acme");
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.tenant.0, "acme");
    }

    #[test]
    fn workload_is_vm_name_verbatim() {
        let plan = synthesize_plan(&input("my-special-vm")).unwrap();
        assert_eq!(plan.workload.0, "my-special-vm");
    }

    #[test]
    fn round_trips_through_serde() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let parsed: ExecutionPlan = serde_json::from_str(&json).expect("plan parses");
        assert_eq!(parsed, plan);
    }

    #[test]
    fn generates_unique_plan_id_per_call() {
        // Fresh nonce per synthesis ⇒ distinct content ⇒ distinct
        // content-address, even for byte-identical CLI input.
        let p1 = synthesize_plan(&input("myvm")).unwrap();
        let p2 = synthesize_plan(&input("myvm")).unwrap();
        assert_ne!(p1.plan_id, p2.plan_id);
    }

    #[test]
    fn plan_id_is_the_content_address_of_the_plan() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert!(
            plan.plan_id.0.starts_with("sha256:"),
            "content-addressed, not a UUID: {}",
            plan.plan_id.0
        );
        // The stored id equals the address recomputed from the plan body.
        assert_eq!(crate::plan::verify_plan_id(&plan), Ok(()));
        assert_eq!(plan.plan_id, crate::plan::compute_plan_id(&plan));
    }

    #[test]
    fn signing_does_not_perturb_the_content_address() {
        // The signature lives in the envelope, not the plan body, so the id a
        // verified plan carries is exactly the address of its content.
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let signed = crate::plan::sign_plan(&plan, &key, "host:test");
        let recovered =
            crate::plan::verify_plan(&signed, &[("host:test", &key.verifying_key())]).unwrap();
        assert_eq!(recovered.plan_id, plan.plan_id);
        assert_eq!(crate::plan::verify_plan_id(&recovered), Ok(()));
    }

    #[test]
    fn generates_unique_nonce_per_call() {
        let p1 = synthesize_plan(&input("myvm")).unwrap();
        let p2 = synthesize_plan(&input("myvm")).unwrap();
        assert_ne!(p1.nonce, p2.nonce);
    }

    #[test]
    fn nonce_is_32_hex_chars() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let hex = plan.nonce.as_hex();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn validity_window_is_default_10_minutes() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let elapsed = plan.valid_until - plan.valid_from;
        assert_eq!(elapsed.num_minutes(), VALIDITY_WINDOW_MINUTES);
    }

    #[test]
    fn enforces_minimum_cpus_of_one() {
        let mut inp = input("myvm");
        inp.cpus = 0;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.cpus, 1, "CPUs floor at 1");
    }

    #[test]
    fn enforces_minimum_memory_of_64mib() {
        let mut inp = input("myvm");
        inp.mem_mib = 0;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.mem_mib, 64, "memory floor at 64MiB");
    }

    #[test]
    fn rejects_empty_vm_name() {
        let err = synthesize_plan(&input("")).unwrap_err();
        assert!(err.to_string().contains("vm_name"));
    }

    #[test]
    fn rejects_empty_tenant() {
        let mut inp = input("myvm");
        inp.tenant = Some("");
        let err = synthesize_plan(&inp).unwrap_err();
        assert!(err.to_string().contains("tenant"));
    }

    #[test]
    fn rejects_wrong_length_sha256() {
        let mut inp = input("myvm");
        inp.image_sha256 = "deadbeef";
        let err = synthesize_plan(&inp).unwrap_err();
        assert!(err.to_string().contains("64-character"));
    }

    #[test]
    fn defaults_attestation_to_noop_and_no_release_pin() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.attestation.mode, AttestationMode::Noop);
        assert!(plan.release_pin.is_none());
    }

    #[test]
    fn carries_explicit_attestation_mode_into_the_plan() {
        let mut input = input("attested-vm");
        input.attestation_mode = AttestationMode::Tpm2;

        let plan = synthesize_plan(&input).expect("explicit attestation mode synthesizes");

        assert_eq!(plan.attestation.mode, AttestationMode::Tpm2);
    }

    #[test]
    fn all_policy_refs_default_to_local_default() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.network_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.fs_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.egress_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.tool_policy.0, DEFAULT_POLICY_REF);
    }

    #[test]
    fn admission_profile_binds_default_intent_to_controls() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.admission_profile.intent.0, DEFAULT_INTENT);
        assert_eq!(
            plan.admission_profile.seccomp_tier,
            PlanSeccompTier::Standard
        );
        assert_eq!(plan.admission_profile.network_policy, plan.network_policy);
        assert_eq!(plan.admission_profile.fs_policy, plan.fs_policy);
        assert_eq!(plan.admission_profile.egress_policy, plan.egress_policy);
        assert_eq!(plan.admission_profile.tool_policy, plan.tool_policy);
        assert_eq!(
            plan.admission_profile.secret_release,
            SecretReleasePolicy::None
        );
        assert_eq!(
            plan.admission_profile.audit.event_prefix,
            DEFAULT_AUDIT_EVENT_PREFIX
        );
        assert_eq!(plan.audit_labels["intent"], DEFAULT_INTENT);
        assert_eq!(
            plan.audit_labels["admission_profile"],
            plan.admission_profile.id
        );
        assert_eq!(plan.audit_labels["seccomp_tier"], "standard");
    }

    #[test]
    fn admission_profile_honors_intent_bound_overrides() {
        let mut inp = input("myvm");
        inp.intent = Some("agent:web-research");
        inp.seccomp_tier = PlanSeccompTier::Network;
        inp.network_policy_ref = Some("acme:web-agent");
        inp.fs_policy_ref = Some("acme:web-agent");
        inp.egress_policy_ref = Some("acme:web-agent");
        inp.tool_policy_ref = Some("acme:web-agent");
        inp.secret_release = SecretReleasePolicy::PlanBound;

        let plan = synthesize_plan(&inp).unwrap();

        assert_eq!(plan.admission_profile.intent.0, "agent:web-research");
        assert_eq!(plan.admission_profile.id, "agent:web-research:network");
        assert_eq!(
            plan.admission_profile.seccomp_tier,
            PlanSeccompTier::Network
        );
        assert_eq!(plan.network_policy.0, "acme:web-agent");
        assert_eq!(plan.admission_profile.network_policy.0, "acme:web-agent");
        assert_eq!(
            plan.admission_profile.secret_release,
            SecretReleasePolicy::PlanBound
        );
        assert_eq!(plan.admission_profile.audit.event_prefix, "agent.web");
        assert_eq!(plan.audit_labels["intent"], "agent:web-research");
        assert_eq!(plan.audit_labels["seccomp_tier"], "network");
    }

    #[test]
    fn synthesized_plan_carries_secret_bindings() {
        let mut inp = input("myvm");
        inp.secret_release = SecretReleasePolicy::PlanBound;
        inp.secrets = vec![SecretBinding {
            name: "API_KEY".into(),
            source: crate::plan::SecretSource::Keystore {
                address: "api-key".into(),
            },
        }];
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.secrets, inp.secrets);
    }

    #[test]
    fn synthesized_plan_carries_redaction_profiles() {
        use crate::policy::{
            EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile,
        };
        let mut inp = input("myvm");
        inp.redaction = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "api.openai.com".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    names: NameMode::Redact,
                    ..Default::default()
                },
            }],
        };
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.redaction.profiles.len(), 1);
        assert_eq!(plan.redaction.profiles[0].host, "api.openai.com");
    }

    #[test]
    fn schema_version_is_pinned() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn without_deps_volume_plan_carries_none() {
        // Claim-8 preservation guard: when the caller doesn't pin a
        // deps volume, the plan carries `deps_volume = None` and the
        // supervisor's admission path skips the gate.
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert!(plan.deps_volume.is_none());
    }

    #[test]
    fn with_deps_volume_plan_carries_binding_verbatim() {
        // `mvmctl up`'s install pipeline yielded an `InstallResult`;
        // the caller turns it into a `DepsVolumeBinding` and threads it
        // through synthesis. The plan field must round-trip the volume
        // + manifest hashes verbatim so the supervisor's verifier
        // re-derives them against the on-disk volume.
        let volume_hash = "a".repeat(64);
        let manifest_sha256 = "b".repeat(64);
        let binding = DepsVolumeBinding::new(&volume_hash, &manifest_sha256).expect("binding");
        let mut inp = input("myvm");
        inp.deps_volume = Some(binding.clone());
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.deps_volume, Some(binding));
    }

    #[test]
    fn deps_volume_round_trips_through_serde() {
        let binding = DepsVolumeBinding::new("a".repeat(64), "b".repeat(64)).expect("binding");
        let mut inp = input("myvm");
        inp.deps_volume = Some(binding.clone());
        let plan = synthesize_plan(&inp).unwrap();
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let parsed: ExecutionPlan = serde_json::from_str(&json).expect("plan parses");
        assert_eq!(parsed.deps_volume, Some(binding));
    }

    #[test]
    fn caller_audit_labels_merge_into_signed_plan() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("origin.descriptor".to_string(), "blake3:abc".to_string());
        // A reserved profile key the caller must NOT be able to override.
        labels.insert("intent".to_string(), "spoofed".to_string());
        let mut inp = input("vm");
        inp.audit_labels = labels;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.audit_labels["origin.descriptor"], "blake3:abc");
        // Profile-derived key wins over the caller's attempt.
        assert_ne!(plan.audit_labels["intent"], "spoofed");

        // The label survives the sign -> verify round-trip inside the signed bytes.
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let signed = crate::plan::sign_plan(&plan, &key, "host:test");
        let recovered =
            crate::plan::verify_plan(&signed, &[("host:test", &key.verifying_key())]).unwrap();
        assert_eq!(recovered.audit_labels["origin.descriptor"], "blake3:abc");
    }

    #[test]
    fn caller_commitment_survives_synthesis_and_plan_signature() {
        let commitment = crate::plan::CallerCommitment::from_bytes([0x42; 32]);
        let mut inp = input("vm");
        inp.caller_commitment = Some(commitment.clone());
        let plan = synthesize_plan(&inp).expect("plan synthesizes");
        assert_eq!(plan.caller_commitment, Some(commitment.clone()));

        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let signed = crate::plan::sign_plan(&plan, &key, "host:test");
        let recovered = crate::plan::verify_plan(&signed, &[("host:test", &key.verifying_key())])
            .expect("signed plan verifies");
        assert_eq!(recovered.caller_commitment, Some(commitment));
    }
}

#[cfg(test)]
mod synthesis_input_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = SynthesisInput::builder().build() else {
            panic!("an empty SynthesisInput builder must not build");
        };
        assert_eq!(err, BuilderError::missing("SynthesisInput", "vm_name"));
    }
}
