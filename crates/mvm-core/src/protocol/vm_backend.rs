//! Backend-agnostic VM lifecycle trait + the trait-coupled composite launch
//! configs.
//!
//! The DTO half — every backend-agnostic launch/status/capability/
//! standby-pool wire type, plus the pure cmdline codec functions —
//! lives in `mvm_contract::protocol::vm_backend` and is re-exported below so
//! every existing `crate::protocol::vm_backend::X` / `mvm_core::vm_backend::X`
//! path keeps resolving unchanged. The `VmBackend` trait and its
//! trait-coupled composite configs stay here: `VmStartConfig` is the
//! backend-facing launch config the trait's methods take directly;
//! `StandbyClaim` embeds `Option<VmStartConfig>` and so can't move without
//! it; `VerbGrantEnvelope` stays paired with its `anyhow`-based cmdline
//! codec (`encode_verb_grant_cmdline`/`decode_verb_grant_cmdline`), the same
//! itself lives in `mvm-contract`.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

pub use mvm_contract::protocol::capability_negotiation::{CapabilityAlternative, CapabilityGap};
pub use mvm_contract::protocol::resource_controls::{
    CpuControl, EnforcedGrants, EnforcedTier, ResourceControls, WallClockControl,
};
pub use mvm_contract::protocol::vm_backend::{
    BackendKind, BackendSecurityProfile, BalloonState, ClaimStatus, GuestChannelInfo,
    LayerCoverage, RequiredCapabilities, ReseedStatus, RuntimeSourceLaunchKind,
    RuntimeSourceRootStrategy, SnapshotCapability, StandbyCompat, StandbyError, StandbyHandle,
    StandbySpec, StandbyState, StartMode, VmCapabilities, VmExitStatus, VmFile, VmId, VmInfo,
    VmNetworkInfo, VmPortMapping, VmStatus, VmVolume, VmVolumeKind, WarmArtifactIdentity,
    WarmClaimOutcome, WarmClaimRefusal, WarmClaimTiming, WarmLaunchMode, WarmPrewarmSource,
    WarmServiceRequest, WarmServiceResponse, WarmStartError, WarmStartOutcome, clamp_vcpus,
    encode_egress_ca_cmdline, encode_secret_env_cmdline, encode_user_volumes_cmdline,
};

// ---------------------------------------------------------------------------
// VmStartConfig — backend-agnostic VM launch configuration
// ---------------------------------------------------------------------------

/// Backend-agnostic configuration describing *what* to run.
///
/// Callers build a `VmStartConfig` from CLI arguments and build output.
/// Each backend converts this into its own internal config type, filling
/// in backend-specific details (Firecracker: kernel path, TAP slot;
/// libkrun: bundled kernel extraction; HVF: per-port vsock listeners).
///
/// # Examples
///
/// ```ignore
/// let config = VmStartConfig {
///     name: "my-vm".into(),
///     rootfs_path: "/nix/store/.../rootfs.ext4".into(),
///     cpus: 2,
///     memory_mib: 512,
///     ..Default::default()
/// };
/// backend.start(&config)?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct VmStartConfig {
    /// VM name (user-provided or auto-generated).
    pub name: String,
    /// Stable registered-template identity for warm-parent compatibility.
    ///
    /// `None` is reserved for image-agnostic launches. A warm parent carrying
    /// a template identity may only be claimed by a child of that same
    /// template; filesystem paths are not identities and must not be used for
    /// this comparison.
    pub template_id: Option<String>,
    /// Absolute path to the root filesystem (ext4 image).
    pub rootfs_path: String,
    /// When set, boot from a read-only **virtiofs root** serving this host
    /// directory (the unpacked+injected OCI tree) instead of a block `rootfs_path`
    /// — the Plan-223 dev-tier boot on a virtiofs-capable backend. The run-path
    /// tier gate sets this only for non-prod, non-sealed dev workloads; other
    /// backends/tiers leave it `None` and use `rootfs_path`.
    pub virtiofs_root: Option<String>,
    /// Absolute path to the kernel image (Firecracker needs this; others may ignore).
    pub kernel_path: Option<String>,
    /// Absolute path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Absolute path to the dm-verity Merkle hash sidecar.
    /// Present when the flake was built with `verifiedBoot = true`
    /// (the production default). Must be paired with `roothash`.
    /// Backends without verity support may ignore both.
    pub verity_path: Option<String>,
    /// 64-char lowercase-hex root hash from `rootfs.roothash`. Baked
    /// into the kernel cmdline as `dm-mod.create=`.
    pub roothash: Option<String>,
    /// Absolute path to the mvm runtime overlay ext4. When all three of
    /// `runtime_overlay_path`, `runtime_overlay_verity_path`,
    /// and `runtime_overlay_roothash` are `Some`, the backend
    /// attaches the overlay as a second virtio-blk drive at
    /// `/dev/vdc` and threads `mvm.runtime_roothash=<hex>` into
    /// the kernel cmdline so `mvm-verity-init` (PID 1) sets up the
    /// second dm-verity target and bind-mounts it at
    /// `/sysroot/mvm/runtime`. All three `None` ⇒ legacy boot path
    /// (rootfs verity only).
    pub runtime_overlay_path: Option<String>,
    /// Absolute path to the mvm runtime overlay verity sidecar. Paired
    /// with `runtime_overlay_path` + `runtime_overlay_roothash`; the
    /// backend attaches it as the fourth virtio-blk drive at
    /// `/dev/vdd`.
    pub runtime_overlay_verity_path: Option<String>,
    /// 64-char lowercase-hex root hash for the runtime overlay. Baked
    /// into the kernel cmdline as `mvm.runtime_roothash=<hex>`.
    pub runtime_overlay_roothash: Option<String>,
    /// Resolved runtime-overlay artifact version for this boot. Persisted into
    /// runtime metadata so lifecycle operations can reason about the exact
    /// overlay the VM booted with rather than consulting mutable cache state.
    pub runtime_overlay_version: Option<String>,
    /// Nix store revision hash.
    pub revision_hash: String,
    /// Original flake reference (for display / status).
    pub flake_ref: String,
    /// Flake profile name (e.g. "worker", "gateway").
    pub profile: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// The CPU bound this launch was admitted under, if any.
    ///
    /// A different control from [`cpus`](Self::cpus), and not a refinement of
    /// it: the vCPU count is how many processors the guest sees, while this is
    /// the share of host CPU time the whole VM may consume. Four vCPUs under a
    /// 1.5-core share is a legitimate, common shape.
    ///
    /// Carried on the launch config rather than applied after `start` because a
    /// backend has to wrap its own spawn for the per-VM process to be *born*
    /// bounded — see [`crate::cpu_scope`]. `None` is uncapped.
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
    /// Memory cap in MiB. The guest may not allocate beyond this. When
    /// [`mem_initial_mib`](Self::mem_initial_mib) is `None`, this is
    /// also the host-committed amount at boot (the historical mvm
    /// shape). When `mem_initial_mib` is `Some`, this becomes a cap
    /// rather than a commitment — see that field's docs.
    pub memory_mib: u32,
    /// Optional initial host commitment in MiB, opting the workload
    /// into virtio-balloon elasticity. When `Some(n)`, the backend
    /// creates a virtio-balloon device pre-inflated to
    /// `memory_mib - n` MiB so the host only commits `n` MiB at boot;
    /// the host-side reclaim controller adjusts the balloon over the
    /// VM's life. Must satisfy `0 < n <= memory_mib`. When `None`,
    /// no balloon is attached and the full `memory_mib` is committed
    /// at boot (backward-compatible default).
    pub mem_initial_mib: Option<u32>,
    /// Declared port mappings (host:guest) for forwarding and guest config.
    pub ports: Vec<VmPortMapping>,
    /// Extra volumes to mount in the guest.
    pub volumes: Vec<VmVolume>,
    /// Exact optional extension bindings re-verified during admission. Empty
    /// for every ordinary launch.
    pub extensions: Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>,
    /// Plan identity shared by all entries in `extensions`.
    pub extension_plan_id: Option<String>,
    /// Optional controller-backed typed broker services. Empty for ordinary
    /// launches; populated only after admission creates a host-only endpoint.
    pub service_proxies: Vec<mvm_contract::protocol::broker_control::ServiceProxyBinding>,
    /// Extra config files to make available to the guest.
    pub config_files: Vec<VmFile>,
    /// Secret files (written with restricted permissions).
    pub secret_files: Vec<VmFile>,
    /// Directory containing microvm.nix-lineage runner scripts (QEMU backend only).
    pub runner_dir: Option<String>,
    /// Tenant identifier from the admitted `ExecutionPlan`
    /// (`AdmittedPlan.plan.tenant.0`). When `Some`, the libkrun/HVF
    /// backends activate the gateway audit substrate (bridge factory +
    /// chain-signed audit emit). `None` keeps the legacy
    /// `run_supervisor` path for callers
    /// without admission (the builder VM bootstrap, session VMs,
    /// template restore).
    pub tenant_id: Option<String>,
    /// JSON-encoded `SignedExecutionPlan` envelope. Carried as a
    /// `String` so this wire type stays a serde seam with no typed
    /// coupling to `mvm_core::plan`. **The supervisor
    /// re-verifies the signature** before trusting any decoded field;
    /// the host is in the TCB but the supervisor still runs Ed25519
    /// verification. **Do not log this value** — the envelope may carry
    /// secret bindings, env vars, or policy refs that resolve to
    /// credentials.
    pub plan_json: Option<String>,
    /// JSON-encoded `PlanArtifact` (bundle pin)
    /// when `admitted.plan.bundle.is_some()`. `None` when the plan
    /// has no `.mvmpkg` pin (the common case). Same "do not log"
    /// rule as `plan_json`.
    pub bundle_json: Option<String>,
    /// Target warm-pool size. `0` (default) = feature off: no
    /// standbys, no idle RAM, no control UDS, no behaviour change. A future
    /// Firecracker standby reads the same field (it's why this lives on the
    /// backend-agnostic config, not a libkrun-specific knob).
    pub warm_pool_size: u32,
    /// Effective egress policy for this VM, enforced identically across
    /// every workload backend (Firecracker nftables, libkrun/HVF gateway
    /// bridge). The mechanism is the per-backend enforcer; the policy and
    /// its observable deny/allow effect are the same value here.
    ///
    /// Defaults (via `#[derive(Default)]`) to `NetworkPolicy::deny_all()`,
    /// so any caller that omits the field keeps deny-by-default. Trusted
    /// infrastructure that genuinely needs egress (the Stage-0 builder VM,
    /// dev shells) sets this to `NetworkPolicy::unrestricted()` explicitly;
    /// it is never an implicit, backend-specific fallback.
    pub network_policy: crate::network_policy::NetworkPolicy,
    /// Pre-open the host-side interactive-console data-port range so a PTY can
    /// attach (`machine run -t`, `machine shell`, `up --console`). The
    /// per-port-UDS backends (libkrun, HVF) bind a static vsock port list at
    /// start and otherwise can't reach the agent's dynamic
    /// `CONSOLE_PORT_BASE + session_id` data port; Firecracker multiplexes
    /// every port over one UDS and ignores this. Off by default — set only
    /// for dev-accessible managed machines and `--console`. Claim 15's
    /// runtime profile + signed grant + the host `enforce_accessible_gate` still bar
    /// interactive access to a sealed prod guest regardless of this flag, so
    /// the extra listeners are inert there.
    pub dev_console: bool,
}

/// Envelope carried in the `mvm.verb_grant=<base64(JSON)>` kernel-cmdline token.
///
/// The host base64-encodes the JSON so the value is a single space/newline-free
/// token that `/proc/cmdline` round-trips without quoting. base64 rather than
/// hex because this is the largest token on the cmdline and the kernel silently
/// drops anything past `COMMAND_LINE_SIZE`. The guest decodes it, parses the
/// JSON with `deny_unknown_fields`, then passes the inner `VerbGrant` to
/// `pin_verb_grant` for signature verification before use.
///
/// `pubkey_hex` is the 32-byte Ed25519 verifying key in lowercase hex.
/// `plan_nonce_hex` is the `Nonce::as_hex()` of the plan nonce the grant was
/// issued under — the guest uses it as the `plan_nonce` argument to
/// `VerbGrant::verify`. Fixed-field-order struct: `serde_json::to_vec` output
/// is byte-deterministic with no external canonicalizer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct VerbGrantEnvelope {
    pub pubkey_hex: String,
    pub plan_nonce_hex: String,
    /// When present on a restore-time re-pin envelope, proves which pinned
    /// grant lineage the new grant is replacing. Boot-time cmdline envelopes
    /// leave both predecessor fields absent.
    pub predecessor_session_id: Option<String>,
    pub predecessor_plan_nonce_hex: Option<String>,
    pub grant: crate::plan::VerbGrant,
}

/// Encode a `VerbGrantEnvelope` as a single `mvm.verb_grant=<base64(JSON)>`
/// kernel-cmdline token. Returns `None` if `env.pubkey_hex` is empty (no
/// key ⇒ nothing to verify against) or if serialization fails.
///
/// base64 rather than hex: this envelope is by far the largest thing on the
/// guest cmdline, and the kernel silently drops everything past
/// `COMMAND_LINE_SIZE`. Hex doubles the payload; base64 costs ~4/3, which buys
/// back roughly a quarter of the whole budget. The standard alphabet is
/// space- and newline-free, so the token stays a single `/proc/cmdline` word,
/// and `=` padding is only ever trailing — the kernel splits a parameter on
/// its first `=`, and the guest captures to the next space.
pub fn encode_verb_grant_cmdline(env: &VerbGrantEnvelope) -> Option<String> {
    if env.pubkey_hex.is_empty() {
        return None;
    }
    let json = serde_json::to_vec(env).ok()?;
    Some(format!("mvm.verb_grant={}", B64.encode(&json)))
}

/// Decode the base64 value of a `mvm.verb_grant=` cmdline token (the part
/// after the first `=`) into a `VerbGrantEnvelope`. Returns `Err` on malformed
/// base64 or unknown JSON fields (fail-closed).
pub fn decode_verb_grant_cmdline(token_value_b64: &str) -> anyhow::Result<VerbGrantEnvelope> {
    let bytes = B64
        .decode(token_value_b64.trim())
        .map_err(|e| anyhow::anyhow!("malformed base64 verb-grant token: {e}"))?;
    let env: VerbGrantEnvelope = serde_json::from_slice(&bytes)?;
    Ok(env)
}

/// What to attach to a claimed standby — the workload-specific half (the admitted,
/// signed plan + rootfs + audit substrate). Backend-agnostic.
#[derive(Debug, Clone)]
pub struct StandbyClaim {
    /// Full launch config for backends whose "claim" step must still configure
    /// machine-local boot devices before starting vCPUs. Firecracker uses this
    /// to configure a prestarted daemon with the same kernel/initrd/rootfs,
    /// overlays, policy, ports, and drive files a cold boot would use. Existing
    /// supervisor-style backends consume the explicit claim fields below.
    pub start_config: Option<VmStartConfig>,
    /// Workload rootfs ext4.
    pub rootfs_path: String,
    pub tenant_id: String,
    pub audit_dir: std::path::PathBuf,
    pub gateway_audit_socket: std::path::PathBuf,
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// JSON-encoded signed `ExecutionPlan` envelope (claim 8).
    pub plan_json: String,
    /// JSON-encoded `PolicyBundle`, if any.
    pub bundle_json: Option<String>,
    /// The launcher's resolved bare egress policy, threaded so a warm-claimed
    /// standby enforces the SAME deny-by-default posture a cold boot would. The
    /// no-bundle bridge arm lowers this; without it a pool hit on a bundle-less
    /// admitted plan would silently widen to an allow-all (permissive) gate.
    pub network_policy: crate::network_policy::NetworkPolicy,
}

/// Backend-agnostic VM lifecycle trait.
///
/// Defines the minimal interface for starting, stopping, inspecting, and
/// listing VMs. All backends accept [`VmStartConfig`] which describes
/// *what* to run; each backend translates it into backend-specific actions.
///
/// This trait lives in `mvm-core` so it has no runtime dependencies.
/// Implementations live in `mvm` (Firecracker, Apple Container)
/// or backend-specific crates.
///
/// # Examples
///
/// ```ignore
/// use mvm_core::vm_backend::{VmBackend, VmStartConfig};
///
/// fn run_vm(backend: &impl VmBackend, config: &VmStartConfig) -> anyhow::Result<()> {
///     let id = backend.start(config)?;
///     println!("Started VM: {}", id);
///     backend.stop(&id)?;
///     Ok(())
/// }
/// ```
pub trait VmBackend: Send + Sync {
    /// Human-readable backend name (e.g., "firecracker", "hvf", "libkrun").
    fn name(&self) -> &str;

    /// The typed discriminant; branch on this, never on `name()`.
    fn kind(&self) -> BackendKind;

    /// Capabilities supported by this backend.
    fn capabilities(&self) -> VmCapabilities;

    /// Check `required` against this backend, naming a substitute for every
    /// capability it cannot serve.
    ///
    /// This is the uniform entry point for a caller holding a backend it did
    /// not choose — a library consumer, or any code behind `AnyBackend`. It
    /// answers in one call what the backend refuses *and* what to do instead,
    /// so a refusal is actionable without a table of per-backend lore.
    ///
    /// Not overridable: it is `capabilities()` and `kind()` composed, and a
    /// backend that could answer differently here than its own capability
    /// matrix says would be exactly the dishonest tier the backend ADR forbids.
    fn negotiate(&self, required: &RequiredCapabilities) -> Result<(), Vec<CapabilityGap>> {
        self.capabilities().negotiate(required, self.kind())
    }

    /// Apply `grants` to a running VM and report what was actually achieved.
    ///
    /// The default enforces nothing and says so. A backend that silently
    /// ignored grants while reporting success would produce a receipt
    /// asserting an enforcement that never happened, which is worse than
    /// having no control at all.
    fn apply_grants(
        &self,
        _id: &VmId,
        _grants: &mvm_contract::grants::Grants,
    ) -> Result<mvm_contract::protocol::resource_controls::EnforcedGrants> {
        Ok(mvm_contract::protocol::resource_controls::EnforcedGrants::all_declared())
    }

    /// Whether a warm claim transfers a resident paused VMM directly into the
    /// child, instead of restoring a saved-state bundle.
    fn supports_resident_handoff(&self) -> bool {
        false
    }

    /// Warm-start snapshot tier. This compatibility accessor reads the
    /// authoritative value in [`VmCapabilities`]; backend implementations
    /// should set `capabilities().snapshot_capability` instead of overriding
    /// this method. A raw substrate may implement a tier that its selectable
    /// workload runner deliberately does not expose.
    fn snapshot_capability(&self) -> SnapshotCapability {
        self.capabilities().snapshot_capability
    }

    /// Warm-start a VM, requesting at least the `requested` snapshot tier.
    ///
    /// Fails closed: if [`snapshot_capability`](Self::snapshot_capability)
    /// cannot satisfy `requested`, returns [`WarmStartError::Unsupported`] carrying a
    /// recovery hint — never a silent cold boot. When the tier
    /// admits the request but the backend wires no warm-start path, the
    /// default returns [`WarmStartError::Failed`] rather than fabricating a
    /// VM; a backend overrides this only when its selectable runner owns the
    /// complete recovery path.
    fn warm_start(
        &self,
        _config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<WarmStartOutcome, WarmStartError> {
        let available = self.snapshot_capability();
        if !available.satisfies(requested) {
            return Err(WarmStartError::Unsupported {
                requested,
                available,
                hint: format!(
                    "this backend warm-starts at the '{}' tier; re-run with that tier \
                     or `mvmctl up` for a cold boot",
                    available.label()
                ),
            });
        }
        Err(WarmStartError::Failed(format!(
            "{}: warm-start is not wired for this backend yet",
            self.name()
        )))
    }

    /// Does this backend support a prelaunched-supervisor standby pool?
    /// This compatibility accessor reads the authoritative value in
    /// [`VmCapabilities`]. Snapshot restore and standby remain separate
    /// recovery tiers.
    fn supports_standby_pool(&self) -> bool {
        self.capabilities().standby_pool
    }

    /// Spawn a prelaunched standby per `spec`, detached, blocked on its control UDS
    /// before any boot. Returns a [`StandbyHandle`] the pool records. Fail-closed:
    /// the default refuses so a backend opts in explicitly (mirrors [`warm_start`]).
    ///
    /// [`warm_start`]: Self::warm_start
    fn spawn_standby(
        &self,
        _spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Claim an idle standby: send its one-shot attach (the admitted signed plan +
    /// rootfs + audit substrate), which the supervisor re-verifies before boot.
    /// Returns the booted VM's [`VmId`]. Fail-closed default.
    fn claim_standby(
        &self,
        _handle: &StandbyHandle,
        _claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        Err(StandbyError::Unsupported {
            backend: self.name().to_string(),
        })
    }

    /// Start a new VM from the given configuration.
    ///
    /// Returns the [`VmId`] assigned to the running VM.
    /// Equivalent to [`start_with_mode`](Self::start_with_mode) with
    /// [`StartMode::Detached`] — preserved for back-compat with
    /// existing consumers + because Detached is the right default
    /// for the most common path (`mvmctl up`).
    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.start_with_mode(config, StartMode::Detached)
    }

    /// Host process that owns a running VM's address space, when the backend
    /// can identify it. The process may exit immediately after this call, so
    /// consumers must treat the PID as a point-in-time observation only.
    fn host_process_id(&self, _id: &VmId) -> Result<Option<u32>> {
        Ok(None)
    }

    /// Start a VM with explicit attach/detach semantics.
    ///
    /// See [`StartMode`] for the contract. The default impl bails —
    /// backends MUST override either this or [`start`](Self::start);
    /// the other gets the default-trampoline. Most production
    /// backends override this method (the more general one) and let
    /// `start` delegate.
    fn start_with_mode(&self, _config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        anyhow::bail!(
            "{}: start_with_mode is not implemented for this backend",
            self.name()
        )
    }

    /// Block until a VM exits and return its exit status.
    ///
    /// Only meaningful for VMs started with [`StartMode::Attached`]
    /// (or freshly attached via `reattach`, if/when
    /// that gets implemented). Backends that lack a wait surface
    /// (e.g., a detached daemon with no PID handle) return an error
    /// pointing at the limitation; the default impl bails with a
    /// reasonable message so consumers get a clear failure mode.
    fn wait(&self, _id: &VmId) -> Result<VmExitStatus> {
        anyhow::bail!(
            "{}: wait is not supported for this backend (or this VM is detached)",
            self.name()
        )
    }

    /// Convert an attached VM into a detached one without restarting it.
    ///
    /// Mirrors libkrun's `Sandbox::detach(self)` — disarms the
    /// SIGTERM safety net so the caller can exit without taking the
    /// VM down with it. After `detach`, `wait` is no longer
    /// meaningful (you'd have to re-attach via `start_with_mode`
    /// against an existing name).
    ///
    /// Backends that always run detached (Firecracker, libkrun in
    /// daemon mode) treat this as a no-op and return Ok. Backends
    /// that don't support it bail with a clear error.
    ///
    /// The default impl is a no-op + Ok — appropriate for backends
    /// that don't have an attached/detached split, since for them
    /// "detach" is the steady state.
    fn detach(&self, _id: &VmId) -> Result<()> {
        Ok(())
    }

    /// Stop a running VM.
    fn stop(&self, id: &VmId) -> Result<()>;

    /// Fast teardown for an *ephemeral* VM — a transient `run` / `machine run`
    /// guest whose command has already returned, so there is nothing to
    /// flush. Implementors may skip the graceful-shutdown grace and kill the
    /// VMM immediately. The default delegates to [`stop`](Self::stop), so
    /// backends without a dedicated fast path keep their graceful behavior.
    fn stop_transient(&self, id: &VmId) -> Result<()> {
        self.stop(id)
    }

    /// Stop all VMs managed by this backend.
    fn stop_all(&self) -> Result<()>;

    /// Pause the vCPUs of a running VM, leaving the VMM alive.
    ///
    /// Used by the orchestrator's sleep/wake path: pause → snapshot →
    /// resume, or pause → stop for a clean shutdown.
    ///
    /// Backends without pause/resume support — see
    /// [`VmCapabilities::pause_resume`] — return `Err`. Implementors
    /// MUST keep the capability flag and this method's behavior in
    /// sync: if `capabilities().pause_resume == true`, `pause` must
    /// be a real operation; if `false`, `pause` errors clearly.
    fn pause(&self, id: &VmId) -> Result<()>;

    /// Resume vCPUs previously paused with [`pause`](Self::pause).
    ///
    /// See [`pause`](Self::pause) for the contract.
    fn resume(&self, id: &VmId) -> Result<()>;

    /// Query the status of a specific VM.
    fn status(&self, id: &VmId) -> Result<VmStatus>;

    /// List all VMs managed by this backend.
    fn list(&self) -> Result<Vec<VmInfo>>;

    /// Retrieve log output from a VM.
    ///
    /// `lines` controls how many recent lines to return.
    /// `hypervisor` selects hypervisor logs vs guest console logs.
    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String>;

    /// Check whether the backend runtime is installed and available.
    fn is_available(&self) -> Result<bool>;

    /// Install or download the backend runtime (if supported).
    fn install(&self) -> Result<()>;

    /// Return network information for a running VM.
    ///
    /// Backends that don't support networking may return an error.
    fn network_info(&self, _id: &VmId) -> Result<VmNetworkInfo> {
        anyhow::bail!("{} does not provide network info", self.name())
    }

    /// Return guest communication channel info for a running VM.
    ///
    /// Backends that don't support guest communication may return an error.
    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        anyhow::bail!("{} does not provide guest channel info", self.name())
    }

    /// Set the virtio-balloon inflation target (in MiB).
    ///
    /// `target_inflate_mib` is the number of MiB the guest should
    /// hand back to the host. `0` deflates the balloon completely;
    /// `VmStartConfig::memory_mib` would (in principle) reclaim
    /// everything but is rejected by sensible backends since the
    /// guest needs *some* memory to function.
    ///
    /// Only meaningful when [`VmCapabilities::balloon`] is `true`
    /// **and** the VM was started with `VmStartConfig::mem_initial_mib`
    /// set — otherwise the backend never created a balloon device and
    /// this call has nothing to operate on.
    ///
    /// The default impl bails so backends that don't support balloon
    /// surface a clear error to the reclaim controller.
    fn balloon_set_target(&self, _id: &VmId, _target_inflate_mib: u32) -> Result<()> {
        anyhow::bail!(
            "{}: virtio-balloon is not supported by this backend",
            self.name()
        )
    }

    /// Read the current balloon state of a VM.
    ///
    /// Same support contract as
    /// [`balloon_set_target`](Self::balloon_set_target).
    fn balloon_state(&self, _id: &VmId) -> Result<BalloonState> {
        anyhow::bail!(
            "{}: virtio-balloon is not supported by this backend",
            self.name()
        )
    }

    /// Return the security profile for this backend.
    ///
    /// Each backend declares which of the seven CI-enforced claims hold,
    /// which Matryoshka layers it covers, and a tier label. `mvmctl doctor`
    /// renders this; `mvmctl run` uses it to emit a loud, suppressible
    /// banner whenever the active backend is not a microVM tier.
    ///
    /// The default impl returns a conservative "claims unknown" profile
    /// (all `DoesNotHold`, no layer coverage). All in-tree backends
    /// override this with an explicit declaration.
    fn security_profile(&self) -> BackendSecurityProfile {
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Unknown",
            notes: &[
                "Backend has not declared its security profile.",
                "Treat as untrusted until profile is explicit.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_standby_spec() -> StandbySpec {
        StandbySpec {
            id: "standby-x".into(),
            template_id: None,
            kernel_path: "/k/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 1024,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "ab".repeat(32),
            control_socket: "/p/standby-x/control.sock".into(),
            vm_state_dir: "/p/standby-x".into(),
            image_path: None,
            image_sha256: None,
            vsock_egress: false,
        }
    }

    fn sample_standby_claim() -> StandbyClaim {
        StandbyClaim {
            start_config: None,
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/g.sock".into(),
            gateway_events_socket: None,
            plan_json: "{}".into(),
            bundle_json: None,
            network_policy: crate::network_policy::NetworkPolicy::deny_all(),
        }
    }

    #[test]
    fn standby_pool_defaults_are_fail_closed() {
        // TierOnlyBackend opts into no standby pool — the trait defaults must refuse.
        let b = TierOnlyBackend(SnapshotCapability::DiskOnly);
        assert!(!b.supports_standby_pool());
        match b.spawn_standby(&sample_standby_spec()) {
            Err(StandbyError::Unsupported { backend }) => assert_eq!(backend, "tier-only"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
        match b.claim_standby(
            &StandbyHandle {
                id: "s".into(),
                template_id: None,
                control_socket: "/p/s.sock".into(),
                pid: 1,
                kernel_sha256: "a".repeat(64),
                vcpus: 2,
                mem_mib: 1024,
                binding_nonce: "ab".repeat(32),
                spawned_unix_secs: 1,
                state: StandbyState::Idle,
                image_sha256: None,
                parent_checkpoint: None,
                vsock_egress: false,
                preloaded_child_vm_name: None,
            },
            &sample_standby_claim(),
        ) {
            Err(StandbyError::Unsupported { backend }) => assert_eq!(backend, "tier-only"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn warm_pool_size_defaults_to_zero() {
        assert_eq!(VmStartConfig::default().warm_pool_size, 0);
    }

    // A backend that declares a tier but wires no warm-start operation —
    // exercises the trait's fail-closed default.
    struct TierOnlyBackend(SnapshotCapability);
    impl VmBackend for TierOnlyBackend {
        fn name(&self) -> &str {
            "tier-only"
        }
        fn kind(&self) -> BackendKind {
            BackendKind::Mock
        }
        fn capabilities(&self) -> VmCapabilities {
            VmCapabilities::default()
        }
        fn snapshot_capability(&self) -> SnapshotCapability {
            self.0
        }
        fn stop(&self, _id: &VmId) -> Result<()> {
            Ok(())
        }
        fn stop_all(&self) -> Result<()> {
            Ok(())
        }
        fn pause(&self, _id: &VmId) -> Result<()> {
            Ok(())
        }
        fn resume(&self, _id: &VmId) -> Result<()> {
            Ok(())
        }
        fn status(&self, _id: &VmId) -> Result<VmStatus> {
            Ok(VmStatus::Stopped)
        }
        fn list(&self) -> Result<Vec<VmInfo>> {
            Ok(vec![])
        }
        fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
            Ok(String::new())
        }
        fn is_available(&self) -> Result<bool> {
            Ok(true)
        }
        fn install(&self) -> Result<()> {
            Ok(())
        }
    }

    // Records whether `stop` was invoked, so we can assert the default
    // `stop_transient` delegates to it.
    struct RecordingStopBackend(std::sync::atomic::AtomicBool);
    impl VmBackend for RecordingStopBackend {
        fn name(&self) -> &str {
            "recording-stop"
        }
        fn kind(&self) -> BackendKind {
            BackendKind::Mock
        }
        fn capabilities(&self) -> VmCapabilities {
            VmCapabilities::default()
        }
        fn stop(&self, _id: &VmId) -> Result<()> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn stop_all(&self) -> Result<()> {
            Ok(())
        }
        fn pause(&self, _id: &VmId) -> Result<()> {
            Ok(())
        }
        fn resume(&self, _id: &VmId) -> Result<()> {
            Ok(())
        }
        fn status(&self, _id: &VmId) -> Result<VmStatus> {
            Ok(VmStatus::Stopped)
        }
        fn list(&self) -> Result<Vec<VmInfo>> {
            Ok(vec![])
        }
        fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
            Ok(String::new())
        }
        fn is_available(&self) -> Result<bool> {
            Ok(true)
        }
        fn install(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stop_transient_defaults_to_stop() {
        let b = RecordingStopBackend(std::sync::atomic::AtomicBool::new(false));
        b.stop_transient(&VmId("ephemeral".to_string())).unwrap();
        assert!(
            b.0.load(std::sync::atomic::Ordering::SeqCst),
            "the default stop_transient must delegate to stop for backends without a fast path"
        );
    }

    #[test]
    fn default_warm_start_fails_closed_on_over_request() {
        // DiskOnly backend, live-memory request → typed Unsupported, not a
        // silent cold boot. The hint must name a recovery action.
        let b = TierOnlyBackend(SnapshotCapability::DiskOnly);
        let cfg = VmStartConfig::default();
        match b.warm_start(&cfg, SnapshotCapability::LiveMemory) {
            Err(WarmStartError::Unsupported {
                requested,
                available,
                hint,
            }) => {
                assert_eq!(requested, SnapshotCapability::LiveMemory);
                assert_eq!(available, SnapshotCapability::DiskOnly);
                assert!(!hint.is_empty());
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn default_warm_start_is_unimplemented_when_tier_admits() {
        // Tier admits the request, but the default wires no operation — it
        // must fail closed (Failed), never fabricate a VmId.
        let b = TierOnlyBackend(SnapshotCapability::DiskOnly);
        let cfg = VmStartConfig::default();
        match b.warm_start(&cfg, SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Failed(_)) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn encode_verb_grant_cmdline_empty_pubkey_is_none() {
        use crate::plan::{Nonce, VerbGrant, VerbId};
        use chrono::{Duration, Utc};
        use ed25519_dalek::{Signer, SigningKey};

        let k = SigningKey::from_bytes(&[3u8; 32]);
        let nonce = Nonce::from_bytes([1u8; 16]);
        let now = Utc::now();
        let mut grant = VerbGrant {
            session_id: "sess-x".into(),
            plan_nonce: nonce.clone(),
            not_after: now + Duration::minutes(5),
            verbs: vec![VerbId::new("run-entrypoint").unwrap()],
            sig: vec![],
        };
        grant.sig = k.sign(&grant.signing_bytes()).to_bytes().to_vec();
        let env = VerbGrantEnvelope {
            pubkey_hex: String::new(),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        assert!(encode_verb_grant_cmdline(&env).is_none());
    }

    #[test]
    fn encode_verb_grant_cmdline_round_trips_as_single_token() {
        use crate::plan::{Nonce, VerbGrant, VerbId};
        use chrono::{Duration, Utc};
        use ed25519_dalek::{Signer, SigningKey};

        let k = SigningKey::from_bytes(&[7u8; 32]);
        let nonce = Nonce::from_bytes([2u8; 16]);
        let now = Utc::now();
        let mut grant = VerbGrant {
            session_id: "sess-rt".into(),
            plan_nonce: nonce.clone(),
            not_after: now + Duration::minutes(10),
            verbs: vec![
                VerbId::new("run-entrypoint").unwrap(),
                VerbId::new("ping").unwrap(),
            ],
            sig: vec![],
        };
        grant.sig = k.sign(&grant.signing_bytes()).to_bytes().to_vec();

        let pubkey_hex: String = k
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let plan_nonce_hex = nonce.as_hex().to_string();

        let env = VerbGrantEnvelope {
            pubkey_hex: pubkey_hex.clone(),
            plan_nonce_hex: plan_nonce_hex.clone(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: grant.clone(),
        };

        let token = encode_verb_grant_cmdline(&env).unwrap();
        assert!(token.starts_with("mvm.verb_grant="));
        // Single cmdline token — no spaces or newlines.
        assert!(!token.contains(' ') && !token.contains('\n'));

        let encoded_value = token.strip_prefix("mvm.verb_grant=").unwrap();
        let decoded = decode_verb_grant_cmdline(encoded_value).unwrap();

        assert_eq!(decoded.pubkey_hex, pubkey_hex);
        assert_eq!(decoded.plan_nonce_hex, plan_nonce_hex);
        assert_eq!(decoded.grant.session_id, grant.session_id);
        assert_eq!(decoded.grant.verbs, grant.verbs);
        assert_eq!(decoded.grant.sig, grant.sig);
    }

    #[test]
    fn decode_rejects_malformed_base64() {
        // `!` is outside the standard alphabet. (Note `zzzz` would *not* do:
        // those are legal base64 characters and would fail later, at JSON.)
        assert!(
            decode_verb_grant_cmdline("!!!!").is_err(),
            "non-base64 input must be rejected"
        );
    }

    #[test]
    fn decode_rejects_unknown_field() {
        // Build valid JSON with an extra field; deny_unknown_fields must reject it.
        let bad = r#"{"pubkey_hex":"aa","plan_nonce_hex":"bb","grant":{},"extra":"bad"}"#;
        let result = decode_verb_grant_cmdline(&B64.encode(bad));
        assert!(result.is_err(), "unknown field must be rejected");
    }
}
