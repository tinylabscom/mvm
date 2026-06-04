use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// VmStartConfig — backend-agnostic VM launch configuration
// ---------------------------------------------------------------------------

/// Backend-agnostic configuration describing *what* to run.
///
/// Callers build a `VmStartConfig` from CLI arguments and build output.
/// Each backend converts this into its own internal config type, filling
/// in backend-specific details (Firecracker: kernel path, TAP slot;
/// Apple Container: VZ block attachment; Docker: container image).
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
    /// Absolute path to the root filesystem (ext4 image).
    pub rootfs_path: String,
    /// Absolute path to the kernel image (Firecracker needs this; others may ignore).
    pub kernel_path: Option<String>,
    /// Absolute path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Absolute path to the dm-verity Merkle hash sidecar.
    /// Present when the flake was built with `verifiedBoot = true`
    /// (the production default per ADR-002 §W3). Must be paired with
    /// `roothash`. Backends without verity support may ignore both.
    pub verity_path: Option<String>,
    /// 64-char lowercase-hex root hash from `rootfs.roothash`. Baked
    /// into the kernel cmdline as `dm-mod.create=`. ADR-002 §W3.2.
    pub roothash: Option<String>,
    /// Plan 74 W1.4b — absolute path to the mvm runtime overlay
    /// ext4 (ADR-051). When all three of
    /// `runtime_overlay_path`, `runtime_overlay_verity_path`,
    /// and `runtime_overlay_roothash` are `Some`, the backend
    /// attaches the overlay as a second virtio-blk drive at
    /// `/dev/vdc` and threads `mvm.runtime_roothash=<hex>` into
    /// the kernel cmdline so `mvm-verity-init` (the W1.4b.3b.2
    /// PID 1) sets up the second dm-verity target and
    /// bind-mounts it at `/sysroot/mvm/runtime`. All three
    /// `None` ⇒ legacy boot path (rootfs verity only).
    pub runtime_overlay_path: Option<String>,
    /// Plan 74 W1.4b — absolute path to the mvm runtime overlay
    /// verity sidecar (ADR-051). Paired with
    /// `runtime_overlay_path` + `runtime_overlay_roothash`; the
    /// backend attaches it as the fourth virtio-blk drive at
    /// `/dev/vdd`.
    pub runtime_overlay_verity_path: Option<String>,
    /// Plan 74 W1.4b — 64-char lowercase-hex root hash for the
    /// runtime overlay (ADR-051). Baked into the kernel cmdline
    /// as `mvm.runtime_roothash=<hex>`.
    pub runtime_overlay_roothash: Option<String>,
    /// Nix store revision hash.
    pub revision_hash: String,
    /// Original flake reference (for display / status).
    pub flake_ref: String,
    /// Flake profile name (e.g. "worker", "gateway").
    pub profile: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
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
    /// Extra config files to make available to the guest.
    pub config_files: Vec<VmFile>,
    /// Secret files (written with restricted permissions).
    pub secret_files: Vec<VmFile>,
    /// Directory containing microvm.nix runner scripts (microvm.nix backend only).
    pub runner_dir: Option<String>,
    /// Plan 102 Phase 3c — tenant identifier from the admitted
    /// `ExecutionPlan` (`AdmittedPlan.plan.tenant.0`). When `Some`,
    /// the libkrun/Vz backends activate the gateway audit substrate
    /// (bridge factory + chain-signed audit emit per ADR-058).
    /// `None` keeps the legacy `run_supervisor` path for callers
    /// without admission (`mvmctl dev` Stage 0 builder, session VMs,
    /// template restore).
    pub tenant_id: Option<String>,
    /// Plan 102 Phase 3c — JSON-encoded `SignedExecutionPlan`
    /// envelope. Carried as a `String` so `mvm-core` does not depend
    /// on `mvm-plan` (avoids the `mvm-plan → mvm-libkrun → mvm-core`
    /// cycle). **The supervisor re-verifies the signature** before
    /// trusting any decoded field (ADR-041 §"Verification at
    /// admission"); the host is in the TCB per ADR-002 but the
    /// supervisor still runs Ed25519 verification. **Do not log
    /// this value** — the envelope may carry secret bindings, env
    /// vars, or policy refs that resolve to credentials.
    pub plan_json: Option<String>,
    /// Plan 102 Phase 3c — JSON-encoded `PlanArtifact` (bundle pin)
    /// when `admitted.plan.bundle.is_some()`. `None` when the plan
    /// has no `.mvmpkg` pin (the common case). Same "do not log"
    /// rule as `plan_json`.
    pub bundle_json: Option<String>,
}

/// A host:guest port mapping, backend-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmPortMapping {
    pub host: u16,
    pub guest: u16,
}

/// Which hypervisor device a [`VmVolume`] / `RuntimeVolume` maps to.
///
/// Default is `Disk`: the legacy `RuntimeVolume` carrier (and any
/// runtime-config file written before this field existed) means a disk
/// image. A live directory share is the new case and is always set
/// explicitly, so defaulting to `Disk` keeps old configs correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmVolumeKind {
    /// Persistent ext4 disk image attached as a virtio-blk device.
    #[default]
    Disk,
    /// Live host-directory share over virtio-fs (two-way unless read-only).
    DirShare,
}

/// A volume to mount in the guest, backend-agnostic.
#[derive(Debug, Clone, Default)]
pub struct VmVolume {
    /// Host-side path or identifier.
    pub host: String,
    /// Mount point inside the guest.
    pub guest: String,
    /// Size hint (e.g. "1G"). Used as the sparse cap for a `Disk`; a
    /// `DirShare` ignores it.
    pub size: String,
    /// Mark the underlying device read-only at the hypervisor level.
    pub read_only: bool,
    /// Directory share (virtio-fs) vs disk image (virtio-blk). Backends
    /// attach the right device per kind rather than inferring from `size`.
    pub kind: VmVolumeKind,
    /// `:enc` — route a `Disk` volume through in-guest encryption
    /// (Plan 101). Fails closed at launch until that lands; never
    /// silently plaintext. Always false for a `DirShare`.
    pub encrypted: bool,
}

/// Encode user volumes as a kernel-cmdline parameter the guest init
/// (`mvm-host-vm-init`) parses to mount each at its requested path.
///
/// Format (one entry per volume, `;`-separated):
/// `mvm.uvols=<tag>:<hex(guest_path)>:<ro|rw>:<fs|blk>`
/// where `tag` is `uvol{idx}` — the virtio-fs tag / virtio-blk id the
/// backend assigned for the volume at the same index. The guest path is
/// hex-encoded so an arbitrary path can't collide with the cmdline's
/// space / `:` / `;` delimiters. Returns `None` for an empty volume set
/// so no parameter is appended.
///
/// The decoder lives in `mvm-host-vm-init` (kept dependency-free for its
/// size budget); both sides are unit-tested against this exact format.
pub fn encode_user_volumes_cmdline(volumes: &[VmVolume]) -> Option<String> {
    if volumes.is_empty() {
        return None;
    }
    let mut entries = Vec::with_capacity(volumes.len());
    for (idx, v) in volumes.iter().enumerate() {
        let kind = match v.kind {
            VmVolumeKind::DirShare => "fs",
            VmVolumeKind::Disk => "blk",
        };
        let mode = if v.read_only { "ro" } else { "rw" };
        let hexpath: String = v.guest.bytes().map(|b| format!("{b:02x}")).collect();
        entries.push(format!("uvol{idx}:{hexpath}:{mode}:{kind}"));
    }
    Some(format!("mvm.uvols={}", entries.join(";")))
}

/// A file to inject into the guest (config or secret).
#[derive(Debug, Clone)]
pub struct VmFile {
    /// Filename inside the guest.
    pub name: String,
    /// File contents (inline).
    pub content: String,
    /// Unix permissions (octal). Config: 0o444, secrets: 0o400.
    pub mode: u32,
}

impl Default for VmFile {
    fn default() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            mode: 0o444,
        }
    }
}

// ---------------------------------------------------------------------------
// VmNetworkInfo — backend-reported network state
// ---------------------------------------------------------------------------

/// Network information for a running VM, reported by the backend.
///
/// Replaces hardcoded IPs (e.g. `172.16.0.2`) with backend-provided values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmNetworkInfo {
    /// IP address assigned to the guest.
    pub guest_ip: String,
    /// Gateway IP (host-side endpoint).
    pub gateway_ip: String,
    /// Subnet in CIDR notation (e.g. "172.16.0.0/24").
    pub subnet_cidr: String,
}

// ---------------------------------------------------------------------------
// GuestChannel — backend-agnostic guest communication
// ---------------------------------------------------------------------------

/// Describes how to connect to the guest agent for a given VM.
///
/// Firecracker and Apple Containers use vsock; Docker uses a unix socket
/// mounted as a volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuestChannelInfo {
    /// Vsock connection (Firecracker, Apple Container).
    Vsock {
        /// Context ID (Firecracker assigns per-VM; Apple Container auto-assigns).
        cid: u32,
        /// Port the guest agent listens on.
        port: u32,
    },
    /// Unix socket path (Docker — mounted as a volume in the container).
    UnixSocket {
        /// Path to the socket on the host.
        path: PathBuf,
    },
}

/// Unique identifier for a VM managed by a backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VmId(pub String);

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for VmId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VmId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Runtime status of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmStatus {
    /// VM exists but is not running.
    Stopped,
    /// VM is booting / initializing.
    Starting,
    /// VM is running and accepting work.
    Running,
    /// VM vCPUs are paused (Firecracker warm state).
    Paused,
    /// VM is in an error state.
    Failed { reason: String },
}

/// How the lifecycle of a freshly-started VM is bound to the caller.
///
/// Modeled after libkrun's `SpawnMode` (`Attached` vs `Detached`).
/// The two are orthogonal to *what* the VM runs — they control *how
/// long* it lives relative to the process that started it.
///
/// ## `Attached` (interactive default)
///
/// The VM lifecycle is bound to the calling process. If the caller
/// exits without explicitly detaching, the VM is sent SIGTERM. Use
/// for:
///
///   - `mvmctl run` followed by `mvmctl exec` in the same shell.
///   - `mvmctl dev` interactive sessions where the user expects the
///     VM to disappear when they Ctrl-C.
///   - Test harnesses that want deterministic teardown.
///
/// Pair with [`VmBackend::wait`] to block until the VM exits, and
/// [`VmBackend::detach`] to convert an attached VM into a detached
/// one without restarting it.
///
/// ## `Detached` (production / daemon default)
///
/// The VM survives the calling process. Use for:
///
///   - `mvmctl up` (background "up + run" model — the CLI returns,
///     the VM keeps running).
///   - Production agents (mvmd) that boot VMs and immediately move on.
///   - CI fixtures that boot once and run several phases against the
///     same long-lived VM.
///
/// Once detached, only `mvmctl down` (or the equivalent
/// [`VmBackend::stop`] call) terminates the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartMode {
    /// VM lifecycle bound to the calling process; SIGTERM on caller exit.
    Attached,
    /// VM survives caller exit; explicit stop required to terminate.
    Detached,
}

impl Default for StartMode {
    /// `Detached` is the safer default — the worst failure of a
    /// detached VM is "you have to clean it up later"; the worst
    /// failure of an attached VM is "your CI run abandoned a VM
    /// because the runner crashed before sending SIGTERM."
    fn default() -> Self {
        StartMode::Detached
    }
}

/// Result of a VM exiting (returned by [`VmBackend::wait`]).
///
/// Mirrors [`std::process::ExitStatus`] semantically but is
/// serializable + dyn-trait-friendly for the host-side IPC path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmExitStatus {
    /// Numeric exit code, when one was reported. None if the VM was
    /// terminated by signal or didn't expose a status.
    pub code: Option<i32>,
    /// True if the VM exited normally (i.e. through its entrypoint
    /// returning, not via signal or crash). Always `true` if
    /// `code == Some(_)`.
    pub success: bool,
}

impl VmExitStatus {
    /// A successful zero-exit-code status — used by backends that
    /// don't expose a real wait surface but want a sentinel value.
    pub const SUCCESS: Self = VmExitStatus {
        code: Some(0),
        success: true,
    };

    /// "Exited, but the exit code is not recoverable" — used by
    /// backends that observe a sandbox/VM has gone away (e.g. by
    /// polling `list()`) without retaining the lifecycle handle that
    /// would carry the real exit code. `success: false` because the
    /// caller cannot assume zero; `code: None` because we don't have
    /// one to report.
    ///
    /// Distinct from `SUCCESS` so audit / policy consumers can detect
    /// "backend reports unknown exit" and react (typically: treat as
    /// failure unless a corroborating signal says otherwise).
    pub const UNKNOWN: Self = VmExitStatus {
        code: None,
        success: false,
    };
}

/// Capabilities that a backend may or may not support.
///
/// Used by consumers to check what operations are available before
/// attempting them. For example, WASM backends won't support snapshots.
#[derive(Debug, Clone, Default)]
pub struct VmCapabilities {
    /// Can pause/resume vCPUs (Firecracker: yes, WASM: no).
    pub pause_resume: bool,
    /// Can create/restore memory snapshots (Firecracker: yes, Docker: checkpoints, WASM: no).
    pub snapshots: bool,
    /// Supports vsock guest communication (Firecracker: yes, others: typically no).
    pub vsock: bool,
    /// Supports TAP-based networking (Firecracker/Docker: yes, WASM: no).
    pub tap_networking: bool,
    /// Supports a virtio-balloon device with runtime inflate/deflate.
    /// When `true`, [`VmBackend::balloon_set_target`] is wired and the
    /// host-side reclaim controller can adjust guest commitment
    /// without rebooting the VM. cgroup-style memory limiting (Docker)
    /// is **not** a balloon and stays `false`.
    pub balloon: bool,
}

/// Snapshot of a VM's virtio-balloon state, returned by
/// [`VmBackend::balloon_state`].
///
/// All values are in MiB. The reclaim controller compares
/// `host_committed_mib` against host memory pressure to decide
/// whether to call [`VmBackend::balloon_set_target`] up or down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonState {
    /// The cap declared by the workload — equal to
    /// `VmStartConfig::memory_mib` at boot. Useful as the upper bound
    /// for `inflated_mib` (the balloon cannot inflate past this).
    pub max_mib: u32,
    /// Current balloon inflation, i.e. memory the guest has handed
    /// back to the host. Increases under host pressure; decreases
    /// when the guest needs the pages.
    pub inflated_mib: u32,
    /// Effective host commitment after subtracting the balloon —
    /// `max_mib - inflated_mib`. Tracked separately because some
    /// VMMs report it directly and the subtraction may not be
    /// perfectly exact across the wire.
    pub host_committed_mib: u32,
}

// ---------------------------------------------------------------------------
// BackendSecurityProfile — per-backend ADR-002 claim coverage
// ---------------------------------------------------------------------------

/// Status of a single ADR-002 security claim for a backend.
///
/// See ADR-002 §"The seven CI-enforced claims" for the claim definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// The claim holds for this backend; the CI gate enforces it.
    Holds,
    /// The claim does not apply to this backend (e.g. vsock-framing
    /// fuzzing for a backend that uses unix sockets instead of vsock).
    DoesNotApply,
    /// The claim does **not** hold for this backend — the security tier
    /// is reduced and `mvmctl doctor` flags it.
    DoesNotHold,
}

/// Coverage of the five Matryoshka trust layers (ADR-002 §"Trust layers").
///
/// `true` means the layer is enforced by hardware/software isolation under
/// this backend; `false` means the layer collapses into the host kernel
/// or another preceding layer (e.g. Docker has L1–L3 = false because it
/// shares the host kernel with the workload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayerCoverage {
    /// L1 — Host + hypervisor (KVM, VZ, HVF).
    pub l1_host_hypervisor: bool,
    /// L2 — VMM (Firecracker, Containerization, libkrun).
    pub l2_vmm: bool,
    /// L3 — Guest kernel (ephemeral, isolated).
    pub l3_guest_kernel: bool,
    /// L4 — Guest agent (uid 901 setpriv, no_new_privs).
    pub l4_guest_agent: bool,
    /// L5 — Workload (per-service uid, bounding-set drop, seccomp).
    pub l5_workload: bool,
}

impl LayerCoverage {
    /// All five layers enforced — the Tier 1 / Tier 2 shape.
    pub const fn all_layers() -> Self {
        Self {
            l1_host_hypervisor: true,
            l2_vmm: true,
            l3_guest_kernel: true,
            l4_guest_agent: true,
            l5_workload: true,
        }
    }

    /// Whether this backend provides hardware-isolated microVM execution
    /// (L1+L2+L3 all enforced). When `false`, the backend is a Tier 3
    /// shared-kernel container — `mvmctl run` emits a loud banner.
    pub const fn is_microvm(self) -> bool {
        self.l1_host_hypervisor && self.l2_vmm && self.l3_guest_kernel
    }
}

/// Per-backend declaration of ADR-002 security-claim coverage.
///
/// `mvmctl doctor` and `mvmctl run` consume this to render the active
/// backend's security posture. The seven claims are stored at indices
/// `0..7` (claim 1 = `claims[0]`):
///
/// 1. No host-fs access from a guest beyond explicit shares
/// 2. No guest binary can elevate to uid 0
/// 3. A tampered rootfs ext4 fails to boot
/// 4. The guest agent does not contain `do_exec` in production builds
/// 5. Vsock framing is fuzzed
/// 6. Pre-built dev image is hash-verified
/// 7. Cargo deps are audited on every PR
///
/// `notes` provides per-backend rationale shown in doctor output and is
/// where backends explain partial claims (e.g. "claim 3 partial — verified
/// boot for VZ-backed rootfs not yet wired up").
#[derive(Debug, Clone)]
pub struct BackendSecurityProfile {
    /// Status of claims 1..=7 (indexed 0..7).
    pub claims: [ClaimStatus; 7],
    /// Layer coverage in the Matryoshka model.
    pub layer_coverage: LayerCoverage,
    /// Human-readable security tier: `"Tier 1"`, `"Tier 2"`, `"Tier 3"`.
    pub tier: &'static str,
    /// Backend-specific rationale shown in doctor output.
    pub notes: &'static [&'static str],
}

impl BackendSecurityProfile {
    /// 1-indexed claim numbers (1..=7) that do not hold for this backend.
    pub fn dropped_claims(&self) -> Vec<u8> {
        self.claims
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, ClaimStatus::DoesNotHold))
            .map(|(i, _)| (i + 1) as u8)
            .collect()
    }

    /// 1-indexed claim numbers that don't apply to this backend (e.g.
    /// vsock-framing fuzzing for a unix-socket backend).
    pub fn na_claims(&self) -> Vec<u8> {
        self.claims
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, ClaimStatus::DoesNotApply))
            .map(|(i, _)| (i + 1) as u8)
            .collect()
    }
}

/// Summary info for a managed VM, returned by [`VmBackend::list`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    /// Backend-assigned VM identifier.
    pub id: VmId,
    /// Human-readable name.
    pub name: String,
    /// Current status.
    pub status: VmStatus,
    /// Guest IP address, if networking is configured.
    #[serde(default)]
    pub guest_ip: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Flake profile name (e.g. "worker", "gateway").
    #[serde(default)]
    pub profile: Option<String>,
    /// Nix store revision hash.
    #[serde(default)]
    pub revision: Option<String>,
    /// Original flake reference.
    #[serde(default)]
    pub flake_ref: Option<String>,
    /// Active port forwardings (host:guest).
    #[serde(default)]
    pub ports: Vec<VmPortMapping>,
}

/// Backend-agnostic VM lifecycle trait.
///
/// Defines the minimal interface for starting, stopping, inspecting, and
/// listing VMs. All backends accept [`VmStartConfig`] which describes
/// *what* to run; each backend translates it into backend-specific actions.
///
/// This trait lives in `mvm-core` so it has no runtime dependencies.
/// Implementations live in `mvm` (Firecracker, Apple Container)
/// or future crates (Docker).
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
    /// Human-readable backend name (e.g., "firecracker", "apple-container", "docker").
    fn name(&self) -> &str;

    /// Capabilities supported by this backend.
    fn capabilities(&self) -> VmCapabilities;

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
    /// (or freshly attached via [`reattach`](Self::reattach), if/when
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

    /// Stop all VMs managed by this backend.
    fn stop_all(&self) -> Result<()>;

    /// Pause the vCPUs of a running VM, leaving the VMM alive.
    ///
    /// Used by the orchestrator's sleep/wake path (mvmd Track I in the
    /// `what-do-we-need-deep-dolphin` plan): pause → snapshot → resume,
    /// or pause → stop for a clean shutdown.
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

    /// Return the ADR-002 security profile for this backend.
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

    #[test]
    fn test_vm_id_display() {
        let id = VmId("my-vm".to_string());
        assert_eq!(format!("{id}"), "my-vm");
    }

    #[test]
    fn encode_user_volumes_cmdline_empty_is_none() {
        assert!(encode_user_volumes_cmdline(&[]).is_none());
    }

    #[test]
    fn encode_user_volumes_cmdline_format() {
        let vols = vec![
            VmVolume {
                host: "/h/src".into(),
                guest: "/work2".into(),
                read_only: true,
                kind: VmVolumeKind::DirShare,
                ..Default::default()
            },
            VmVolume {
                host: "/h/d.img".into(),
                guest: "/data".into(),
                kind: VmVolumeKind::Disk,
                ..Default::default()
            },
        ];
        // "/work2" = 2f776f726b32, "/data" = 2f64617461
        assert_eq!(
            encode_user_volumes_cmdline(&vols).unwrap(),
            "mvm.uvols=uvol0:2f776f726b32:ro:fs;uvol1:2f64617461:rw:blk"
        );
        // No spaces — must be a single cmdline token.
        assert!(!encode_user_volumes_cmdline(&vols).unwrap().contains(' '));
    }

    #[test]
    fn test_vm_id_from_str() {
        let id: VmId = "test".into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn test_vm_id_from_string() {
        let id: VmId = String::from("test").into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn test_vm_id_serde_roundtrip() {
        let id = VmId("vm-001".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let parsed: VmId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_vm_status_serde_roundtrip() {
        let statuses = vec![
            VmStatus::Stopped,
            VmStatus::Starting,
            VmStatus::Running,
            VmStatus::Paused,
            VmStatus::Failed {
                reason: "oom".to_string(),
            },
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: VmStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_vm_capabilities_default() {
        let caps = VmCapabilities::default();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
    }

    #[test]
    fn test_balloon_state_serde_roundtrip() {
        let s = BalloonState {
            max_mib: 2048,
            inflated_mib: 512,
            host_committed_mib: 1536,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: BalloonState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn test_vm_info_serde_roundtrip() {
        let info = VmInfo {
            id: VmId("vm-1".to_string()),
            name: "worker-1".to_string(),
            status: VmStatus::Running,
            guest_ip: Some("172.16.0.2".to_string()),
            cpus: 2,
            memory_mib: 512,
            profile: Some("worker".to_string()),
            revision: Some("abc123".to_string()),
            flake_ref: Some("/home/user/project".to_string()),
            ports: vec![VmPortMapping {
                host: 8888,
                guest: 8080,
            }],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: VmInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, info.id);
        assert_eq!(parsed.name, "worker-1");
        assert_eq!(parsed.cpus, 2);
        assert_eq!(parsed.memory_mib, 512);
        assert_eq!(parsed.guest_ip.as_deref(), Some("172.16.0.2"));
        assert_eq!(parsed.profile.as_deref(), Some("worker"));
        assert_eq!(parsed.revision.as_deref(), Some("abc123"));
        assert_eq!(parsed.flake_ref.as_deref(), Some("/home/user/project"));
    }

    #[test]
    fn test_vm_info_serde_without_optional_fields() {
        let json = r#"{"id":"vm-1","name":"w","status":"Running","cpus":1,"memory_mib":256}"#;
        let parsed: VmInfo = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, "w");
        assert!(parsed.guest_ip.is_none());
        assert!(parsed.profile.is_none());
        assert!(parsed.revision.is_none());
        assert!(parsed.flake_ref.is_none());
    }

    #[test]
    fn test_vm_start_config_default() {
        let config = VmStartConfig::default();
        assert!(config.name.is_empty());
        assert!(config.rootfs_path.is_empty());
        assert!(config.kernel_path.is_none());
        assert!(config.initrd_path.is_none());
        assert_eq!(config.cpus, 0);
        assert_eq!(config.memory_mib, 0);
        // Default opts out of balloon — preserves the historical
        // "memory_mib is committed at boot" contract.
        assert!(config.mem_initial_mib.is_none());
        assert!(config.ports.is_empty());
        assert!(config.volumes.is_empty());
        assert!(config.config_files.is_empty());
        assert!(config.secret_files.is_empty());
        // Plan 102 Phase 3c — audit substrate fields default to None
        // so legacy callers (no AdmittedPlan in scope) get the legacy
        // supervisor path.
        assert!(config.tenant_id.is_none());
        assert!(config.plan_json.is_none());
        assert!(config.bundle_json.is_none());
    }

    #[test]
    fn test_vm_port_mapping_serde_roundtrip() {
        let mapping = VmPortMapping {
            host: 8080,
            guest: 80,
        };
        let json = serde_json::to_string(&mapping).unwrap();
        let parsed: VmPortMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, 8080);
        assert_eq!(parsed.guest, 80);
    }

    #[test]
    fn test_vm_file_default() {
        let file = VmFile::default();
        assert!(file.name.is_empty());
        assert!(file.content.is_empty());
        assert_eq!(file.mode, 0o444);
    }

    #[test]
    fn test_vm_network_info_serde_roundtrip() {
        let info = VmNetworkInfo {
            guest_ip: "172.16.0.2".to_string(),
            gateway_ip: "172.16.0.1".to_string(),
            subnet_cidr: "172.16.0.0/24".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: VmNetworkInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.guest_ip, "172.16.0.2");
        assert_eq!(parsed.gateway_ip, "172.16.0.1");
        assert_eq!(parsed.subnet_cidr, "172.16.0.0/24");
    }

    #[test]
    fn test_guest_channel_info_vsock_serde_roundtrip() {
        // Arbitrary cid/port — this test exercises serde, not the
        // agent port choice. The agent's actual port lives in
        // `mvm_guest::vsock::GUEST_AGENT_PORT`.
        let info = GuestChannelInfo::Vsock { cid: 3, port: 4242 };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: GuestChannelInfo = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            GuestChannelInfo::Vsock { cid: 3, port: 4242 }
        ));
    }

    #[test]
    fn test_guest_channel_info_unix_socket_serde_roundtrip() {
        let info = GuestChannelInfo::UnixSocket {
            path: PathBuf::from("/tmp/guest.sock"),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: GuestChannelInfo = serde_json::from_str(&json).unwrap();
        match parsed {
            GuestChannelInfo::UnixSocket { path } => {
                assert_eq!(path, PathBuf::from("/tmp/guest.sock"));
            }
            _ => panic!("Expected UnixSocket variant"),
        }
    }

    #[test]
    fn test_layer_coverage_all_layers_is_microvm() {
        let cov = LayerCoverage::all_layers();
        assert!(cov.is_microvm());
        assert!(cov.l1_host_hypervisor);
        assert!(cov.l2_vmm);
        assert!(cov.l3_guest_kernel);
        assert!(cov.l4_guest_agent);
        assert!(cov.l5_workload);
    }

    #[test]
    fn test_layer_coverage_default_is_not_microvm() {
        let cov = LayerCoverage::default();
        assert!(!cov.is_microvm());
    }

    #[test]
    fn test_layer_coverage_docker_shape_is_not_microvm() {
        let cov = LayerCoverage {
            l1_host_hypervisor: false,
            l2_vmm: false,
            l3_guest_kernel: false,
            l4_guest_agent: true,
            l5_workload: true,
        };
        assert!(!cov.is_microvm());
    }

    #[test]
    fn test_claim_status_serde_roundtrip() {
        let statuses = [
            ClaimStatus::Holds,
            ClaimStatus::DoesNotApply,
            ClaimStatus::DoesNotHold,
        ];
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: ClaimStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn test_backend_security_profile_dropped_claims() {
        let profile = BackendSecurityProfile {
            claims: [
                ClaimStatus::DoesNotHold,  // 1
                ClaimStatus::DoesNotHold,  // 2
                ClaimStatus::DoesNotHold,  // 3
                ClaimStatus::Holds,        // 4
                ClaimStatus::DoesNotApply, // 5
                ClaimStatus::Holds,        // 6
                ClaimStatus::Holds,        // 7
            ],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 3",
            notes: &[],
        };
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3]);
        assert_eq!(profile.na_claims(), vec![5]);
    }

    #[test]
    fn test_backend_security_profile_tier_1_drops_nothing() {
        let profile = BackendSecurityProfile {
            claims: [ClaimStatus::Holds; 7],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 1",
            notes: &[],
        };
        assert!(profile.dropped_claims().is_empty());
        assert!(profile.na_claims().is_empty());
    }
}
