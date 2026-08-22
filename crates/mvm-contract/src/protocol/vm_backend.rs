//! Backend-agnostic VM lifecycle DTOs.
//!
//! The pure serde/data types every `VmBackend` implementation shares:
//! launch-descriptor building blocks (ports/volumes/files), status and
//! capability reporting, the warm-start/snapshot tier model, and the
//! supervisor standby-pool wire shapes. The `VmBackend` trait itself and
//! the trait-coupled composite configs (`VmStartConfig`, `VerbGrantEnvelope`,
//! `StandbyClaim`) stay in `mvm-core`, which re-exports every type here at
//! its historical path so existing call sites keep resolving unchanged.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

/// Which guest-runtime source policy this boot declares.
///
/// This is intentionally a **contract field**, not a backend behavior switch by
/// itself. The first rollout slice uses it to make the intended runtime source
/// machine-readable in launch configs and audit events without changing any
/// backend behavior yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSourcePolicy {
    /// This boot expects the mvm guest runtime to come from the sealed runtime
    /// overlay, and should fail closed if that overlay is unavailable.
    RequiredOverlay,
    /// This boot prefers the runtime overlay when available, but currently keeps
    /// a baked rootfs fallback for compatibility with backends/tier
    /// combinations that have not flipped to required-overlay yet.
    PreferOverlay,
    /// This boot does not rely on the runtime overlay path at all; the guest
    /// runtime is expected to come from the rootfs.
    #[default]
    RootfsOnly,
}

impl RuntimeSourcePolicy {
    pub const fn audit_label(self) -> &'static str {
        match self {
            Self::RequiredOverlay => "required-overlay",
            Self::PreferOverlay => "prefer-overlay",
            Self::RootfsOnly => "rootfs-only",
        }
    }

    pub const fn cmdline_value(self) -> &'static str {
        match self {
            Self::RequiredOverlay => "required_overlay",
            Self::PreferOverlay => "prefer_overlay",
            Self::RootfsOnly => "rootfs_only",
        }
    }

    pub fn from_cmdline_value(value: &str) -> Option<Self> {
        match value {
            "required_overlay" => Some(Self::RequiredOverlay),
            "prefer_overlay" => Some(Self::PreferOverlay),
            "rootfs_only" => Some(Self::RootfsOnly),
            _ => None,
        }
    }
}

/// Which kind of guest launch is selecting a runtime-source policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSourceLaunchKind {
    /// A workload image/rootfs whose launch path can attach the runtime overlay.
    WorkloadImage,
    /// A builder/dev VM image whose control plane still relies on the baked
    /// rootfs path when no overlay is attached.
    BuilderDevVm,
    /// An injected/staged rootfs (for example the transient OCI run path).
    /// Block-backed boots can still prefer the shared runtime overlay when the
    /// backend can attach it; virtiofs-root keeps using the staged rootfs copy
    /// until a real overlay mount exists on that launch shape.
    InjectedRootfs,
}

/// The selected rootfs strategy for a workload boot, when the caller knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSourceRootStrategy {
    VirtiofsRoot,
    BlockExt4,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// `:enc` — route a `Disk` volume through in-guest encryption.
    /// Fails closed at launch until that lands; never silently
    /// plaintext. Always false for a `DirShare`.
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

/// Encode the per-VM egress intermediate **cert** (PEM) as a single
/// `mvm.egress_ca=pem:<body>` kernel-cmdline token, mirroring `mvm.uvols`.
/// `/init` reconstructs the PEM, writes the cert to tmpfs
/// (`/run/mvm/egress-ca.crt`), and points the guest's TLS trust at a combined
/// bundle so a workload trusts host-terminated bound-host TLS. The fresh FC
/// boot attaches no secrets drive, so the cmdline is the only per-VM channel to
/// a sealed guest. Cert-only — never the key (host-side). `None` for an empty
/// cert (no https leg).
///
/// The token carries only the PEM body (no armor lines or embedded newlines),
/// not a hex-encoded full PEM. That keeps the token compact enough for the
/// workload cmdline budget while still staying a single space-free token that
/// `/proc/cmdline` round-trips. Guest launchers accept the legacy hex-encoded
/// full-PEM form too, so existing boots keep working while the host-side
/// encoder moves to the compact format.
pub fn encode_egress_ca_cmdline(cert_pem: &str) -> Option<String> {
    if cert_pem.is_empty() {
        return None;
    }
    let body: String = cert_pem
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            (!trimmed.is_empty()
                && !trimmed.starts_with("-----BEGIN ")
                && !trimmed.starts_with("-----END "))
            .then_some(trimmed)
        })
        .collect();
    if body.is_empty() {
        return None;
    }
    Some(format!("mvm.egress_ca=pem:{body}"))
}

/// `mvm.runtime_source_policy=<snake_case>` kernel-cmdline token. This lets the
/// guest-side launcher distinguish required-overlay vs preferred-overlay boots
/// without inventing a second policy channel.
pub fn encode_runtime_source_policy_cmdline(policy: RuntimeSourcePolicy) -> String {
    format!("mvm.runtime_source_policy={}", policy.cmdline_value())
}

/// Encode the per-run secret **placeholder** env as a single
/// `mvm.secret_env=<hex>` kernel-cmdline token: a newline-joined
/// `VAR=placeholder` blob, hex-encoded so it survives `/proc/cmdline` as one
/// space-free token. `/init` decodes it and `export`s each `VAR=placeholder`
/// into the sealed entrypoint's environment, so an SDK-free workload reads its
/// opaque placeholder from `$VAR` and the host substitutes the real credential
/// at egress. **Never a value** — only the `mvm-secret-…` placeholder (claim 13).
/// `None` for no secrets. The cmdline is the only per-VM channel a *fresh* FC
/// boot has to a sealed guest (no secrets drive attached), and the placeholder
/// must be minted **before** boot so it can ride here.
pub fn encode_secret_env_cmdline(pairs: &[(String, String)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let blob = pairs
        .iter()
        .map(|(var, ph)| format!("{var}={ph}"))
        .collect::<Vec<_>>()
        .join("\n");
    let hex: String = blob.bytes().map(|b| format!("{b:02x}")).collect();
    Some(format!("mvm.secret_env={hex}"))
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
/// Firecracker and Apple Containers use vsock.
/// No other channel shape is supported today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuestChannelInfo {
    /// Vsock connection (Firecracker, Apple Container).
    Vsock {
        /// Context ID (Firecracker assigns per-VM; Apple Container auto-assigns).
        cid: u32,
        /// Port the guest agent listens on.
        port: u32,
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
///   - Interactive foreground sessions where the user expects the
///     VM to disappear when they Ctrl-C.
///   - Test harnesses that want deterministic teardown.
///
/// Pair with `VmBackend::wait` to block until the VM exits, and
/// `VmBackend::detach` to convert an attached VM into a detached
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
/// `VmBackend::stop` call) terminates the VM.
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

/// Result of a VM exiting (returned by `VmBackend::wait`).
///
/// Mirrors `std::process::ExitStatus` semantically but is
/// serializable + dyn-trait-friendly for the host-side IPC path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmExitStatus {
    /// Numeric exit code, when one was reported. None if the VM was
    /// terminated by signal or didn't expose a status.
    pub code: Option<i32>,
    /// `true` only when the VM exited normally with code 0 (or a
    /// backend-defined clean exit); a non-zero captured `code` is
    /// `success: false`. `false` for signal/crash/unknown exits.
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
/// Used by consumers to check what operations are available before attempting
/// them. Recovery capabilities are deliberately part of this same value so a
/// caller cannot accidentally combine a snapshot tier from one backend with a
/// standby answer from another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmCapabilities {
    /// Can pause/resume vCPUs (Firecracker: yes, WASM: no).
    pub pause_resume: bool,
    /// Legacy coarse snapshot flag. New recovery callers should use
    /// [`snapshot_capability`](Self::snapshot_capability), which distinguishes
    /// live-memory, save/restore, disk-only, and unsupported paths.
    pub snapshots: bool,
    /// The strongest recovery tier this backend actually wires.
    pub snapshot_capability: SnapshotCapability,
    /// Can maintain a prelaunched supervisor standby pool. This is separate
    /// from snapshots: a standby pays spawn/setup latency in advance but does
    /// not restore saved machine state.
    pub standby_pool: bool,
    /// Supports vsock guest communication (Firecracker: yes, others: typically no).
    pub vsock: bool,
    /// Supports TAP-based networking.
    pub tap_networking: bool,
    /// Supports a virtio-balloon device with runtime inflate/deflate.
    /// When `true`, `VmBackend::balloon_set_target` is wired and the
    /// host-side reclaim controller can adjust guest commitment
    /// without rebooting the VM.
    /// is **not** a balloon and stays `false`.
    pub balloon: bool,
    /// Can freeze a quiesced rootfs into an fs-quick checkpoint via filesystem
    /// copy-on-write (APFS `clonefile` on macOS). Independent of `snapshots`,
    /// which is the memory-state save/restore capability.
    pub fs_quick_checkpoint: bool,
    /// Backend can map a host file-backed region and present it to the guest
    /// as RAM — the prerequisite for eager copy-on-write restore.
    pub guest_memory_mapping: bool,
    /// Backend can remap guest RAM at a fixed host virtual address across a
    /// restore cycle (eager-CoW return-to-pool).
    pub fixed_address_remap: bool,
    /// Backend can capture device state into a snapshot frame mvm controls.
    pub device_state_snapshot: bool,
    /// Backend can capture vCPU state into a snapshot frame mvm controls.
    pub vcpu_state_snapshot: bool,
    /// Backend can restore a guest by eager copy-on-write (`MAP_PRIVATE`) of a
    /// snapshot RAM section — the primary local warm-restore path.
    pub eager_cow_restore: bool,
    /// Guest has no host-routable NIC: nothing in the guest can reach the
    /// network by IP. This is a reachability guarantee, not a device-count one
    /// — a backend that attaches a virtio-net device but drains/sinks it with
    /// no upstream route still satisfies this (libkrun), and so does a backend
    /// that presents no NIC at all (HVF). Egress, when permitted, rides the
    /// vsock proxy instead.
    pub no_routable_guest_nic: bool,
    /// Backend supports host/vsock-mediated networking (egress/ingress brokers
    /// over vsock) instead of a guest NIC.
    pub host_vsock_proxy: bool,
    /// Backend can carry an interactive PTY exec/console session.
    pub pty_exec: bool,
    /// Backend permits an in-guest SSH server (production SSH). Always `false`
    /// for every production backend; a plan requiring it is rejected.
    pub production_ssh: bool,
    /// Backend can attach the unpacked OCI tree as a read-only **virtiofs root**
    /// device, so a dev-tier boot skips ext4 materialization. `false` for
    /// Firecracker (no virtiofs root device) and the default. The run-path tier
    /// gate selects virtiofs-root only when this is `true` *and* the workload is
    /// non-prod, non-sealed; the virtiofs-root dev path carries a weaker
    /// integrity contract and does **not** witness the verified-boot claim.
    pub virtiofs_root: bool,
    /// Which resource dimensions this backend can actually bound. Declared
    /// separately from what a caller requests so a refusal can name the gap.
    #[serde(default)]
    pub resource_controls: crate::protocol::resource_controls::ResourceControls,
    /// Portable, typed dimensions that describe the backend's guest
    /// environment, CPU execution mode, isolation boundary, and lifecycle
    /// scope. Added so browser and native builds share the same capability
    /// identity without pulling backend-specific constructors into the
    /// contract crate.
    #[serde(default)]
    pub capability_dimensions: BackendCapabilityDimensions,
}

/// The capabilities a run/plan requires from its backend.
///
/// Selection fails closed: a backend that does not advertise every required
/// capability is rejected with the named shortfall rather than silently
/// degraded onto a weaker backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequiredCapabilities {
    pub eager_cow_restore: bool,
    pub guest_memory_mapping: bool,
    pub fixed_address_remap: bool,
    pub device_state_snapshot: bool,
    pub vcpu_state_snapshot: bool,
    pub vsock: bool,
    pub no_routable_guest_nic: bool,
    pub host_vsock_proxy: bool,
    pub pty_exec: bool,
}

impl VmCapabilities {
    /// Names of the capabilities `required` asks for that this backend does
    /// not advertise. Empty means the backend can serve the request.
    pub fn shortfall(&self, required: &RequiredCapabilities) -> Vec<&'static str> {
        let checks: [(bool, bool, &'static str); 9] = [
            (
                required.eager_cow_restore,
                self.eager_cow_restore,
                "eager_cow_restore",
            ),
            (
                required.guest_memory_mapping,
                self.guest_memory_mapping,
                "guest_memory_mapping",
            ),
            (
                required.fixed_address_remap,
                self.fixed_address_remap,
                "fixed_address_remap",
            ),
            (
                required.device_state_snapshot,
                self.device_state_snapshot,
                "device_state_snapshot",
            ),
            (
                required.vcpu_state_snapshot,
                self.vcpu_state_snapshot,
                "vcpu_state_snapshot",
            ),
            (required.vsock, self.vsock, "vsock"),
            (
                required.no_routable_guest_nic,
                self.no_routable_guest_nic,
                "no_routable_guest_nic",
            ),
            (
                required.host_vsock_proxy,
                self.host_vsock_proxy,
                "host_vsock_proxy",
            ),
            (required.pty_exec, self.pty_exec, "pty_exec"),
        ];
        checks
            .into_iter()
            .filter_map(|(req, have, name)| (req && !have).then_some(name))
            .collect()
    }

    /// Whether this backend can serve every capability `required` asks for.
    pub fn satisfies(&self, required: &RequiredCapabilities) -> bool {
        self.shortfall(required).is_empty()
    }
}

/// How thoroughly a backend can warm-start a VM from a snapshot. Distinct
/// from `VmCapabilities::snapshots` (a coarse "can checkpoint" bool): this is
/// the honest per-backend warm-start *tier*. No path silently degrades —
/// a request beyond the reported tier returns a typed error once the
/// snapshot RPC is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCapability {
    /// Full live-memory snapshot + fast resume (Firecracker: UFFD/NBD/hugepages).
    LiveMemory,
    /// Coarse save/restore of machine state (HVF `saveMachineState`, macOS 26+).
    SaveRestore,
    /// No memory snapshot — warm-start is a fast reboot from a disk/overlay
    /// snapshot (libkrun).
    DiskOnly,
    /// No snapshot/warm-start support.
    #[default]
    Unsupported,
}

impl SnapshotCapability {
    /// Stable lowercase token for doctor / audit output.
    pub const fn label(self) -> &'static str {
        match self {
            SnapshotCapability::LiveMemory => "live-memory",
            SnapshotCapability::SaveRestore => "save-restore",
            SnapshotCapability::DiskOnly => "disk-only",
            SnapshotCapability::Unsupported => "unsupported",
        }
    }

    /// Strength ordering: a richer tier can always serve a weaker warm-start
    /// (a live-memory backend can disk-reboot), never the reverse.
    const fn rank(self) -> u8 {
        match self {
            SnapshotCapability::LiveMemory => 3,
            SnapshotCapability::SaveRestore => 2,
            SnapshotCapability::DiskOnly => 1,
            SnapshotCapability::Unsupported => 0,
        }
    }

    /// Whether a backend at this tier can honor a request for `requested`.
    /// Used to fail closed on an over-request (e.g. live-memory asked of
    /// libkrun's disk-only) rather than silently degrade.
    pub const fn satisfies(self, requested: SnapshotCapability) -> bool {
        self.rank() >= requested.rank()
    }
}

/// Why a warm-start request could not be honored. Typed so the caller gets a
/// recovery action instead of a silent degrade.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WarmStartError {
    /// The backend's snapshot tier can't satisfy the requested tier. Carries
    /// both tiers and a hint naming the action the caller should take.
    #[error(
        "warm-start tier '{}' not supported by this backend (available: '{}'); {hint}",
        requested.label(),
        available.label()
    )]
    Unsupported {
        requested: SnapshotCapability,
        available: SnapshotCapability,
        hint: String,
    },
    /// The warm-start machinery failed (snapshot missing, disk reboot failed).
    #[error("warm-start failed: {0}")]
    Failed(String),
}

/// Whether a live-memory warm-start rotated the guest's VMGenID.
///
/// A snapshot restore must reseed the guest CSPRNG so two clones of one
/// snapshot diverge. The host mints a fresh token per resume and delivers it
/// over vsock; this records the *honest* outcome of that delivery so the
/// resume verb never claims a rotation that did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReseedStatus {
    /// Confirmed: the guest acknowledged the post-restore signal and rotated
    /// its VMGenID from the host token.
    Rotated,
    /// The guest was reachable and answered, but did not rotate — a negative
    /// `reseeded` acknowledgement or a non-success ack.
    NotRotated,
    /// The token was never confirmed delivered: the guest agent was not
    /// reachable within the post-resume wait window, or the signal RPC
    /// errored. The VM is resumed but its reseed state is unknown.
    Undelivered,
    /// This backend's warm-start carries no VMGenID rotation (libkrun
    /// disk-only reboot, the trait default).
    NotApplicable,
}

impl ReseedStatus {
    /// Human-facing clause for the resume verb's success line — honest about
    /// whether the guest actually rotated its VMGenID.
    pub fn resume_summary(self) -> &'static str {
        match self {
            ReseedStatus::Rotated => "VMGenID rotated",
            ReseedStatus::NotRotated => "VMGenID NOT rotated (guest did not reseed)",
            ReseedStatus::Undelivered => {
                "VMGenID token not delivered (guest agent unreachable) — re-run resume to retry"
            }
            ReseedStatus::NotApplicable => "no VMGenID rotation for this backend",
        }
    }
}

/// A successful warm-start: the booted VM plus the honest reseed outcome.
///
/// Returned by `VmBackend::warm_start` so a caller can surface whether the
/// guest actually rotated its VMGenID rather than asserting it unconditionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmStartOutcome {
    /// The warm-started VM.
    pub id: VmId,
    /// Whether the guest rotated its VMGenID on this resume.
    pub reseed: ReseedStatus,
}

/// Whether a launch may use a cold boot when no compatible warm capacity is
/// immediately available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmLaunchMode {
    /// Use warm capacity when available, but preserve a cold-boot path.
    #[default]
    Optional,
    /// Refuse the launch unless a compatible warm parent can be claimed.
    Required,
    /// Do not consult the warm pool.
    Cold,
}

impl WarmLaunchMode {
    /// Whether this mode requires an authenticated warm claim.
    pub const fn requires_warm(self) -> bool {
        matches!(self, Self::Required)
    }

    /// Whether this mode permits a cold boot.
    pub const fn permits_cold(self) -> bool {
        !self.requires_warm()
    }
}

/// A typed reason a warm claim was refused. These reasons are part of the
/// host-side launch contract: callers can distinguish capacity pressure from
/// an incompatible or unhealthy parent without parsing log text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum WarmClaimRefusal {
    /// The selected backend cannot provide a warm pool.
    #[error("backend '{backend}' does not support warm claims")]
    BackendUnsupported { backend: String },
    /// No parent matches the complete compatibility key at claim time.
    #[error("no compatible warm parent is available")]
    NoCompatibleParent,
    /// The launch shape cannot be represented by the current pool topology.
    #[error("warm claim is incompatible: {reason}")]
    Incompatible { reason: String },
    /// The claim could not be prepared before it reached the backend.
    #[error("warm claim preparation failed: {reason}")]
    PreparationFailed { reason: String },
    /// The backend rejected the claim after reservation.
    #[error("warm claim rejected: {reason}")]
    ClaimRejected { reason: String },
}

/// The backend-neutral result of a warm-pool decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarmClaimOutcome {
    /// A compatible parent was claimed and the child is becoming ready.
    Claimed,
    /// No warm parent was used; the caller may cold-boot if its mode permits it.
    ColdBoot,
    /// The caller requested warm service and must not cold-boot.
    Refused(WarmClaimRefusal),
}

/// Monotonic timing marks for one warm decision. Values are integer
/// microseconds so the same record is stable across JSON, logs, and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmClaimTiming {
    /// Time spent waiting for a compatible pool entry.
    pub pool_wait_us: u64,
    /// Time spent claiming and authenticating the child.
    pub claim_us: u64,
    /// Total warm window from claim dispatch to authenticated readiness.
    pub warm_window_us: u64,
}

/// Host-path-free source descriptor for an asynchronous warm-artifact job.
/// Mutable source references are resolved by the worker and are never used as
/// the published artifact identity; the resulting content digests remain the
/// cache key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WarmPrewarmSource {
    /// Resolve an OCI image reference through the trusted local image cache or
    /// its configured registry policy.
    OciImage { reference: String },
    /// Resolve a previously registered template by identity.
    Template { template_id: String },
}

impl WarmPrewarmSource {
    /// Reject empty or NUL-containing source identifiers before they reach a
    /// resolver or an audit record.
    pub fn validate(&self) -> Result<(), String> {
        let value = match self {
            Self::OciImage { reference } => reference,
            Self::Template { template_id } => template_id,
        };
        if value.trim().is_empty() {
            return Err("warm prewarm source identifier is empty".into());
        }
        if value.contains('\0') {
            return Err("warm prewarm source identifier contains NUL".into());
        }
        Ok(())
    }
}

/// Host-path-free content identity supplied with an asynchronous prewarm
/// request. The runtime converts this DTO into its validated cache key before
/// it can enter the artifact store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmArtifactIdentity {
    /// Backend and configuration identity for the golden VM.
    pub backend: String,
    pub backend_version: String,
    /// Guest-agent content identity.
    pub guest_agent_sha256: String,
    /// Kernel content identity.
    pub kernel_sha256: String,
    /// Universal initramfs content identity.
    pub initramfs_sha256: String,
    /// Workload rootfs content identity.
    pub rootfs_sha256: String,
    /// Runtime overlay content identity, when required.
    pub runtime_overlay_sha256: Option<String>,
}

/// Control-plane request for the resident warm-launch service.
///
/// The admitted workload envelope remains owned by the trusted launch role;
/// this boundary carries the request identity and compatibility shape used to
/// schedule it, never a host path or user secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WarmServiceRequest {
    /// Claim one compatible warm parent for a launch lease.
    Claim {
        /// Caller-generated id used for audit correlation and replay checks.
        request_id: String,
        /// Lease id that will own the claimed child until release.
        lease_id: String,
        /// Whether cold fallback is permitted.
        mode: WarmLaunchMode,
        /// Complete parent compatibility shape; host paths are excluded.
        compatibility: StandbyCompat,
    },
    /// Release a previously accepted lease.
    Release {
        /// Caller-generated id used for audit correlation.
        request_id: String,
        /// Lease to stop and remove from active service state.
        lease_id: String,
    },
    /// Ask the service to prepare capacity for a compatibility shape.
    Prewarm {
        /// Caller-generated id used for audit correlation.
        request_id: String,
        /// Immutable-source intent resolved by the asynchronous worker.
        source: WarmPrewarmSource,
        /// Complete content identity for the artifact object to prepare.
        artifact: WarmArtifactIdentity,
        /// Shape the published parents must satisfy.
        compatibility: StandbyCompat,
        /// Desired number of idle parents.
        target: u32,
    },
}

/// Control-plane response from the resident warm-launch service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WarmServiceResponse {
    /// A child is authenticated and owned by `lease_id`.
    Claimed {
        request_id: String,
        lease_id: String,
        vm_id: VmId,
        timing: WarmClaimTiming,
    },
    /// Optional mode had no usable warm capacity and may cold-boot.
    ColdBoot {
        request_id: String,
        lease_id: String,
        vm_id: VmId,
        timing: WarmClaimTiming,
    },
    /// Required mode could not be honored.
    Refused {
        request_id: String,
        refusal: WarmClaimRefusal,
        timing: WarmClaimTiming,
    },
    /// The service accepted release and removed the active lease.
    Released {
        request_id: String,
        lease_id: String,
    },
    /// The service accepted an asynchronous prewarm request.
    PrewarmAccepted {
        request_id: String,
        target: u32,
        current: u32,
    },
}

// ---------------------------------------------------------------------------
// Supervisor standby pool
// ---------------------------------------------------------------------------

/// How a prelaunched standby is to be set up. Backend-agnostic:
/// the caller (the launch path) fills this in; the backend's
/// `VmBackend::spawn_standby` translates it to its own wire config
/// (libkrun → `SupervisorBaseConfig`; HVF → boots a seed VM, captures its
/// memory state, and stops the supervisor).
#[derive(Debug, Clone)]
pub struct StandbySpec {
    /// Stable id for this standby (also the `~/.mvm/pool/<id>/` dir name).
    pub id: String,
    /// Registered template identity, when this parent is template-bound.
    /// `None` means the parent is image-agnostic.
    pub template_id: Option<String>,
    /// Kernel image path the standby pre-loads.
    pub kernel_path: String,
    /// Lowercase-hex sha256 of the kernel image — part of the base-compat key.
    pub kernel_sha256: String,
    /// vCPU count fixed at spawn (libkrun `set_vm_config` runs from the base
    /// KrunContext, before attach — so a launch needing a different count cold-boots).
    pub vcpus: u8,
    /// Guest memory (MiB) fixed at spawn — same reasoning as `vcpus`.
    pub mem_mib: u32,
    /// Host-signer key path (claim 8) the standby re-verifies the attach plan against.
    pub signing_key_path: String,
    /// Expected envelope signer id (`host:{hostname}`) — the attach plan must match it.
    pub signer_id: String,
    /// Per-spawn binding nonce (hex of 32 random bytes); the attach must echo it.
    pub binding_nonce: String,
    /// Control UDS the standby binds and blocks on (0700 in a 0700 dir, nonce in path).
    pub control_socket: String,
    /// Per-VM state dir the standby writes its pid into.
    pub vm_state_dir: String,
    /// Source rootfs image path for image-bound standbys. `None` for libkrun
    /// (no rootfs is baked in at spawn; any workload rootfs attaches at claim time).
    pub image_path: Option<String>,
    /// Sha256 hex of `image_path` for the compat key. `None` for libkrun.
    pub image_sha256: Option<String>,
    /// Whether the parent boots the guest's vsock egress client on
    /// (see [`StandbyCompat::vsock_egress`]).
    ///
    /// The spawn takes this from the compat key it is recording rather than
    /// re-deriving it, so the parent that boots and the record a claim matches
    /// can never describe different guests.
    pub vsock_egress: bool,
}

/// The base-compat key — everything a standby fixes at spawn and must therefore match the
/// workload exactly, else the launch cold-boots.
///
/// `image_sha256` is `Some(sha)` for a standby captured from a rootfs — a saved-state
/// standby is a frozen {rootfs, memory, machine-id} triple taken from one particular
/// image, and every child is cloned from that captured content, so the image is part of
/// the standby's identity rather than something attached to it later. It is `None` only
/// for a standby carrying no rootfs at all (a bare pre-spawned supervisor any image could
/// attach to). Compatibility is exact in both directions — `None == None` and
/// `Some(a) == Some(b)` iff `a == b` — so a claim that computes this field differently
/// from the spawn that recorded it matches nothing, silently and forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyCompat {
    /// Registered template identity. Compatibility is exact, including the
    /// distinction between a template-bound and image-agnostic standby.
    pub template_id: Option<String>,
    pub kernel_sha256: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    /// `Some(sha256-hex)` for a standby captured from a rootfs; `None` only for
    /// one that carries no rootfs.
    pub image_sha256: Option<String>,
    /// Whether the guest boots with its in-guest vsock egress client started.
    ///
    /// A restored child inherits its kernel cmdline from the parent's saved
    /// memory rather than deriving its own, so the one guest-visible egress
    /// token (`mvm.vsock_egress=1`) is fixed at the parent's boot and cannot be
    /// changed at claim time. A launch whose guest would start that client must
    /// therefore claim a parent that started it, and a launch whose guest would
    /// not must claim one that did not — hence a compat field rather than a
    /// launch-shape exclusion.
    ///
    /// This is the *enablement* only. The set of destinations a workload may
    /// reach is resolved host-side, on the claimed child's own egress endpoint,
    /// from that launch's own policy — so a shared parent carries no launch's
    /// allow-list and there is nothing per-launch here to leak to the next
    /// claim.
    pub vsock_egress: bool,
}

/// A recorded standby (persisted as `~/.mvm/pool/<id>/standby.json`).
///
/// `pid` is 0 for saved-state standbys: the supervisor that booted the seed VM
/// was stopped at capture time; no process is running. A live standby retains
/// its supervisor PID and is parked until a claim hands it off. `reap_stale`
/// treats pid=0 as "TTL-only"; no real process has pid 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyHandle {
    pub id: String,
    /// Registered template identity, when the standby is template-bound.
    #[serde(default)]
    pub template_id: Option<String>,
    pub control_socket: String,
    pub pid: u32,
    pub kernel_sha256: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub binding_nonce: String,
    pub spawned_unix_secs: u64,
    pub state: StandbyState,
    /// `None` for libkrun (image-agnostic); `Some(sha256-hex)` for image-bound
    /// standbys.
    #[serde(default)]
    pub image_sha256: Option<String>,
    /// The content-addressed checkpoint this parent was captured as, set once
    /// a spawn has captured it. `None` means the parent was never captured, so
    /// it cannot be claimed: a claim verifies content and lineage against this
    /// checkpoint before cloning anything.
    ///
    /// Held as the raw id string rather than a `CheckpointId` because that type
    /// lives a layer up; the runtime converts at its boundary.
    #[serde(default)]
    pub parent_checkpoint: Option<String>,
    /// An already-loaded, paused child VMM prepared from `parent_checkpoint`.
    ///
    /// When present, the pool owns this child process instead of a saved-only
    /// parent. The child name becomes the final workload VM identity at claim
    /// time; it is never exposed to a workload before fresh admission,
    /// channel wiring, and post-restore identity reseeding complete.
    #[serde(default)]
    pub preloaded_child_vm_name: Option<String>,
    /// Whether this parent booted its guest's vsock egress client on
    /// (see [`StandbyCompat::vsock_egress`]).
    ///
    /// Defaults to `false` so a record written before the field existed reads as
    /// a parent that booted no egress client — which is what those parents did,
    /// and which keeps them claimable only by launches whose guest wants none.
    #[serde(default)]
    pub vsock_egress: bool,
}

impl StandbyHandle {
    /// The base-compat key this standby was spawned with.
    pub fn compat(&self) -> StandbyCompat {
        StandbyCompat {
            template_id: self.template_id.clone(),
            kernel_sha256: self.kernel_sha256.clone(),
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            image_sha256: self.image_sha256.clone(),
            vsock_egress: self.vsock_egress,
        }
    }

    /// A launch may claim this standby only if its kernel, fixed resources, image
    /// sha256 and guest egress enablement all match exactly — no silent
    /// wrong-kernel, wrong-size, wrong-image or no-network boot.
    pub fn is_compatible(&self, want: &StandbyCompat) -> bool {
        &self.compat() == want
    }

    /// True if this standby holds a captured memory state rather than a live supervisor.
    /// Saved standbys carry pid=0 (no running process) and are reaped by TTL only.
    pub fn is_saved_state(&self) -> bool {
        self.pid == 0
    }
}

/// Lifecycle state of a recorded standby.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyState {
    /// Spawned, blocked on its control UDS, not yet claimed.
    Idle,
    /// An attach was sent; the standby is booting or has booted.
    Claimed,
    /// Aged out of the warm set but kept as a claimable saved-state snapshot.
    Parked,
}

impl StandbyState {
    /// A launch may claim a standby that is warm (`Idle`) or parked.
    pub fn is_claimable(&self) -> bool {
        matches!(self, StandbyState::Idle | StandbyState::Parked)
    }
}

/// Why a standby spawn/claim failed. Fail-closed: every variant means the caller must
/// fall back to a cold boot, never silently proceed without the workload.
#[derive(Debug, thiserror::Error)]
pub enum StandbyError {
    #[error("{backend}: standby pool is not supported by this backend")]
    Unsupported { backend: String },
    #[error("spawn standby: {0}")]
    SpawnFailed(String),
    #[error("claim standby: {0}")]
    ClaimFailed(String),
}

/// Snapshot of a VM's virtio-balloon state, returned by
/// `VmBackend::balloon_state`.
///
/// All values are in MiB. The reclaim controller compares
/// `host_committed_mib` against host memory pressure to decide
/// whether to call `VmBackend::balloon_set_target` up or down.
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
// BackendSecurityProfile — per-backend security-claim coverage
// ---------------------------------------------------------------------------

/// Status of a single security claim for a backend.
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

/// Coverage of the five Matryoshka trust layers.
///
/// `true` means the layer is enforced by hardware/software isolation under
/// this backend; `false` means the layer collapses into the host kernel
/// or another preceding layer.
/// shares the host kernel with the workload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayerCoverage {
    /// L1 — Host + hypervisor (KVM, HVF).
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

/// Per-backend declaration of security-claim coverage.
///
/// `mvmctl doctor` and `mvmctl run` consume this to render the active
/// backend's security posture. The seven claims are stored at indices
/// `0..7` (claim 1 = `claims[0]`):
///
/// 1. No host-fs access from a guest beyond explicit shares
/// 2. No guest binary can elevate to uid 0
/// 3. A tampered rootfs ext4 fails to boot
/// 4. A production-safe run cannot invoke DevOnly guest-agent verbs
/// 5. Vsock framing is fuzzed
/// 6. Pre-built dev image is hash-verified
/// 7. Cargo deps are audited on every PR
///
/// `notes` provides per-backend rationale shown in doctor output and is
/// where backends explain partial claims (e.g. "claim 3 partial — verified
/// boot for HVF-backed rootfs not yet wired up").
///
/// This profile is **advisory** — it describes posture for `doctor` output.
/// The load-bearing guarantee that a non-workload backend cannot carry an
/// untrusted workload is enforced by the `WorkloadBackend` type-bar on the
/// admitted launch path, not by this array.
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
// ---------------------------------------------------------------------------
pub mod portable;

pub use portable::{
    ArtifactRef, ArtifactSetRef, AttestationTier, BackendCapabilityDimensions, BackendRequest,
    BackendResponse, CpuExecution, GuestEnvironment, IsolationBoundary, LifecycleScope,
};

/// Summary info for a managed VM, returned by `VmBackend::list`.
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

/// The typed discriminant of a `VmBackend` implementation.
///
/// Callers branch on `BackendKind::Hvf` etc. instead of string-matching
/// `VmBackend::name` — a `match` on this enum is exhaustive, so a removed
/// or added backend is a compile error at every dispatch site instead of a
/// silent gap. Prefer a descriptor capability flag or a `VmBackend` trait
/// method for anything that varies *behaviorally* per backend; reserve
/// `kind() == BackendKind::X` for a genuine single-backend identity check.
///
/// Lives beside the trait in `mvm-core`, which re-exports this DTO here so
/// `&dyn VmBackend` callers can call `.kind()` without an upward dependency
/// on the higher-level backend registry that knows how to *construct* each
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Firecracker,
    Libkrun,
    Qemu,
    Mock,
    Hvf,
    /// Host-`wasmtime` tier running a user-supplied WASI module. Claim-free
    /// portability/demo backend: opt-in only, never returned by auto-detect,
    /// no hardware isolation boundary.
    Wasm,
    /// Browser-hosted Linux tier running a real Nix-built Linux kernel under
    /// QEMU-Wasm. Claim-free portability/development backend: opt-in only,
    /// never returned by native auto-detect, no hardware isolation boundary.
    WebLinux,
    /// Apple Container tier: workloads boot Apple's prebuilt container
    /// kernel (a fetched binary artifact) with the same universal initramfs
    /// and `ActivateEnvironment` flow as every other runner backend, on the
    /// in-house HVF VMM. Opt-in only; never returned by auto-detect.
    AppleContainer,
}

impl BackendKind {
    /// A stable label for this backend, for diagnostics and reports.
    ///
    /// This renders the typed discriminant; it is not a selector. Nothing may
    /// compare against it to decide behaviour — dispatch stays on the enum so
    /// a new variant remains a compile error at every site that must handle
    /// it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Libkrun => "libkrun",
            Self::Qemu => "qemu",
            Self::Mock => "mock",
            Self::Hvf => "hvf",
            Self::Wasm => "wasm",
            Self::WebLinux => "web-linux",
            Self::AppleContainer => "apple-container",
        }
    }

    /// The inverse of [`as_str`](Self::as_str).
    ///
    /// A plan names its backend as a string, so somewhere a label has to
    /// become a discriminant again. One parser, over the same labels `as_str`
    /// renders, keeps that conversion from being re-guessed per call site: a
    /// hand-rolled `match` that misspells one label resolves to the wrong tier,
    /// and the tier is what decides which resource controls a run is measured
    /// against.
    ///
    /// `None` for an unrecognised label rather than a fallback variant — what
    /// an unknown backend means differs by caller, and a shared default is how
    /// one caller's leniency becomes another's silent misclassification.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        let kind = match label {
            "firecracker" => Self::Firecracker,
            "libkrun" => Self::Libkrun,
            "qemu" => Self::Qemu,
            "mock" => Self::Mock,
            "hvf" => Self::Hvf,
            "wasm" => Self::Wasm,
            "web-linux" => Self::WebLinux,
            "apple-container" => Self::AppleContainer,
            _ => return None,
        };
        Some(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_resource_controls_deserialize_to_the_fail_closed_default() {
        let mut encoded = serde_json::to_value(VmCapabilities::default())
            .expect("default capabilities serialize");
        encoded
            .as_object_mut()
            .expect("capabilities serialize as an object")
            .remove("resource_controls");

        let decoded: VmCapabilities =
            serde_json::from_value(encoded).expect("legacy capabilities deserialize");
        assert_eq!(
            decoded.resource_controls,
            crate::protocol::resource_controls::ResourceControls::default()
        );
    }

    #[test]
    fn every_label_parses_back_to_the_kind_that_rendered_it() {
        for kind in [
            BackendKind::Firecracker,
            BackendKind::Libkrun,
            BackendKind::Qemu,
            BackendKind::Mock,
            BackendKind::Hvf,
            BackendKind::Wasm,
            BackendKind::WebLinux,
            BackendKind::AppleContainer,
        ] {
            assert_eq!(
                BackendKind::from_label(kind.as_str()),
                Some(kind),
                "{kind:?} does not survive a label round trip"
            );
        }
    }

    #[test]
    fn an_unknown_label_does_not_resolve_to_some_backend() {
        // Resolving an unknown name to a real tier would let a typo pick the
        // resource controls a run is checked against.
        assert_eq!(BackendKind::from_label("applecontainer"), None);
        assert_eq!(BackendKind::from_label("Firecracker"), None);
        assert_eq!(BackendKind::from_label(""), None);
    }

    #[test]
    fn every_backend_kind_has_a_distinct_stable_label() {
        let kinds = [
            BackendKind::Firecracker,
            BackendKind::Libkrun,
            BackendKind::Qemu,
            BackendKind::Mock,
            BackendKind::Hvf,
            BackendKind::Wasm,
            BackendKind::WebLinux,
            BackendKind::AppleContainer,
        ];
        // Pin the labels a report is read against.
        assert_eq!(BackendKind::Hvf.as_str(), "hvf");
        assert_eq!(BackendKind::Firecracker.as_str(), "firecracker");
        assert_eq!(BackendKind::AppleContainer.as_str(), "apple-container");
        assert_eq!(BackendKind::WebLinux.as_str(), "web-linux");
        // Two backends sharing a label would silently merge their samples.
        for (i, a) in kinds.iter().enumerate() {
            for b in &kinds[i + 1..] {
                assert_ne!(a.as_str(), b.as_str(), "{a:?} and {b:?} share a label");
            }
        }
    }

    #[test]
    fn warm_launch_mode_defaults_to_optional_and_round_trips() {
        assert_eq!(WarmLaunchMode::default(), WarmLaunchMode::Optional);
        assert!(WarmLaunchMode::Required.requires_warm());
        assert!(!WarmLaunchMode::Optional.requires_warm());
        assert!(!WarmLaunchMode::Required.permits_cold());
        assert!(WarmLaunchMode::Cold.permits_cold());

        for mode in [
            WarmLaunchMode::Optional,
            WarmLaunchMode::Required,
            WarmLaunchMode::Cold,
        ] {
            let encoded = serde_json::to_string(&mode).expect("warm launch mode serializes");
            let decoded: WarmLaunchMode =
                serde_json::from_str(&encoded).expect("warm launch mode deserializes");
            assert_eq!(decoded, mode);
        }
    }

    #[test]
    fn warm_claim_refusal_keeps_capacity_and_failure_distinct() {
        let unavailable = WarmClaimRefusal::NoCompatibleParent;
        let rejected = WarmClaimRefusal::ClaimRejected {
            reason: "identity handshake failed".into(),
        };
        assert_ne!(unavailable, rejected);
        assert_eq!(
            unavailable.to_string(),
            "no compatible warm parent is available"
        );
        assert!(rejected.to_string().contains("identity handshake failed"));
        assert_eq!(
            WarmClaimOutcome::Refused(unavailable.clone()),
            WarmClaimOutcome::Refused(unavailable)
        );
    }

    #[test]
    fn warm_service_request_and_response_roundtrip_without_host_paths() {
        let compatibility = StandbyCompat {
            template_id: Some("python-312".into()),
            kernel_sha256: "aa".repeat(32),
            vcpus: 2,
            mem_mib: 128,
            image_sha256: Some("bb".repeat(32)),
            vsock_egress: false,
        };
        let request = WarmServiceRequest::Claim {
            request_id: "req-1".into(),
            lease_id: "lease-1".into(),
            mode: WarmLaunchMode::Required,
            compatibility,
        };
        let json = serde_json::to_string(&request).expect("warm request serializes");
        assert!(!json.contains("/") && !json.contains("host"));
        let decoded: WarmServiceRequest =
            serde_json::from_str(&json).expect("warm request deserializes");
        assert_eq!(decoded, request);

        let response = WarmServiceResponse::Refused {
            request_id: "req-1".into(),
            refusal: WarmClaimRefusal::NoCompatibleParent,
            timing: WarmClaimTiming {
                pool_wait_us: 12,
                claim_us: 0,
                warm_window_us: 12,
            },
        };
        let response_json = serde_json::to_string(&response).expect("warm response serializes");
        let decoded_response: WarmServiceResponse =
            serde_json::from_str(&response_json).expect("warm response deserializes");
        assert_eq!(decoded_response, response);

        let prewarm = WarmServiceRequest::Prewarm {
            request_id: "req-2".into(),
            source: WarmPrewarmSource::OciImage {
                reference: "python:3.12".into(),
            },
            artifact: WarmArtifactIdentity {
                backend: "hvf".into(),
                backend_version: "v1".into(),
                guest_agent_sha256: "aa".repeat(32),
                kernel_sha256: "bb".repeat(32),
                initramfs_sha256: "cc".repeat(32),
                rootfs_sha256: "dd".repeat(32),
                runtime_overlay_sha256: Some("ee".repeat(32)),
            },
            compatibility: StandbyCompat {
                template_id: None,
                kernel_sha256: "cc".repeat(32),
                vcpus: 2,
                mem_mib: 128,
                image_sha256: Some("dd".repeat(32)),
                vsock_egress: false,
            },
            target: 1,
        };
        let prewarm_json = serde_json::to_string(&prewarm).expect("prewarm serializes");
        assert!(!prewarm_json.contains("/"));
        assert_eq!(
            serde_json::from_str::<WarmServiceRequest>(&prewarm_json)
                .expect("prewarm deserializes"),
            prewarm
        );
    }

    #[test]
    fn warm_prewarm_source_rejects_empty_and_nul_identifiers() {
        assert!(
            WarmPrewarmSource::OciImage {
                reference: " ".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            WarmPrewarmSource::Template {
                template_id: "template\0id".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            WarmPrewarmSource::Template {
                template_id: "template-312".into()
            }
            .validate()
            .is_ok()
        );
    }
    use alloc::collections::BTreeSet;
    use alloc::vec;

    #[test]
    fn standby_handle_serde_roundtrip_and_compat_match() {
        let h = StandbyHandle {
            id: "standby-abc".into(),
            template_id: None,
            control_socket: "/p/standby-abc/control-deadbeef.sock".into(),
            pid: 4242,
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "deadbeef".repeat(8),
            spawned_unix_secs: 1_700_000_000,
            state: StandbyState::Idle,
            image_sha256: None,
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: StandbyHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "standby-abc");
        assert_eq!(back.state, StandbyState::Idle);
        assert_eq!(back.preloaded_child_vm_name, None);
        let want = StandbyCompat {
            template_id: None,
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: None,
            vsock_egress: false,
        };
        assert!(back.is_compatible(&want));
        // wrong kernel, wrong cpus, and wrong mem each break compat.
        assert!(!back.is_compatible(&StandbyCompat {
            kernel_sha256: "b".repeat(64),
            ..want.clone()
        }));
        assert!(!back.is_compatible(&StandbyCompat {
            vcpus: 4,
            ..want.clone()
        }));
        assert!(!back.is_compatible(&StandbyCompat {
            mem_mib: 2048,
            ..want.clone()
        }));
        // HVF image sha must match exactly: Some(a) ≠ None, Some(a) ≠ Some(b).
        let hvf_handle = StandbyHandle {
            image_sha256: Some("c".repeat(64)),
            ..h.clone()
        };
        let hvf_want = StandbyCompat {
            image_sha256: Some("c".repeat(64)),
            ..want.clone()
        };
        assert!(hvf_handle.is_compatible(&hvf_want));
        assert!(!hvf_handle.is_compatible(&want)); // None ≠ Some
        assert!(!hvf_handle.is_compatible(&StandbyCompat {
            image_sha256: Some("d".repeat(64)),
            ..want.clone()
        }));
        // Guest egress enablement partitions the pool in both directions: a
        // parent that booted no egress client cannot serve a launch whose guest
        // wants one (the child would silently have no network), and a parent
        // that booted one cannot serve a launch whose guest must not have it.
        assert!(!h.is_compatible(&StandbyCompat {
            vsock_egress: true,
            ..want.clone()
        }));
        let egress_parent = StandbyHandle {
            vsock_egress: true,
            ..h.clone()
        };
        assert!(!egress_parent.is_compatible(&want));
        assert!(egress_parent.is_compatible(&StandbyCompat {
            vsock_egress: true,
            ..want
        }));
    }

    #[test]
    fn standby_error_is_std_error() {
        fn assert_err<E: core::error::Error>(_: &E) {}
        assert_err(&StandbyError::Unsupported {
            backend: "x".into(),
        });
    }

    #[test]
    fn standby_state_parked_serde_roundtrips_snake_case() {
        let j = serde_json::to_string(&StandbyState::Parked).unwrap();
        assert_eq!(j, "\"parked\"");
        let back: StandbyState = serde_json::from_str("\"parked\"").unwrap();
        assert_eq!(back, StandbyState::Parked);
    }

    #[test]
    fn idle_and_parked_are_claimable_claimed_is_not() {
        assert!(StandbyState::Idle.is_claimable());
        assert!(StandbyState::Parked.is_claimable());
        assert!(!StandbyState::Claimed.is_claimable());
    }

    /// Old standby.json records written before the image_sha256 and
    /// vsock_egress fields were added must still deserialise cleanly via
    /// `#[serde(default)]`.
    #[test]
    fn standby_handle_old_record_without_image_sha_deserialises_as_none() {
        let old_json = r#"{
            "id": "standby-old",
            "control_socket": "/p/standby-old/control.sock",
            "pid": 9999,
            "kernel_sha256": "aabbcc",
            "vcpus": 2,
            "mem_mib": 1024,
            "binding_nonce": "deadbeef",
            "spawned_unix_secs": 1000,
            "state": "idle"
        }"#;
        let h: StandbyHandle = serde_json::from_str(old_json).unwrap();
        assert_eq!(h.image_sha256, None, "absent field must default to None");
        assert!(
            !h.vsock_egress,
            "a record from before the field existed booted no egress client"
        );
        assert_eq!(
            h.preloaded_child_vm_name, None,
            "a record from before the field existed has no preloaded child"
        );
        assert!(!h.is_saved_state(), "pid != 0 → live standby");
        // An old libkrun standby is compatible with a libkrun launch (both None).
        let want = StandbyCompat {
            template_id: None,
            kernel_sha256: "aabbcc".into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: None,
            vsock_egress: false,
        };
        assert!(h.is_compatible(&want));
        assert!(
            !h.is_compatible(&StandbyCompat {
                vsock_egress: true,
                ..want
            }),
            "an old record must never satisfy a launch whose guest needs egress"
        );
    }

    /// A saved-state standby uses pid=0 (no running supervisor) and must be
    /// treated as TTL-only by the liveness path (is_saved_state()).
    #[test]
    fn standby_handle_saved_state_pid_zero_flag() {
        let saved = StandbyHandle {
            id: "standby-hvf".into(),
            template_id: None,
            control_socket: "/p/standby-hvf/control.sock".into(),
            pid: 0,
            kernel_sha256: "cc".repeat(32),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: Some("dd".repeat(32)),
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        };
        assert!(saved.is_saved_state());
        // serde roundtrip preserves the image sha and pid=0.
        let json = serde_json::to_string(&saved).unwrap();
        let back: StandbyHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_sha256, Some("dd".repeat(32)));
        assert_eq!(back.pid, 0);
    }

    #[test]
    fn snapshot_capability_defaults_to_unsupported() {
        // The trait method defaults to this, so a backend that forgets to opt
        // in fails closed (no silent live-memory claim).
        assert_eq!(
            SnapshotCapability::default(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn snapshot_capability_labels_are_stable_tokens() {
        // doctor renders these per backend; keep them stable, lowercase,
        // delimiter-free tokens.
        assert_eq!(SnapshotCapability::LiveMemory.label(), "live-memory");
        assert_eq!(SnapshotCapability::SaveRestore.label(), "save-restore");
        assert_eq!(SnapshotCapability::DiskOnly.label(), "disk-only");
        assert_eq!(SnapshotCapability::Unsupported.label(), "unsupported");
    }

    #[test]
    fn snapshot_capability_satisfies_weaker_or_equal_requests() {
        use SnapshotCapability::*;
        // A tier satisfies its own request and any weaker one.
        assert!(LiveMemory.satisfies(LiveMemory));
        assert!(LiveMemory.satisfies(DiskOnly));
        assert!(SaveRestore.satisfies(DiskOnly));
        assert!(DiskOnly.satisfies(DiskOnly));
        // libkrun (DiskOnly) cannot honor a live-memory request — the C4 case.
        assert!(!DiskOnly.satisfies(LiveMemory));
        assert!(!DiskOnly.satisfies(SaveRestore));
        assert!(!Unsupported.satisfies(DiskOnly));
    }

    #[test]
    fn warm_start_error_unsupported_carries_tiers_and_hint() {
        let err = WarmStartError::Unsupported {
            requested: SnapshotCapability::LiveMemory,
            available: SnapshotCapability::DiskOnly,
            hint: "use `mvmctl up` for a cold boot".to_string(),
        };
        let msg = err.to_string();
        // Display names both tiers and surfaces the recovery action.
        assert!(msg.contains("live-memory"), "{msg}");
        assert!(msg.contains("disk-only"), "{msg}");
        assert!(msg.contains("mvmctl up"), "{msg}");
        // It's a real core error so callers can `?`/box it.
        let _: &dyn core::error::Error = &err;
    }

    #[test]
    fn reseed_status_resume_summary_is_honest_and_distinct() {
        // The resume verb prints this clause; each state must read differently
        // so the message reflects whether the guest actually reseeded.
        assert!(
            ReseedStatus::Rotated.resume_summary().contains("rotated"),
            "{}",
            ReseedStatus::Rotated.resume_summary()
        );
        assert!(
            ReseedStatus::NotRotated
                .resume_summary()
                .to_lowercase()
                .contains("not"),
            "{}",
            ReseedStatus::NotRotated.resume_summary()
        );
        let undel = ReseedStatus::Undelivered.resume_summary().to_lowercase();
        assert!(
            undel.contains("not delivered") || undel.contains("unreachable"),
            "{undel}"
        );
        let all = [
            ReseedStatus::Rotated.resume_summary(),
            ReseedStatus::NotRotated.resume_summary(),
            ReseedStatus::Undelivered.resume_summary(),
            ReseedStatus::NotApplicable.resume_summary(),
        ];
        let uniq: BTreeSet<_> = all.iter().collect();
        assert_eq!(uniq.len(), 4, "each reseed state must read differently");
    }

    #[test]
    fn warm_start_outcome_carries_id_and_reseed() {
        let o = WarmStartOutcome {
            id: VmId("vm".into()),
            reseed: ReseedStatus::Rotated,
        };
        assert_eq!(o.id.0, "vm");
        assert_eq!(o.reseed, ReseedStatus::Rotated);
    }

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
    fn encode_egress_ca_cmdline_empty_is_none() {
        assert!(encode_egress_ca_cmdline("").is_none());
    }

    #[test]
    fn encode_secret_env_cmdline_empty_is_none() {
        assert!(encode_secret_env_cmdline(&[]).is_none());
    }

    #[test]
    fn encode_secret_env_cmdline_round_trips_pairs_as_single_token() {
        let pairs = vec![
            ("API_KEY".to_string(), "mvm-secret-abc123".to_string()),
            ("DB_TOKEN".to_string(), "mvm-secret-def456".to_string()),
        ];
        let got = encode_secret_env_cmdline(&pairs).unwrap();
        assert!(got.starts_with("mvm.secret_env="));
        // Single cmdline token — no spaces/newlines survive.
        assert!(!got.contains(' ') && !got.contains('\n'));
        // The hex decodes back to the newline-joined `VAR=placeholder` blob.
        let hex = got.strip_prefix("mvm.secret_env=").unwrap();
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "API_KEY=mvm-secret-abc123\nDB_TOKEN=mvm-secret-def456"
        );
    }

    #[test]
    fn encode_egress_ca_cmdline_compacts_pem_body_as_single_token() {
        let pem = "-----BEGIN CERTIFICATE-----\nAB\nCD\n-----END CERTIFICATE-----\n";
        let got = encode_egress_ca_cmdline(pem).unwrap();
        assert_eq!(got, "mvm.egress_ca=pem:ABCD");
        // Single cmdline token — no spaces/newlines survive the compaction.
        assert!(!got.contains(' ') && !got.contains('\n'));
    }

    #[test]
    fn encode_runtime_source_policy_cmdline_round_trips_as_single_token() {
        let token = encode_runtime_source_policy_cmdline(RuntimeSourcePolicy::RequiredOverlay);
        assert_eq!(token, "mvm.runtime_source_policy=required_overlay");
        assert!(!token.contains(' '));
        let value = token
            .strip_prefix("mvm.runtime_source_policy=")
            .expect("token prefix");
        assert_eq!(
            RuntimeSourcePolicy::from_cmdline_value(value),
            Some(RuntimeSourcePolicy::RequiredOverlay)
        );
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
    fn shortfall_names_each_required_but_missing_capability() {
        // A backend advertising nothing cannot satisfy a run that requires
        // eager-CoW restore + vsock; the shortfall must name both so selection
        // fails closed with a recovery hint instead of silently degrading.
        let caps = VmCapabilities::default();
        let required = RequiredCapabilities {
            eager_cow_restore: true,
            vsock: true,
            ..Default::default()
        };

        let missing = caps.shortfall(&required);

        assert!(missing.contains(&"eager_cow_restore"));
        assert!(missing.contains(&"vsock"));
        assert!(!caps.satisfies(&required));
    }

    /// Capability-honesty selection over `no_routable_guest_nic`. A vsock-only
    /// backend (libkrun / HVF advertise this guarantee) satisfies a run that
    /// requires it, while a NIC-bearing backend (Firecracker / qemu) shortfalls
    /// and the diagnostic names the field so selection fails closed with a
    /// recovery hint instead of silently degrading onto a routable-NIC backend.
    /// The concrete per-backend values are witnessed in the backend crate; this
    /// pins the selection LOGIC over that renamed capability.
    #[test]
    fn no_routable_guest_nic_required_selects_only_vsock_only_backends() {
        let required = RequiredCapabilities {
            no_routable_guest_nic: true,
            ..Default::default()
        };

        // libkrun / HVF shape: no host-routable guest NIC ⇒ satisfied.
        let vsock_only = VmCapabilities {
            no_routable_guest_nic: true,
            ..VmCapabilities::default()
        };
        assert!(vsock_only.shortfall(&required).is_empty());
        assert!(vsock_only.satisfies(&required));

        // Firecracker / qemu shape: routable guest NIC ⇒ shortfall names the field.
        let nic_bearing = VmCapabilities {
            no_routable_guest_nic: false,
            ..VmCapabilities::default()
        };
        assert_eq!(
            nic_bearing.shortfall(&required),
            vec!["no_routable_guest_nic"]
        );
        assert!(!nic_bearing.satisfies(&required));
    }

    #[test]
    fn satisfies_when_backend_advertises_every_required_capability() {
        let caps = VmCapabilities {
            vsock: true,
            eager_cow_restore: true,
            host_vsock_proxy: true,
            ..VmCapabilities::default()
        };
        let required = RequiredCapabilities {
            vsock: true,
            eager_cow_restore: true,
            host_vsock_proxy: true,
            ..Default::default()
        };

        assert!(caps.shortfall(&required).is_empty());
        assert!(caps.satisfies(&required));
    }

    #[test]
    fn empty_requirement_is_satisfied_by_any_backend() {
        // A run requiring nothing must not be rejected.
        assert!(VmCapabilities::default().satisfies(&RequiredCapabilities::default()));
    }

    #[test]
    fn default_capabilities_forbid_production_ssh() {
        // The capability layer records the SSH ban: backends build their caps
        // from this default, so none advertises an in-guest SSH server unless a
        // future change explicitly (and visibly) flips it.
        assert!(!VmCapabilities::default().production_ssh);
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
        // `mvm_agentd::vsock::GUEST_AGENT_PORT`.
        let info = GuestChannelInfo::Vsock { cid: 3, port: 4242 };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: GuestChannelInfo = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            GuestChannelInfo::Vsock { cid: 3, port: 4242 }
        ));
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

    /// The audit label is what the chain-signed log records for the boot's
    /// runtime source. A blank or wrong label is a corrupt audit record,
    /// and every variant must be distinguishable from every other.
    #[test]
    fn runtime_source_audit_labels_are_exact_and_distinct() {
        assert_eq!(
            RuntimeSourcePolicy::RequiredOverlay.audit_label(),
            "required-overlay"
        );
        assert_eq!(
            RuntimeSourcePolicy::PreferOverlay.audit_label(),
            "prefer-overlay"
        );
        assert_eq!(RuntimeSourcePolicy::RootfsOnly.audit_label(), "rootfs-only");

        let labels = [
            RuntimeSourcePolicy::RequiredOverlay.audit_label(),
            RuntimeSourcePolicy::PreferOverlay.audit_label(),
            RuntimeSourcePolicy::RootfsOnly.audit_label(),
        ];
        for label in labels {
            assert!(!label.is_empty());
        }
        assert_ne!(labels[0], labels[1]);
        assert_ne!(labels[1], labels[2]);
        assert_ne!(labels[0], labels[2]);
    }

    /// Every cmdline spelling round-trips to its own variant. Dropping an
    /// arm makes that value unparseable, so the boot silently falls back to
    /// a runtime source the cmdline did not ask for.
    #[test]
    fn every_runtime_source_cmdline_value_round_trips() {
        for policy in [
            RuntimeSourcePolicy::RequiredOverlay,
            RuntimeSourcePolicy::PreferOverlay,
            RuntimeSourcePolicy::RootfsOnly,
        ] {
            assert_eq!(
                RuntimeSourcePolicy::from_cmdline_value(policy.cmdline_value()),
                Some(policy),
                "{} must parse back to itself",
                policy.cmdline_value()
            );
        }
        assert_eq!(RuntimeSourcePolicy::from_cmdline_value("nonsense"), None);
        assert_eq!(RuntimeSourcePolicy::from_cmdline_value(""), None);
        // The audit spelling is not the cmdline spelling; neither is accepted
        // in the other's place.
        assert_eq!(
            RuntimeSourcePolicy::from_cmdline_value("prefer-overlay"),
            None
        );
    }

    /// `is_microvm` gates the Tier 3 shared-kernel banner, so it must be a
    /// conjunction: any missing isolation layer means not a microVM. With
    /// a disjunction, a container that only clears the host-hypervisor
    /// layer reports as hardware-isolated and the banner never fires.
    #[test]
    fn is_microvm_requires_every_isolation_layer() {
        assert!(LayerCoverage::all_layers().is_microvm());

        let base = LayerCoverage::all_layers();
        for drop_one in [
            LayerCoverage {
                l1_host_hypervisor: false,
                ..base
            },
            LayerCoverage {
                l2_vmm: false,
                ..base
            },
            LayerCoverage {
                l3_guest_kernel: false,
                ..base
            },
        ] {
            assert!(
                !drop_one.is_microvm(),
                "a backend missing an isolation layer must not report as a microVM: {drop_one:?}"
            );
        }

        // The Tier 3 shape: only the host hypervisor, no VMM, no guest
        // kernel of its own.
        let shared_kernel = LayerCoverage {
            l1_host_hypervisor: true,
            l2_vmm: false,
            l3_guest_kernel: false,
            l4_guest_agent: true,
            l5_workload: true,
        };
        assert!(!shared_kernel.is_microvm());
    }
}
