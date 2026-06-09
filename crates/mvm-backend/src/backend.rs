use anyhow::Result;
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};

// W8: every backend variant + the FC support modules live in this
// crate now. `microvm`, `microvm_nix`, `image` are siblings under
// `crate::`; the substrate (`config`, `shell`, `runtime_meta`) lives
// in `mvm-base`.
use crate::apple_container::AppleContainerBackend;
use crate::base::config::{PortMapping, VMS_DIR};
use crate::base::shell::run_in_vm_stdout;
use crate::cloud_hypervisor::CloudHypervisorBackend;
use crate::docker::DockerBackend;
use crate::image::RuntimeVolume;
use crate::libkrun::LibkrunBackend;
use crate::microvm::{DriveFile, FlakeRunConfig};
use crate::mock::MockBackend;
use crate::qemu::QemuBackend;
use crate::vz::VzBackend;
use crate::{firecracker, microvm, microvm_nix};

pub use microvm_nix::{MicrovmNixBackend, MicrovmNixConfig};

/// Firecracker VM configuration for the [`VmBackend`] trait.
///
/// Wraps [`FlakeRunConfig`](microvm::FlakeRunConfig) which contains all
/// data needed for starting a Firecracker VM from Nix-built artifacts.
pub struct FirecrackerConfig {
    pub run_config: microvm::FlakeRunConfig,
}

impl FirecrackerConfig {
    /// Convert a backend-agnostic `VmStartConfig` into a Firecracker-specific
    /// `FlakeRunConfig`, allocating a network slot automatically.
    pub fn from_start_config(config: &VmStartConfig) -> Result<Self> {
        // Firecracker has no virtio-fs — a directory share can't be
        // attached. Disk-image volumes (host:/guest:SIZE) are fine.
        if let Some(v) = config
            .volumes
            .iter()
            .find(|v| matches!(v.kind, mvm_core::vm_backend::VmVolumeKind::DirShare))
        {
            anyhow::bail!(
                "Firecracker has no virtio-fs, so directory share '{}' -> '{}' isn't supported; \
                 use a disk-image volume instead (host:/guest:SIZE).",
                v.host,
                v.guest
            );
        }
        let slot = microvm::allocate_slot(&config.name)?;
        let run_config = FlakeRunConfig {
            name: config.name.clone(),
            slot,
            vmlinux_path: config.kernel_path.clone().unwrap_or_default(),
            initrd_path: config.initrd_path.clone(),
            rootfs_path: config.rootfs_path.clone(),
            verity_path: config.verity_path.clone(),
            roothash: config.roothash.clone(),
            runtime_overlay_path: config.runtime_overlay_path.clone(),
            runtime_overlay_verity_path: config.runtime_overlay_verity_path.clone(),
            runtime_overlay_roothash: config.runtime_overlay_roothash.clone(),
            revision_hash: config.revision_hash.clone(),
            flake_ref: config.flake_ref.clone(),
            profile: config.profile.clone(),
            cpus: config.cpus,
            memory: config.memory_mib,
            mem_initial: config.mem_initial_mib,
            volumes: config
                .volumes
                .iter()
                .map(|v| RuntimeVolume {
                    host: v.host.clone(),
                    guest: v.guest.clone(),
                    size: v.size.clone(),
                    read_only: v.read_only,
                    kind: v.kind,
                    encrypted: v.encrypted,
                })
                .collect(),
            config_files: config
                .config_files
                .iter()
                .map(|f| DriveFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            secret_files: config
                .secret_files
                .iter()
                .map(|f| DriveFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            ports: config
                .ports
                .iter()
                .map(|p| PortMapping {
                    host: p.host,
                    guest: p.guest,
                })
                .collect(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
        };
        Ok(Self { run_config })
    }
}

/// Firecracker backend implementation.
///
/// Wraps the existing free functions in [`microvm`] and [`firecracker`]
/// behind the [`VmBackend`] trait. This is a thin adapter — all real
/// work is delegated to the existing implementation.
pub struct FirecrackerBackend;

impl VmBackend for FirecrackerBackend {
    fn name(&self) -> &str {
        "firecracker"
    }

    fn capabilities(&self) -> VmCapabilities {
        // Firecracker ships a virtio-balloon device with PATCH-able
        // target via `/balloon`; the start path attaches it whenever
        // `VmStartConfig::mem_initial_mib` is `Some`. Capability is
        // advertised unconditionally so the host-side controller can
        // discover support before deciding to plumb a workload.
        VmCapabilities {
            pause_resume: true,
            snapshots: true,
            vsock: true,
            tap_networking: true,
            balloon: true,
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // Firecracker is the live-memory fast-resume backend (UFFD / NBD /
        // hugepages) — plan 123 C2.
        SnapshotCapability::LiveMemory
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        // Task 2.2 / ADR-072 — fail closed when KVM is absent rather than
        // letting the Firecracker boot fault deep in the API handshake.
        // Firecracker is the production runtime and *requires* `/dev/kvm`;
        // a no-KVM host should use `--hypervisor qemu` for local dev/test
        // (Tier-3 TCG), never a silent Firecracker fallback. On macOS the
        // runtime path nests through libkrun/Vz, so this probe is Linux-only.
        #[cfg(target_os = "linux")]
        if !crate::qemu::kvm_available() {
            anyhow::bail!(
                "Firecracker requires /dev/kvm, which is not available on this host. \
                 Firecracker is the production runtime; for local dev/test on a no-KVM \
                 host run with `--hypervisor qemu` (Tier-3 TCG software emulation, \
                 ADR-072). To run Firecracker, use a host with KVM enabled."
            );
        }
        let fc_config = FirecrackerConfig::from_start_config(config)?;
        // Thread the W6.2.1 sidecar into per-VM runtime metadata so
        // `mvmctl console` can enforce the accessible/sealed gate.
        // Best-effort: a malformed sidecar surfaces an error here
        // (build pipeline bug); a missing sidecar defaults to
        // accessible=true.
        let rootfs = std::path::Path::new(&config.rootfs_path);
        // Plan 74 W2 / ADR-051 admission gate — refuse pre-W1.4b
        // rootfs that lack the `/mvm/runtime` mount point. Runs
        // before `microvm::run_from_build` so a refusal exits
        // clean — no FC API socket, no VM dir half-populated.
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| std::path::Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;
        microvm::run_from_build(&fc_config.run_config)?;
        Ok(VmId(fc_config.run_config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        microvm::stop_vm(&id.0)
    }

    fn stop_all(&self) -> Result<()> {
        microvm::stop_all_vms()
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        microvm::pause_vm(&id.0)
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        microvm::resume_vm(&id.0)
    }

    fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> Result<()> {
        microvm::balloon_set_target(&id.0, target_inflate_mib)
    }

    fn balloon_state(&self, id: &VmId) -> Result<mvm_core::vm_backend::BalloonState> {
        let inflated = microvm::balloon_state(&id.0)?;
        // FC reports the inflation amount via /balloon; the cap is
        // tracked host-side in the VM's runtime metadata (RunInfo).
        // List the VM to recover its declared cap.
        let vms = microvm::list_vms()?;
        let info = vms
            .into_iter()
            .find(|i| i.name.as_deref() == Some(&*id.0))
            .ok_or_else(|| anyhow::anyhow!("balloon_state: VM '{}' not found in list", id.0))?;
        let max_mib = info.memory;
        Ok(mvm_core::vm_backend::BalloonState {
            max_mib,
            inflated_mib: inflated,
            host_committed_mib: max_mib.saturating_sub(inflated),
        })
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let vms = microvm::list_vms()?;
        match vms.iter().find(|info| info.name.as_deref() == Some(&*id.0)) {
            Some(_) => Ok(VmStatus::Running),
            None => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let vms = microvm::list_vms()?;
        Ok(vms
            .into_iter()
            .filter_map(|info| {
                let name = info.name.clone()?;
                Some(VmInfo {
                    id: VmId(name.clone()),
                    name,
                    status: VmStatus::Running,
                    guest_ip: info.guest_ip,
                    cpus: info.cpus,
                    memory_mib: info.memory,
                    profile: info.profile,
                    revision: info.revision,
                    flake_ref: info.flake_ref,
                    ports: Vec::new(),
                })
            })
            .collect())
    }

    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
        let abs_vms = abs_vms.trim();
        let filename = if hypervisor {
            "firecracker.log"
        } else {
            "console.log"
        };
        let log_file = format!("{}/{}/{}", abs_vms, id.0, filename);
        run_in_vm_stdout(&format!(
            "tail -n {} {} 2>/dev/null || true",
            lines, log_file
        ))
    }

    fn is_available(&self) -> Result<bool> {
        firecracker::is_installed()
    }

    fn install(&self) -> Result<()> {
        firecracker::install()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 1: full ADR-002. All seven CI-enforced claims hold.
        // Hardware isolation via KVM; verified boot via dm-verity (W3,
        // shipped 2026-04-30).
        BackendSecurityProfile {
            claims: [ClaimStatus::Holds; 7],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 1",
            notes: &[
                "Full ADR-002 — all seven CI-enforced claims hold.",
                "Hardware isolation via KVM. Verified boot via dm-verity (W3).",
            ],
        }
    }
}

/// Isolation tier of a `VmBackend`. Plan 76 Phase 7.
///
/// Captures the host/guest boundary strength so the CLI can refuse
/// to silently downgrade from a hardened production tier to a
/// developer-ergonomics tier when an operator asked for a
/// production-like launch.
///
/// **Tier 1** — Firecracker (with jailer + seccomp) and Cloud
/// Hypervisor (rust-vmm peer at the same maturity). The hardened
/// production posture: KVM-only, minimal device surface, audited
/// codebase, ADR-002 §W1–§W5 claims hold against this tier.
///
/// **Tier 2** — libkrun. Fast, well-engineered, but its host/guest
/// boundary is **not equivalent to Firecracker + jailer + seccomp**.
/// Best for local dev on macOS Apple Silicon (HVF) and builder VMs.
/// Plan 76 §"libkrun isolation is not Firecracker isolation": prod
/// selection must require explicit operator acknowledgement.
///
/// **Tier 3** — Docker, microvm.nix runner, Mock. Fallback or
/// test-only; `mvmctl up` emits a loud banner before using them.
/// Apple Container sits at Tier 3 today as well: while VZ provides
/// real virtualization, the security claims have not been audited
/// against ADR-002.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendTier {
    Tier1,
    Tier2,
    Tier3,
}

impl BackendTier {
    /// Short stable string for CLI / doctor output. Wire-stable —
    /// scripts grepping `mvmctl doctor` rely on these names.
    pub fn label(&self) -> &'static str {
        match self {
            BackendTier::Tier1 => "tier1-hardened",
            BackendTier::Tier2 => "tier2-fast-local",
            BackendTier::Tier3 => "tier3-fallback",
        }
    }
}

/// Backend-agnostic dispatch enum.
///
/// Wraps concrete backends so CLI commands don't need to know which
/// backend is active. Each variant delegates to its inner implementation.
pub enum AnyBackend {
    Firecracker(FirecrackerBackend),
    MicrovmNix(MicrovmNixBackend),
    AppleContainer(AppleContainerBackend),
    Docker(DockerBackend),
    /// libkrun (plan 53 §"Plan E") — Linux KVM / macOS Apple Silicon HVF.
    Libkrun(LibkrunBackend),
    /// Vz (Apple Virtualization.framework) — Plan 97 / ADR-056. Direct
    /// host-level Vz integration on macOS 13+; collapses the nested
    /// macOS → libkrun → Firecracker workload-microVM path. Opt-in via
    /// `--backend vz` / `MVM_BACKEND=vz`; `auto_select` keeps libkrun
    /// as the macOS default per Plan 97 §"Phase D".
    Vz(VzBackend),
    /// Cloud Hypervisor — rust-vmm peer of Firecracker at Tier 1. Adds
    /// VFIO passthrough, virtio-gpu, virtio-fs, and larger guests
    /// beyond what FC supports. Opt-in via `--hypervisor cloud-hypervisor`;
    /// auto_select keeps Firecracker as the KVM default.
    CloudHypervisor(CloudHypervisorBackend),
    /// QEMU workload runtime (Plan 166 Phase 2 / ADR-072) — Linux dev/test
    /// substrate (KVM where present, TCG fallback). Opt-in via
    /// `--hypervisor qemu` / `MVM_BACKEND=qemu`; `auto_select` never picks
    /// it (Firecracker stays the production runtime). Dev tier only,
    /// outside ADR-002 claims.
    Qemu(QemuBackend),
    /// In-memory mock — test-only. Records `start`/`stop`/`pause`/
    /// `resume` calls against a `Mutex<HashMap>` and never touches
    /// the host. Selected only via explicit `--hypervisor mock`;
    /// `auto_select` never falls through here. See
    /// [`crate::mock::MockBackend`] for the rationale and security
    /// profile (Tier 3 / claims unknown).
    Mock(MockBackend),
}

impl AnyBackend {
    /// Create the default backend (Firecracker).
    pub fn default_backend() -> Self {
        Self::Firecracker(FirecrackerBackend)
    }

    /// Select backend based on whether the build output includes a
    /// microvm.nix runner script.
    pub fn from_build_output(has_runner: bool) -> Self {
        if has_runner {
            Self::MicrovmNix(MicrovmNixBackend)
        } else {
            Self::Firecracker(FirecrackerBackend)
        }
    }

    /// Select backend by hypervisor name.
    ///
    /// Supported: `"firecracker"` (default), `"qemu"` (via microvm.nix),
    /// `"apple-container"` (macOS 26+), `"libkrun"` (Linux KVM / macOS
    /// HVF), `"docker"` (Tier 3 fallback). Unknown names fall back to
    /// Firecracker.
    pub fn from_hypervisor(name: &str) -> Self {
        match name {
            "apple-container" => Self::AppleContainer(AppleContainerBackend),
            "docker" => Self::Docker(DockerBackend),
            "libkrun" | "krun" => Self::Libkrun(LibkrunBackend),
            "vz" | "virtualization" => Self::Vz(VzBackend),
            "cloud-hypervisor" | "cloud_hypervisor" | "ch" | "clh" => {
                Self::CloudHypervisor(CloudHypervisorBackend)
            }
            // Plan 166 Phase 2 — `"qemu"` now routes to the real QEMU
            // workload backend, not the vestigial microvm.nix alias.
            // `MicrovmNixBackend` stays selectable via `from_build_output`
            // (a flake that emits a microvm.nix runner), not by name.
            "qemu" => Self::Qemu(QemuBackend),
            // Test-only in-memory backend. See `crate::mock`. Routing
            // here from a production caller is a misconfiguration, but
            // the explicit selector lets integration tests drive every
            // VM-lifecycle CLI verb hermetically.
            "mock" => Self::Mock(MockBackend::new()),
            _ => Self::Firecracker(FirecrackerBackend),
        }
    }

    /// Select the best backend for the current platform.
    ///
    /// Firecracker is the production target — it always wins when KVM
    /// is available. Non-KVM hosts continue down the fallback ladder.
    ///
    /// Priority:
    /// 1. **Firecracker** (if native Linux `/dev/kvm` is available — production Tier 1)
    /// 2. Apple Container (macOS 26+)
    /// 3. raw libkrun
    /// 4. Docker (Tier 3 fallback — banner emitted; not promoted)
    ///
    /// If none of the above match, the function returns Firecracker as
    /// the default — `start()` will then surface the host-side
    /// "Firecracker not available" error pointed at the production path,
    /// which is a clearer failure mode than picking a backend the
    /// caller didn't ask for.
    pub fn auto_select() -> Self {
        let plat = mvm_core::platform::current();

        // 1. Native Linux KVM → Firecracker directly (fastest — dev & production).
        //    WSL2 nested KVM is future/experimental and is not auto-selected today.
        if plat.supports_native_runner() {
            return Self::Firecracker(FirecrackerBackend);
        }

        // 2. macOS 26+ → Apple Virtualization.framework.
        if plat.has_apple_containers() {
            return Self::AppleContainer(AppleContainerBackend);
        }

        // 3. libkrun installed → use the raw libkrun shim.
        if plat.has_libkrun() {
            return Self::Libkrun(LibkrunBackend);
        }

        // 4. Docker available → universal Tier 3 fallback. The CLI emits
        //    a loud, suppressible banner when this path is taken (plan 53
        //    Plan B). Not preferred; only chosen when no microVM tier is
        //    available on this host.
        if plat.has_docker() {
            return Self::Docker(DockerBackend);
        }

        // Final default. Reachable when no tier is available; start()
        // then fails with the production-path error message rather than
        // silently picking a backend the caller didn't ask for.
        Self::Firecracker(FirecrackerBackend)
    }

    /// Resolve the backend that owns an already-started VM by its per-VM
    /// state-dir marker file, so `down` / `status` dispatch to the VMM that
    /// actually launched it rather than a platform default. The pid-file
    /// backends each drop a distinct marker under `vm_state_dir(name)`:
    /// QEMU `qemu.pid`, libkrun `libkrun.pid`, Firecracker `fc.pid`.
    ///
    /// Returns `None` when no marker is present — the VM isn't one of the
    /// pid-file backends (e.g. Apple Container / Docker, which track state
    /// out-of-band) or doesn't exist. Callers fall back to the platform
    /// default in that case.
    pub fn for_started_vm(name: &str) -> Option<Self> {
        let dir = mvm_core::config::vm_state_dir(name);
        if dir.join("qemu.pid").is_file() {
            Some(Self::Qemu(QemuBackend))
        } else if dir.join("libkrun.pid").is_file() {
            Some(Self::Libkrun(LibkrunBackend))
        } else if dir.join("fc.pid").is_file() {
            Some(Self::Firecracker(FirecrackerBackend))
        } else {
            None
        }
    }

    /// Aggregate the running-VM listing across every backend that can be
    /// probed on this host (best-effort; a backend that errors is skipped).
    /// Single source of truth for `mvmctl ls` and `mvmctl down` (no-arg) so
    /// a VM started under any VMM — including QEMU and libkrun — is visible
    /// and stoppable, not just whichever backend the CLI defaulted to.
    pub fn list_all() -> Vec<VmInfo> {
        let mut vms = Vec::new();
        for backend in [
            Self::Qemu(QemuBackend),
            Self::Libkrun(LibkrunBackend),
            Self::Firecracker(FirecrackerBackend),
            Self::AppleContainer(AppleContainerBackend),
            Self::Docker(DockerBackend),
        ] {
            if let Ok(found) = backend.list() {
                vms.extend(found);
            }
        }
        vms
    }

    /// Plan 76 Phase 7 — isolation tier of this backend. Used by
    /// `mvmctl up` to refuse silent Tier 2 downgrades on
    /// production-like launches, and by `mvmctl doctor` to surface
    /// what's actually running on the host.
    ///
    /// Classification mirrors each backend's existing
    /// `BackendSecurityProfile.tier` (`crates/mvm-backend/src/*.rs::security_profile`),
    /// the long-standing per-backend declaration consulted by
    /// `mvmctl doctor --json::security_posture.tier`. A test below
    /// asserts the two stay in sync; bumping one without the other
    /// fails CI.
    pub fn tier(&self) -> BackendTier {
        match self {
            // Tier 1: hardened production. Firecracker (with
            // jailer + seccomp) and Cloud Hypervisor (peer at the
            // same maturity).
            Self::Firecracker(_) | Self::CloudHypervisor(_) => BackendTier::Tier1,

            // Tier 2: fast local. libkrun's host/guest boundary
            // is well-engineered but not equivalent to
            // Firecracker + jailer + seccomp; plan 76 §"libkrun
            // isolation is not Firecracker isolation". Apple
            // Container (Virtualization.framework) and microvm.nix
            // (qemu) also sit here per their existing
            // `BackendSecurityProfile.tier` strings.
            // QEMU: best-case Tier 2 (KVM-accelerated). The TCG (no-KVM)
            // mode is a runtime Tier-3 degradation surfaced by the QEMU
            // backend's `start` banner + doctor, not by this compile-time
            // classification (Plan 166 / ADR-072).
            Self::Libkrun(_)
            | Self::AppleContainer(_)
            | Self::MicrovmNix(_)
            | Self::Vz(_)
            | Self::Qemu(_) => BackendTier::Tier2,

            // Tier 3: fallback / test. Docker is a userspace
            // container fallback; Mock is in-memory test-only.
            Self::Docker(_) | Self::Mock(_) => BackendTier::Tier3,
        }
    }

    /// Dispatch helper — returns a `&dyn VmBackend` for the inner backend.
    fn inner(&self) -> &dyn VmBackend {
        match self {
            Self::Firecracker(b) => b,
            Self::MicrovmNix(b) => b,
            Self::AppleContainer(b) => b,
            Self::Docker(b) => b,
            Self::Libkrun(b) => b,
            Self::Vz(b) => b,
            Self::CloudHypervisor(b) => b,
            Self::Qemu(b) => b,
            Self::Mock(b) => b,
        }
    }

    pub fn name(&self) -> &str {
        self.inner().name()
    }

    pub fn capabilities(&self) -> VmCapabilities {
        self.inner().capabilities()
    }

    pub fn snapshot_capability(&self) -> SnapshotCapability {
        self.inner().snapshot_capability()
    }

    /// Warm-start a VM at (at least) the requested snapshot tier. See
    /// [`VmBackend::warm_start`] — fails closed with a typed error on an
    /// over-request rather than degrading to a cold boot (plan 123 C4).
    pub fn warm_start(
        &self,
        config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<VmId, mvm_core::vm_backend::WarmStartError> {
        self.inner().warm_start(config, requested)
    }

    /// Start a VM using the backend-agnostic config.
    ///
    /// Each backend converts `VmStartConfig` into its own internal
    /// configuration (e.g., Firecracker allocates a VmSlot and builds
    /// a `FlakeRunConfig`; Apple Container creates a LinuxContainer).
    pub fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.inner().start(config)
    }

    /// Start a VM using a pre-built `FirecrackerConfig`.
    ///
    /// This is a convenience method for callers that already have a
    /// `FlakeRunConfig` (e.g., template snapshot restore). Prefer
    /// [`start`](Self::start) for new VMs.
    pub fn start_firecracker(&self, config: &FirecrackerConfig) -> Result<VmId> {
        match self {
            Self::Firecracker(_) => {
                microvm::run_from_build(&config.run_config)?;
                Ok(VmId(config.run_config.name.clone()))
            }
            _ => {
                anyhow::bail!(
                    "Cannot start Firecracker config with {} backend",
                    self.name()
                )
            }
        }
    }

    pub fn stop(&self, id: &VmId) -> Result<()> {
        self.inner().stop(id)
    }

    /// Block until a VM exits and return its captured exit status.
    /// Plan 152 WS-A Task 3.1. Delegates to the inner backend; only
    /// libkrun (and mock) implement a real wait surface — other backends
    /// return a clear bail via the default VmBackend impl.
    pub fn wait(&self, id: &VmId) -> Result<mvm_core::vm_backend::VmExitStatus> {
        self.inner().wait(id)
    }

    pub fn stop_all(&self) -> Result<()> {
        self.inner().stop_all()
    }

    /// Pause the vCPUs of a running VM. See [`VmBackend::pause`].
    pub fn pause(&self, id: &VmId) -> Result<()> {
        self.inner().pause(id)
    }

    /// Resume a paused VM. See [`VmBackend::resume`].
    pub fn resume(&self, id: &VmId) -> Result<()> {
        self.inner().resume(id)
    }

    /// Set the virtio-balloon inflation target. See
    /// [`VmBackend::balloon_set_target`].
    pub fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> Result<()> {
        self.inner().balloon_set_target(id, target_inflate_mib)
    }

    /// Read the current balloon state. See [`VmBackend::balloon_state`].
    pub fn balloon_state(&self, id: &VmId) -> Result<mvm_core::vm_backend::BalloonState> {
        self.inner().balloon_state(id)
    }

    pub fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.inner().status(id)
    }

    pub fn list(&self) -> Result<Vec<VmInfo>> {
        self.inner().list()
    }

    pub fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        self.inner().logs(id, lines, hypervisor)
    }

    pub fn is_available(&self) -> Result<bool> {
        self.inner().is_available()
    }

    pub fn install(&self) -> Result<()> {
        self.inner().install()
    }

    pub fn security_profile(&self) -> BackendSecurityProfile {
        self.inner().security_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firecracker_backend_name() {
        let backend = FirecrackerBackend;
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_firecracker_capabilities() {
        let backend = FirecrackerBackend;
        let caps = backend.capabilities();
        assert!(caps.pause_resume);
        assert!(caps.snapshots);
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn test_firecracker_security_profile_tier_1_holds_all_claims() {
        let backend = FirecrackerBackend;
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 1");
        assert!(profile.layer_coverage.is_microvm());
        assert!(profile.dropped_claims().is_empty());
        assert!(profile.na_claims().is_empty());
        assert!(
            profile
                .claims
                .iter()
                .all(|s| matches!(s, ClaimStatus::Holds))
        );
    }

    #[test]
    fn test_microvm_nix_backend_name() {
        let backend = MicrovmNixBackend;
        assert_eq!(backend.name(), "microvm-nix");
    }

    #[test]
    fn test_microvm_nix_capabilities() {
        let backend = MicrovmNixBackend;
        let caps = backend.capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn test_microvm_nix_security_profile_tier_2_partial_claim_3() {
        let backend = MicrovmNixBackend;
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        assert_eq!(profile.dropped_claims(), vec![3]);
    }

    #[test]
    fn test_any_backend_dispatches_security_profile_for_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 1");
    }

    #[test]
    fn test_any_backend_dispatches_security_profile_for_docker() {
        let backend = AnyBackend::from_hypervisor("docker");
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 3");
        assert!(!profile.layer_coverage.is_microvm());
    }

    #[test]
    fn test_any_backend_from_hypervisor_vz() {
        // Plan 97 Phase B — `--backend vz` and the longer
        // `--backend virtualization` both route to the new Vz backend.
        // `auto_select()` itself stays unchanged on macOS (libkrun
        // remains the default per the user's "don't replace libkrun"
        // instruction).
        for alias in ["vz", "virtualization"] {
            let backend = AnyBackend::from_hypervisor(alias);
            assert!(matches!(backend, AnyBackend::Vz(_)), "alias {alias}");
            assert_eq!(backend.name(), "vz");
            assert_eq!(backend.tier(), BackendTier::Tier2);
        }
    }

    #[test]
    fn test_any_backend_from_hypervisor_libkrun() {
        // Both `libkrun` and `krun` aliases route to the same backend
        // — `krun` is the libkrun project's preferred short name and
        // appears in some user docs.
        for name in ["libkrun", "krun"] {
            let backend = AnyBackend::from_hypervisor(name);
            assert_eq!(backend.name(), "libkrun");
        }
    }

    #[test]
    fn test_any_backend_libkrun_is_tier_2() {
        let backend = AnyBackend::from_hypervisor("libkrun");
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        assert_eq!(profile.dropped_claims(), vec![3]);
    }

    #[test]
    fn test_any_backend_default_is_firecracker() {
        let backend = AnyBackend::default_backend();
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_build_output_no_runner() {
        let backend = AnyBackend::from_build_output(false);
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_build_output_with_runner() {
        let backend = AnyBackend::from_build_output(true);
        assert_eq!(backend.name(), "microvm-nix");
    }

    #[test]
    fn test_any_backend_from_hypervisor_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_hypervisor_qemu() {
        // Plan 166 Phase 2 — `"qemu"` routes to the real QEMU workload
        // backend, not the retired microvm.nix alias.
        let backend = AnyBackend::from_hypervisor("qemu");
        assert_eq!(backend.name(), "qemu");
        assert!(matches!(backend, AnyBackend::Qemu(_)));
    }

    #[test]
    fn microvm_nix_no_longer_reachable_by_name() {
        // The "qemu" alias was retired; MicrovmNix is selected via
        // `from_build_output(true)`, never by hypervisor name.
        assert_eq!(AnyBackend::from_build_output(true).name(), "microvm-nix");
        assert_ne!(AnyBackend::from_hypervisor("qemu").name(), "microvm-nix");
    }

    #[test]
    fn test_any_backend_from_hypervisor_unknown_defaults() {
        let backend = AnyBackend::from_hypervisor("unknown");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_hypervisor_cloud_hypervisor() {
        // CH is selectable under multiple aliases — full name, the
        // snake-case form some tooling emits, and two short aliases
        // (ch / clh) common in cloud-hypervisor's own docs.
        for alias in ["cloud-hypervisor", "cloud_hypervisor", "ch", "clh"] {
            let backend = AnyBackend::from_hypervisor(alias);
            assert_eq!(
                backend.name(),
                "cloud-hypervisor",
                "alias `{alias}` must resolve to cloud-hypervisor"
            );
        }
    }

    #[test]
    fn test_cloud_hypervisor_via_any_backend_security_profile_tier_1() {
        // Same Tier-1 posture as Firecracker (rust-vmm; passes the
        // fork test). Regression-guard against AnyBackend silently
        // dropping the variant from inner().
        let backend = AnyBackend::from_hypervisor("cloud-hypervisor");
        let p = backend.security_profile();
        assert_eq!(p.tier, "Tier 1");
        assert!(p.layer_coverage.is_microvm());
    }

    #[test]
    fn test_any_backend_capabilities() {
        let backend = AnyBackend::default_backend();
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn test_any_backend_from_hypervisor_apple_container() {
        let backend = AnyBackend::from_hypervisor("apple-container");
        assert_eq!(backend.name(), "apple-container");
    }

    #[test]
    fn test_apple_container_via_any_backend_capabilities() {
        let backend = AnyBackend::from_hypervisor("apple-container");
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(!caps.snapshots);
        assert!(!caps.tap_networking);
        assert!(!caps.pause_resume);
    }

    #[test]
    fn test_apple_container_via_any_backend_list_empty() {
        // Isolate HOME so the persisted ~/.mvm/vms registry doesn't bleed
        // into this assertion when the developer's real dev VM is running.
        let temp = std::path::PathBuf::from(format!(
            "/tmp/mvmac-anybe-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&temp).expect("create temp HOME");
        let saved = std::env::var("HOME").ok();
        // SAFETY: list() is the only HOME consumer in this test; no other
        // threads in this test process race with it.
        unsafe { std::env::set_var("HOME", &temp) };

        let backend = AnyBackend::from_hypervisor("apple-container");
        let vms = backend.list().unwrap();
        assert!(vms.is_empty());

        unsafe {
            match saved {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn for_started_vm_resolves_owning_backend_by_marker() {
        // A started VM's owning backend is resolved from its state-dir pid
        // marker so `down`/`status`/`ls` dispatch to the right VMM.
        let temp = std::path::PathBuf::from(format!(
            "/tmp/mvmac-fsv-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let vms = temp.join(".mvm/vms");
        for (name, marker) in [("q1", "qemu.pid"), ("l1", "libkrun.pid"), ("f1", "fc.pid")] {
            std::fs::create_dir_all(vms.join(name)).expect("mkdir vm dir");
            std::fs::write(vms.join(name).join(marker), "123").expect("write marker");
        }
        let saved = std::env::var("HOME").ok();
        // SAFETY: for_started_vm (HOME consumer) is the only env reader in
        // this test; restored below.
        unsafe { std::env::set_var("HOME", &temp) };

        let q = AnyBackend::for_started_vm("q1");
        let l = AnyBackend::for_started_vm("l1");
        let f = AnyBackend::for_started_vm("f1");
        let none = AnyBackend::for_started_vm("does-not-exist");

        unsafe {
            match saved {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&temp);

        assert!(matches!(q, Some(AnyBackend::Qemu(_))), "qemu.pid → Qemu");
        assert!(
            matches!(l, Some(AnyBackend::Libkrun(_))),
            "libkrun.pid → Libkrun"
        );
        assert!(
            matches!(f, Some(AnyBackend::Firecracker(_))),
            "fc.pid → Firecracker"
        );
        assert!(none.is_none(), "no marker → None");
    }

    #[test]
    fn test_any_backend_from_hypervisor_docker() {
        let backend = AnyBackend::from_hypervisor("docker");
        assert_eq!(backend.name(), "docker");
    }

    #[test]
    fn test_docker_via_any_backend_capabilities() {
        let backend = AnyBackend::from_hypervisor("docker");
        let caps = backend.capabilities();
        assert!(caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn test_auto_select_returns_valid_backend() {
        let backend = AnyBackend::auto_select();
        let name = backend.name();
        assert!(
            // The full set of legitimate auto_select returns is:
            matches!(
                name,
                "firecracker" | "apple-container" | "libkrun" | "docker"
            ),
            "auto_select returned unexpected backend: {name}"
        );
    }

    // ------------------------------------------------------------------
    // pause/resume — Track B / PR 1a coverage
    //
    // Backends that don't support pause/resume (capabilities.pause_resume
    // == false) must surface a clear, named bail. Backends that *do*
    // support it (Firecracker, Cloud Hypervisor, Docker) have real impls
    // that talk to a live VMM and aren't exercised here — see their
    // module-level tests for input-validation coverage.
    // ------------------------------------------------------------------

    fn assert_unsupported_pause_resume(backend: AnyBackend, expected_name: &str) {
        let id = VmId("nonexistent".into());
        let pause_err = backend
            .pause(&id)
            .expect_err("pause must bail when unsupported");
        let resume_err = backend
            .resume(&id)
            .expect_err("resume must bail when unsupported");
        let pause_msg = pause_err.to_string().to_lowercase();
        let resume_msg = resume_err.to_string().to_lowercase();
        assert!(
            pause_msg.contains("not supported") && pause_msg.contains(expected_name),
            "pause bail must mention 'not supported' and backend name '{expected_name}', got: {pause_err}"
        );
        assert!(
            resume_msg.contains("not supported") && resume_msg.contains(expected_name),
            "resume bail must mention 'not supported' and backend name '{expected_name}', got: {resume_err}"
        );
    }

    #[test]
    fn pause_resume_unsupported_on_libkrun() {
        assert_unsupported_pause_resume(AnyBackend::from_hypervisor("libkrun"), "libkrun");
    }

    #[test]
    fn pause_resume_unsupported_on_microvm_nix() {
        // MicrovmNix is no longer reachable by name; construct it directly.
        assert_unsupported_pause_resume(AnyBackend::MicrovmNix(MicrovmNixBackend), "microvm-nix");
    }

    #[test]
    fn pause_resume_unsupported_on_qemu() {
        assert_unsupported_pause_resume(AnyBackend::from_hypervisor("qemu"), "qemu");
    }

    #[test]
    fn pause_resume_unsupported_on_apple_container() {
        assert_unsupported_pause_resume(
            AnyBackend::from_hypervisor("apple-container"),
            "apple-container",
        );
    }

    #[test]
    fn snapshot_capability_live_memory_on_firecracker() {
        assert_eq!(
            AnyBackend::from_hypervisor("firecracker").snapshot_capability(),
            SnapshotCapability::LiveMemory
        );
    }

    #[test]
    fn snapshot_capability_disk_only_on_libkrun() {
        assert_eq!(
            AnyBackend::from_hypervisor("libkrun").snapshot_capability(),
            SnapshotCapability::DiskOnly
        );
    }

    #[test]
    fn snapshot_capability_unsupported_on_microvm_nix() {
        // MicrovmNix is no longer reachable by name (the "qemu" alias was
        // retired in Plan 166 Phase 2); construct it directly.
        assert_eq!(
            AnyBackend::MicrovmNix(MicrovmNixBackend).snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn snapshot_capability_disk_only_on_qemu() {
        // QEMU warm-start is a disk-image fast reboot (no live-memory QMP
        // snapshot wired) — same posture as libkrun.
        assert_eq!(
            AnyBackend::from_hypervisor("qemu").snapshot_capability(),
            SnapshotCapability::DiskOnly
        );
    }

    #[test]
    fn libkrun_warm_start_refuses_live_memory_with_recovery_hint() {
        // A live-memory warm-start asked of libkrun's disk-only tier must
        // fail closed (no cold-boot fallback) and name a recovery action —
        // plan 123 C4 / ADR-053. The Unsupported branch returns before any
        // boot, so this needs no VM/KVM.
        use mvm_core::vm_backend::WarmStartError;
        let cfg = VmStartConfig {
            name: "warm-gate-test".into(),
            rootfs_path: "/nonexistent/rootfs.ext4".into(),
            ..Default::default()
        };
        match AnyBackend::from_hypervisor("libkrun")
            .warm_start(&cfg, SnapshotCapability::LiveMemory)
        {
            Err(WarmStartError::Unsupported {
                requested,
                available,
                hint,
            }) => {
                assert_eq!(requested, SnapshotCapability::LiveMemory);
                assert_eq!(available, SnapshotCapability::DiskOnly);
                assert!(
                    hint.contains("Firecracker") || hint.contains("Vz"),
                    "{hint}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_capability_vz_tracks_macos_support() {
        // SaveRestore on macOS 26+, Unsupported elsewhere — never silently
        // LiveMemory/DiskOnly. (Runs on Linux CI, where it's Unsupported.)
        let cap = AnyBackend::from_hypervisor("vz").snapshot_capability();
        assert!(matches!(
            cap,
            SnapshotCapability::SaveRestore | SnapshotCapability::Unsupported
        ));
    }

    #[test]
    fn pause_resume_capability_flag_matches_backend_disposition() {
        // The capability flag and the method behavior must agree —
        // a backend reporting `pause_resume: true` must not bail with
        // "not supported"; one reporting `false` must.
        //
        // We can't *successfully* call pause/resume here without a
        // live VM, but we can check that the bail (if any) for a
        // missing VM does NOT claim the backend itself is unsupported
        // when the capability says it is.
        let unsupported: &[&str] = &[
            "libkrun",
            "qemu", // → microvm-nix
            "apple-container",
        ];
        for &name in unsupported {
            let b = AnyBackend::from_hypervisor(name);
            assert!(
                !b.capabilities().pause_resume,
                "{name}: capability flag must say pause_resume=false (matches bail in pause/resume)"
            );
        }
        for name in ["firecracker", "cloud-hypervisor", "docker"] {
            let b = AnyBackend::from_hypervisor(name);
            assert!(
                b.capabilities().pause_resume,
                "{name}: capability flag must say pause_resume=true (matches the real impl)"
            );
        }
    }

    // Plan 76 Phase 7 — BackendTier coverage.

    #[test]
    fn tier_classification_locks_each_backend_variant() {
        let cases: &[(&str, BackendTier)] = &[
            ("firecracker", BackendTier::Tier1),
            ("cloud-hypervisor", BackendTier::Tier1),
            ("libkrun", BackendTier::Tier2),
            ("apple-container", BackendTier::Tier2),
            ("qemu", BackendTier::Tier2),
            ("docker", BackendTier::Tier3),
            ("mock", BackendTier::Tier3),
        ];
        for (name, expected) in cases {
            let b = AnyBackend::from_hypervisor(name);
            assert_eq!(b.tier(), *expected, "{name}: tier mismatch");
        }
    }

    #[test]
    fn tier_matches_existing_backend_security_profile_string() {
        // The `BackendSecurityProfile.tier` field (consulted by
        // `mvmctl doctor --json::security_posture.tier`) is the
        // long-standing per-backend tier declaration. `AnyBackend::tier()`
        // is the Plan 76 Phase 7 closed-enum view of the same fact.
        // Bumping one without the other is a regression — keep them
        // wired.
        let names = [
            "firecracker",
            "cloud-hypervisor",
            "libkrun",
            "apple-container",
            "qemu",
            "docker",
            "mock",
        ];
        for name in names {
            let b = AnyBackend::from_hypervisor(name);
            let enum_tier = b.tier();
            let profile_tier = b.security_profile().tier;
            // The profile tier is a `&'static str` like "Tier 1" or
            // "Tier 3 (test-only)"; reduce to the leading "Tier N"
            // prefix and assert it agrees with the enum.
            let expected_prefix = match enum_tier {
                BackendTier::Tier1 => "Tier 1",
                BackendTier::Tier2 => "Tier 2",
                BackendTier::Tier3 => "Tier 3",
            };
            assert!(
                profile_tier.starts_with(expected_prefix),
                "{name}: AnyBackend::tier() = {:?}; \
                 BackendSecurityProfile.tier = {:?} — drift; \
                 update one to match the other.",
                enum_tier,
                profile_tier
            );
        }
    }

    #[test]
    fn tier_label_is_wire_stable() {
        // `mvmctl doctor`'s text output and any downstream scripts
        // grep these strings. A rename here is a wire change.
        assert_eq!(BackendTier::Tier1.label(), "tier1-hardened");
        assert_eq!(BackendTier::Tier2.label(), "tier2-fast-local");
        assert_eq!(BackendTier::Tier3.label(), "tier3-fallback");
    }
}
