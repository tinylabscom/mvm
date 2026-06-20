use crate::catalog;
use anyhow::Result;
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};

// Every backend variant + the FC support modules live in this crate.
// `microvm`, `image` are siblings under `crate::`; the substrate
// (`config`, `shell`, `runtime_meta`) lives in `crate::base`.
use crate::base::config::{PortMapping, VMS_DIR};
use crate::base::shell::run_in_vm_stdout;
use crate::image::RuntimeVolume;
use crate::libkrun::LibkrunBackend;
use crate::microvm::{DriveFile, FlakeRunConfig};
use crate::mock::MockBackend;
use crate::qemu::QemuBackend;
use crate::vz::VzBackend;
use crate::{firecracker, microvm};

/// Firecracker VM configuration for the [`VmBackend`] trait.
///
/// Wraps `FlakeRunConfig` which contains all
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
            network_policy: config.network_policy.clone(),
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
            fs_quick_checkpoint: false,
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // Firecracker is the live-memory fast-resume backend (UFFD / NBD /
        // hugepages).
        SnapshotCapability::LiveMemory
    }

    fn warm_start(
        &self,
        config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<VmId, mvm_core::vm_backend::WarmStartError> {
        use mvm_core::vm_backend::WarmStartError;
        // Fail closed on an over-request rather than silently degrading — the
        // same gate the trait default applies (C4).
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
        // Mint a fresh generation token so two clones of one snapshot reseed to
        // distinct CSPRNG state, then load + resume + deliver it.
        let token = mvm_core::crypto::vmgenid::fresh_generation_token(&config.name).token;
        microvm::warm_restore_instance(&config.name, token)
            .map_err(|e| WarmStartError::Failed(format!("{e:#}")))?;
        Ok(VmId(config.name.clone()))
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        // Fail closed when KVM is absent rather than letting the
        // Firecracker boot fault deep in the API handshake. Firecracker
        // is the production runtime and *requires* `/dev/kvm`; a no-KVM
        // host should use `--hypervisor qemu` for local dev/test
        // (Tier-3 TCG), never a silent Firecracker fallback. On macOS
        // the runtime path nests through libkrun/Vz, so this probe is
        // Linux-only.
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
        // Thread the sidecar into per-VM runtime metadata so
        // `mvmctl console` can enforce the accessible/sealed gate.
        // Best-effort: a malformed sidecar surfaces an error here
        // (build pipeline bug); a missing sidecar defaults to
        // accessible=true.
        let rootfs = std::path::Path::new(&config.rootfs_path);
        // Admission gate — refuse older rootfs that lack the
        // `/mvm/runtime` mount point. Runs before
        // `microvm::run_from_build` so a refusal exits clean — no FC
        // API socket, no VM dir half-populated.
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| std::path::Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;
        let mut slot_reservation = microvm::SlotReservationGuard::new(&fc_config.run_config.slot);
        microvm::run_from_build(&fc_config.run_config)?;
        slot_reservation.defuse();
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
        // Tier 1: full security posture. All seven CI-enforced claims
        // hold. Hardware isolation via KVM; verified boot via
        // dm-verity.
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

/// Isolation tier of a `VmBackend`.
///
/// Captures the host/guest boundary strength so the CLI can refuse
/// to silently downgrade from a hardened production tier to a
/// developer-ergonomics tier when an operator asked for a
/// production-like launch.
///
/// **Tier 1** — Firecracker (with jailer + seccomp) and Cloud
/// Hypervisor (rust-vmm peer at the same maturity). The hardened
/// production posture: KVM-only, minimal device surface, audited
/// codebase, the full security claim set holds against this tier.
///
/// **Tier 2** — libkrun. Fast, well-engineered, but its host/guest
/// boundary is **not equivalent to Firecracker + jailer + seccomp**.
/// Best for local dev on macOS Apple Silicon (HVF) and builder VMs.
/// Prod selection must require explicit operator acknowledgement.
///
/// **Tier 3** — Mock, test-only.
/// Apple Container sits at Tier 3 today as well: while VZ provides
/// real virtualization, the security claims have not been audited.
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
    /// libkrun — Linux KVM / macOS Apple Silicon HVF.
    Libkrun(LibkrunBackend),
    /// Vz — the one Apple Virtualization.framework backend (per-VM Rust
    /// objc2 supervisor: snapshot/restore, pause/resume, flow-audited
    /// networking). The macOS-26 auto-default; opt-in elsewhere via
    /// `--hypervisor vz` / `MVM_BACKEND=vz`.
    Vz(VzBackend),
    /// QEMU workload runtime — Linux dev/test substrate (KVM where
    /// present, TCG fallback). Opt-in via `--hypervisor qemu` /
    /// `MVM_BACKEND=qemu`; `auto_select` never picks it (Firecracker
    /// stays the production runtime). Dev tier only, outside the
    /// security claims.
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

    /// Select backend based on whether the build output is a non-KVM
    /// dev/test runner. A runner-style output routes to the QEMU dev/test
    /// backend (TCG where KVM is absent); otherwise Firecracker.
    pub fn from_build_output(has_runner: bool) -> Self {
        if has_runner {
            Self::Qemu(QemuBackend)
        } else {
            Self::Firecracker(FirecrackerBackend)
        }
    }

    /// Select backend by hypervisor name.
    ///
    /// Supported: `"firecracker"` (default), `"qemu"` (Linux dev/test),
    /// `"vz"` (Apple Virtualization.framework, macOS), `"libkrun"`
    /// (Linux KVM / macOS HVF). Unknown names fall back to Firecracker.
    pub fn from_hypervisor(name: &str) -> Self {
        catalog::descriptor_for_selector(name)
            .map(|descriptor| descriptor.instantiate())
            .unwrap_or_else(Self::default_backend)
    }

    /// Select the best backend for the current platform.
    ///
    /// Firecracker is the production target — it always wins when KVM
    /// is available. Non-KVM hosts continue down the fallback ladder.
    ///
    /// Priority:
    /// 1. **Firecracker** (if native Linux `/dev/kvm` is available — production Tier 1)
    /// 2. Vz — Apple Virtualization.framework (macOS 13+)
    /// 3. raw libkrun
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

        // 2. macOS 26+ → Apple Virtualization.framework via the vz supervisor.
        if plat.is_vz_default_tier() {
            return Self::Vz(VzBackend);
        }

        // 3. libkrun installed → use the raw libkrun shim.
        if plat.has_libkrun() {
            return Self::Libkrun(LibkrunBackend);
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
    /// QEMU `qemu.pid`, libkrun `libkrun.pid`, Firecracker `fc.pid`, Vz `vz.pid`.
    ///
    /// Returns `None` when no marker is present — the VM isn't one of the
    /// pid-file backends (e.g. Apple Container, which tracks state
    /// out-of-band) or doesn't exist. Callers fall back to the platform
    /// default in that case.
    pub fn for_started_vm(name: &str) -> Option<Self> {
        let dir = mvm_core::config::vm_state_dir(name);
        catalog::started_vm_probe_descriptors()
            .into_iter()
            .filter_map(|descriptor| descriptor.marker_file)
            .find(|marker_file| dir.join(marker_file).is_file())
            .and_then(catalog::descriptor_for_marker_file)
            .map(|descriptor| descriptor.instantiate())
    }

    /// Aggregate the running-VM listing across every backend that can be
    /// probed on this host (best-effort; a backend that errors is skipped).
    /// Single source of truth for `mvmctl ls` and `mvmctl down` (no-arg) so
    /// a VM started under any VMM — including QEMU and libkrun — is visible
    /// and stoppable, not just whichever backend the CLI defaulted to.
    pub fn list_all() -> Vec<VmInfo> {
        let mut vms = Vec::new();
        for backend in catalog::list_all_descriptors().map(|descriptor| descriptor.instantiate()) {
            if let Ok(found) = backend.list() {
                vms.extend(found);
            }
        }
        vms
    }

    /// Isolation tier of this backend. Used by `mvmctl up` to refuse
    /// silent Tier 2 downgrades on production-like launches, and by
    /// `mvmctl doctor` to surface what's actually running on the host.
    ///
    /// Classification mirrors each backend's existing
    /// `BackendSecurityProfile.tier` (`crates/mvm-backend/src/*.rs::security_profile`),
    /// the long-standing per-backend declaration consulted by
    /// `mvmctl doctor --json::security_posture.tier`. A test below
    /// asserts the two stay in sync; bumping one without the other
    /// fails CI.
    pub fn tier(&self) -> BackendTier {
        catalog::descriptor(self.kind()).tier
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

    /// Borrow the wrapped backend as `&dyn VmBackend` — for callers (the warm-pool
    /// orchestration helpers) that are generic over `VmBackend` rather than the enum.
    pub fn as_vm_backend(&self) -> &dyn VmBackend {
        self.inner()
    }

    /// Borrow as `&dyn WorkloadBackend` — `Some` only for backends permitted
    /// to carry an untrusted workload. The exhaustive match means a new
    /// `AnyBackend` variant forces an explicit workload/non-workload decision
    /// here (compile error otherwise). `Qemu` is barred (a real VMM scoped to
    /// dev/test); `Mock` is permitted as the hermetic lifecycle test double —
    /// it carries no real workload, so it is the stand-in tests drive through
    /// the admitted path.
    pub fn as_workload_backend(&self) -> Option<&dyn crate::workload_backend::WorkloadBackend> {
        match self {
            AnyBackend::Firecracker(b) => Some(b),
            AnyBackend::Libkrun(b) => Some(b),
            AnyBackend::Vz(b) => Some(b),
            AnyBackend::Mock(b) => Some(b),
            AnyBackend::Qemu(_) => None,
        }
    }

    /// Does this backend support a prelaunched-supervisor standby
    /// pool? See [`VmBackend::supports_standby_pool`]. Only libkrun does today.
    pub fn supports_standby_pool(&self) -> bool {
        self.inner().supports_standby_pool()
    }

    /// Spawn a prelaunched standby. See [`VmBackend::spawn_standby`].
    pub fn spawn_standby(
        &self,
        spec: &mvm_core::vm_backend::StandbySpec,
    ) -> std::result::Result<mvm_core::vm_backend::StandbyHandle, mvm_core::vm_backend::StandbyError>
    {
        self.inner().spawn_standby(spec)
    }

    /// Claim an idle standby. See [`VmBackend::claim_standby`].
    pub fn claim_standby(
        &self,
        handle: &mvm_core::vm_backend::StandbyHandle,
        claim: &mvm_core::vm_backend::StandbyClaim,
    ) -> std::result::Result<VmId, mvm_core::vm_backend::StandbyError> {
        self.inner().claim_standby(handle, claim)
    }

    /// Warm-start a VM at (at least) the requested snapshot tier. See
    /// [`VmBackend::warm_start`] — fails closed with a typed error on an
    /// over-request rather than degrading to a cold boot.
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

    /// Fast teardown for an ephemeral transient run. See
    /// [`VmBackend::stop_transient`]. Vz overrides it to skip the graceful
    /// grace; other backends fall through to the default (== `stop`).
    pub fn stop_transient(&self, id: &VmId) -> Result<()> {
        self.inner().stop_transient(id)
    }

    /// Block until a VM exits and return its captured exit status.
    /// Delegates to the inner backend; only libkrun (and mock)
    /// implement a real wait surface — other backends return a clear
    /// bail via the default VmBackend impl.
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
    fn test_any_backend_dispatches_security_profile_for_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 1");
    }

    #[test]
    fn test_any_backend_from_hypervisor_vz() {
        // `--backend vz` and the longer `--backend virtualization`
        // both route to the new Vz backend.
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
        // A non-KVM dev/test runner output routes to the QEMU backend
        // (microvm.nix folded into QEMU).
        let backend = AnyBackend::from_build_output(true);
        assert_eq!(backend.name(), "qemu");
    }

    #[test]
    fn test_any_backend_from_hypervisor_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_hypervisor_qemu() {
        // `"qemu"` routes to the real QEMU workload backend, not the
        // retired microvm.nix alias.
        let backend = AnyBackend::from_hypervisor("qemu");
        assert_eq!(backend.name(), "qemu");
        assert!(matches!(backend, AnyBackend::Qemu(_)));
    }

    #[test]
    fn test_any_backend_from_hypervisor_mock() {
        let backend = AnyBackend::from_hypervisor("mock");
        assert_eq!(backend.name(), "mock");
        assert!(matches!(backend, AnyBackend::Mock(_)));
    }

    #[test]
    fn test_any_backend_from_hypervisor_unknown_defaults() {
        let backend = AnyBackend::from_hypervisor("unknown");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_capabilities() {
        let backend = AnyBackend::default_backend();
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn for_started_vm_resolves_owning_backend_by_marker() {
        // A started VM's owning backend is resolved from its state-dir pid
        // marker so `down`/`status`/`ls` dispatch to the right VMM.
        let _legacy_guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let temp = tempfile::tempdir().expect("create temp HOME");
        let vms = temp.path().join(".mvm/vms");
        for (name, marker) in [("q1", "qemu.pid"), ("l1", "libkrun.pid"), ("f1", "fc.pid")] {
            std::fs::create_dir_all(vms.join(name)).expect("mkdir vm dir");
            std::fs::write(vms.join(name).join(marker), "123").expect("write marker");
        }
        env.set("HOME", temp.path());
        env.set("MVM_DATA_DIR", temp.path().join(".mvm"));

        let q = AnyBackend::for_started_vm("q1");
        let l = AnyBackend::for_started_vm("l1");
        let f = AnyBackend::for_started_vm("f1");
        let none = AnyBackend::for_started_vm("does-not-exist");

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
    fn for_started_vm_resolves_vz_by_marker() {
        let _legacy_guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let temp = tempfile::tempdir().expect("create temp HOME");
        let vms = temp.path().join(".mvm/vms");
        std::fs::create_dir_all(vms.join("vzvm")).expect("mkdir vm dir");
        std::fs::write(vms.join("vzvm").join("vz.pid"), "12345").expect("write marker");
        env.set("HOME", temp.path());
        env.set("MVM_DATA_DIR", temp.path().join(".mvm"));
        let result = AnyBackend::for_started_vm("vzvm");
        assert!(matches!(result, Some(AnyBackend::Vz(_))), "vz.pid → Vz");
    }

    #[test]
    fn test_auto_select_returns_valid_backend() {
        let backend = AnyBackend::auto_select();
        let name = backend.name();
        assert!(
            // The full set of legitimate auto_select returns is:
            matches!(name, "firecracker" | "vz" | "libkrun"),
            "auto_select returned unexpected backend: {name}"
        );
    }

    #[test]
    fn backend_catalog_matrix_is_stable() {
        let actual: Vec<_> = catalog::descriptors()
            .iter()
            .map(|descriptor| {
                (
                    descriptor.selector,
                    descriptor.aliases.to_vec(),
                    descriptor.tier,
                    descriptor.marker_file,
                    descriptor.started_vm_probe_order,
                    descriptor.include_in_list_all,
                    descriptor.include_in_balloon_support,
                    descriptor.include_in_warm_start_support,
                )
            })
            .collect();

        assert_eq!(
            actual,
            vec![
                (
                    "firecracker",
                    Vec::new(),
                    BackendTier::Tier1,
                    Some("fc.pid"),
                    Some(3),
                    true,
                    true,
                    true,
                ),
                (
                    "libkrun",
                    vec!["krun"],
                    BackendTier::Tier2,
                    Some("libkrun.pid"),
                    Some(2),
                    true,
                    true,
                    true,
                ),
                (
                    "vz",
                    vec!["virtualization"],
                    BackendTier::Tier2,
                    Some("vz.pid"),
                    Some(4),
                    false,
                    false,
                    true,
                ),
                (
                    "qemu",
                    Vec::new(),
                    BackendTier::Tier2,
                    Some("qemu.pid"),
                    Some(1),
                    true,
                    true,
                    true,
                ),
                (
                    "mock",
                    Vec::new(),
                    BackendTier::Tier3,
                    None,
                    None,
                    false,
                    false,
                    false,
                ),
            ]
        );
    }

    /// Boundary between the descriptor registry and the `AnyBackend` enum:
    /// a generic consumer constructs and uses every backend straight from the
    /// registry as a trait object, with no variant matching; the enum remains
    /// only for backend-specific flows — `auto_select` (platform policy) and
    /// the `as_vm_backend` bridge for callers that already hold an enum.
    #[test]
    fn descriptor_registry_serves_generic_consumers_without_the_enum() {
        for descriptor in catalog::descriptors() {
            let backend = descriptor.instantiate_dyn();
            assert!(!backend.name().is_empty(), "{:?}", descriptor.kind);
        }

        let selected = AnyBackend::auto_select();
        assert!(!selected.as_vm_backend().name().is_empty());
    }

    // ------------------------------------------------------------------
    // pause/resume coverage
    //
    // Backends that don't support pause/resume (capabilities.pause_resume
    // == false) must surface a clear, named bail. Backends that *do*
    // support it (Firecracker, Cloud Hypervisor) have real impls
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
    fn pause_resume_unsupported_on_qemu() {
        assert_unsupported_pause_resume(AnyBackend::from_hypervisor("qemu"), "qemu");
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
        // fail closed (no cold-boot fallback) and name a recovery action.
        // The Unsupported branch returns before any boot, so this needs
        // no VM/KVM.
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
        let unsupported: &[&str] = &["libkrun", "qemu"];
        for &name in unsupported {
            let b = AnyBackend::from_hypervisor(name);
            assert!(
                !b.capabilities().pause_resume,
                "{name}: capability flag must say pause_resume=false (matches bail in pause/resume)"
            );
        }
        let fc = AnyBackend::from_hypervisor("firecracker");
        assert!(
            fc.capabilities().pause_resume,
            "firecracker: capability flag must say pause_resume=true (matches the real impl)"
        );
        let vz = AnyBackend::from_hypervisor("vz");
        assert!(
            vz.capabilities().pause_resume,
            "vz: capability flag must say pause_resume=true (matches the real impl)"
        );
    }

    // BackendTier coverage.

    #[test]
    fn tier_classification_locks_each_backend_variant() {
        let cases: &[(&str, BackendTier)] = &[
            ("firecracker", BackendTier::Tier1),
            ("libkrun", BackendTier::Tier2),
            ("vz", BackendTier::Tier2),
            ("qemu", BackendTier::Tier2),
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
        // is the closed-enum view of the same fact. Bumping one without
        // the other is a regression — keep them wired.
        let names = ["firecracker", "libkrun", "vz", "qemu", "mock"];
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
    fn as_workload_backend_some_for_workload_variants() {
        // mock is included: it is the hermetic lifecycle test double that
        // stands in for a workload backend on the admitted path.
        for name in ["firecracker", "libkrun", "vz", "mock"] {
            let backend = AnyBackend::from_hypervisor(name);
            assert!(
                backend.as_workload_backend().is_some(),
                "{name}: must be a workload backend"
            );
        }
    }

    #[test]
    fn as_workload_backend_none_for_qemu() {
        // qemu is the meaningful carve-out: a real dev/test VMM that must not
        // carry an untrusted workload.
        let backend = AnyBackend::from_hypervisor("qemu");
        assert!(
            backend.as_workload_backend().is_none(),
            "qemu: dev/test VMM must not be a workload backend"
        );
    }

    #[test]
    fn tier_label_is_wire_stable() {
        // `mvmctl doctor`'s text output and any downstream scripts
        // grep these strings. A rename here is a wire change.
        assert_eq!(BackendTier::Tier1.label(), "tier1-hardened");
        assert_eq!(BackendTier::Tier2.label(), "tier2-fast-local");
        assert_eq!(BackendTier::Tier3.label(), "tier3-fallback");
    }

    #[test]
    fn warm_start_on_libkrun_refuses_live_memory_with_typed_hint() {
        use mvm_core::vm_backend::{SnapshotCapability, VmStartConfig, WarmStartError};
        // libkrun is disk-only: a live-memory warm-start request must fail
        // closed with the typed Unsupported variant + a recovery hint, never a
        // silent cold boot.
        let backend = AnyBackend::from_hypervisor("libkrun");
        let config = VmStartConfig {
            name: "ghost".to_string(),
            ..Default::default()
        };
        let err = backend
            .warm_start(&config, SnapshotCapability::LiveMemory)
            .expect_err("disk-only backend must refuse a live-memory request");
        match err {
            WarmStartError::Unsupported {
                requested,
                available,
                hint,
            } => {
                assert_eq!(requested, SnapshotCapability::LiveMemory);
                assert_eq!(available, SnapshotCapability::DiskOnly);
                assert!(hint.contains("disk-only"), "hint names the tier: {hint}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn warm_start_on_firecracker_admits_the_live_memory_tier() {
        use mvm_core::vm_backend::SnapshotCapability;
        // Firecracker advertises the live-memory tier, so the C4 gate admits a
        // live-memory request (the restore itself needs a live KVM VM and is
        // exercised on the gated lane, not here).
        let fc = FirecrackerBackend;
        assert!(
            fc.snapshot_capability()
                .satisfies(SnapshotCapability::LiveMemory)
        );
    }
}
