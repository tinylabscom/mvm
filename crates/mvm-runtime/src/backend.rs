use crate::catalog;
use anyhow::Result;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, SnapshotCapability, VmBackend, VmCapabilities, VmId,
    VmInfo, VmStartConfig, VmStatus, WarmStartOutcome,
};

// Every backend variant + the FC support modules live in this crate.
// `microvm`, `image` are siblings under `crate::`; the substrate
// (`config`, `shell`, `runtime_meta`) lives in `crate::base`.
use crate::apple_container_backend::AppleContainerBackend;
use crate::base::config::{PortMapping, VmSlot};
use crate::driver::FcDriver;
use crate::image::RuntimeVolume;
use crate::microvm;
use crate::microvm::FlakeRunConfig;
#[cfg(feature = "test-support")]
use crate::mock::MockBackend;
use crate::wasm_backend::WasmBackend;
use crate::web_linux_backend::WebLinuxBackend;
use crate::workload_runner::{
    RealBrokerRegistrar, RealNetworkEndpointSpawner, StopTiming, WorkloadRunner,
};
use mvm_backends::driver::hvf::HvfDriver;
use mvm_backends::driver::{LibkrunDriver, QemuDriver};
use mvm_vmm::host::drive_file::DriveFile;

/// The hvf VMM driven through the unified workload-runner role over the driver
/// seam — hvf's sole workload launch path (`--hypervisor hvf` and the macOS-26
/// `auto_select` default). NIC-less: egress routes to the per-VM gating endpoint
/// over vsock only; the legacy direct `HvfBackend` shim has been deleted, so
/// this runner is the only hvf workload launch path.
pub(crate) type HvfRunner =
    WorkloadRunner<HvfDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;

/// Construct the hvf VMM's workload runner. Like [`libkrun_runner`] and
/// [`fc_runner`] the runner is not const-constructible, so this helper is the
/// one construction site the enum variant, `auto_select`, the descriptor
/// catalog, and the capability selector all call.
pub(crate) fn hvf_runner() -> HvfRunner {
    WorkloadRunner::new(
        HvfDriver::new(),
        RealNetworkEndpointSpawner,
        RealBrokerRegistrar,
    )
}

/// libkrun driven through the same unified workload-runner role — libkrun's
/// sole production launch path (both `--hypervisor libkrun` and `auto_select`).
/// Egress routes to the per-VM gating endpoint over vsock only; the legacy
/// direct `LibkrunBackend` shim has been deleted, so this runner is the only
/// libkrun workload launch path.
type LibkrunRunner = WorkloadRunner<LibkrunDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;

/// Construct libkrun's workload runner. The runner is not const-constructible,
/// so this helper is the one construction site the enum variant, `auto_select`,
/// the descriptor catalog, and the capability selector all call.
pub(crate) fn libkrun_runner() -> LibkrunRunner {
    WorkloadRunner::new(
        LibkrunDriver::new(),
        RealNetworkEndpointSpawner,
        RealBrokerRegistrar,
    )
}

/// QEMU (Linux dev/test substrate; KVM where present, TCG fallback) driven
/// through the same unified workload-runner role — qemu's sole workload launch
/// path (`--hypervisor qemu` / `MVM_BACKEND=qemu`; `auto_select` never picks
/// it). NIC-less: the converged boot attaches no slirp user-mode network, so
/// egress routes to the per-VM gating endpoint over vsock only, through the
/// per-VM AF_VSOCK↔UNIX bridge. The legacy direct `QemuBackend`
/// has been deleted; this runner is the only QEMU workload launch path.
type QemuRunner = WorkloadRunner<QemuDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;

/// Construct QEMU's workload runner. Like [`libkrun_runner`] the runner is not
/// const-constructible, so this helper is the one construction site the enum
/// variant, `from_build_output`, the descriptor catalog, and the capability
/// selector all call.
pub(crate) fn qemu_runner() -> QemuRunner {
    WorkloadRunner::new(
        QemuDriver::new(),
        RealNetworkEndpointSpawner,
        RealBrokerRegistrar,
    )
}

/// Firecracker (Linux KVM) driven through the unified workload-runner role
/// — Firecracker's sole mvmctl-CLI workload launch path (`--hypervisor
/// firecracker`, `default_backend`, and `auto_select`). NIC-less: egress routes
/// to the per-VM gating endpoint over vsock only.
type FcRunner = WorkloadRunner<FcDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>;

/// Construct Firecracker's workload runner. Like [`libkrun_runner`] the runner
/// is not const-constructible, so this helper is the one construction site the
/// enum variant, `auto_select`, the descriptor catalog, and the capability
/// selector all call.
pub(crate) fn fc_runner() -> FcRunner {
    WorkloadRunner::new(
        FcDriver::new(),
        RealNetworkEndpointSpawner,
        RealBrokerRegistrar,
    )
}

/// Compatibility wrapper for the retired raw Firecracker configuration.
///
/// Normal workloads use the runner-backed [`AnyBackend::Firecracker`] variant;
/// this wrapper remains only for callers that still inspect the legacy artifact
/// shape before migrating.
pub struct FirecrackerConfig {
    pub run_config: microvm::FlakeRunConfig,
}

impl FirecrackerConfig {
    /// Convert a backend-agnostic config into the legacy artifact shape.
    pub fn from_start_config(config: &VmStartConfig) -> Result<Self> {
        validate_firecracker_start_config(config)?;
        let slot = microvm::allocate_slot(&config.name)?;
        Self::from_start_config_with_slot(config, slot)
    }

    /// Convert a config using a slot that has already been reserved.
    pub fn from_start_config_with_slot(config: &VmStartConfig, slot: VmSlot) -> Result<Self> {
        validate_firecracker_start_config(config)?;
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
        };
        Ok(Self { run_config })
    }
}

fn validate_firecracker_start_config(config: &VmStartConfig) -> Result<()> {
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
    Ok(())
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

/// The three host capabilities the auto-detect ladder branches on,
/// resolved once so the ladder itself can be a pure function of them.
///
/// Probing and deciding are separated because the decision is the part
/// worth testing and the probe is the part that pins a test to whatever
/// host runs it. With them fused, "an opt-in tier is never auto-selected"
/// could only ever be checked for the tier the test machine happened to
/// be — which is how a macOS-only regression stayed invisible to a Linux
/// CI runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostTiers {
    /// Native Linux with `/dev/kvm` — the Firecracker production tier.
    native_runner: bool,
    /// macOS 26+ Apple Silicon, where HVF is the auto-detect default.
    hvf_default: bool,
    /// libkrun is installed.
    libkrun: bool,
}

impl HostTiers {
    fn probe() -> Self {
        let plat = mvm_core::platform::current();
        Self {
            native_runner: plat.supports_native_runner(),
            hvf_default: plat.is_hvf_default_tier(),
            libkrun: plat.has_libkrun(),
        }
    }
}

/// The auto-detect ladder.
///
/// Only production-tier backends appear here. Every other backend —
/// apple-container, qemu, wasm, mock — is opt-in, reachable only
/// through an explicit `--hypervisor` / `MVM_BACKEND` selection, and must
/// never be reachable from this function. Adding a return site for one
/// silently moves a workload onto a backend the caller did not ask for.
fn select_kind(tiers: HostTiers) -> catalog::BackendKind {
    use catalog::BackendKind;

    // 1. Native Linux KVM → the Firecracker workload runner (vsock-only
    //    egress; fastest — dev & production). WSL2 nested KVM is
    //    future/experimental and is not auto-selected today.
    if tiers.native_runner {
        return BackendKind::Firecracker;
    }
    // 2. macOS 26+ Apple Silicon → the HVF VMM.
    if tiers.hvf_default {
        return BackendKind::Hvf;
    }
    // 3. libkrun installed → the libkrun workload runner (vsock-only egress).
    if tiers.libkrun {
        return BackendKind::Libkrun;
    }
    // Final default. Reachable when no tier is available; start() then
    // fails with the production-path error message rather than silently
    // picking a backend the caller didn't ask for.
    BackendKind::Firecracker
}

/// Backend-agnostic dispatch enum.
///
/// Wraps concrete backends so CLI commands don't need to know which
/// backend is active. Each variant delegates to its inner implementation.
pub enum AnyBackend {
    /// Firecracker (Linux KVM), driven through the unified `WorkloadRunner` over
    /// the driver seam — Firecracker's sole mvmctl-CLI workload path, selected
    /// by `--hypervisor firecracker`, `default_backend`, and `auto_select`.
    /// NIC-less: egress routes to the per-VM gating endpoint over vsock only
    /// (claim-10 + claims 12/13 at the endpoint); no routable guest NIC and no
    /// transparent `:80/:443` terminator.
    Firecracker(FcRunner),
    /// libkrun (Linux KVM / macOS Apple Silicon HVF), driven through the unified
    /// `WorkloadRunner` over the driver seam — libkrun's sole production path,
    /// selected by `--hypervisor libkrun` and `auto_select`. Egress routes to
    /// the per-VM gating endpoint over vsock only (claim-10 + claims 12/13 at
    /// the endpoint); no transparent `:80/:443` terminator.
    Libkrun(LibkrunRunner),
    /// QEMU workload runtime — Linux dev/test substrate (KVM where
    /// present, TCG fallback), driven through the unified `WorkloadRunner`
    /// over the driver seam — qemu's sole workload path, selected by
    /// `--hypervisor qemu` / `MVM_BACKEND=qemu`; `auto_select` never picks
    /// it (Firecracker stays the production runtime). The boot attaches the
    /// universal initramfs and receives `ActivateEnvironment` over vsock
    /// (via the AF_VSOCK↔UNIX bridge), exactly like the other runner
    /// backends. Dev tier only, outside the security claims.
    Qemu(QemuRunner),
    /// In-memory mock — test-only. Records `start`/`stop`/`pause`/
    /// `resume` calls against a `Mutex<HashMap>` and never touches
    /// the host. Selected only via explicit `--hypervisor mock`;
    /// `auto_select` never falls through here. See
    /// [`crate::mock::MockBackend`] for the rationale and security
    /// profile (Tier 3 / claims unknown). Gated behind `test-support` so
    /// this variant — and the mock backend it wraps — never compiles into
    /// a production `mvmctl` binary.
    #[cfg(feature = "test-support")]
    Mock(MockBackend),
    /// HVF (Hypervisor.framework on macOS / Apple silicon), driven through the
    /// unified `WorkloadRunner` over the driver seam — hvf's sole workload path,
    /// selected by `--hypervisor hvf` / `MVM_BACKEND=hvf` and the macOS-26
    /// auto-detect default. NIC-less: egress routes to the per-VM gating endpoint
    /// over vsock only (claim-10 + claims 12/13 at the endpoint); no routable
    /// guest NIC. The destination macOS backend.
    Hvf(HvfRunner),
    /// Host-`wasmtime` claim-free portability tier — see
    /// [`crate::wasm_backend`]. Selectable only via explicit
    /// `--hypervisor wasm` / `MVM_BACKEND=wasm`; `auto_select` never falls
    /// through here. Always constructible; the real engine only compiles in
    /// behind the `wasm-backend` feature, so a build without it fails
    /// closed with a typed error the first time the backend is actually
    /// used, not at construction.
    Wasm(WasmBackend),
    /// Apple Container backend — see [`crate::apple_container_backend`].
    /// The HVF workload runner with Apple's prebuilt container kernel
    /// substituted for the boot image. Selectable only via explicit
    /// `--hypervisor apple-container` (alias `container`); `auto_select`
    /// never falls through here. Always constructible and side-effect free;
    /// a missing kernel artifact fails `start` closed with a typed error
    /// naming the fetch source.
    AppleContainer(AppleContainerBackend),
    /// Browser-hosted WebLinux backend — see [`crate::web_linux_backend`].
    /// Runs a Nix-built Linux kernel under QEMU-Wasm inside a browser
    /// Worker. The native stub is selectable via `--hypervisor web-linux`
    /// but fails closed on any lifecycle operation; `auto_select` never
    /// returns this kind.
    WebLinux(WebLinuxBackend),
}

impl AnyBackend {
    /// Create the default backend (Firecracker).
    pub fn default_backend() -> Self {
        Self::Firecracker(fc_runner())
    }

    /// Select backend based on whether the build output is a non-KVM
    /// dev/test runner. A runner-style output routes to the QEMU dev/test
    /// backend (TCG where KVM is absent); otherwise Firecracker.
    pub fn from_build_output(has_runner: bool) -> Self {
        if has_runner {
            Self::Qemu(qemu_runner())
        } else {
            Self::Firecracker(fc_runner())
        }
    }

    /// Select backend by hypervisor name.
    ///
    /// Supported: `"firecracker"` (default), `"qemu"` (Linux dev/test),
    /// `"hvf"` (in-house Hypervisor.framework VMM, macOS), `"libkrun"`
    /// (Linux KVM / macOS HVF). Unknown names fall back to Firecracker.
    /// `"mock"` resolves to the hermetic in-memory test double only in a
    /// `test-support` build; outside it, `"mock"` is unrecognised the same
    /// way a typo is and falls back to Firecracker too — call
    /// [`Self::require_hypervisor_selectable`] first at a user-facing
    /// `--hypervisor` boundary to refuse it loudly instead.
    pub fn from_hypervisor(name: &str) -> Self {
        catalog::descriptor_for_selector(name)
            .map(|descriptor| descriptor.instantiate())
            .unwrap_or_else(Self::default_backend)
    }

    /// Refuse a `--hypervisor` name this build cannot actually select,
    /// instead of letting it silently resolve to a different backend.
    /// `from_hypervisor` degrades *any* unrecognised name (including a
    /// plain typo) to the Firecracker default; that tolerance is wrong for
    /// documented selectors that are unavailable in this build.
    ///
    /// Refused selectors:
    /// - `"mock"` outside a `test-support` build (a real, documented selector
    ///   that would silently run the wrong backend).
    /// - `"docker"` everywhere (the Docker dev-tier backend was removed).
    ///
    /// Call this before [`Self::from_hypervisor`] at any user-facing
    /// `--hypervisor` entry point.
    pub fn require_hypervisor_selectable(name: &str) -> Result<()> {
        if name == "docker" {
            anyhow::bail!(
                "the Docker backend has been removed; use a microVM backend (firecracker, libkrun, hvf, qemu) or apple-container"
            );
        }
        if name == "mock" && !cfg!(feature = "test-support") {
            anyhow::bail!("the mock backend is only available in test-support builds");
        }
        Ok(())
    }

    /// Select the best backend for the current platform.
    ///
    /// Firecracker is the production target — it always wins when KVM
    /// is available. Non-KVM hosts continue down the fallback ladder.
    ///
    /// Priority:
    /// 1. **Firecracker** (if native Linux `/dev/kvm` is available — production Tier 1)
    /// 2. HVF VMM (macOS 26+ Apple Silicon — vsock-only egress, no guest-NIC helper path)
    /// 3. raw libkrun
    ///
    /// If none of the above match, the function returns Firecracker as
    /// the default — `start()` will then surface the host-side
    /// "Firecracker not available" error pointed at the production path,
    /// which is a clearer failure mode than picking a backend the
    /// caller didn't ask for.
    pub fn auto_select() -> Self {
        catalog::descriptor(select_kind(HostTiers::probe())).instantiate()
    }

    /// Resolve the backend that owns an already-started VM by its per-VM
    /// state-dir marker file, so `down` / `status` dispatch to the VMM that
    /// actually launched it rather than a platform default. The pid-file
    /// backends each drop a distinct marker under `vm_state_dir(name)`:
    /// QEMU `qemu.pid`, libkrun `libkrun.pid`, Firecracker `fc.pid`.
    ///
    /// Returns `None` when no marker is present — the VM doesn't exist, or
    /// isn't one of the pid-file backends (Apple Container boots through
    /// the same HVF supervisor, so its live VMs deliberately surface under
    /// the HVF marker — same supervisor, same lifecycle). Callers fall back
    /// to the platform default in that case.
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
    ///
    /// Deduplicated by name, keeping the row from the backend that owns the
    /// VM. Backend listings are not disjoint: they all scan the same per-VM
    /// state dir, so one running VM is discovered by every backend — but only
    /// the marker-file owner reads its true status, the rest report `Stopped`
    /// because *their* marker is absent. Picking by declaration order would
    /// therefore render a running VM as stopped.
    pub fn list_all() -> Vec<VmInfo> {
        let rows = catalog::list_all_descriptors()
            .map(|descriptor| (descriptor.kind, descriptor.instantiate()))
            .flat_map(|(kind, backend)| {
                backend
                    .list()
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |vm| (kind, vm))
            });
        dedup_by_owning_backend(rows, |name| Self::for_started_vm(name).map(|b| b.kind()))
    }

    /// The typed discriminant for this backend. Lets callers branch on
    /// `BackendKind::Hvf` etc. instead of string-matching `name()`. Delegates
    /// to the wrapped backend's own `VmBackend::kind()` — the HVF variant holds
    /// the runner, and `WorkloadRunner<HvfDriver, _>` reports `BackendKind::Hvf`,
    /// so the discriminant is unchanged by the runner convergence.
    pub fn kind(&self) -> catalog::BackendKind {
        self.inner().kind()
    }

    pub(crate) fn inner(&self) -> &dyn VmBackend {
        match self {
            Self::Firecracker(backend) => backend,
            Self::Libkrun(backend) => backend,
            Self::Qemu(backend) => backend,
            #[cfg(feature = "test-support")]
            Self::Mock(backend) => backend,
            Self::Hvf(backend) => backend,
            Self::Wasm(backend) => backend,
            Self::AppleContainer(backend) => backend,
            Self::WebLinux(backend) => backend,
        }
    }

    /// Consume the enum into a shared `VmBackend` trait object for generic
    /// consumers that only need the behavior surface.
    pub fn into_dyn(self) -> std::sync::Arc<dyn VmBackend> {
        match self {
            Self::Firecracker(backend) => {
                std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>
            }
            Self::Libkrun(backend) => std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>,
            Self::Qemu(backend) => std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>,
            #[cfg(feature = "test-support")]
            Self::Mock(backend) => std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>,
            Self::Hvf(backend) => std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>,
            Self::Wasm(backend) => std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>,
            Self::AppleContainer(backend) => {
                std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>
            }
            Self::WebLinux(backend) => {
                std::sync::Arc::new(backend) as std::sync::Arc<dyn VmBackend>
            }
        }
    }

    /// Isolation tier of this backend. Used by `mvmctl up` to refuse
    /// silent Tier 2 downgrades on production-like launches, and by
    /// `mvmctl doctor` to surface what's actually running on the host.
    ///
    /// Classification mirrors each backend's existing
    /// `BackendSecurityProfile.tier` (`crates/mvm-runtime/src/*.rs::security_profile`),
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
        self.capabilities().snapshot_capability
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
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(b) => Some(b),
            AnyBackend::Qemu(_) => None,
            // HVF carries untrusted workloads through the runner role: a real
            // mkGuest workload boot, a host-reachable guest agent, and an egress
            // relay to the per-VM endpoint that owns claim-10 and claims 12/13.
            AnyBackend::Hvf(b) => Some(b),
            // Wasm mediates egress through a host import that relays to the
            // same substitution endpoint the vsock-backed tiers use. It is a
            // real workload backend, just claim-free.
            AnyBackend::Wasm(b) => Some(b),
            // Apple Container boots the full admitted stack — it IS the HVF
            // workload runner with only the kernel image substituted, so the
            // same egress endpoint, broker registration, and activation gate
            // apply verbatim.
            AnyBackend::AppleContainer(b) => Some(b),
            // WebLinux is browser-only in this build; the native stub cannot
            // carry an untrusted workload.
            AnyBackend::WebLinux(_) => None,
        }
    }

    /// Does this backend support a prelaunched-supervisor standby
    /// pool? See [`VmBackend::supports_standby_pool`]. The capability is
    /// authoritative for the selectable runner.
    pub fn supports_standby_pool(&self) -> bool {
        self.capabilities().standby_pool
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

    /// Fill the warm pool through the backend's real spawn-and-capture path: boot
    /// a clean factory parent, capture its whole live state into the caller's
    /// checkpoint store, and release it, so a pool slot costs disk rather than a
    /// resident VM. Routes exactly like
    /// [`claim_standby_via_runner`](Self::claim_standby_via_runner) — the
    /// runner-backed workload backends (Firecracker, libkrun, hvf) reach the
    /// runner, the mock lifecycle double services it in memory, and non-workload
    /// backends (qemu, wasm) fail closed. Refusing the same backends both halves
    /// refuse is what keeps a pool from being filled for a backend that could
    /// never claim from it.
    pub fn spawn_standby_via_runner(
        &self,
        ctx: &crate::workload_runner::SpawnContext<'_>,
        spec: &mvm_core::vm_backend::StandbySpec,
    ) -> std::result::Result<mvm_core::vm_backend::StandbyHandle, mvm_core::vm_backend::StandbyError>
    {
        match self {
            AnyBackend::Firecracker(runner) => runner.spawn_standby_captured(ctx, spec),
            AnyBackend::Libkrun(runner) => runner.spawn_standby_captured(ctx, spec),
            AnyBackend::Hvf(runner) => runner.spawn_standby_captured(ctx, spec),
            // The hermetic lifecycle double mirrors the runner's captured
            // checkpoint contract while keeping the VM itself in memory.
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(backend) => backend.spawn_standby_captured(ctx, spec),
            // No warm pool on these backends: qemu and wasm are not
            // workload-bearing; apple-container is, but the HVF driver has no
            // standby support — all fail closed.
            AnyBackend::Qemu(_)
            | AnyBackend::Wasm(_)
            | AnyBackend::AppleContainer(_)
            | AnyBackend::WebLinux(_) => Err(mvm_core::vm_backend::StandbyError::Unsupported {
                backend: self.inner().name().to_string(),
            }),
        }
    }

    /// Pause/save-memory/resume control over a running VM this backend owns —
    /// the mechanics a `vm_full` checkpoint capture drives.
    ///
    /// `None` is the fail-closed answer for a backend with no memory-capture
    /// mechanics; a caller must refuse the capture rather than substituting
    /// another backend's control, which would pause the wrong process. The
    /// exhaustive match means a new variant has to make that choice explicitly.
    pub fn vm_full_control(
        &self,
        vm_name: &str,
    ) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
        use mvm_vmm::driver::traits::VmmDriver as _;
        match self {
            AnyBackend::Firecracker(runner) => runner.vm_full_control(vm_name),
            AnyBackend::Libkrun(runner) => runner.vm_full_control(vm_name),
            AnyBackend::Hvf(runner) => runner.vm_full_control(vm_name),
            // Apple Container boots through the HVF supervisor, so its live VMs
            // are captured by the same control the HVF driver hands back.
            AnyBackend::AppleContainer(_) => HvfDriver::new().vm_full_control(vm_name),
            // No memory capture: the mock keeps its VMs in memory, and qemu
            // and wasm have no save/restore mechanics at all.
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(_) => None,
            AnyBackend::Qemu(_) | AnyBackend::Wasm(_) | AnyBackend::WebLinux(_) => None,
        }
    }

    /// Whether refill can load a child VMM and keep it paused until claim.
    pub fn supports_preloaded_standby(&self) -> bool {
        match self {
            AnyBackend::Firecracker(runner) => runner.supports_preloaded_standby(),
            AnyBackend::Libkrun(runner) => runner.supports_preloaded_standby(),
            AnyBackend::Hvf(runner) => runner.supports_preloaded_standby(),
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(_) => false,
            AnyBackend::Qemu(_)
            | AnyBackend::Wasm(_)
            | AnyBackend::AppleContainer(_)
            | AnyBackend::WebLinux(_) => false,
        }
    }

    /// Prepare one paused child for a saved-state standby after its checkpoint
    /// has been audited. Unsupported backends leave the existing saved-state
    /// pool path intact.
    pub fn preload_standby_via_runner(
        &self,
        ctx: &crate::workload_runner::PreloadContext<'_>,
        handle: &mut mvm_core::vm_backend::StandbyHandle,
    ) -> std::result::Result<(), mvm_core::vm_backend::StandbyError> {
        match self {
            AnyBackend::Firecracker(runner) => runner.preload_standby_child(ctx, handle),
            AnyBackend::Libkrun(runner) => runner.preload_standby_child(ctx, handle),
            AnyBackend::Hvf(runner) => runner.preload_standby_child(ctx, handle),
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(_) => Err(mvm_core::vm_backend::StandbyError::Unsupported {
                backend: self.inner().name().to_string(),
            }),
            AnyBackend::Qemu(_)
            | AnyBackend::Wasm(_)
            | AnyBackend::AppleContainer(_)
            | AnyBackend::WebLinux(_) => Err(mvm_core::vm_backend::StandbyError::Unsupported {
                backend: self.inner().name().to_string(),
            }),
        }
    }

    /// Drive a warm-pool claim through the backend's real, context-aware claim
    /// path — the entry the CLI warm-claim layer assembles a [`ClaimContext`]
    /// for. The runner-backed workload backends (Firecracker, libkrun, hvf)
    /// route to the runner's inherent guarded `claim_standby`, which reserves and
    /// lineage-verifies a clean parent, binds the admitted plan to it, scrubs the
    /// child identity, and forks a fresh admitted child — gated exactly as
    /// strictly as a cold boot. The mock lifecycle double routes to its own
    /// in-memory claim so hermetic tests can drive this path end to end.
    /// Non-workload backends (qemu, wasm) fail closed.
    ///
    /// This is distinct from the parameterless [`claim_standby`](Self::claim_standby)
    /// accessor, which cannot carry a [`ClaimContext`] — the context reaches the
    /// checkpoint/snapshot stores and the signed-audit anchor, whose host key
    /// lives above this crate — and therefore stays the fail-closed default for
    /// the runner-backed variants. Assembling the context is the caller's job;
    /// the runner never loads the host key itself.
    ///
    /// [`ClaimContext`]: crate::workload_runner::ClaimContext
    pub fn claim_standby_via_runner(
        &self,
        ctx: &crate::workload_runner::ClaimContext<'_>,
        handle: &mvm_core::vm_backend::StandbyHandle,
        claim: &mvm_core::vm_backend::StandbyClaim,
    ) -> std::result::Result<VmId, mvm_core::vm_backend::StandbyError> {
        match self {
            AnyBackend::Firecracker(runner) => runner.claim_standby(ctx, handle, claim),
            AnyBackend::Libkrun(runner) => runner.claim_standby(ctx, handle, claim),
            AnyBackend::Hvf(runner) => runner.claim_standby(ctx, handle, claim),
            // The mock is the hermetic lifecycle double the CLI drives through
            // the admitted path; it has no runner, so it services the claim from
            // its own in-memory state (the context is a runner detail it ignores).
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(backend) => backend.claim_standby(handle, claim),
            // No warm pool on these backends: qemu and wasm are not
            // workload-bearing; apple-container is, but the HVF driver has no
            // standby support — all fail closed.
            AnyBackend::Qemu(_)
            | AnyBackend::Wasm(_)
            | AnyBackend::AppleContainer(_)
            | AnyBackend::WebLinux(_) => Err(mvm_core::vm_backend::StandbyError::Unsupported {
                backend: self.inner().name().to_string(),
            }),
        }
    }

    /// Warm-start a VM at (at least) the requested snapshot tier. See
    /// [`VmBackend::warm_start`] — fails closed with a typed error on an
    /// over-request rather than degrading to a cold boot.
    pub fn warm_start(
        &self,
        config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<WarmStartOutcome, mvm_core::vm_backend::WarmStartError> {
        self.inner().warm_start(config, requested)
    }

    /// Start a VM using the backend-agnostic config.
    ///
    /// Each backend converts `VmStartConfig` into its own internal
    /// configuration (e.g., Firecracker allocates a VmSlot and builds
    /// a `FlakeRunConfig`; Apple Container substitutes Apple's prebuilt
    /// container kernel into the HVF runner's launch).
    pub fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.inner().start(config)
    }

    /// Host process that owns the running VM's address space, when known.
    pub fn host_process_id(&self, id: &VmId) -> Result<Option<u32>> {
        self.inner().host_process_id(id)
    }

    pub fn stop(&self, id: &VmId) -> Result<()> {
        self.inner().stop(id)
    }

    /// Stop a VM and return runner teardown timings when this backend exposes
    /// the shared workload-runner lifecycle.
    pub fn stop_with_timing(&self, id: &VmId) -> Result<Option<StopTiming>> {
        match self {
            Self::Firecracker(backend) => backend.stop_with_timing(id).map(Some),
            Self::Libkrun(backend) => backend.stop_with_timing(id).map(Some),
            Self::Qemu(backend) => backend.stop_with_timing(id).map(Some),
            #[cfg(feature = "test-support")]
            Self::Mock(backend) => backend.stop(id).map(|_| None),
            Self::Hvf(backend) => backend.stop_with_timing(id).map(Some),
            Self::Wasm(backend) => backend.stop(id).map(|_| None),
            Self::AppleContainer(backend) => backend.stop_with_timing(id).map(Some),
            Self::WebLinux(backend) => backend.stop(id).map(|_| None),
        }
    }

    /// Fast teardown for an ephemeral transient run. See
    /// [`VmBackend::stop_transient`]. No backend currently overrides it —
    /// every backend falls through to the default (== `stop`).
    pub fn stop_transient(&self, id: &VmId) -> Result<()> {
        self.inner().stop_transient(id)
    }

    /// Stop a transient VM and return runner teardown timings when the
    /// selected backend exposes the shared workload-runner lifecycle.
    ///
    /// The transient backend hook currently has no backend-specific
    /// overrides, so this follows the same stop operation while preserving
    /// the timing detail for launch diagnostics.
    pub fn stop_transient_with_timing(&self, id: &VmId) -> Result<Option<StopTiming>> {
        self.stop_with_timing(id)
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

/// Collapse per-backend listings to one row per VM name, preserving discovery
/// order. `owner_of` names the backend that actually owns a VM (the one whose
/// marker file is present); that backend's row wins, since it is the only one
/// reporting a true status. A name no backend claims — a stopped VM, where no
/// marker exists — keeps its first-discovered row.
///
/// The name is the identity every listing consumer joins on: the name
/// registry, the state dir, `mvmctl down <name>`.
fn dedup_by_owning_backend(
    rows: impl IntoIterator<Item = (BackendKind, VmInfo)>,
    owner_of: impl Fn(&str) -> Option<BackendKind>,
) -> Vec<VmInfo> {
    let mut order: Vec<String> = Vec::new();
    let mut chosen: std::collections::BTreeMap<String, (bool, VmInfo)> =
        std::collections::BTreeMap::new();

    for (kind, vm) in rows {
        let is_owner = owner_of(&vm.name) == Some(kind);
        match chosen.get(&vm.name) {
            // An owner's row is authoritative; nothing later displaces it.
            Some((true, _)) => continue,
            Some((false, _)) if !is_owner => continue,
            Some(_) => {
                chosen.insert(vm.name.clone(), (is_owner, vm));
            }
            None => {
                order.push(vm.name.clone());
                chosen.insert(vm.name.clone(), (is_owner, vm));
            }
        }
    }

    order
        .into_iter()
        .filter_map(|name| chosen.remove(&name).map(|(_, vm)| vm))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::ClaimStatus;

    fn vm_named(name: &str, cpus: u32) -> VmInfo {
        VmInfo {
            id: VmId(name.to_string()),
            name: name.to_string(),
            status: VmStatus::Running,
            guest_ip: None,
            cpus,
            memory_mib: 512,
            profile: None,
            revision: None,
            flake_ref: None,
            ports: Vec::new(),
        }
    }

    fn stopped(name: &str) -> VmInfo {
        VmInfo {
            status: VmStatus::Stopped,
            ..vm_named(name, 0)
        }
    }

    /// Every backend scans the shared per-VM state dir, so one running VM is
    /// discovered by all of them — but only the marker-file owner sees it as
    /// running. The owner's row must win regardless of declaration order, or
    /// a running VM lists as stopped.
    #[test]
    fn dedup_keeps_the_owning_backends_row_over_earlier_stopped_rows() {
        // Mirrors the observed host: firecracker/libkrun/qemu each rediscover
        // an HVF-owned VM and report it stopped, hvf reports it running.
        let rows = vec![
            (BackendKind::Firecracker, stopped("shared")),
            (BackendKind::Libkrun, stopped("shared")),
            (BackendKind::Qemu, stopped("shared")),
            (BackendKind::Hvf, vm_named("shared", 2)),
            (BackendKind::AppleContainer, vm_named("shared", 99)),
        ];

        let listed = dedup_by_owning_backend(rows, |_| Some(BackendKind::Hvf));

        assert_eq!(listed.len(), 1, "one VM must produce one row");
        assert_eq!(listed[0].status, VmStatus::Running);
        assert_eq!(
            listed[0].cpus, 2,
            "the owning backend's row wins, not a later rediscovery"
        );
    }

    /// A stopped VM has no marker file, so no backend claims it. It must still
    /// list exactly once, keeping its first-discovered row.
    #[test]
    fn dedup_keeps_one_row_for_an_unclaimed_vm() {
        let rows = vec![
            (BackendKind::Firecracker, stopped("orphan")),
            (BackendKind::Libkrun, stopped("orphan")),
        ];

        let listed = dedup_by_owning_backend(rows, |_| None);

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, VmStatus::Stopped);
    }

    /// Distinct VMs must survive dedup, in discovery order.
    #[test]
    fn dedup_preserves_distinct_names_in_discovery_order() {
        let rows = vec![
            (BackendKind::Hvf, vm_named("first", 1)),
            (BackendKind::Firecracker, vm_named("second", 2)),
            (BackendKind::Libkrun, vm_named("third", 3)),
        ];

        let listed = dedup_by_owning_backend(rows, |_| None);

        assert_eq!(
            listed.iter().map(|vm| vm.name.as_str()).collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }

    /// The host-wide aggregate `mvmctl ls` and `mvmctl down` read must never
    /// surface a name twice, whatever the host happens to be running.
    #[test]
    fn list_all_returns_no_duplicate_names() {
        let listed = AnyBackend::list_all();
        let unique: std::collections::BTreeSet<_> =
            listed.iter().map(|vm| vm.name.clone()).collect();
        assert_eq!(
            unique.len(),
            listed.len(),
            "list_all emitted a duplicate name: {:?}",
            listed.iter().map(|vm| &vm.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_firecracker_backend_name() {
        let backend = fc_runner();
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_firecracker_capabilities() {
        let backend = fc_runner();
        let caps = backend.capabilities();
        assert!(caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(caps.vsock);
        assert!(!caps.tap_networking);
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
    }

    #[test]
    fn firecracker_reports_standby_pool_support() {
        let backend = fc_runner();
        assert!(backend.supports_standby_pool());
    }

    #[test]
    fn firecracker_config_reuses_reserved_slot() {
        let slot = VmSlot::new("standby-a", 7);
        let config = VmStartConfig {
            name: "standby-a".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            kernel_path: Some("/kernels/vmlinux".into()),
            cpus: 2,
            memory_mib: 1024,
            ..Default::default()
        };

        let fc = FirecrackerConfig::from_start_config_with_slot(&config, slot.clone())
            .expect("slot-backed config");

        assert_eq!(fc.run_config.name, "standby-a");
        assert_eq!(fc.run_config.slot.index, slot.index);
        assert_eq!(fc.run_config.slot.tap_dev, slot.tap_dev);
        assert_eq!(fc.run_config.vmlinux_path, "/kernels/vmlinux");
        assert_eq!(fc.run_config.rootfs_path, "/images/rootfs.ext4");
    }

    #[test]
    fn firecracker_config_rejects_dirshare_before_claim() {
        let config = VmStartConfig {
            name: "standby-a".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            kernel_path: Some("/kernels/vmlinux".into()),
            volumes: vec![mvm_core::vm_backend::VmVolume {
                materialized_image: None,
                volume_label: None,
                host: "/host".into(),
                guest: "/guest".into(),
                size: String::new(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::DirShare,
                encrypted: false,
            }],
            ..Default::default()
        };

        let err = match FirecrackerConfig::from_start_config_with_slot(
            &config,
            VmSlot::new("standby-a", 7),
        ) {
            Ok(_) => panic!("dir shares are unsupported"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Firecracker has no virtio-fs"));
    }

    #[test]
    fn test_firecracker_security_profile_tier_1_holds_all_claims() {
        let backend = fc_runner();
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
    fn from_hypervisor_falls_back_to_default_for_unrecognised_selectors() {
        // An unknown selector must resolve to the default backend rather than
        // silently naming itself, so a typo cannot conjure a backend.
        for alias in ["virtualization", "not-a-hypervisor", ""] {
            let backend = AnyBackend::from_hypervisor(alias);
            assert_ne!(
                backend.name(),
                alias,
                "unrecognised selector {alias:?} must fall through to the default"
            );
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
    #[cfg(feature = "test-support")]
    fn test_any_backend_from_hypervisor_mock() {
        let backend = AnyBackend::from_hypervisor("mock");
        assert_eq!(backend.name(), "mock");
        assert!(matches!(backend, AnyBackend::Mock(_)));
    }

    #[test]
    #[cfg(not(feature = "test-support"))]
    fn from_hypervisor_mock_falls_back_outside_test_support() {
        // Outside `test-support`, `"mock"` is unrecognised the same way a
        // typo is — `from_hypervisor` itself stays infallible and degrades
        // to the Firecracker default. `require_hypervisor_selectable` is
        // the fail-closed check a user-facing `--hypervisor` boundary uses
        // instead of relying on this fallback.
        let backend = AnyBackend::from_hypervisor("mock");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn require_hypervisor_selectable_refuses_mock_without_test_support() {
        let result = AnyBackend::require_hypervisor_selectable("mock");
        if cfg!(feature = "test-support") {
            assert!(result.is_ok(), "test-support build must allow mock");
        } else {
            let err = result.expect_err("mock must be refused outside test-support");
            assert!(
                err.to_string().contains("test-support"),
                "error must name the missing feature: {err}"
            );
        }
    }

    #[test]
    fn require_hypervisor_selectable_refuses_docker_everywhere() {
        let err = AnyBackend::require_hypervisor_selectable("docker")
            .expect_err("docker must be refused in every build");
        let msg = err.to_string();
        assert!(
            msg.contains("Docker backend has been removed"),
            "error must explain docker was removed: {err}"
        );
    }

    #[test]
    fn require_hypervisor_selectable_allows_every_other_name() {
        for name in [
            "firecracker",
            "libkrun",
            "qemu",
            "hvf",
            "apple-container",
            "unknown-typo",
        ] {
            assert!(
                AnyBackend::require_hypervisor_selectable(name).is_ok(),
                "{name}: must never be refused"
            );
        }
    }

    #[test]
    fn test_any_backend_from_hypervisor_hvf() {
        // `--hypervisor hvf` (and the `hypervisor` alias) resolve to the HVF
        // workload runner (the sole `Hvf` variant), whose name delegates to the
        // hvf driver ("hvf") and whose kind is `BackendKind::Hvf`.
        for sel in ["hvf", "hypervisor"] {
            let backend = AnyBackend::from_hypervisor(sel);
            assert!(matches!(backend, AnyBackend::Hvf(_)), "selector {sel}");
            assert_eq!(backend.name(), "hvf");
        }
        assert_eq!(
            AnyBackend::from_hypervisor("hvf").kind(),
            catalog::BackendKind::Hvf
        );
    }

    #[test]
    fn from_hypervisor_hvf_selects_the_workload_runner() {
        // The `Hvf` variant now IS the runner (no separate raw-HVF / runner
        // selectors): `hvf` resolves through the catalog to the workload runner.
        // It is a workload backend and advertises the fail-closed egress posture
        // — no routable guest NIC, egress only via the per-VM vsock endpoint.
        let backend = AnyBackend::from_hypervisor("hvf");
        assert!(matches!(backend, AnyBackend::Hvf(_)));
        assert_eq!(backend.as_vm_backend().name(), "hvf");
        assert_eq!(backend.kind(), catalog::BackendKind::Hvf);
        assert!(
            backend.as_workload_backend().is_some(),
            "runner must be a workload backend"
        );
        let caps = backend.capabilities();
        assert!(
            caps.no_routable_guest_nic,
            "HVF must advertise no guest NIC"
        );
        assert!(
            caps.host_vsock_proxy,
            "HVF egress must ride the vsock proxy"
        );
    }

    #[test]
    fn test_any_backend_from_hypervisor_unknown_defaults() {
        let backend = AnyBackend::from_hypervisor("unknown");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_capabilities() {
        // The default backend is the converged Firecracker runner: NIC-less,
        // vsock-only egress. It advertises the vsock control channel and no
        // routable guest NIC, not the raw TAP the entangled Firecracker path
        // used to carry.
        let backend = AnyBackend::default_backend();
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(!caps.tap_networking);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn for_started_vm_resolves_owning_backend_by_marker() {
        // A started VM's owning backend is resolved from its state-dir pid
        // marker so `down`/`status`/`ls` dispatch to the right VMM.
        let _legacy_guard = mvm_vmm::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let temp = tempfile::tempdir().expect("create temp HOME");
        let vms = temp.path().join("vms");
        for (name, marker) in [("q1", "qemu.pid"), ("l1", "libkrun.pid"), ("f1", "fc.pid")] {
            std::fs::create_dir_all(vms.join(name)).expect("mkdir vm dir");
            std::fs::write(vms.join(name).join(marker), "123").expect("write marker");
        }
        env.set("HOME", temp.path());
        env.set("MVM_HOME", temp.path());

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
    fn test_auto_select_returns_valid_backend() {
        let backend = AnyBackend::auto_select();
        let name = backend.name();
        assert!(
            // The full set of legitimate auto_select returns is:
            //   firecracker (KVM), hvf (macOS 26+ hvf VMM, via the HVF workload
            //   runner whose name() delegates to the hvf driver), libkrun
            //   (macOS 13-25 / Linux non-KVM fallback).
            matches!(name, "firecracker" | "hvf" | "libkrun"),
            "auto_select returned unexpected backend: {name}"
        );
    }

    /// `auto_select` must never return the wasm portability tier — it is
    /// opt-in only (explicit `--hypervisor wasm` / `MVM_BACKEND=wasm`), never
    /// a platform-ladder fallback. `auto_select`'s implementation has exactly
    /// three return sites (Firecracker/Hvf/Libkrun) and none of them
    /// construct `Self::Wasm`, so this holds on every platform the ladder
    /// can resolve to, not just the host running this test.
    #[test]
    fn auto_select_never_returns_wasm() {
        assert_ne!(
            AnyBackend::auto_select().kind(),
            mvm_core::vm_backend::BackendKind::Wasm,
            "auto_select must never fall through to the wasm portability tier"
        );
    }

    /// Every host tier the ladder can see, enumerated. `auto_select` on
    /// its own can only ever exercise the one tier the test machine
    /// happens to be, so a return site added under a `macOS 26+` branch
    /// is unreachable — and therefore untested — on a Linux CI runner.
    fn every_host_tier() -> Vec<HostTiers> {
        let mut all = Vec::new();
        for native_runner in [false, true] {
            for hvf_default in [false, true] {
                for libkrun in [false, true] {
                    all.push(HostTiers {
                        native_runner,
                        hvf_default,
                        libkrun,
                    });
                }
            }
        }
        all
    }

    /// The ladder resolves to a production tier and nothing else, on
    /// every host it can see — not just this one.
    ///
    /// apple-container, qemu, wasm, and mock are opt-in tiers
    /// reachable only through an explicit `--hypervisor`. A branch
    /// returning one of them moves a workload onto a backend nobody asked
    /// for, which is exactly the shape of defect this enumerates against.
    #[test]
    fn the_ladder_never_yields_an_opt_in_tier_on_any_host() {
        use mvm_core::vm_backend::BackendKind;
        for tiers in every_host_tier() {
            let kind = select_kind(tiers);
            assert!(
                matches!(
                    kind,
                    BackendKind::Firecracker | BackendKind::Hvf | BackendKind::Libkrun
                ),
                "auto-detect on {tiers:?} yielded the opt-in backend {kind:?}"
            );
        }
    }

    /// The ladder's priority order, pinned per tier. Without this the
    /// test above passes for any permutation of the three production
    /// backends, including one that would pick libkrun over KVM.
    #[test]
    fn the_ladder_prefers_kvm_then_hvf_then_libkrun() {
        use mvm_core::vm_backend::BackendKind;
        let tiers = |native_runner, hvf_default, libkrun| HostTiers {
            native_runner,
            hvf_default,
            libkrun,
        };
        // Native KVM wins even when every other tier is also present.
        assert_eq!(
            select_kind(tiers(true, true, true)),
            BackendKind::Firecracker
        );
        // HVF outranks libkrun on the macOS 26+ tier where both exist.
        assert_eq!(select_kind(tiers(false, true, true)), BackendKind::Hvf);
        assert_eq!(select_kind(tiers(false, false, true)), BackendKind::Libkrun);
        // Nothing available: Firecracker, so start() fails pointing at the
        // production path rather than at a backend nobody selected.
        assert_eq!(
            select_kind(tiers(false, false, false)),
            BackendKind::Firecracker
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
                    false,
                    false,
                ),
                (
                    "libkrun",
                    vec!["krun"],
                    BackendTier::Tier2,
                    Some("libkrun.pid"),
                    Some(2),
                    true,
                    false,
                    false,
                ),
                (
                    "qemu",
                    Vec::new(),
                    BackendTier::Tier2,
                    Some("qemu.pid"),
                    Some(1),
                    true,
                    true,
                    false,
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
                (
                    "hvf",
                    vec!["hypervisor"],
                    BackendTier::Tier2,
                    Some("hvf.pid"),
                    Some(5),
                    true,
                    false,
                    false,
                ),
                (
                    "wasm",
                    Vec::new(),
                    BackendTier::Tier3,
                    None,
                    None,
                    true,
                    false,
                    false,
                ),
                (
                    "apple-container",
                    vec!["container"],
                    BackendTier::Tier2,
                    None,
                    None,
                    true,
                    false,
                    false,
                ),
                (
                    "web-linux",
                    Vec::new(),
                    BackendTier::Tier3,
                    None,
                    None,
                    true,
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
    fn snapshot_capability_unsupported_on_firecracker_runner() {
        // The runner-backed Firecracker path is cold-boot only. The old raw
        // snapshot helper is not part of the selectable backend.
        assert_eq!(
            AnyBackend::from_hypervisor("firecracker").snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn snapshot_capability_unsupported_on_selectable_libkrun_runner() {
        assert_eq!(
            AnyBackend::from_hypervisor("libkrun").snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn snapshot_capability_unsupported_on_qemu() {
        // QEMU has no wired snapshot/restore operation; a possible QMP future
        // must not be advertised as a recovery tier today.
        assert_eq!(
            AnyBackend::from_hypervisor("qemu").snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn recovery_capability_matrix_is_explicit_for_every_selectable_backend() {
        let mut expected = vec![
            // Apple Container boots through the HVF supervisor, so it inherits
            // that VMM's save/restore tier — one supervisor, one mechanism.
            ("apple-container", SnapshotCapability::SaveRestore, false),
            ("firecracker", SnapshotCapability::Unsupported, true),
            ("hvf", SnapshotCapability::SaveRestore, true),
            ("libkrun", SnapshotCapability::Unsupported, false),
            ("qemu", SnapshotCapability::Unsupported, false),
            ("wasm", SnapshotCapability::Unsupported, false),
        ];
        if cfg!(feature = "test-support") {
            expected.push(("mock", SnapshotCapability::LiveMemory, false));
        }
        for (name, snapshot, standby) in expected {
            let backend = AnyBackend::from_hypervisor(name);
            let capabilities = backend.capabilities();
            assert_eq!(
                capabilities.snapshot_capability, snapshot,
                "{name}: snapshot tier drifted from the recovery matrix"
            );
            assert_eq!(
                capabilities.standby_pool, standby,
                "{name}: standby capability drifted from the recovery matrix"
            );
            assert_eq!(
                backend.snapshot_capability(),
                snapshot,
                "{name}: compatibility snapshot accessor drifted"
            );
            assert_eq!(
                backend.supports_standby_pool(),
                standby,
                "{name}: compatibility standby accessor drifted"
            );
        }
    }

    #[test]
    fn libkrun_warm_start_refuses_live_memory_with_recovery_hint() {
        // A live-memory warm-start asked of the selectable libkrun runner must
        // fail closed (no cold-boot fallback) and name a recovery action.
        // The Unsupported branch returns before any boot, so this needs
        // no VM/KVM. Post-runner-flip libkrun takes the trait-default warm_start,
        // whose hint points at a cold boot rather than naming a sibling backend.
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
                assert_eq!(available, SnapshotCapability::Unsupported);
                assert!(hint.contains("cold boot"), "{hint}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
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
        let hvf = AnyBackend::from_hypervisor("hvf");
        assert!(
            hvf.capabilities().pause_resume,
            "hvf: capability flag must say pause_resume=true (matches signal-backed pause/resume)"
        );
    }

    // BackendTier coverage.

    #[test]
    fn tier_classification_locks_each_backend_variant() {
        let mut cases: Vec<(&str, BackendTier)> = vec![
            ("apple-container", BackendTier::Tier2),
            ("firecracker", BackendTier::Tier1),
            ("libkrun", BackendTier::Tier2),
            ("qemu", BackendTier::Tier2),
        ];
        // No `AnyBackend::Mock`/`MockBackend` reference here — just a name +
        // tier pair — so a plain runtime check (not `#[cfg]`) is enough to
        // keep this test-support-agnostic and `mut` genuinely used in both
        // configs.
        if cfg!(feature = "test-support") {
            cases.push(("mock", BackendTier::Tier3));
        }
        for (name, expected) in cases {
            let b = AnyBackend::from_hypervisor(name);
            assert_eq!(b.tier(), expected, "{name}: tier mismatch");
        }
    }

    #[test]
    fn tier_matches_existing_backend_security_profile_string() {
        // The `BackendSecurityProfile.tier` field (consulted by
        // `mvmctl doctor --json::security_posture.tier`) is the
        // long-standing per-backend tier declaration. `AnyBackend::tier()`
        // is the closed-enum view of the same fact. Bumping one without
        // the other is a regression — keep them wired.
        let mut names = vec!["apple-container", "firecracker", "libkrun", "qemu"];
        if cfg!(feature = "test-support") {
            names.push("mock");
        }
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
        let mut names = vec!["firecracker", "libkrun", "hvf", "wasm"];
        if cfg!(feature = "test-support") {
            names.push("mock");
        }
        for name in names {
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
    fn as_workload_backend_some_for_apple_container() {
        // Apple Container boots the full admitted stack through the shared
        // HVF runner — only the kernel image differs — so it is a workload
        // backend under its own kind.
        let backend = AnyBackend::from_hypervisor("apple-container");
        let workload = backend
            .as_workload_backend()
            .expect("apple-container boots the admitted stack — it is a workload backend");
        assert_eq!(workload.kind(), BackendKind::AppleContainer);
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
        // The selectable libkrun runner does not advertise a warm-start tier:
        // a live-memory request must fail
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
                assert_eq!(available, SnapshotCapability::Unsupported);
                // The recovery hint points at a cold boot rather than a silent
                // degrade (libkrun overrides with a richer message; the stable
                // phrase both it and the default share is the cold-boot hint).
                assert!(hint.contains("cold boot"), "hint offers recovery: {hint}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn warm_start_on_firecracker_refuses_the_legacy_live_memory_tier() {
        use mvm_core::vm_backend::SnapshotCapability;
        // The raw Firecracker live-memory restore path could restore a captured
        // NIC, so the vsock-only backend refuses that legacy tier.
        let fc = fc_runner();
        assert_eq!(fc.snapshot_capability(), SnapshotCapability::Unsupported);
    }

    /// Isolates the `AnyBackend::Mock` construction (unavailable outside
    /// `test-support`) behind a function that's always defined, so its only
    /// caller can `.extend(..)` unconditionally instead of needing a
    /// `#[cfg]`'d `push` — which would otherwise make the collection's
    /// `mut` binding spuriously unused in a non-`test-support` build.
    #[cfg(feature = "test-support")]
    fn mock_variant_for_ssh_check() -> Option<(&'static str, AnyBackend)> {
        Some(("mock", AnyBackend::Mock(MockBackend::new())))
    }
    #[cfg(not(feature = "test-support"))]
    fn mock_variant_for_ssh_check() -> Option<(&'static str, AnyBackend)> {
        None
    }

    #[test]
    fn no_backend_advertises_production_ssh() {
        // The capability layer encodes the SSH ban: no backend may advertise an
        // in-guest SSH server. A future backend that flips this trips here.
        // Covers every `AnyBackend` variant, including the HVF workload-runner path.
        let mut backends: Vec<(&str, AnyBackend)> = vec![
            ("firecracker", AnyBackend::Firecracker(fc_runner())),
            ("libkrun", AnyBackend::Libkrun(libkrun_runner())),
            ("qemu", AnyBackend::Qemu(qemu_runner())),
            ("hvf", AnyBackend::Hvf(hvf_runner())),
            (
                "apple-container",
                AnyBackend::AppleContainer(AppleContainerBackend::new()),
            ),
        ];
        backends.extend(mock_variant_for_ssh_check());
        for (name, backend) in backends {
            assert!(
                !backend.capabilities().production_ssh,
                "{name} backend must not advertise production SSH"
            );
        }
    }

    /// Routing witnesses for the warm-claim seam: the CLI-facing
    /// `claim_standby_via_runner` reaches each backend's real claim path — the
    /// runner's guarded fork for a runner-backed workload backend, the mock's
    /// lifecycle claim for the hermetic double — and fails closed for a
    /// non-workload backend. Assembling the `ClaimContext` is the caller's job;
    /// these build a minimal one and prove the dispatch, not a real fork (which
    /// needs a live VMM).
    mod claim_routing {
        use super::*;
        use crate::checkpoint::{CheckpointChainAnchor, CheckpointStore};
        use crate::standby_pool::SupervisorStandbyPool;
        use crate::workload_runner::ClaimContext;
        use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};
        use mvm_core::vm_backend::{StandbyClaim, StandbyError, StandbyHandle, StandbyState};
        use mvm_fs::snapshot_store::FsSnapshotStore;

        /// A lineage anchor that records nothing, so every lookup is `None`. The
        /// routing tests fail earlier (at the empty-pool reserve) than any
        /// lineage check, so it only has to satisfy the context type.
        struct NoAnchor;
        impl CheckpointChainAnchor for NoAnchor {
            fn recorded_creation_digest(
                &self,
                _meta: &CheckpointMeta,
            ) -> anyhow::Result<Option<CheckpointDigest>> {
                Ok(None)
            }
        }

        fn idle_handle() -> StandbyHandle {
            StandbyHandle {
                id: "warm-parent".into(),
                template_id: None,
                control_socket: "/tmp/does-not-exist.sock".into(),
                pid: 0,
                kernel_sha256: "a".repeat(64),
                vcpus: 2,
                mem_mib: 512,
                binding_nonce: "b".repeat(64),
                spawned_unix_secs: 1,
                state: StandbyState::Idle,
                image_sha256: None,
                root_strategy: Default::default(),
                parent_checkpoint: None,
                preloaded_child_vm_name: None,
                vsock_egress: false,
            }
        }

        fn minimal_claim() -> StandbyClaim {
            StandbyClaim {
                start_config: None,
                rootfs_path: "/vol/rootfs.ext4".into(),
                tenant_id: "tenant-x".into(),
                audit_dir: std::path::PathBuf::from("/tmp/audit"),
                gateway_audit_socket: std::path::PathBuf::from("/tmp/gw.sock"),
                gateway_events_socket: None,
                plan_json: String::new(),
                bundle_json: None,
                network_policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
            }
        }

        /// The owned pieces a [`ClaimContext`] borrows. Held together so the
        /// context's borrows outlive the claim call; the temp dir stays alive
        /// for the store paths.
        struct Scaffold {
            pool: SupervisorStandbyPool,
            checkpoints: CheckpointStore,
            snapshots: FsSnapshotStore,
            anchor: NoAnchor,
            parent: CheckpointId,
            registry_path: std::path::PathBuf,
            _tmp: tempfile::TempDir,
        }

        impl Scaffold {
            fn new() -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
                let checkpoints = CheckpointStore::at(tmp.path().join("checkpoints"));
                let snapshots = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();
                let parent = CheckpointId::new("nonexistent-parent");
                let registry_path = tmp.path().join("vm-names.json");
                Self {
                    pool,
                    checkpoints,
                    snapshots,
                    anchor: NoAnchor,
                    parent,
                    registry_path,
                    _tmp: tmp,
                }
            }

            fn ctx(&self) -> ClaimContext<'_> {
                ClaimContext {
                    pool: &self.pool,
                    checkpoints: &self.checkpoints,
                    snapshots: &self.snapshots,
                    anchor: &self.anchor,
                    parent_checkpoint: &self.parent,
                    registry_path: &self.registry_path,
                    grant_issuer: None,
                }
            }
        }

        #[test]
        fn routes_firecracker_into_the_runner_not_the_trait_stub() {
            let s = Scaffold::new();
            let backend = AnyBackend::from_hypervisor("firecracker");
            let err = backend
                .claim_standby_via_runner(&s.ctx(), &idle_handle(), &minimal_claim())
                .expect_err("an empty pool has no parent to fork");
            // Reaching the runner's guarded sequence (which fails reserving a
            // parent from the empty pool) instead of short-circuiting on the
            // fail-closed trait stub is the proof the fork substrate is reachable.
            assert!(
                !matches!(err, StandbyError::Unsupported { .. }),
                "firecracker must route to the runner, not the Unsupported trait stub: {err}"
            );
            assert!(
                matches!(err, StandbyError::ClaimFailed(_)),
                "the runner refuses inside its guarded claim sequence: {err}"
            );
        }

        #[test]
        fn fails_closed_for_non_workload_backends() {
            let s = Scaffold::new();
            for name in ["qemu", "wasm", "apple-container"] {
                let backend = AnyBackend::from_hypervisor(name);
                let err = backend
                    .claim_standby_via_runner(&s.ctx(), &idle_handle(), &minimal_claim())
                    .expect_err("a non-workload backend has no warm pool");
                assert!(
                    matches!(err, StandbyError::Unsupported { .. }),
                    "{name} must fail closed: {err}"
                );
            }
        }

        /// The spawn half must refuse exactly the backends the claim half does,
        /// or a pool could be filled for a backend that can never claim from it.
        #[test]
        fn spawn_fails_closed_for_the_same_non_workload_backends() {
            use crate::workload_runner::SpawnContext;

            let s = Scaffold::new();
            let spec = mvm_core::vm_backend::StandbySpec {
                id: "parent-a".into(),
                template_id: None,
                kernel_path: "/img/kernel".into(),
                kernel_sha256: "a".repeat(64),
                vcpus: 2,
                mem_mib: 512,
                signing_key_path: "/keys/host-signer.ed25519".into(),
                signer_id: "host:test".into(),
                binding_nonce: "b".repeat(64),
                control_socket: "/tmp/does-not-exist.sock".into(),
                vm_state_dir: "/tmp/does-not-exist".into(),
                image_path: None,
                image_sha256: None,
                root_strategy: Default::default(),
                vsock_egress: false,
            };

            for name in ["qemu", "wasm", "apple-container"] {
                let backend = AnyBackend::from_hypervisor(name);
                let err = backend
                    .spawn_standby_via_runner(
                        &SpawnContext {
                            checkpoints: &s.checkpoints,
                            launch: None,
                        },
                        &spec,
                    )
                    .expect_err("a non-workload backend has no warm pool to fill");
                assert!(
                    matches!(err, StandbyError::Unsupported { .. }),
                    "{name} must fail closed on spawn: {err}"
                );
            }
        }

        // The mock is only compiled under `test-support`; this witness rides the
        // workspace suite (where the feature is unified on) and proves the CLI
        // dispatch reaches a working claim via the hermetic double, not the stub.
        #[cfg(feature = "test-support")]
        #[test]
        fn reaches_the_mock_lifecycle_claim() {
            let s = Scaffold::new();
            let backend = AnyBackend::Mock(MockBackend::new().with_standby());
            let id = backend
                .claim_standby_via_runner(&s.ctx(), &idle_handle(), &minimal_claim())
                .expect("the mock services the claim from its own in-memory state");
            assert_eq!(
                id,
                mvm_core::vm_backend::VmId("warm-parent".into()),
                "the mock boots the claim under the standby id"
            );
        }
    }
}
