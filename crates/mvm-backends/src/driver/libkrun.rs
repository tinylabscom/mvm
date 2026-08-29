//! `LibkrunDriver` — the `VmmDriver` for the libkrun VMM (Linux KVM, macOS
//! Apple Silicon). `boot` maps a policy-free `VmmSpec` to a relay
//! `SupervisorConfig`, spawns `mvm-libkrun-supervisor`, and returns a live
//! handle. Egress policy, the claim-10 gate, and secret substitution live in
//! the host-side endpoint the role runner binds to the spec's `EGRESS_PORT`
//! socket; the driver only wires that port through as a guest-dialed relay — it
//! carries no policy and never sees a `NetworkPolicy`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use libkrun_sys::{BridgeRestartPolicy, KrunContext, SupervisorConfig};
use mvm_agentd::vsock::{CONSOLE_PORT_BASE, GUEST_AGENT_PORT, dev_console_data_ports};
use mvm_core::config::{vm_libkrun_pid, vm_state_dir, vm_vsock_port_socket_at};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    ResourceControls, SnapshotCapability, VmCapabilities, VmExitStatus, VmId, VmStatus,
};
use mvm_net::channel::GuestService;

use mvm_vmm::driver::spec::{BlockDev, KernelImage, VmmSpec, VsockDirection};
use mvm_vmm::driver::traits::{DuplexStream, RunningVm, VmmDriver};

/// DAX window size exported to libkrun for any virtio-fs share that
/// requests DAX. 256 MiB matches the HVF DAX window and is large enough
/// for typical workload roots without overcommitting guest address space.
const VIRTIO_FS_DAX_SHM_SIZE: u64 = 256 * 1024 * 1024;

/// The libkrun VMM driver: pure VMM mechanics, no policy and no admission. It
/// boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge,
/// not here.
pub struct LibkrunDriver;

impl LibkrunDriver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LibkrunDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The default base kernel cmdline for a libkrun workload boot. libkrun guests
/// use the virtio-console `console=hvc0` (there is no pl011 UART), and the
/// root/init selection follows the boot shape. The shared cmdline assembler
/// layers verity/grants/egress/uvols tokens on top of this.
fn libkrun_base_bootargs(virtiofs_root: bool, has_disk: bool) -> String {
    if virtiofs_root {
        // Dev virtiofs-root boot: hvc0 console + the virtiofs guest root.
        "console=hvc0 rootfstype=virtiofs root=mvmroot ro init=/init".to_string()
    } else if has_disk {
        "console=hvc0 root=/dev/vda ro init=/init".to_string()
    } else {
        // Verity / initramfs boot: the initramfs PID 1 owns root/init selection,
        // so only the console base is emitted here.
        crate::driver::libkrun_process::VERITY_CMDLINE.to_string()
    }
}

/// Attach one slot-ordered block as a libkrun extra virtio-blk device. libkrun
/// serves every disk from its host file — there is no RAM-backed ephemeral
/// mode, so `BlockDev::ephemeral` is not representable here. Workload blocks are
/// sealed read-only + non-ephemeral, so nothing is dropped.
fn attach_block(krun: KrunContext, block: &BlockDev) -> KrunContext {
    krun.add_disk(
        format!("disk{}", block.slot),
        block.source.to_string_lossy().into_owned(),
        block.read_only,
    )
}

/// Map a policy-free `VmmSpec` to a relay `SupervisorConfig`: the physical
/// recipe (kernel, resources, slot-ordered disks, vsock wiring, console) with
/// every role field inert. Role policy (tenant/plan/egress/audit) lives in the
/// runner above this driver, so `relay` never sets an admission field — the
/// supervisor takes its legacy run path and enforces nothing here.
fn relay_libkrun_supervisor_config(spec: &VmmSpec, state_dir: &Path) -> Result<SupervisorConfig> {
    let kernel_path = match &spec.kernel {
        KernelImage::Path(p) => p.to_string_lossy().into_owned(),
        KernelImage::Bundled => {
            bail!("the libkrun driver requires an explicit kernel Image; VmmSpec.kernel is Bundled")
        }
    };
    // Prepare the kernel exactly as the raw libkrun path does, reusing the same
    // shared helper rather than forking it: on x86_64 this converts the workload
    // kernel to a libkrun-loadable ELF and reports the format; on aarch64 it is a
    // passthrough at Raw. The driver must not diverge from the host kernel-prep.
    let (kernel, kernel_format) =
        crate::driver::libkrun_process::libkrun_kernel_for_host(&kernel_path)?;

    let vcpus = u8::try_from(spec.vcpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
    let state_dir_str = state_dir.to_string_lossy().into_owned();
    let console_log = state_dir.join("console.log");

    // KrunContext::new seeds a rootfs arg we immediately null; the disk layout
    // below owns the rootfs/extra-disk decision from spec.blocks.
    let mut krun = KrunContext::new(&spec.name, kernel, "")
        .with_resources(vcpus, spec.memory_mib)
        .with_kernel_format(kernel_format)
        .with_vsock_socket_dir(state_dir_str.clone())
        .with_console_output(console_log.to_string_lossy().into_owned())
        // A libkrun workload has no guest NIC: an explicit virtio-vsock device
        // with libkrun's implicit TSI transport disabled. vsock is the only
        // channel off the guest besides storage.
        .with_vsock_direct();
    krun.rootfs_path = None;

    // An empty spec cmdline means "the driver supplies its own default base"
    // (the shared assembler returns None when no extra tokens are needed); a
    // non-empty one already carries the console + root/init base plus every
    // layered token, so it is threaded verbatim.
    let has_virtiofs_root = spec.shares.iter().any(|s| s.tag == "mvmroot");
    let has_disk = spec.initramfs.is_none() && !spec.blocks.is_empty();
    let trimmed = spec.cmdline.trim();
    let cmdline = if trimmed.is_empty() {
        libkrun_base_bootargs(has_virtiofs_root, has_disk)
    } else {
        trimmed.to_string()
    };
    krun = krun.with_cmdline(cmdline);

    // Slot-ordered virtio-blk layout. libkrun serves /dev/vda from either the
    // rootfs disk (plain-rootfs boot) or the first extra disk (initramfs boot,
    // where the initramfs PID 1 owns root selection), so an initramfs spec puts
    // every block in extra_disks and a plain spec pins slot 0 as the rootfs.
    // A virtiofs-root boot has no block rootfs either; all blocks are extra disks.
    let mut ordered: Vec<&BlockDev> = spec.blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    match &spec.initramfs {
        Some(initramfs) => {
            krun.initramfs_path = Some(initramfs.to_string_lossy().into_owned());
            for block in &ordered {
                krun = attach_block(krun, block);
            }
        }
        None if has_virtiofs_root => {
            for block in &ordered {
                krun = attach_block(krun, block);
            }
        }
        None => {
            let mut disks = ordered.iter();
            if let Some(root) = disks.next() {
                krun.rootfs_path = Some(root.source.to_string_lossy().into_owned());
            }
            for block in disks {
                krun = attach_block(krun, block);
            }
        }
    }

    // Attach every virtio-fs share declared by the spec. DAX is enabled when
    // the share requests it; read-only shares use libkrun's v3 API so the
    // host-side export is enforced read-only rather than merely guest-mount ro.
    for share in &spec.shares {
        let shm_size = if share.dax {
            Some(VIRTIO_FS_DAX_SHM_SIZE)
        } else if share.read_only {
            Some(0)
        } else {
            None
        };
        krun = krun.add_virtio_fs_full(
            &share.tag,
            share.host_path.to_string_lossy(),
            shm_size,
            share.read_only,
        );
    }

    // Wire every standing vsock port by direction: the host dials the guest's
    // listeners (agent + dev-console data ports), and the guest dials the
    // host-bound listeners (egress + exit + broker). libkrun derives
    // each unix socket from vsock_socket_dir, so the spec's host_uds is not
    // re-bound here.
    for port in &spec.vsock {
        krun = match port.direction {
            VsockDirection::HostDials => krun.add_vsock_port(port.port()),
            VsockDirection::GuestDials => krun.add_host_listen_port(port.port()),
        };
    }

    Ok(SupervisorConfig {
        krun,
        vm_state_dir: state_dir_str,
        pid_file_name: None,
        // Role fields — tenant/policy/gateway substrate lives in the runner
        // above this driver, never in the pure VMM mechanics. Inert here so the
        // supervisor takes its legacy run path and enforces no admission: that
        // branch keys off `tenant_id`, which stays `None`.
        tenant_id: None,
        gateway_audit_socket: None,
        gateway_events_socket: None,
        bundle: None,
        // The plan and the two paths its wall-clock kill is audited under are
        // the exception. The supervisor owns the guest for its whole life, so
        // it holds the only timer that can still fire once `mvmctl` is gone —
        // and it arms that timer from `plan`. Leaving these `None` is what left
        // every wall-clock bound unenforced. They select no admission route;
        // the audit entry takes its tenant from the plan itself.
        plan: spec.plan_binding.as_ref().map(|b| b.plan_json.clone()),
        audit_dir: spec.plan_binding.as_ref().map(|b| b.audit_dir.clone()),
        signing_key_path: spec
            .plan_binding
            .as_ref()
            .map(|b| b.signing_key_path.clone()),
        network_policy: None,
        bridge_restart_policy: BridgeRestartPolicy::HardFail,
        // No transparent :80/:443 terminator: the runner routes egress through
        // the per-VM gating endpoint over vsock only. The runner puts that
        // endpoint's host UDS on the spec's EGRESS_PORT channel, so pinning the
        // guest egress port's host-listen socket to it makes the endpoint the
        // sole path off the box — the claim-10 gate and secret substitution live
        // there. A spec without an EGRESS_PORT channel (none of the workload
        // paths) leaves this unset and the derived socket unchanged.
        transparent_terminator_port: None,
        egress_relay_socket: spec.host_socket_for_service(GuestService::NetworkFlow),
        exclusive_image_lock: None,
    })
}

/// Return the kernel path and format produced by the real libkrun relay
/// mapping, without spawning a supervisor. Available only to the conformance
/// harness so it can verify the host-specific kernel preparation contract.
#[cfg(feature = "test-support")]
pub fn map_kernel_for_test(
    spec: &VmmSpec,
    state_dir: &Path,
) -> Result<(Option<String>, mvm_core::kernel_format::KernelFormat)> {
    let config = relay_libkrun_supervisor_config(spec, state_dir)?;
    Ok((config.krun.kernel_path, config.krun.kernel_format))
}

/// The supervisor launch, bounded by whatever CPU share this VM was admitted
/// under.
///
/// libkrun runs *inside* the supervisor process, so bounding the supervisor
/// bounds the VM. Wrapping the spawn rather than adjusting the process
/// afterwards is what makes it born bounded — there is no interval in which the
/// workload runs uncapped.
///
/// A function rather than three inline lines so a test can read the argv back
/// and prove the wrap is there. An unwrapped spawn is silent: the VM boots
/// perfectly and simply is not bounded.
fn bounded_supervisor_command(supervisor: &Path, spec: &VmmSpec, state_dir: &Path) -> Command {
    mvm_core::cpu_scope::bind_cpu_grant(
        Command::new(supervisor),
        &spec.name,
        state_dir,
        spec.cpu_grant.as_ref(),
    )
}

impl VmmDriver for LibkrunDriver {
    fn name(&self) -> &str {
        "libkrun"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Libkrun
    }

    fn is_available(&self) -> Result<bool> {
        Ok(libkrun_sys::is_available())
    }

    fn capabilities(&self) -> VmCapabilities {
        // 255: libkrun's C API takes the count as a `u8`, and this driver
        // already clamps to that range before the call. Declaring it here means
        // the clamp is reported to the caller instead of happening silently one
        // layer down.
        //
        // libkrun does not support memory snapshots (same trade as
        // Apple Container). The mvm libkrun launch path is intentionally
        // vsock-only: the supervisor accepts only `NetworkingMode::VsockDirect`,
        // which configures a virtio-vsock device and no net device at all, and
        // serves egress through the host-bound vsock proxy.
        // Pause/resume is theoretically possible but not exposed by libkrun's
        // public C API today. The selectable workload runner does not route
        // standalone disk-warm or supervisor-pool operations through its
        // admission and endpoint guards, so the runner-facing capability set
        // reports both snapshot and standby pool as unsupported.
        let mut capabilities = VmCapabilities {
            max_vcpus: Some(u32::from(u8::MAX)),
            pause_resume: false,
            snapshots: false,
            // Both of the next two are overwritten below — see the
            // reassignment after this literal. They describe the raw libkrun
            // substrate, not what the selectable runner advertises. Quoting
            // either value from here is wrong, and has been more than once.
            snapshot_capability: SnapshotCapability::DiskOnly,
            standby_pool: true,
            vsock: true,
            tap_networking: false,
            // Stronger than the field name asks for: the guest has no NIC at
            // all, not a NIC without a route. `VsockDirect` configures a
            // virtio-vsock device and never calls libkrun's net attach, so
            // there is no net device in the guest's device tree to route.
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            // libkrun's C API doesn't expose virtio-balloon control
            // today; the upstream crate carries no `.balloon(...)`
            // builder. Declared `false` until wiring lands.
            balloon: false,
            // libkrun's krun_add_virtiofs2/3 APIs can export a host directory
            // as a virtio-fs share, including DAX and host-enforced read-only.
            virtiofs_root: true,
            // libkrun runs on macOS but the rootfs lives in a regular
            // file, not an APFS clone-eligible volume mount; no
            // clonefile shortcut here.
            fs_quick_checkpoint: false,
            // Named explicitly, not left at the all-`None` struct-update
            // default: on Linux a cgroup can bound whatever process this
            // backend runs — libkrun does go through the dedicated
            // mvm-libkrun-supervisor binary, but the cgroup claim doesn't
            // depend on that; it holds for any Linux process. libkrun's
            // macOS 13-25 default host has no cgroup at all, so
            // `for_backend` answers host-conditionally rather than by kind.
            resource_controls: ResourceControls::for_backend(BackendKind::Libkrun),
            ..VmCapabilities::default()
        };
        // The runner-facing answer, and the one every caller sees. The
        // substrate has the primitives; this runner does not route them
        // through its admission and endpoint guards, so it advertises
        // neither.
        capabilities.snapshot_capability = SnapshotCapability::Unsupported;
        capabilities.standby_pool = false;
        capabilities
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 2: hardware isolation via KVM (Linux) or Hypervisor.framework
        // (macOS). Comparable VMM TCB to Firecracker — libkrun is rust-vmm
        // based, ~80K LOC, no Firecracker-excluded features (so it passes
        // the "fork test"). Claim 3 (verified boot) is partial
        // because the dm-verity pipeline currently targets Firecracker;
        // libkrun support is a follow-up.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via KVM/HVF
                ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
                ClaimStatus::DoesNotHold, // 3 — verified boot for libkrun rootfs not yet wired
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
                ClaimStatus::Holds,       // 6 — image hash verification
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "Hardware isolation via KVM (Linux) or Hypervisor.framework (macOS).",
                "Comparable VMM TCB to Firecracker; passes plan 53 \"fork test\".",
                "Claim 3 (verified boot) is partial — dm-verity pipeline targets Firecracker today.",
                "Supported on Linux KVM and macOS Apple Silicon; macOS Intel is not a supported local host.",
            ],
        }
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        libkrun_base_bootargs(virtiofs_root, has_disk)
    }

    #[tracing::instrument(
        name = "libkrun.boot",
        skip_all,
        fields(vm = %spec.name, vcpus = spec.vcpus, memory_mib = spec.memory_mib)
    )]
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        let console_log = state_dir.join("console.log");
        // Clear any prior run's captured exit code and usage record so `wait`
        // and the exit report read only this launch's, and the console capture
        // so a stale panic isn't mistaken for this boot's.
        mvm_core::run_sidecars::clear_prior_run(&state_dir);
        let _ = mvm_vmm::host::console_capture::open_console_capture(&console_log);

        let cfg = relay_libkrun_supervisor_config(spec, &state_dir)?;

        let pid_file = vm_libkrun_pid(&spec.name);
        // Remove any stale PID file so the poll below detects this launch's.
        let _ = std::fs::remove_file(&pid_file);

        let json = serde_json::to_string(&cfg)
            .map_err(|e| anyhow!("serialize libkrun SupervisorConfig: {e}"))?;

        let supervisor = crate::driver::libkrun_process::resolve_supervisor_path()?;
        let stdout = mvm_vmm::host::console_capture::open_console_capture(&console_log)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        let stderr = mvm_vmm::host::console_capture::supervisor_stderr(&state_dir);
        let mut child = bounded_supervisor_command(&supervisor, spec, &state_dir)
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe libkrun SupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file (boot confirmed). If the supervisor exits first,
        // surface that — its console capture carries the actionable detail.
        let deadline = Instant::now() + crate::driver::libkrun_process::PID_FILE_TIMEOUT;
        loop {
            if pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "libkrun supervisor exited before writing its PID file (status: {status}); see {}",
                    console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "libkrun supervisor did not confirm boot within {:?}; see {}",
                    crate::driver::libkrun_process::PID_FILE_TIMEOUT,
                    console_log.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // The PID file means the supervisor is up, but it binds the per-port
        // vsock listener a beat later. Wait for the agent socket so a console
        // attach / shell_exec that immediately follows doesn't race a
        // not-yet-bound socket and report the VM "not running".
        let agent_socket = vm_vsock_port_socket_at(&state_dir, GUEST_AGENT_PORT);
        let sock_deadline = Instant::now() + crate::driver::libkrun_process::VSOCK_SOCKET_TIMEOUT;
        while !agent_socket.exists() {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "libkrun supervisor exited before binding vsock socket {} (status: {status}); see {}",
                    agent_socket.display(),
                    console_log.display()
                );
            }
            if Instant::now() >= sock_deadline {
                let _ = child.kill();
                bail!(
                    "libkrun supervisor did not bind vsock socket {} within {:?}; killed; see {}",
                    agent_socket.display(),
                    crate::driver::libkrun_process::VSOCK_SOCKET_TIMEOUT,
                    console_log.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Detach: dropping the `Child` does not kill it, so the supervisor
        // outlives this call (reaped via its PID file by `kill`).
        drop(child);

        Ok(Box::new(LibkrunRunningVm {
            id: VmId(spec.name.clone()),
            state_dir,
            pid_file,
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the supervisor's pid file + the
        // persisted workload-exit code under the VM's state dir), so reattaching
        // is just re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(LibkrunRunningVm {
            pid_file: vm_libkrun_pid(&id.0),
            state_dir,
            id: id.clone(),
        }))
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // libkrun exposes vsock as a host-side abstract socket; the
        // guest agent listens on the shared `GUEST_AGENT_PORT` port,
        // identical to Firecracker and Apple Container, so callers can
        // share the same vsock client implementation across backends.
        Ok(GuestChannelInfo::Vsock {
            cid: 3, // standard guest CID
            port: mvm_agentd::vsock::GUEST_AGENT_PORT,
        })
    }
}

/// A live libkrun VM: the detached `mvm-libkrun-supervisor` tracked by its PID
/// file, with the workload's exit code persisted under its state dir.
struct LibkrunRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
}

impl RunningVm for LibkrunRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn host_process_id(&self) -> Option<u32> {
        crate::driver::libkrun_process::read_pid(&self.pid_file)
            .and_then(|pid| u32::try_from(pid).ok())
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(mvm_vmm::host::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        // Arm before SIGTERM so a short-lived supervisor cannot exit between
        // signal delivery and observer registration.
        if let Some(pid) = crate::driver::libkrun_process::read_pid(&self.pid_file)
            && crate::driver::libkrun_process::pid_alive(pid)
        {
            let observer = mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid).ok();
            // SIGTERM gives libkrun a chance to close its virtio-blk file
            // descriptors, then SIGKILL if it ignores us within the grace
            // window.
            crate::driver::libkrun_process::send_signal(pid, libc::SIGTERM);
            let exited = mvm_vmm::host::process_exit::wait_for_pid_exit(
                pid,
                Instant::now() + crate::driver::libkrun_process::STOP_TIMEOUT,
                observer.as_ref(),
            );
            if !exited {
                crate::driver::libkrun_process::send_signal(pid, libc::SIGKILL);
                if !mvm_vmm::host::process_exit::wait_for_pid_exit(
                    pid,
                    Instant::now() + Duration::from_millis(500),
                    observer.as_ref(),
                ) {
                    return Err(anyhow!(
                        "libkrun PID {pid} could not be proven dead after SIGKILL; preserving {}",
                        self.pid_file.display()
                    ));
                }
            }
        }
        let _ = std::fs::remove_file(&self.pid_file);
        crate::driver::libkrun_process::cleanup_vsock_sockets(&self.state_dir);
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        bail!(
            "pause is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn resume(&self) -> Result<()> {
        bail!(
            "resume is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(
            match crate::driver::libkrun_process::read_pid(&self.pid_file) {
                Some(pid) if crate::driver::libkrun_process::pid_alive(pid) => VmStatus::Running,
                _ => VmStatus::Stopped,
            },
        )
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        // Console-port asymmetry, intentional: the runner's spec_map computes
        // console data-socket paths under HVF's nested `vsock/` convention, but
        // libkrun binds every per-port UDS FLAT (`<state_dir>/vsock-<port>.sock`)
        // and its host-side resolver probes flat-first, so the driver ignores the
        // spec's console `host_uds` and re-derives the flat path here. The nested
        // spec path is therefore inert for libkrun by design — a future refactor
        // must not "fix" it into the flat driver.
        // libkrun's per-port UDS convention: `<state_dir>/vsock-<port>.sock`
        // (flat), resolved through the single source of truth shared with the
        // host-side resolver — NOT HVF's nested `vsock/` convention. Restricted
        // to the agent port and the dev-only console data ports (claim 15: a
        // sealed prod boot registers no console listeners).
        if guest_port != GUEST_AGENT_PORT && !dev_console_data_ports().any(|p| p == guest_port) {
            bail!(
                "libkrun driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}) and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        }
        let socket_path = vm_vsock_port_socket_at(&self.state_dir, guest_port);
        let stream = std::os::unix::net::UnixStream::connect(&socket_path).with_context(|| {
            format!("connect to libkrun vsock socket {}", socket_path.display())
        })?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT, WORKLOAD_EXIT_PORT};
    use mvm_core::vm_backend::SnapshotCapability;
    use mvm_vmm::driver::spec::{ConsoleCapture, VirtioFsShare, VsockPort};

    fn host_dials(service: GuestService, uds: &str) -> VsockPort {
        VsockPort {
            service,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    fn guest_dials(service: GuestService, uds: &str) -> VsockPort {
        VsockPort {
            service,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn spec_with(kernel: KernelImage, vsock: Vec<VsockPort>, blocks: Vec<BlockDev>) -> VmmSpec {
        VmmSpec {
            name: "w".into(),
            kernel,
            initramfs: None,
            cmdline: String::new(),
            vcpus: 2,
            cpu_grant: None,
            memory_mib: 512,
            mem_initial_mib: None,
            blocks,
            shares: vec![],
            vsock,
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
            plan_binding: None,
        }
    }

    fn relay(spec: &VmmSpec) -> SupervisorConfig {
        relay_libkrun_supervisor_config(spec, Path::new("/state/w")).unwrap()
    }

    fn binding() -> mvm_vmm::driver::spec::PlanBinding {
        mvm_vmm::driver::spec::PlanBinding {
            plan_json: serde_json::json!({"resources": {"timeouts": {"exec_secs": 30}}}),
            audit_dir: "/fixture/audit".into(),
            signing_key_path: "/fixture/keys/host-signer.ed25519".into(),
        }
    }

    #[test]
    fn a_plan_bound_spec_hands_the_supervisor_what_it_needs_to_enforce_the_bound() {
        let mut spec = spec_with(KernelImage::Path("/k/Image".into()), vec![], vec![]);
        spec.plan_binding = Some(binding());
        let cfg = relay(&spec);

        assert_eq!(
            cfg.plan
                .as_ref()
                .map(|p| p["resources"]["timeouts"]["exec_secs"].clone()),
            Some(serde_json::json!(30)),
            "the supervisor arms its wall-clock timer from `plan`; without it every bound is inert"
        );
        assert_eq!(cfg.audit_dir.as_deref(), Some(Path::new("/fixture/audit")));
        assert_eq!(
            cfg.signing_key_path.as_deref(),
            Some(Path::new("/fixture/keys/host-signer.ed25519"))
        );
    }

    #[test]
    fn carrying_a_plan_does_not_move_the_supervisor_onto_the_admission_route() {
        let mut spec = spec_with(KernelImage::Path("/k/Image".into()), vec![], vec![]);
        spec.plan_binding = Some(binding());
        let cfg = relay(&spec);

        // The supervisor selects its admission route on `tenant_id`, not on
        // `plan`. Enforcing a wall-clock bound must not silently switch a
        // workload onto the admission path; the audit entry takes its tenant
        // from the plan itself.
        assert!(
            cfg.tenant_id.is_none(),
            "a wall-clock bound must not change which route the supervisor takes"
        );
        assert!(cfg.gateway_audit_socket.is_none());
        assert!(cfg.gateway_events_socket.is_none());
    }

    #[test]
    fn a_spec_without_a_plan_leaves_the_role_fields_inert() {
        let cfg = relay(&spec_with(
            KernelImage::Path("/k/Image".into()),
            vec![],
            vec![],
        ));
        assert!(cfg.plan.is_none());
        assert!(cfg.audit_dir.is_none());
        assert!(cfg.signing_key_path.is_none());
    }

    #[test]
    fn identity_and_capabilities_delegate_to_the_libkrun_backend() {
        let d = LibkrunDriver::new();
        assert_eq!(d.name(), "libkrun");
        assert_eq!(d.kind(), BackendKind::Libkrun);
        let caps = d.capabilities();
        assert!(caps.virtiofs_root, "libkrun must advertise virtiofs_root");
        assert!(caps.vsock);
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
        assert_eq!(d.security_profile().tier, "Tier 2");
    }

    #[test]
    fn workload_base_bootargs_uses_the_hvc0_console_not_ttyama0() {
        let d = LibkrunDriver::new();
        let disk = d.workload_base_bootargs(false, true);
        assert!(disk.contains("console=hvc0"), "got: {disk}");
        assert!(!disk.contains("ttyAMA0"), "got: {disk}");
        assert!(disk.contains("root=/dev/vda"), "got: {disk}");

        // Verity / initramfs base: hvc0 console only, no root/init token.
        let verity = d.workload_base_bootargs(false, false);
        assert_eq!(verity, "console=hvc0");

        // The virtiofs-root variant still uses hvc0, not the pl011 UART.
        let virtiofs = d.workload_base_bootargs(true, false);
        assert!(virtiofs.contains("console=hvc0"), "got: {virtiofs}");
        assert!(!virtiofs.contains("ttyAMA0"), "got: {virtiofs}");
        assert!(virtiofs.contains("rootfstype=virtiofs"), "got: {virtiofs}");
    }

    #[test]
    fn guest_channel_info_reports_the_standard_vsock_agent_channel() {
        // The driver reports the same fixed vsock agent channel the legacy
        // libkrun shell reported; nothing is invented here.
        let d = LibkrunDriver::new();
        let id = VmId("libkrun-guest-channel-info-test-vm".into());
        assert_eq!(
            format!("{:?}", d.guest_channel_info(&id).unwrap()),
            format!(
                "{:?}",
                GuestChannelInfo::Vsock {
                    cid: 3,
                    port: mvm_agentd::vsock::GUEST_AGENT_PORT,
                }
            )
        );
    }

    #[test]
    fn relay_config_leaves_every_role_field_inert() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                host_dials(GuestService::MachineControl, "/run/agent.sock"),
                guest_dials(GuestService::NetworkFlow, "/run/egress.sock"),
            ],
            vec![],
        );
        let cfg = relay(&spec);
        // Role fields all inert — no admission, no policy, no audit substrate.
        assert_eq!(cfg.tenant_id, None);
        assert_eq!(cfg.plan, None);
        assert_eq!(cfg.bundle, None);
        assert_eq!(cfg.network_policy, None);
        assert_eq!(cfg.audit_dir, None);
        assert_eq!(cfg.gateway_audit_socket, None);
        assert_eq!(cfg.gateway_events_socket, None);
        assert_eq!(cfg.signing_key_path, None);
        assert_eq!(cfg.transparent_terminator_port, None);
        // Egress is not a role field: the spec's EGRESS_PORT channel names the
        // per-VM gating endpoint UDS, and the relay pins the guest egress port's
        // host-listen socket to it so the endpoint is the sole path off the box.
        assert_eq!(
            cfg.egress_relay_socket,
            Some(std::path::PathBuf::from("/run/egress.sock"))
        );
        // Physical recipe carried through.
        assert_eq!(cfg.krun.vcpus, 2);
        assert_eq!(cfg.krun.ram_mib, 512);
        assert_eq!(cfg.krun.kernel_path.as_deref(), Some("/img/Image"));
        assert_eq!(cfg.vm_state_dir, "/state/w");
        assert_eq!(cfg.pid_file_name, None);
    }

    #[test]
    fn relay_config_prepares_the_kernel_for_the_host_format() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        std::fs::write(&kernel, b"\x7fELFconformance-kernel").unwrap();
        let spec = spec_with(KernelImage::Path(kernel.clone()), vec![], vec![]);

        let cfg = relay_libkrun_supervisor_config(&spec, dir.path()).unwrap();
        if cfg!(target_arch = "x86_64") {
            assert_eq!(
                cfg.krun.kernel_format,
                mvm_core::kernel_format::KernelFormat::Elf
            );
        } else {
            assert_eq!(
                cfg.krun.kernel_format,
                mvm_core::kernel_format::KernelFormat::Raw
            );
        }
        assert_eq!(cfg.krun.kernel_path.as_deref(), kernel.to_str());
    }

    #[test]
    fn relay_config_maps_a_plain_rootfs_to_vda_and_extras_to_vdb() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![],
            vec![
                // Out of slot order to prove sorting.
                BlockDev {
                    source: "/img/data.img".into(),
                    read_only: false,
                    ephemeral: false,
                    slot: 1,
                },
                BlockDev {
                    source: "/img/rootfs.ext4".into(),
                    read_only: true,
                    ephemeral: false,
                    slot: 0,
                },
            ],
        );
        let cfg = relay(&spec);
        // No initramfs ⇒ slot 0 is the rootfs (/dev/vda), rest are extra disks.
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/img/rootfs.ext4"));
        assert_eq!(cfg.krun.initramfs_path, None);
        assert_eq!(cfg.krun.extra_disks.len(), 1);
        assert_eq!(cfg.krun.extra_disks[0].path, "/img/data.img");
        assert!(!cfg.krun.extra_disks[0].read_only);
    }

    #[test]
    fn relay_config_puts_every_block_in_extra_disks_for_an_initramfs_boot() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![],
            vec![
                BlockDev {
                    source: "/img/rootfs.ext4".into(),
                    read_only: true,
                    ephemeral: false,
                    slot: 0,
                },
                BlockDev {
                    source: "/img/rootfs.verity".into(),
                    read_only: true,
                    ephemeral: false,
                    slot: 1,
                },
            ],
        );
        spec.initramfs = Some("/img/initrd.cpio".into());
        let cfg = relay(&spec);
        // initramfs boot ⇒ no rootfs_path; slot 0 is the first extra disk (vda).
        assert_eq!(cfg.krun.rootfs_path, None);
        assert_eq!(cfg.krun.initramfs_path.as_deref(), Some("/img/initrd.cpio"));
        let paths: Vec<&str> = cfg
            .krun
            .extra_disks
            .iter()
            .map(|d| d.path.as_str())
            .collect();
        assert_eq!(paths, vec!["/img/rootfs.ext4", "/img/rootfs.verity"]);
    }

    #[test]
    fn relay_config_treats_virtiofs_root_as_a_share_not_a_block() {
        let mut spec = spec_with(KernelImage::Path("/img/Image".into()), vec![], vec![]);
        spec.shares.push(VirtioFsShare {
            tag: "mvmroot".into(),
            host_path: "/host/root".into(),
            read_only: true,
            dax: true,
        });
        let cfg = relay(&spec);
        // No block rootfs; the root is supplied by the virtiofs share.
        assert_eq!(cfg.krun.rootfs_path, None);
        assert_eq!(cfg.krun.initramfs_path, None);
        assert_eq!(cfg.krun.extra_disks.len(), 0);
        assert_eq!(cfg.krun.virtio_fs_mounts.len(), 1);
        let root = &cfg.krun.virtio_fs_mounts[0];
        assert_eq!(root.tag, "mvmroot");
        assert_eq!(root.host_path, "/host/root");
        assert!(root.read_only);
        assert_eq!(root.shm_size, Some(VIRTIO_FS_DAX_SHM_SIZE));
        // Empty cmdline ⇒ the driver supplies the virtiofs-root base.
        assert_eq!(
            cfg.krun.kernel_cmdline.as_deref(),
            Some("console=hvc0 rootfstype=virtiofs root=mvmroot ro init=/init")
        );
    }

    #[test]
    fn relay_config_keeps_blocks_as_extras_when_virtiofs_root_is_present() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![],
            vec![BlockDev {
                source: "/img/data.img".into(),
                read_only: false,
                ephemeral: false,
                slot: 0,
            }],
        );
        spec.shares.push(VirtioFsShare {
            tag: "mvmroot".into(),
            host_path: "/host/root".into(),
            read_only: true,
            dax: true,
        });
        let cfg = relay(&spec);
        // The share is the root; the block is an extra disk, not /dev/vda rootfs.
        assert_eq!(cfg.krun.rootfs_path, None);
        assert_eq!(cfg.krun.extra_disks.len(), 1);
        assert_eq!(cfg.krun.extra_disks[0].path, "/img/data.img");
        assert_eq!(cfg.krun.virtio_fs_mounts.len(), 1);
    }

    #[test]
    fn relay_config_maps_dir_shares_with_dax_and_read_only() {
        let mut spec = spec_with(KernelImage::Path("/img/Image".into()), vec![], vec![]);
        spec.shares.push(VirtioFsShare {
            tag: "uvol0".into(),
            host_path: "/host/rw".into(),
            read_only: false,
            dax: true,
        });
        spec.shares.push(VirtioFsShare {
            tag: "uvol1".into(),
            host_path: "/host/ro".into(),
            read_only: true,
            dax: true,
        });
        spec.shares.push(VirtioFsShare {
            tag: "uvol2".into(),
            host_path: "/host/legacy".into(),
            read_only: false,
            dax: false,
        });
        let cfg = relay(&spec);
        let mounts: std::collections::HashMap<&str, &libkrun_sys::KrunVirtioFs> = cfg
            .krun
            .virtio_fs_mounts
            .iter()
            .map(|m| (m.tag.as_str(), m))
            .collect();
        assert_eq!(mounts.len(), 3);
        let rw = mounts["uvol0"];
        assert_eq!(rw.host_path, "/host/rw");
        assert!(!rw.read_only);
        assert_eq!(rw.shm_size, Some(VIRTIO_FS_DAX_SHM_SIZE));

        let ro = mounts["uvol1"];
        assert_eq!(ro.host_path, "/host/ro");
        assert!(ro.read_only);
        assert_eq!(ro.shm_size, Some(VIRTIO_FS_DAX_SHM_SIZE));

        let legacy = mounts["uvol2"];
        assert_eq!(legacy.host_path, "/host/legacy");
        assert!(!legacy.read_only);
        assert_eq!(legacy.shm_size, None);
    }

    #[test]
    fn relay_config_splits_vsock_ports_by_direction() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                host_dials(GuestService::MachineControl, "/run/agent.sock"),
                guest_dials(GuestService::NetworkFlow, "/run/egress.sock"),
                guest_dials(GuestService::WorkloadExit, "/run/exit.sock"),
                guest_dials(GuestService::Broker, "/run/broker.sock"),
                host_dials(
                    GuestService::ConsoleData {
                        port: CONSOLE_PORT_BASE + 1,
                    },
                    "/run/console.sock",
                ),
            ],
            vec![],
        );
        let cfg = relay(&spec);
        // HostDials → the host dials the guest's listeners (add_vsock_port).
        assert!(cfg.krun.vsock_ports.contains(&GUEST_AGENT_PORT));
        assert!(cfg.krun.vsock_ports.contains(&(CONSOLE_PORT_BASE + 1)));
        // GuestDials → the host binds the listener the guest dials.
        assert!(cfg.krun.host_listen_ports.contains(&EGRESS_PORT));
        assert!(cfg.krun.host_listen_ports.contains(&WORKLOAD_EXIT_PORT));
        assert!(cfg.krun.host_listen_ports.contains(&BROKER_PORT));
        // Disjoint: neither set carries a port from the other direction.
        assert!(!cfg.krun.vsock_ports.contains(&EGRESS_PORT));
        assert!(!cfg.krun.host_listen_ports.contains(&GUEST_AGENT_PORT));
    }

    #[test]
    fn relay_config_threads_a_non_empty_cmdline_and_defaults_an_empty_one() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![],
            vec![BlockDev {
                source: "/img/rootfs.ext4".into(),
                read_only: true,
                ephemeral: false,
                slot: 0,
            }],
        );
        // Non-empty (already carries the assembled base + tokens) ⇒ verbatim.
        spec.cmdline = "  console=hvc0 root=/dev/vda rw init=/init mvm.vsock_egress=1  ".into();
        let cfg = relay(&spec);
        assert_eq!(
            cfg.krun.kernel_cmdline.as_deref(),
            Some("console=hvc0 root=/dev/vda rw init=/init mvm.vsock_egress=1")
        );

        // Empty + a disk ⇒ the driver's default disk base.
        spec.cmdline = "   ".into();
        let cfg = relay(&spec);
        assert_eq!(
            cfg.krun.kernel_cmdline.as_deref(),
            Some("console=hvc0 root=/dev/vda ro init=/init")
        );

        // Empty + an initramfs (no disk root) ⇒ the console-only verity base.
        spec.initramfs = Some("/img/initrd.cpio".into());
        spec.blocks.clear();
        spec.cmdline = String::new();
        let cfg = relay(&spec);
        assert_eq!(
            cfg.krun.kernel_cmdline.as_deref(),
            Some(crate::driver::libkrun_process::VERITY_CMDLINE)
        );
    }

    #[test]
    fn relay_config_rejects_a_bundled_kernel() {
        // libkrun's workload disk-boot path requires an explicit kernel; a
        // bundled-kernel spec must not reach the supervisor.
        let spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        assert!(relay_libkrun_supervisor_config(&spec, Path::new("/state/w")).is_err());
    }

    #[test]
    fn relay_config_disables_the_guest_nic() {
        let spec = spec_with(KernelImage::Path("/img/Image".into()), vec![], vec![]);
        let cfg = relay(&spec);
        assert!(matches!(
            cfg.krun.networking,
            libkrun_sys::NetworkingMode::VsockDirect
        ));
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // Reattaching needs no boot state — it re-derives the state dir. A VM
        // that never ran (or has exited) reports Stopped rather than erroring.
        let vm = LibkrunDriver::new()
            .attach(&VmId("libkrun-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "libkrun-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn vsock_connect_reaches_the_agent_socket_and_rejects_other_ports() {
        use mvm_vmm::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        // The libkrun flat convention: <state_dir>/vsock-<port>.sock.
        let sock = vm_vsock_port_socket_at(dir.path(), GUEST_AGENT_PORT);
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut b = [0u8; 1];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });

        let vm = LibkrunRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join("libkrun.pid"),
        };

        // The agent port connects + round-trips through the socket.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // A port outside the agent + console data range is not host-dialable.
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
        assert!(vm.vsock_connect(9999).is_err());
    }

    #[test]
    fn running_vm_reads_the_supervisor_host_process() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("libkrun.pid");
        std::fs::write(&pid_file, "4242\n").unwrap();
        let vm = LibkrunRunningVm {
            id: VmId("measured-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file,
        };
        assert_eq!(vm.host_process_id(), Some(4242));
    }

    #[test]
    fn vsock_connect_reaches_a_dev_console_data_port() {
        use mvm_vmm::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let port = CONSOLE_PORT_BASE + 1;
        let sock = vm_vsock_port_socket_at(dir.path(), port);
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut b = [0u8; 1];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });

        let vm = LibkrunRunningVm {
            id: VmId("console-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join("libkrun.pid"),
        };

        let mut s = vm.vsock_connect(port).unwrap();
        s.write_all(b"y").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"y");
        server.join().unwrap();

        // The last console data port is in range; one past it is not.
        assert!(vm.vsock_connect(CONSOLE_PORT_BASE + 129).is_err());
    }

    /// The wrap has to be on the spawn itself. An unwrapped supervisor boots
    /// the VM perfectly well and is simply unbounded, so nothing but reading
    /// the argv back catches a regression here.
    #[test]
    fn a_granted_share_wraps_the_supervisor_spawn() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let mut spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        spec.cpu_grant = Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 });
        let cmd = bounded_supervisor_command(
            Path::new("/usr/bin/mvm-libkrun-supervisor"),
            &spec,
            scratch.path(),
        );

        // The unit carries a per-boot suffix, so it is matched by shape; every
        // other token is still pinned exactly.
        let mut argv = mvm_core::cpu_scope::rendered_argv(&cmd);
        assert!(
            argv[5].starts_with("w-") && argv[5].ends_with(".scope"),
            "unit should be the machine name plus a per-boot suffix, got {}",
            argv[5]
        );
        argv[5] = "<unit>".to_string();
        assert_eq!(
            argv,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                "<unit>",
                "-p",
                "CPUQuota=150%",
                "--",
                "/usr/bin/mvm-libkrun-supervisor",
            ]
        );
    }

    #[test]
    fn an_ungranted_launch_spawns_the_supervisor_directly() {
        let scratch = tempfile::tempdir().expect("scratch");
        let spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        let cmd = bounded_supervisor_command(
            Path::new("/usr/bin/mvm-libkrun-supervisor"),
            &spec,
            scratch.path(),
        );
        assert_eq!(
            mvm_core::cpu_scope::rendered_argv(&cmd),
            vec!["/usr/bin/mvm-libkrun-supervisor"]
        );
    }

    #[test]
    fn libkrun_spec_carries_exactly_one_network_flow_and_no_l3() {
        let spec = spec_with(
            KernelImage::Bundled,
            vec![
                guest_dials(GuestService::NetworkFlow, "/run/egress.sock"),
                host_dials(GuestService::MachineControl, "/run/agent.sock"),
            ],
            vec![],
        );
        let ports = &spec.vsock;
        let mut services: Vec<_> = ports.iter().map(|p| p.service).collect();
        services.sort();
        let expected = [GuestService::MachineControl, GuestService::NetworkFlow];
        assert_eq!(
            services, expected,
            "libkrun spec vsock must contain exactly one NetworkFlow and no retired L3 services"
        );
    }
}
