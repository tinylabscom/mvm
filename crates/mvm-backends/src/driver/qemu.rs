//! `QemuDriver` — the `VmmDriver` for the QEMU dev/test VMM (Linux; KVM
//! where present, TCG software-emulation fallback otherwise). Identity and
//! boots what a `VmmSpec` describes, reusing the QEMU machinery moved into
//! policy-free `VmmSpec` to `qemu-system` argv reusing the raw backend's
//! machinery (guest-CID allocation, argv assembly, pid-file lifecycle),
//! spawns the detached AF_VSOCK↔UNIX bridge set so the host reaches the
//! guest agent and the guest reaches its egress/exit/broker channels, and
//! returns a live handle. The claim-10 egress gate and secret substitution
//! live in the host-side endpoint the runner binds to the spec's
//! `EGRESS_PORT` socket; the driver only relays that channel through the
//! bridge — it carries no policy and never sees a `NetworkPolicy`.
//!
//! No NIC: the converged spec carries no networking (a guest's only path
//! off the box is the gated vsock egress endpoint), so the slirp
//! user-mode network the raw backend attaches is deliberately absent here —
//! the same NIC-less posture the other runner drivers boot.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_agentd::vsock::{CONSOLE_PORT_BASE, GUEST_AGENT_PORT, dev_console_data_ports};
use mvm_core::config::{vm_state_dir, vm_vsock_port_socket_at};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    ResourceControls, VmCapabilities, VmExitStatus, VmId, VmStatus,
};
use mvm_net::channel::GuestService;

use crate::driver::qemu_process::{
    self, QEMU_LOG_FILE, QEMU_PID_FILE, QemuBridgeGuestDial, QemuBridgeHostDial, QemuBridgeSpec,
};
use mvm_vmm::driver::spec::{KernelImage, VmmSpec, VsockDirection, VsockPort};
use mvm_vmm::driver::traits::{DuplexStream, RunningVm, VmmDriver};
use mvm_vmm::host::ui;
use mvm_vmm::host::virtiofsd::{SpawnParams, VirtiofsdGuard, locate_virtiofsd};
use mvm_vmm::qemu_arch::{machine_for_arch, serial_console_for_arch};

/// The QEMU VMM driver: pure VMM mechanics, no policy and no admission. It
/// boots what a `VmmSpec` describes and relays the guest's channels through
/// the vsock bridge; the claim-10 gate and substitution live in the
/// endpoint behind those channels, not here.
pub struct QemuDriver;

impl QemuDriver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for QemuDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The default base kernel cmdline for a QEMU workload boot. The serial device
/// follows the QEMU machine for the host architecture, and the cmdline carries
/// no NIC tokens — the converged path attaches no guest NIC. The root/init
/// selection follows the boot shape; the shared cmdline assembler layers
/// verity/grants/egress/uvols tokens on top of this.
fn qemu_base_bootargs_for_arch(arch: &str, has_disk: bool) -> String {
    // Serial console + reboot/panic behavior + stable interface naming.
    let console = format!(
        "console={} reboot=k panic=1 net.ifnames=0",
        serial_console_for_arch(arch)
    );
    if has_disk {
        format!("{console} root=/dev/vda ro rootwait init=/init")
    } else {
        // Verity / initramfs boot: the initramfs PID 1 owns root/init selection,
        // so only the serial-console base is emitted here.
        console.to_string()
    }
}

fn qemu_base_bootargs(has_disk: bool) -> String {
    qemu_base_bootargs_for_arch(std::env::consts::ARCH, has_disk)
}

/// AF_UNIX socket path QEMU uses to connect to `virtiofsd` for a given
/// share. Kept under `/tmp` so deeply-nested `MVM_HOME` paths don't bump into
/// the ~108-byte Linux AF_UNIX path limit.
fn qemu_virtiofs_socket_path(vm_name: &str, tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/mvm-vfs-{vm_name}-{tag}.sock"))
}

/// The qemu launch, bounded by whatever CPU share this VM was admitted under.
///
/// qemu `-daemonize`s, so the process this command returns from is not the one
/// that ends up running the guest. That is fine and was measured rather than
/// assumed: the daemonized child inherits the scope's cgroup, and a transient
/// scope stays active while any process remains in it.
fn bounded_qemu_command(
    qemu_bin: &str,
    argv: &[String],
    spec: &VmmSpec,
    state_dir: &Path,
) -> Command {
    let mut launch = Command::new(qemu_bin);
    launch.args(argv);
    mvm_core::cpu_scope::bind_cpu_grant(launch, &spec.name, state_dir, spec.cpu_grant.as_ref())
}

/// Assemble the `qemu-system` argv for a spec boot (everything after the
/// binary name). Pure so the whole spec→argv mapping is unit-testable
/// without a hypervisor. No `-netdev`: the converged spec carries no NIC.
fn qemu_boot_argv(
    spec: &VmmSpec,
    kernel: &Path,
    cid: u32,
    kvm: bool,
    pid_file: &Path,
) -> Vec<String> {
    qemu_boot_argv_for_arch(spec, kernel, cid, kvm, pid_file, std::env::consts::ARCH)
}

fn qemu_boot_argv_for_arch(
    spec: &VmmSpec,
    kernel: &Path,
    cid: u32,
    kvm: bool,
    pid_file: &Path,
    arch: &str,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    args.push("-m".into());
    args.push(spec.memory_mib.to_string());
    let vcpus = spec.vcpus.clamp(1, u32::from(u8::MAX));
    args.push("-smp".into());
    args.push(vcpus.to_string());
    if let Some(machine) = machine_for_arch(arch) {
        args.push("-machine".into());
        args.push(machine.into());
    }
    if kvm {
        args.push("-enable-kvm".into());
        args.push("-cpu".into());
        args.push("host".into());
    } else {
        args.push("-cpu".into());
        args.push("max".into());
    }

    // QEMU requires an explicit machine type on aarch64; the `virt` board
    // is the generic reference platform that matches our virtio-blk/vsock
    // device layout. x86_64 still boots with its built-in default, so we
    // only override on architectures that need it.
    if std::env::consts::ARCH == "aarch64" {
        args.push("-machine".into());
        args.push("virt".into());
    }

    let mem_arg = format!("{}M", spec.memory_mib);

    args.push("-kernel".into());
    args.push(kernel.to_string_lossy().into_owned());
    if let Some(initramfs) = &spec.initramfs {
        args.push("-initrd".into());
        args.push(initramfs.to_string_lossy().into_owned());
    }
    // An empty spec cmdline means "the driver supplies its own default base";
    // a non-empty one already carries the console + root/init base plus every
    // layered token, so it is threaded verbatim.
    let has_disk = spec.initramfs.is_none() && !spec.blocks.is_empty();
    let trimmed = spec.cmdline.trim();
    let cmdline = if trimmed.is_empty() {
        qemu_base_bootargs_for_arch(arch, has_disk)
    } else {
        trimmed.to_string()
    };
    args.push("-append".into());
    args.push(cmdline);

    // Slot-ordered virtio-blk layout: the guest device letters follow the
    // `-drive` order (first → /dev/vda, next → /dev/vdb, …), so the device
    // nodes line up with the slot model the activation message names. QEMU
    // serves every disk from its host file — there is no RAM-backed mode, so
    // `BlockDev::ephemeral` is not representable here; workload blocks are
    // read-only + non-ephemeral, so nothing is dropped.
    let mut ordered: Vec<&mvm_vmm::driver::spec::BlockDev> = spec.blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    for block in ordered {
        let mut drive = format!("file={},if=virtio,format=raw", block.source.display());
        if block.read_only {
            drive.push_str(",readonly=on");
        }
        args.push("-drive".into());
        args.push(drive);
    }

    // virtio-fs shares: one virtiofsd per share, one vhost-user-fs-pci device
    // per share, plus the shared memfd backend that makes vhost-user-fs work.
    if !spec.shares.is_empty() {
        args.push("-object".into());
        args.push(format!(
            "memory-backend-memfd,id=mem,size={mem_arg},share=on"
        ));
        args.push("-numa".into());
        args.push("node,memdev=mem".into());
        for share in &spec.shares {
            let tag = &share.tag;
            let sock = qemu_virtiofs_socket_path(&spec.name, tag);
            args.push("-chardev".into());
            args.push(format!("socket,id=vfs-{tag},path={}", sock.display()));
            args.push("-device".into());
            let mut fs_dev =
                format!("vhost-user-fs-pci,queue-size=1024,chardev=vfs-{tag},tag={tag}");
            if share.dax {
                // DAX window size per share. 256 MiB matches the HVF/libkrun
                // DAX window budget without ballooning the QEMU memory backend.
                fs_dev.push_str(",cache-size=256M");
            }
            args.push(fs_dev);
        }
    }

    // virtio-vsock on the per-VM guest CID. The host reaches the guest's
    // listeners through the AF_VSOCK↔UNIX bridge spawned after the boot.
    args.push("-device".into());
    args.push(format!("vhost-vsock-pci,guest-cid={cid}"));

    args.push("-display".into());
    args.push("none".into());
    args.push("-monitor".into());
    args.push("none".into());
    args.push("-no-reboot".into());
    // Write-only console sink (claim 15): qemu opens `-serial file:` for
    // output only; there is no host fd from which the guest could read
    // console input.
    args.push("-serial".into());
    args.push(format!("file:{}", spec.console.log_path.display()));
    args.push("-D".into());
    args.push(
        pid_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(QEMU_LOG_FILE)
            .to_string_lossy()
            .into_owned(),
    );
    // qemu forks into the background and writes its own pidfile.
    args.push("-daemonize".into());
    args.push("-pidfile".into());
    args.push(pid_file.to_string_lossy().into_owned());
    args
}

fn qemu_log_tail(log_path: &Path, max_lines: usize) -> String {
    let Ok(contents) = std::fs::read_to_string(log_path) else {
        return "qemu log was unavailable".to_string();
    };
    let mut lines: Vec<&str> = contents.lines().rev().take(max_lines).collect();
    lines.reverse();
    if lines.is_empty() {
        "qemu log was empty".to_string()
    } else {
        lines.join("\n")
    }
}

/// Assemble the bridge wiring plan for a spec boot: every host-dialed
/// channel (agent RPC, dev console data) binds the per-port UNIX socket
/// convention the shared client probes, every guest-dialed channel (egress,
/// broker) splices to the runner-bound listener named in the spec, and the
/// workload-exit port is captured under the state dir when the spec carries
/// it.
fn bridge_spec_for_vsock(cid: u32, state_dir: &Path, channels: &[VsockPort]) -> QemuBridgeSpec {
    let mut host_dials = Vec::new();
    let mut guest_dials = Vec::new();
    let mut exit_capture_state_dir = None;
    for port in channels {
        match port.direction {
            VsockDirection::HostDials => host_dials.push(QemuBridgeHostDial {
                guest_port: port.port(),
                // Re-derived from the state dir (the flat `vsock-<port>.sock`
                // convention the host-side resolver probes), never the spec's
                // backend-neutral hint — the same discipline the hvf, libkrun,
                // and Firecracker drivers apply to the agent socket, so binder
                // and resolver can't drift.
                listen_uds: vm_vsock_port_socket_at(state_dir, port.port()),
            }),
            // The workload-exit port has no runner-bound listener — its
            // `host_uds` is the captured-code output file, not a socket. The
            // bridge accepts the report and persists it (see qemu.rs).
            VsockDirection::GuestDials if port.service == GuestService::WorkloadExit => {
                exit_capture_state_dir = Some(state_dir.to_path_buf());
            }
            VsockDirection::GuestDials => guest_dials.push(QemuBridgeGuestDial {
                guest_port: port.port(),
                target_uds: port.host_uds.clone(),
            }),
        }
    }
    QemuBridgeSpec {
        cid,
        watch_pid_file: state_dir.join(QEMU_PID_FILE),
        host_dials,
        guest_dials,
        exit_capture_state_dir,
    }
}

impl VmmDriver for QemuDriver {
    fn name(&self) -> &str {
        "qemu"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Qemu
    }

    fn is_available(&self) -> Result<bool> {
        Ok(qemu_process::locate_qemu().is_ok())
    }

    fn capabilities(&self) -> VmCapabilities {
        // The runner-backed, NIC-less profile: the converged QEMU boot
        // attaches no slirp user-mode network (the raw backend's dev
        // convenience), so nothing in the guest can reach the network by IP
        // and egress rides the vsock endpoint exactly like the other runner
        // backends. Pause/resume stays false (no QMP monitor wired);
        // snapshots and the standby pool stay unsupported.
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            snapshot_capability: mvm_core::vm_backend::SnapshotCapability::Unsupported,
            standby_pool: false,
            vsock: true,
            // User-mode (slirp) networking — no host TAP device.
            tap_networking: false,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            balloon: false,
            fs_quick_checkpoint: false,
            // Named explicitly: this backend's per-VM process is cgroup-able,
            // unlike the all-`None` struct-update default.
            resource_controls: ResourceControls::for_backend(BackendKind::Qemu),
            ..VmCapabilities::default()
        }
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Same claim coverage as the raw backend — Tier 2 best-case (KVM),
        // claim 3 (verified boot) targeting Firecracker — with the notes
        // updated for the converged boot path. The TCG (no-KVM) mode is a
        // runtime Tier-3 degradation surfaced by the boot banner + doctor,
        // not by this compile-time tier.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1
                ClaimStatus::Holds,       // 2
                ClaimStatus::DoesNotHold, // 3 — verified boot targets Firecracker
                ClaimStatus::Holds,       // 4
                ClaimStatus::Holds,       // 5
                ClaimStatus::Holds,       // 6
                ClaimStatus::Holds,       // 7
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "QEMU workload runtime; dev/test tier only, opt-in via --hypervisor qemu, never auto-selected.",
                "Boots through the unified workload runner: attaches the universal initramfs and \
                 receives ActivateEnvironment over vsock, exactly like Firecracker/libkrun/HVF — \
                 QEMU's vhost-vsock speaks AF_VSOCK, so the channels ride the per-VM \
                 AF_VSOCK↔UNIX bridge into the same per-port UNIX-socket convention.",
                "KVM-accelerated where /dev/kvm is present; TCG software-emulation fallback \
                 otherwise (runtime Tier-3, banner-flagged).",
                "Larger device model than Firecracker → higher L2 audit cost; outside the \
                 CI-enforced claim set. Never a production runtime.",
            ],
        }
    }

    fn workload_base_bootargs(&self, has_disk: bool) -> String {
        qemu_base_bootargs(has_disk)
    }

    #[tracing::instrument(
        name = "qemu.boot",
        skip_all,
        fields(vm = %spec.name, vcpus = spec.vcpus, memory_mib = spec.memory_mib)
    )]
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        // QEMU has no bundled kernel (libkrun's libkrunfw is the only
        // bundled-kernel backend): a `Bundled` spec takes the same cached
        // builder-kernel fallback the raw path uses for a kernel-less
        // workload rootfs.
        let kernel = match &spec.kernel {
            KernelImage::Path(p) => p.clone(),
            KernelImage::Bundled => qemu_process::resolve_workload_kernel_path(&spec.name, None)?,
        };
        let qemu_bin = qemu_process::locate_qemu()?;

        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        // Clear any prior run's captured exit code and usage record so `wait`
        // and the exit report read only this launch's, and pre-create the
        // write-only console sink so the invariant + truncate-on-boot match
        // the other backends.
        mvm_core::run_sidecars::clear_prior_run(&state_dir);
        drop(
            mvm_vmm::host::console_capture::open_console_capture(&spec.console.log_path).map_err(
                |e| anyhow!("open console sink {}: {e}", spec.console.log_path.display()),
            )?,
        );

        let kvm = qemu_process::kvm_available();
        if !kvm {
            // Loud Tier-3 banner for the unaccelerated TCG fallback — the
            // same runtime-tier signal the raw path emits.
            ui::warn(&format!(
                "QEMU workload '{}' is running UNACCELERATED (TCG — no /dev/kvm). \
                 This is a Tier-3 dev/test fallback: slow, and unaudited vs the \
                 production security posture. For production use a /dev/kvm host \
                 (Firecracker).",
                spec.name
            ));
        }

        let cid = qemu_process::allocate_cid(&spec.name)?;
        let pid_file = state_dir.join(QEMU_PID_FILE);
        let _ = std::fs::remove_file(&pid_file);

        // Bring up one virtiofsd per share before QEMU. QEMU connects to the
        // sockets as a client at launch, so they must exist first. The guard
        // is moved into the running-VM handle and dropped on kill so daemons
        // and sockets are cleaned up when the VM goes away.
        let mut virtiofsd = None;
        if !spec.shares.is_empty() {
            let (virtiofsd_bin, virtiofsd_flavor) = locate_virtiofsd()?;
            let mut guard = VirtiofsdGuard::default();
            for share in &spec.shares {
                let sock = qemu_virtiofs_socket_path(&spec.name, &share.tag);
                guard.spawn(
                    SpawnParams::new(
                        &virtiofsd_bin,
                        virtiofsd_flavor,
                        &share.tag,
                        &sock,
                        &share.host_path,
                    )
                    .read_only(share.read_only)
                    .dax(share.dax),
                )?;
            }
            virtiofsd = Some(guard);
        }

        let argv = qemu_boot_argv(spec, &kernel, cid, kvm, &pid_file);
        tracing::debug!(qemu_bin = %qemu_bin, argv = ?argv, "launching qemu-system");
        let status = bounded_qemu_command(&qemu_bin, &argv, spec, &state_dir)
            .status()
            .map_err(|e| anyhow!("spawn qemu ({qemu_bin}): {e}"))?;
        if !status.success() {
            let log_path = state_dir.join(QEMU_LOG_FILE);
            bail!(
                "qemu-system exited {} before daemonizing workload '{}'; {} tail:\n{}",
                status.code().unwrap_or(-1),
                spec.name,
                log_path.display(),
                qemu_log_tail(&log_path, 40)
            );
        }

        // `-daemonize` returns only after the pidfile is written, but poll
        // defensively so a slow fork doesn't race the bridge spawn below.
        let deadline = Instant::now() + qemu_process::PID_FILE_TIMEOUT;
        while !pid_file.exists() {
            if Instant::now() >= deadline {
                bail!(
                    "qemu did not write pidfile {} within {:?}",
                    pid_file.display(),
                    qemu_process::PID_FILE_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Wire the whole channel set through the bridge. If the bridge can't
        // come up, the already-daemonized qemu would be orphaned (a failed
        // `boot` won't be followed by `stop`). Roll back: kill qemu + drop
        // the pid/cid sidecars so a retry re-allocates a CID instead of
        // pinning the (possibly conflicting) one this attempt wrote.
        let bridge_spec = bridge_spec_for_vsock(cid, &state_dir, &spec.vsock);
        if let Err(e) = qemu_process::spawn_vsock_bridges(&spec.name, &state_dir, &bridge_spec) {
            if let Some(pid) = qemu_process::read_pid(&pid_file) {
                qemu_process::send_signal(pid, libc::SIGTERM);
            }
            let _ = std::fs::remove_file(&pid_file);
            let _ = std::fs::remove_file(state_dir.join(qemu_process::QEMU_CID_FILE));
            return Err(e);
        }

        Ok(Box::new(QemuRunningVm {
            id: VmId(spec.name.clone()),
            state_dir,
            pid_file,
            virtiofsd: std::sync::Mutex::new(virtiofsd),
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the qemu pid file + the
        // persisted workload-exit code under the VM's state dir), so
        // reattaching is just re-deriving those paths — no live boot state
        // to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(QemuRunningVm {
            pid_file: state_dir.join(QEMU_PID_FILE),
            state_dir,
            id: id.clone(),
            virtiofsd: std::sync::Mutex::new(None),
        }))
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        // The shared agent client connects to the UNIX socket the bridge
        // binds (`vm_vsock_port_socket`); the `cid` here is the guest CID
        // the bridge dials over AF_VSOCK, surfaced for diagnostics.
        let cid = qemu_process::read_cid(&id.0).unwrap_or(3);
        Ok(GuestChannelInfo::Vsock {
            cid,
            port: mvm_agentd::vsock::GUEST_AGENT_PORT,
        })
    }
}

/// A live QEMU VM: the daemonized `qemu-system` process tracked by its PID
/// file, with the workload's exit code persisted under its state dir and the
/// detached bridge serving its vsock channels.
struct QemuRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
    virtiofsd: std::sync::Mutex<Option<VirtiofsdGuard>>,
}

impl RunningVm for QemuRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(mvm_vmm::host::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        // Reap the bridge first so it can't keep serving a half-dead VM.
        // Guard on liveness so a stale pidfile (crash without cleanup) whose
        // PID the OS has since recycled isn't signalled by mistake.
        if let Some(bridge_pid) =
            qemu_process::read_pid(&self.state_dir.join(qemu_process::BRIDGE_PID_FILE))
            && qemu_process::pid_alive(bridge_pid)
        {
            qemu_process::send_signal(bridge_pid, libc::SIGTERM);
        }
        let _ = std::fs::remove_file(self.state_dir.join(qemu_process::BRIDGE_PID_FILE));
        qemu_process::cleanup_vsock_bridge_sockets(&self.state_dir);

        // Arm before SIGTERM so a short-lived QEMU process cannot exit between
        // signal delivery and observer registration.
        if let Some(pid) = qemu_process::read_pid(&self.pid_file)
            && qemu_process::pid_alive(pid)
        {
            let observer = mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid).ok();
            // SIGTERM gives QEMU a chance to close its virtio-blk file
            // descriptors, then SIGKILL if it ignores us within the grace
            // window.
            qemu_process::send_signal(pid, libc::SIGTERM);
            let exited = mvm_vmm::host::process_exit::wait_for_pid_exit(
                pid,
                Instant::now() + qemu_process::STOP_TIMEOUT,
                observer.as_ref(),
            );
            if !exited {
                qemu_process::send_signal(pid, libc::SIGKILL);
                if !mvm_vmm::host::process_exit::wait_for_pid_exit(
                    pid,
                    Instant::now() + Duration::from_millis(500),
                    observer.as_ref(),
                ) {
                    return Err(anyhow!(
                        "QEMU PID {pid} could not be proven dead after SIGKILL; preserving {}",
                        self.pid_file.display()
                    ));
                }
            }
        }
        let _ = std::fs::remove_file(&self.pid_file);

        // Release the virtiofsd daemons now that QEMU is gone. Dropping the
        // guard kills the children and removes their sockets.
        if let Some(guard) = self.virtiofsd.lock().unwrap().take() {
            drop(guard);
        }
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        bail!("pause is not supported by the qemu backend (QMP monitor not wired)")
    }

    fn resume(&self) -> Result<()> {
        bail!("resume is not supported by the qemu backend (QMP monitor not wired)")
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(match qemu_process::read_pid(&self.pid_file) {
            Some(pid) if qemu_process::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        // The bridge binds every host-dialed channel on the flat
        // `<state_dir>/vsock-<port>.sock` convention — the same path the
        // host-side resolver probes. Restricted to the agent port and the
        // dev-only console data ports (claim 15: a sealed prod boot
        // registers no console listeners), mirroring the other drivers'
        // allow-list.
        if guest_port != GUEST_AGENT_PORT && !dev_console_data_ports().any(|p| p == guest_port) {
            bail!(
                "qemu driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}) and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        }
        let socket_path = vm_vsock_port_socket_at(&self.state_dir, guest_port);
        let stream = std::os::unix::net::UnixStream::connect(&socket_path).with_context(|| {
            format!(
                "connect to qemu vsock bridge socket {}",
                socket_path.display()
            )
        })?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT};
    use mvm_core::vm_backend::SnapshotCapability;
    use mvm_vmm::driver::spec::{BlockDev, ConsoleCapture, VirtioFsShare};

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
            initramfs: Some("/img/initramfs.cpio.gz".into()),
            cmdline: String::new(),
            vcpus: 2,
            cpu_grant: None,
            memory_mib: 512,
            mem_initial_mib: None,
            blocks,
            shares: vec![],
            vsock,
            console: ConsoleCapture {
                log_path: "/state/w/console.log".into(),
            },
            trusted_builder: false,
            plan_binding: None,
        }
    }

    fn block(source: &str, read_only: bool, slot: u8) -> BlockDev {
        BlockDev {
            source: source.into(),
            read_only,
            ephemeral: false,
            slot,
        }
    }

    fn argvalue<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    #[test]
    fn argv_maps_virtio_fs_shares() {
        let mut spec = spec_with(KernelImage::Path("/img/Image".into()), vec![], vec![]);
        spec.shares = vec![
            VirtioFsShare {
                tag: "mvmroot".into(),
                host_path: "/host/root".into(),
                read_only: true,
                dax: true,
            },
            VirtioFsShare {
                tag: "uvol0".into(),
                host_path: "/host/vol0".into(),
                read_only: false,
                dax: false,
            },
        ];
        let argv = qemu_boot_argv(
            &spec,
            Path::new("/img/Image"),
            7,
            true,
            Path::new("/state/w/qemu.pid"),
        );

        // Shared memory backend required by vhost-user-fs, sized to match -m.
        let object = argvalue(&argv, "-object").expect("-object");
        assert!(
            object.contains("memory-backend-memfd"),
            "expected memfd backend, got: {object}"
        );
        assert!(
            object.contains("share=on"),
            "expected share=on, got: {object}"
        );
        assert!(object.contains("size=512M"), "expected 512M, got: {object}");
        assert_eq!(argvalue(&argv, "-numa"), Some("node,memdev=mem"));

        // One chardev + one device per share, socket under /tmp.
        let chardevs: Vec<&str> = argv
            .iter()
            .zip(argv.iter().skip(1))
            .filter(|(flag, _)| flag.as_str() == "-chardev")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(chardevs.len(), 2);
        assert!(
            chardevs
                .iter()
                .any(|c| c.contains("id=vfs-mvmroot") && c.contains("/tmp/mvm-vfs-w-mvmroot.sock"))
        );
        assert!(
            chardevs
                .iter()
                .any(|c| c.contains("id=vfs-uvol0") && c.contains("/tmp/mvm-vfs-w-uvol0.sock"))
        );

        let fs_devs: Vec<&str> = argv
            .iter()
            .zip(argv.iter().skip(1))
            .filter(|(flag, _)| flag.as_str() == "-device")
            .map(|(_, value)| value.as_str())
            .filter(|v| v.starts_with("vhost-user-fs-pci"))
            .collect();
        assert_eq!(fs_devs.len(), 2);
        assert!(
            fs_devs
                .iter()
                .any(|d| d.contains("chardev=vfs-mvmroot") && d.contains("tag=mvmroot"))
        );
        assert!(
            fs_devs
                .iter()
                .any(|d| d.contains("chardev=vfs-uvol0") && d.contains("tag=uvol0"))
        );

        // A share no longer steers the root: an `mvmroot` share used to make the
        // default cmdline boot from virtiofs, and that strategy is gone. Shares
        // are still mapped to devices — the builder VM depends on it — but the
        // root is always the block image.
        let append = argvalue(&argv, "-append").expect("-append");
        assert!(
            !append.contains("virtiofs") && !append.contains("root=mvmroot"),
            "no cmdline may boot a virtiofs root: {append}"
        );
    }

    #[test]
    fn identity_and_capabilities_delegate_then_flip_to_the_nic_less_profile() {
        let d = QemuDriver::new();
        assert_eq!(d.name(), "qemu");
        assert_eq!(d.kind(), BackendKind::Qemu);
        let caps = d.capabilities();
        assert!(caps.vsock);
        // The converged boot attaches no slirp NIC: no routable guest NIC,
        // egress rides the vsock endpoint like every other runner backend.
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert!(!caps.tap_networking);
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert_eq!(caps.snapshot_capability, SnapshotCapability::Unsupported);
        assert!(!caps.standby_pool);
    }

    #[test]
    fn security_profile_matches_the_raw_backend_claims_with_runner_notes() {
        let d = QemuDriver::new();
        let profile = d.security_profile();
        assert!(profile.tier.starts_with("Tier 2"));
        // Claim 3 (verified boot) targets Firecracker — same coverage as the
        // raw backend reports.
        assert_eq!(profile.dropped_claims(), vec![3]);
        assert_eq!(
            profile.claims,
            [
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                ClaimStatus::DoesNotHold,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
                ClaimStatus::Holds,
            ]
        );
        assert!(
            profile
                .notes
                .iter()
                .any(|n| n.contains("ActivateEnvironment")),
            "notes must record the unified vsock-activation boot path"
        );
    }

    #[test]
    fn base_bootargs_follow_the_boot_shape_with_no_nic_or_roothash_tokens() {
        let d = QemuDriver::new();
        let console = format!(
            "console={}",
            serial_console_for_arch(std::env::consts::ARCH)
        );
        let disk = d.workload_base_bootargs(true);
        assert!(disk.contains(&console), "got: {disk}");
        assert!(disk.contains("root=/dev/vda"), "got: {disk}");
        assert!(disk.contains("init=/init"), "got: {disk}");
        assert!(!disk.contains("mvm.roothash="), "got: {disk}");
        assert!(!disk.contains("mvm.ip="), "got: {disk}");

        // Verity / initramfs base: serial console only, no root/init token.
        let verity = d.workload_base_bootargs(false);
        assert!(!verity.contains("root="), "got: {verity}");
        assert!(!verity.contains("init=/init"), "got: {verity}");
        assert!(verity.contains(&console), "got: {verity}");

        // No third shape: the virtiofs-root base is gone.
        assert!(!disk.contains("virtiofs") && !verity.contains("virtiofs"));
    }

    #[test]
    fn argv_maps_the_spec_verbatim_and_carries_no_nic() {
        let spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![],
            vec![
                // Out of slot order, mixed read-only policy — proves sorting
                // and per-disk flags land in device-letter order.
                block("/img/rootfs.verity", true, 1),
                block("/img/rootfs.ext4", true, 0),
                block("/vol/data.img", false, 2),
            ],
        );
        let spec = VmmSpec {
            cmdline: "  console=ttyAMA0 mvm.vsock_egress=1  ".into(),
            ..spec
        };
        let argv = qemu_boot_argv(
            &spec,
            Path::new("/img/vmlinux"),
            7,
            true,
            Path::new("/state/w/qemu.pid"),
        );

        assert_eq!(argvalue(&argv, "-kernel"), Some("/img/vmlinux"));
        assert_eq!(argvalue(&argv, "-initrd"), Some("/img/initramfs.cpio.gz"));
        // Non-empty spec cmdline is threaded verbatim (trimmed).
        assert_eq!(
            argvalue(&argv, "-append"),
            Some("console=ttyAMA0 mvm.vsock_egress=1")
        );
        assert_eq!(argvalue(&argv, "-m"), Some("512"));
        assert_eq!(argvalue(&argv, "-smp"), Some("2"));
        assert!(argv.contains(&"-enable-kvm".to_string()));
        assert_eq!(argvalue(&argv, "-cpu"), Some("host"));

        // Drives in slot order (device letters follow -drive order), each
        // carrying its own read-only policy.
        let drives: Vec<&str> = argv
            .iter()
            .zip(argv.iter().skip(1))
            .filter(|(flag, _)| flag.as_str() == "-drive")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            drives,
            vec![
                "file=/img/rootfs.ext4,if=virtio,format=raw,readonly=on",
                "file=/img/rootfs.verity,if=virtio,format=raw,readonly=on",
                "file=/vol/data.img,if=virtio,format=raw",
            ]
        );

        // virtio-vsock on the allocated guest CID; no NIC of any kind.
        assert!(
            argv.iter().any(|a| a == "vhost-vsock-pci,guest-cid=7"),
            "argv: {argv:?}"
        );
        assert!(!argv.iter().any(|a| a == "-netdev"), "argv: {argv:?}");
        assert!(
            !argv.iter().any(|a| a.contains("virtio-net")),
            "argv: {argv:?}"
        );

        // Daemonized, pid-filed, write-only serial capture, qemu log.
        assert!(argv.contains(&"-daemonize".to_string()));
        assert_eq!(argvalue(&argv, "-pidfile"), Some("/state/w/qemu.pid"));
        assert_eq!(
            argvalue(&argv, "-serial"),
            Some("file:/state/w/console.log")
        );
        assert_eq!(argvalue(&argv, "-D"), Some("/state/w/qemu.log"));
    }

    #[test]
    fn argv_defaults_the_cmdline_base_by_boot_shape_and_uses_tcg_without_kvm() {
        // Empty cmdline + an initramfs (no disk root) ⇒ console-only base.
        let spec = spec_with(KernelImage::Path("/img/vmlinux".into()), vec![], vec![]);
        let argv = qemu_boot_argv_for_arch(
            &spec,
            Path::new("/img/vmlinux"),
            3,
            false,
            Path::new("/state/w/qemu.pid"),
            "x86_64",
        );
        let append = argvalue(&argv, "-append").expect("append");
        assert!(append.contains("console=ttyS0"), "got: {append}");
        assert!(!append.contains("root="), "got: {append}");
        // No KVM: software emulation, no -enable-kvm.
        assert!(!argv.contains(&"-enable-kvm".to_string()));
        assert_eq!(argvalue(&argv, "-cpu"), Some("max"));

        // Empty cmdline + a disk and no initramfs ⇒ the disk-root base.
        let mut spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![],
            vec![block("/img/rootfs.ext4", true, 0)],
        );
        spec.initramfs = None;
        let argv = qemu_boot_argv_for_arch(
            &spec,
            Path::new("/img/vmlinux"),
            3,
            true,
            Path::new("/state/w/qemu.pid"),
            "x86_64",
        );
        let append = argvalue(&argv, "-append").expect("append");
        assert!(append.contains("root=/dev/vda"), "got: {append}");
        assert!(append.contains("init=/init"), "got: {append}");
        assert!(!argv.contains(&"-initrd".to_string()));
    }

    #[test]
    fn aarch64_argv_selects_virt_machine_and_pl011_console() {
        let spec = spec_with(KernelImage::Path("/img/vmlinux".into()), vec![], vec![]);
        let argv = qemu_boot_argv_for_arch(
            &spec,
            Path::new("/img/vmlinux"),
            3,
            false,
            Path::new("/state/w/qemu.pid"),
            "aarch64",
        );

        assert_eq!(argvalue(&argv, "-machine"), Some("virt"));
        let append = argvalue(&argv, "-append").expect("append");
        assert!(append.contains("console=ttyAMA0"), "got: {append}");
        assert!(!append.contains("console=ttyS0"), "got: {append}");
    }

    #[test]
    fn qemu_log_tail_keeps_only_the_latest_bounded_diagnostics() {
        let scratch = tempfile::tempdir().expect("scratch");
        let log = scratch.path().join("qemu.log");
        std::fs::write(&log, "one\ntwo\nthree\nfour\n").expect("write qemu log");

        assert_eq!(qemu_log_tail(&log, 2), "three\nfour");
        assert_eq!(
            qemu_log_tail(&scratch.path().join("missing.log"), 2),
            "qemu log was unavailable"
        );
    }

    #[test]
    fn bridge_spec_maps_channels_by_direction_and_re_derives_host_sockets() {
        let state_dir = Path::new("/state/w");
        let channels = vec![
            host_dials(GuestService::MachineControl, "/run/agent-hint.sock"),
            guest_dials(GuestService::NetworkFlow, "/run/egress.sock"),
            guest_dials(GuestService::WorkloadExit, "/state/w/workload.exit"),
            guest_dials(GuestService::Broker, "/run/broker.sock"),
            host_dials(
                GuestService::ConsoleData {
                    port: CONSOLE_PORT_BASE + 1,
                },
                "/run/console-hint.sock",
            ),
        ];
        let spec = bridge_spec_for_vsock(9, state_dir, &channels);

        assert_eq!(spec.cid, 9);
        assert_eq!(spec.watch_pid_file, PathBuf::from("/state/w/qemu.pid"));

        // Host-dialed channels bind the re-derived per-port socket, never
        // the spec's backend-neutral hint.
        assert_eq!(spec.host_dials.len(), 2);
        assert_eq!(spec.host_dials[0].guest_port, GUEST_AGENT_PORT);
        assert_eq!(
            spec.host_dials[0].listen_uds,
            vm_vsock_port_socket_at(state_dir, GUEST_AGENT_PORT)
        );
        assert_eq!(spec.host_dials[1].guest_port, CONSOLE_PORT_BASE + 1);
        assert_eq!(
            spec.host_dials[1].listen_uds,
            vm_vsock_port_socket_at(state_dir, CONSOLE_PORT_BASE + 1)
        );

        // Guest-dialed channels splice to the runner-bound listener verbatim;
        // the exit port is captured, not relayed.
        assert_eq!(
            spec.guest_dials,
            vec![
                QemuBridgeGuestDial {
                    guest_port: EGRESS_PORT,
                    target_uds: PathBuf::from("/run/egress.sock"),
                },
                QemuBridgeGuestDial {
                    guest_port: BROKER_PORT,
                    target_uds: PathBuf::from("/run/broker.sock"),
                },
            ]
        );
        assert_eq!(spec.exit_capture_state_dir, Some(PathBuf::from("/state/w")));
    }

    #[test]
    fn bridge_spec_without_an_exit_port_captures_nothing() {
        let spec = bridge_spec_for_vsock(
            3,
            Path::new("/state/w"),
            &[host_dials(GuestService::MachineControl, "/run/agent.sock")],
        );
        assert_eq!(spec.exit_capture_state_dir, None);
        assert!(spec.guest_dials.is_empty());
    }

    #[test]
    fn bundled_kernel_resolves_the_cached_builder_fallback() {
        let _guard = mvm_vmm::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        // Missing cache entry ⇒ a clear, named failure.
        let err = qemu_process::resolve_workload_kernel_path("w", None).unwrap_err();
        assert!(
            err.to_string().contains("no bootable kernel"),
            "unexpected error: {err}"
        );

        // Seed the cached builder kernel ⇒ the fallback resolves it.
        let cached = dir
            .path()
            .join("cache")
            .join("builder-vm")
            .join(if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            })
            .join("vmlinux");
        std::fs::create_dir_all(cached.parent().expect("cache parent")).unwrap();
        std::fs::write(&cached, b"kernel").unwrap();
        assert_eq!(
            qemu_process::resolve_workload_kernel_path("w", None).unwrap(),
            cached
        );
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        let vm = QemuDriver::new()
            .attach(&VmId("qemu-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "qemu-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
        // Killing a VM with no pid file is a no-op, not an error.
        assert!(vm.kill().is_ok());
    }

    #[test]
    fn guest_channel_info_reports_the_vsock_agent_channel() {
        let d = QemuDriver::new();
        let id = VmId("qemu-guest-channel-info-test-vm".into());
        let info = d.guest_channel_info(&id).unwrap();
        let rendered = format!("{:?}", info);
        assert!(rendered.contains("Vsock"));
        assert!(rendered.contains("cid: 3"));
        assert!(rendered.contains(&format!("port: {}", mvm_agentd::vsock::GUEST_AGENT_PORT)));
    }

    #[test]
    fn vsock_connect_reaches_the_bridge_socket_and_rejects_other_ports() {
        use mvm_vmm::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        // The bridge's agent listener: <state_dir>/vsock-<port>.sock.
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

        let vm = QemuRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(QEMU_PID_FILE),
            virtiofsd: std::sync::Mutex::new(None),
        };

        // The agent port connects + round-trips through the bridge socket —
        // the seam ActivateEnvironment rides.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // Ports outside the agent + console data range are not host-dialable.
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
        assert!(vm.vsock_connect(9999).is_err());
    }

    /// qemu daemonizes, so nothing downstream of the spawn can be inspected for
    /// the bound — the argv is the only place it is visible.
    #[test]
    fn a_granted_share_wraps_the_qemu_spawn_ahead_of_its_own_argv() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let mut spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        spec.cpu_grant = Some(mvm_contract::grants::CpuGrant::Share { millicores: 2000 });
        let argv = vec!["-machine".to_string(), "microvm".to_string()];
        let cmd = bounded_qemu_command("qemu-system-x86_64", &argv, &spec, scratch.path());

        // The unit carries a per-boot suffix, so it is matched by shape; every
        // other token is still pinned exactly.
        let mut rendered = mvm_core::cpu_scope::rendered_argv(&cmd);
        assert!(
            rendered[5].starts_with("w-") && rendered[5].ends_with(".scope"),
            "unit should be the machine name plus a per-boot suffix, got {}",
            rendered[5]
        );
        rendered[5] = "<unit>".to_string();
        assert_eq!(
            rendered,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                "<unit>",
                "-p",
                "CPUQuota=200%",
                "--",
                "qemu-system-x86_64",
                "-machine",
                "microvm",
            ]
        );
    }

    #[test]
    fn an_ungranted_launch_spawns_qemu_directly() {
        let scratch = tempfile::tempdir().expect("scratch");
        let spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        let argv = vec!["-machine".to_string(), "microvm".to_string()];
        let cmd = bounded_qemu_command("qemu-system-x86_64", &argv, &spec, scratch.path());
        assert_eq!(
            mvm_core::cpu_scope::rendered_argv(&cmd),
            vec!["qemu-system-x86_64", "-machine", "microvm"]
        );
    }
}
