//! `FcDriver` — the `VmmDriver` for Firecracker (Linux KVM). Identity delegates
//! to the proven `FirecrackerBackend`, but capabilities are the flipped,
//! NIC-less profile: the converged Firecracker path carries no routable guest
//! NIC and routes egress solely over vsock, exactly like libkrun and hvf.
//!
//! `boot` assembles a NIC-less Firecracker launch from a policy-free `VmmSpec`
//! using the shared `microvm` primitives — the FC-loadable kernel prep, the
//! process spawn, and the raw API client — never the entangled production TAP
//! path. It drives the guest's egress port to the host-side endpoint the runner
//! bound to the spec's `EGRESS_PORT` socket; the claim-10 gate and secret
//! substitution live in that endpoint, not here. The driver carries no policy
//! and never sees a `NetworkPolicy`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_agentd::vsock::{
    CONSOLE_PORT_BASE, GUEST_AGENT_PORT, GUEST_CID, WORKLOAD_EXIT_PORT, connect_to_port,
    dev_console_data_ports,
};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, SnapshotCapability, VmBackend,
    VmCapabilities, VmExitStatus, VmId, VmStatus,
};

use crate::backend::FirecrackerBackend;
use crate::driver::spec::KernelImage;
use crate::driver::{BlockDev, DuplexStream, RunningVm, VmmDriver, VmmSpec, VsockDirection};
use crate::microvm::{
    api_put_socket, balloon_body, boot_source_body, drive_body, fc_pid_path,
    firecracker_vsock_uds_path, logger_body, machine_config_body, start_vm_firecracker, vsock_body,
};

/// Host→guest dial timeout (seconds) for `vsock_connect`. The underlying
/// `connect_to_port` retries the CONNECT handshake internally within this bound.
const VSOCK_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Overall deadline for the guest agent to answer its first CONNECT after
/// `InstanceStart` — the boot-confirmation signal that the guest is up.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// The Firecracker VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge,
/// not here.
pub struct FcDriver {
    backend: FirecrackerBackend,
}

impl FcDriver {
    pub fn new() -> Self {
        Self {
            backend: FirecrackerBackend,
        }
    }
}

impl Default for FcDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The default base kernel cmdline for a Firecracker workload boot. Firecracker
/// guests use the `ttyS0` serial console (not virtio-console `hvc0` or the pl011
/// UART), and carry NO `mvm.ip=` / `mvm.gw=` tokens — the converged path has no
/// guest NIC. The root/init selection follows the boot shape; the shared cmdline
/// assembler layers verity/grants/egress/uvols tokens on top of this.
fn fc_base_bootargs(virtiofs_root: bool, has_disk: bool) -> String {
    // Serial console + reboot/panic behavior + stable interface naming. The NIC
    // fields the raw Firecracker TAP path appends here are deliberately absent.
    let console = "console=ttyS0 reboot=k panic=1 net.ifnames=0";
    if virtiofs_root {
        format!("{console} rootfstype=virtiofs root=mvmroot rw init=/init")
    } else if has_disk {
        format!("{console} root=/dev/vda rw rootwait init=/init")
    } else {
        // Verity / initramfs boot: the initramfs PID 1 owns root/init selection,
        // so only the serial-console base is emitted here.
        console.to_string()
    }
}

/// Resolve the explicit host kernel path from the spec, rejecting a bundled
/// kernel. Firecracker has no bundled kernel (libkrun's libkrunfw is the only
/// bundled-kernel backend), so a `Bundled` spec must not reach the API.
fn resolve_fc_kernel_path(spec: &VmmSpec) -> Result<PathBuf> {
    match &spec.kernel {
        KernelImage::Path(p) => Ok(p.clone()),
        KernelImage::Bundled => {
            bail!(
                "the Firecracker driver requires an explicit kernel Image; VmmSpec.kernel is Bundled"
            )
        }
    }
}

/// One Firecracker API configuration call: an HTTP PUT of `body` to `path` on
/// the per-VM API socket. Kept as data so the whole NIC-less config sequence is
/// a pure, testable value the driver replays through `api_put_socket`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FcApiPut {
    path: String,
    body: String,
}

/// Map slot-ordered blocks to `/drives/*` PUTs in the order Firecracker assigns
/// device letters (first PUT → `/dev/vda`, next → `/dev/vdb`, …), so the guest
/// device nodes line up with the verity slot model the cmdline names
/// (`mvm.data=/dev/vda mvm.hash=/dev/vdb …`). The lowest-slot block is the root
/// device; every block carries its own read-only policy verbatim.
fn fc_drive_puts(blocks: &[BlockDev]) -> Vec<FcApiPut> {
    let mut ordered: Vec<&BlockDev> = blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    ordered
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let drive_id = format!("blk{}", block.slot);
            // The lowest-slot block (first PUT) is the root device; each block
            // keeps its own read-only policy. Body shape shared with the raw path.
            let body = drive_body(
                &drive_id,
                &block.source.to_string_lossy(),
                index == 0,
                block.read_only,
            );
            FcApiPut {
                path: format!("/drives/{drive_id}"),
                body,
            }
        })
        .collect()
}

/// Assemble the full NIC-less Firecracker API config sequence for a spec:
/// logger, boot-source (kernel + initramfs + **`spec.cmdline` verbatim**),
/// machine-config, slot-ordered drives, the vsock device, and — only when the
/// spec opts into balloon elasticity — the virtio-balloon device. There is
/// deliberately no `/network-interfaces` PUT: the converged Firecracker path
/// attaches no guest NIC.
fn fc_config_api_puts(
    spec: &VmmSpec,
    kernel_for_boot: &str,
    vsock_uds: &str,
    log_dir: &str,
) -> Vec<FcApiPut> {
    let mut puts = Vec::new();

    puts.push(FcApiPut {
        path: "/logger".to_string(),
        body: logger_body(log_dir),
    });

    // An empty spec cmdline means "the driver supplies its own default base";
    // a non-empty one already carries the console + root/init base plus every
    // layered token, so it is threaded verbatim.
    let has_disk = spec.initramfs.is_none() && !spec.blocks.is_empty();
    let trimmed = spec.cmdline.trim();
    let cmdline = if trimmed.is_empty() {
        fc_base_bootargs(false, has_disk)
    } else {
        trimmed.to_string()
    };
    let initrd = spec
        .initramfs
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    puts.push(FcApiPut {
        path: "/boot-source".to_string(),
        body: boot_source_body(kernel_for_boot, &cmdline, initrd.as_deref()),
    });

    puts.push(FcApiPut {
        path: "/machine-config".to_string(),
        body: machine_config_body(spec.vcpus, spec.memory_mib),
    });

    puts.extend(fc_drive_puts(&spec.blocks));

    puts.push(FcApiPut {
        path: "/vsock".to_string(),
        body: vsock_body(GUEST_CID, vsock_uds),
    });

    // Balloon only when the workload opted into elasticity: the device boots
    // pre-inflated to `memory - mem_initial` MiB so the host commits only
    // `mem_initial` MiB until the reclaim controller deflates it.
    if let Some(initial) = spec.mem_initial_mib {
        let amount_mib = spec.memory_mib.saturating_sub(initial);
        puts.push(FcApiPut {
            path: "/balloon".to_string(),
            body: balloon_body(amount_mib),
        });
    }

    puts
}

/// The host UDS Firecracker connects *out* to when the guest dials
/// `CID_HOST:<port>`: the sibling `<runtime_dir>/v.sock_<port>` of the vsock mux
/// socket. The host must own a listener there before the guest dials.
fn fc_guest_dial_socket(runtime_dir: &Path, port: u32) -> PathBuf {
    runtime_dir.join(format!("v.sock_{port}"))
}

/// Wire every guest-dialed vsock port (except the workload-exit port, which the
/// driver binds and captures itself) to the runner-owned host socket it relays
/// to. Firecracker connects out to `<runtime_dir>/v.sock_<port>`, so a symlink
/// from that path to the entry's `host_uds` makes the guest's dial follow
/// straight through to the endpoint the runner already bound — the egress
/// endpoint (the claim-critical one), and the host-services broker.
/// `HostDials` ports (agent, dev-console) are not bridged here: the host
/// dials those inbound through the CONNECT handshake on the mux socket.
fn wire_guest_dial_bridges(spec: &VmmSpec, runtime_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut created = Vec::new();
    for port in &spec.vsock {
        if port.direction != VsockDirection::GuestDials {
            continue;
        }
        // The workload-exit port has no runner-bound listener — its `host_uds`
        // is the captured-code output file, not a socket. The driver binds and
        // captures it directly (see `spawn_workload_exit_capture`).
        if port.guest_port == WORKLOAD_EXIT_PORT {
            continue;
        }
        let link = fc_guest_dial_socket(runtime_dir, port.guest_port);
        // Clear any stale link/socket from a prior run so the symlink lands.
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&port.host_uds, &link).with_context(|| {
            format!(
                "link guest-dial vsock bridge {} -> {}",
                link.display(),
                port.host_uds.display()
            )
        })?;
        created.push((link, port.host_uds.clone()));
    }
    Ok(created)
}

/// Bind the workload-exit control socket and capture the guest's exit code on a
/// background thread. Firecracker has no supervisor subprocess to write
/// `workload.exit`, so the driver owns it: the guest dials `WORKLOAD_EXIT_PORT`,
/// Firecracker connects out to `<runtime_dir>/v.sock_<port>`, and the bound
/// listener there reads the 4-byte exit code and persists it under the state
/// dir where `wait_for_workload_exit` reads it. Best-effort — a bind failure
/// leaves `workload.exit` absent, which readers treat as UNKNOWN.
fn spawn_workload_exit_capture(runtime_dir: &Path, state_dir: &Path) {
    let sock = fc_guest_dial_socket(runtime_dir, WORKLOAD_EXIT_PORT);
    let _ = std::fs::remove_file(&sock);
    match std::os::unix::net::UnixListener::bind(&sock) {
        Ok(listener) => {
            let state_dir = state_dir.to_path_buf();
            std::thread::spawn(move || {
                if let Err(e) = mvm_core::exit_capture::capture_once(&listener, &state_dir) {
                    tracing::warn!("Firecracker workload exit capture failed: {e}");
                }
            });
        }
        Err(e) => tracing::warn!(
            "Firecracker driver could not bind the workload-exit socket {}: {e}",
            sock.display()
        ),
    }
}

/// The stop signal to deliver to the Firecracker process during teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FcStopSignal {
    /// Graceful termination — gives Firecracker a chance to close its
    /// virtio-blk file descriptors.
    Terminate,
    /// Force kill after the grace window lapses.
    ForceKill,
}

/// Where the kill escalation ended up, so the caller can fail closed rather
/// than report a stop that never happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillOutcome {
    /// The process was already gone before we signalled.
    AlreadyStopped,
    /// The process exited after SIGTERM or SIGKILL.
    Stopped,
    /// The process was still alive after both signals — the signal could not be
    /// delivered.
    StillRunning,
}

/// Deliver `signal` to the sudo-launched Firecracker process recorded in
/// `pid_file`. Firecracker is started under `sudo` and runs as **root**, so a
/// non-root `mvmctl` cannot signal it directly — a plain `libc::kill` returns
/// `EPERM` and silently no-ops. The signal therefore goes through `sudo kill`,
/// the same mechanism the raw stop path uses. Best-effort: a delivery failure
/// is logged, and the caller's liveness probe is the authority on whether the
/// process actually stopped (so a lost race with a self-exiting process is not
/// mistaken for a failure).
fn fc_sudo_signal(pid_file: &str, signal: FcStopSignal) {
    let flag = match signal {
        FcStopSignal::Terminate => "",
        FcStopSignal::ForceKill => " -9",
    };
    let q_pid = crate::base::shell::shell_quote(pid_file);
    let script = format!(r#"[ -f {q_pid} ] && sudo kill{flag} "$(cat {q_pid})""#);
    match crate::base::shell::run_in_vm(&script) {
        Ok(out) if out.status.success() => {}
        Ok(_) | Err(_) => tracing::warn!(
            "Firecracker stop signal {signal:?} to pid in {pid_file} did not report success \
             (the process may have already exited)"
        ),
    }
}

/// SIGTERM → grace → SIGKILL escalation against a Firecracker process, mirroring
/// the raw stop path's shutdown escalation. The liveness probe, signal
/// delivery, clock, and sleep are injected so the decision — "did the process
/// stop, and if not did the signal even land?" — is unit-testable without a live
/// VM or wall-clock waits.
fn escalate_kill(
    grace: Duration,
    poll: Duration,
    mut is_running: impl FnMut() -> Result<bool>,
    mut signal: impl FnMut(FcStopSignal),
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> Result<KillOutcome> {
    if !is_running()? {
        return Ok(KillOutcome::AlreadyStopped);
    }
    signal(FcStopSignal::Terminate);
    let deadline = now() + grace;
    while now() < deadline {
        if !is_running()? {
            return Ok(KillOutcome::Stopped);
        }
        sleep(poll);
    }
    // Grace lapsed; force-kill and re-probe to decide whether the signal landed.
    signal(FcStopSignal::ForceKill);
    if is_running()? {
        Ok(KillOutcome::StillRunning)
    } else {
        Ok(KillOutcome::Stopped)
    }
}

impl VmmDriver for FcDriver {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn kind(&self) -> BackendKind {
        self.backend.kind()
    }

    fn is_available(&self) -> Result<bool> {
        self.backend.is_available()
    }

    fn capabilities(&self) -> VmCapabilities {
        // The flipped, NIC-less profile — NOT the raw FirecrackerBackend caps
        // (which advertise a routable TAP). The converged Firecracker driver
        // carries no guest NIC and routes egress solely over the vsock proxy,
        // matching libkrun and hvf. Pause/resume and balloon stay true (both are
        // wired through this driver's boot + running-VM handle); live-memory
        // snapshots are dropped, since the runner path warm-starts disk-only.
        VmCapabilities {
            pause_resume: true,
            snapshots: false,
            vsock: true,
            tap_networking: false,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            balloon: true,
            fs_quick_checkpoint: false,
            ..VmCapabilities::default()
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // The runner takes no live-memory warm-start on this path, so the driver
        // is honest about disk-only — matching libkrun and hvf.
        SnapshotCapability::DiskOnly
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.backend.security_profile()
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        fc_base_bootargs(virtiofs_root, has_disk)
    }

    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        let kernel_path = resolve_fc_kernel_path(spec)?;

        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        let runtime_dir = state_dir.join("runtime");
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| anyhow!("create runtime dir {}: {e}", runtime_dir.display()))?;

        let abs_dir = state_dir.to_string_lossy().into_owned();
        let pid_file = fc_pid_path(&spec.name)
            .ok_or_else(|| anyhow!("resolve Firecracker pid path for '{}'", spec.name))?;
        // Clear any prior run's captured exit code and stale pid marker so `wait`
        // and the readiness poll observe only this launch's.
        let _ = std::fs::remove_file(mvm_core::exit_capture::exit_file_path(&state_dir));
        let _ = std::fs::remove_file(&pid_file);

        // Convert the workload kernel to an FC-loadable image (x86_64 bzImage →
        // extracted ELF; aarch64 Image passthrough), reusing the same helper the
        // raw path calls so the driver never diverges from host kernel-prep.
        let kernel_for_boot = mvm_build::fc_kernel::ensure_fc_loadable_kernel(&kernel_path)
            .with_context(|| {
                format!(
                    "preparing FC-loadable kernel from {}",
                    kernel_path.display()
                )
            })?;

        // Spawn the Firecracker daemon (writes fc.pid, waits for its API socket).
        let socket = format!("{abs_dir}/fc.socket");
        start_vm_firecracker(&abs_dir, &socket)?;

        // Drive the NIC-less API config sequence.
        let vsock_uds = firecracker_vsock_uds_path(&abs_dir);
        let puts = fc_config_api_puts(
            spec,
            &kernel_for_boot.to_string_lossy(),
            &vsock_uds,
            &abs_dir,
        );
        for put in &puts {
            api_put_socket(&socket, &put.path, &put.body)
                .with_context(|| format!("Firecracker API PUT {}", put.path))?;
        }

        // Wire the guest-dial egress/broker bridges, then bind the
        // workload-exit capture — both must be in place before the guest boots
        // and dials out.
        wire_guest_dial_bridges(spec, &runtime_dir)?;
        spawn_workload_exit_capture(&runtime_dir, &state_dir);

        // Boot the configured instance.
        api_put_socket(&socket, "/actions", r#"{"action_type": "InstanceStart"}"#)
            .context("Firecracker API PUT /actions InstanceStart")?;

        // Confirm the guest is up: a successful agent CONNECT over the vsock mux
        // means userspace booted and the agent is listening. Bounded so a guest
        // that never comes up fails closed rather than hanging forever.
        let pid_file_str = pid_file.to_string_lossy().into_owned();
        let deadline = Instant::now() + AGENT_READY_TIMEOUT;
        loop {
            // Fail fast if Firecracker itself died on boot (kernel panic,
            // rejected config) rather than waiting out the full agent deadline.
            // The console log carries the actionable detail. Probed ownership-
            // independently since a sudo-launched FC runs as root.
            if !crate::firecracker::is_vm_running(&pid_file_str)? {
                bail!(
                    "Firecracker process for '{}' exited before its guest agent came up; see {}/console.log",
                    spec.name,
                    abs_dir
                );
            }
            if connect_to_port(&vsock_uds, GUEST_AGENT_PORT, VSOCK_CONNECT_TIMEOUT_SECS).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "Firecracker guest agent did not answer within {AGENT_READY_TIMEOUT:?}; see {}/console.log",
                    abs_dir
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        Ok(Box::new(FcRunningVm {
            id: VmId(spec.name.clone()),
            state_dir,
            pid_file,
            vsock_uds,
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the fc.pid marker + the persisted
        // workload-exit code under the VM's state dir), so reattaching is just
        // re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        let vsock_uds = firecracker_vsock_uds_path(&state_dir.to_string_lossy());
        let pid_file = fc_pid_path(&id.0)
            .ok_or_else(|| anyhow!("resolve Firecracker pid path for '{}'", id.0))?;
        Ok(Box::new(FcRunningVm {
            pid_file,
            state_dir,
            vsock_uds,
            id: id.clone(),
        }))
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.backend.guest_channel_info(id)
    }
}

/// A live Firecracker VM: the detached `firecracker` daemon tracked by its PID
/// file, with the workload's exit code persisted under its state dir and the
/// vsock mux UDS for host→guest dials.
struct FcRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
    /// The single host-side vsock mux UDS (`<state_dir>/runtime/v.sock`); the
    /// host dials guest ports through the CONNECT handshake on this socket.
    vsock_uds: String,
}

impl FcRunningVm {
    /// The kill escalation with the grace timeout, liveness probe, signal
    /// delivery, and clock injected, so the fail-closed pid-retention decision
    /// is unit-testable without a live VM or a wall-clock grace wait. `kill`
    /// wires the real FC `/proc` probe + sudo signal here.
    fn kill_with(
        &self,
        grace: Duration,
        poll: Duration,
        is_running: impl FnMut() -> Result<bool>,
        signal: impl FnMut(FcStopSignal),
        now: impl FnMut() -> Instant,
        sleep: impl FnMut(Duration),
    ) -> Result<()> {
        match escalate_kill(grace, poll, is_running, signal, now, sleep)? {
            KillOutcome::AlreadyStopped | KillOutcome::Stopped => {
                let _ = std::fs::remove_file(&self.pid_file);
                Ok(())
            }
            // Fail closed: do NOT remove the pid file or report success when the
            // signal never landed — that would orphan a live root VM silently.
            KillOutcome::StillRunning => bail!(
                "Firecracker VM '{}' is still running after SIGTERM and SIGKILL; \
                 the stop signal could not be delivered",
                self.id.0
            ),
        }
    }
}

impl RunningVm for FcRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(crate::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        // Firecracker is sudo-launched and runs as root, so the libkrun
        // running-VM's plain `libc::kill` would return EPERM from a non-root
        // mvmctl — neither stopping the VM nor reporting the failure. Signal
        // through sudo (reaching the root process) and probe liveness
        // ownership-independently via /proc/<pid>/comm; the escalation is
        // SIGTERM → grace → SIGKILL, mirroring the raw stop path.
        let pid_file = self.pid_file.to_string_lossy().into_owned();
        self.kill_with(
            crate::libkrun::STOP_TIMEOUT,
            Duration::from_millis(100),
            || crate::firecracker::is_vm_running(&pid_file),
            |signal| fc_sudo_signal(&pid_file, signal),
            Instant::now,
            std::thread::sleep,
        )
    }

    fn pause(&self) -> Result<()> {
        // Firecracker exposes vCPU pause via the control API; reuse the existing
        // FC control helper (PATCH /vm InstanceState) keyed by the VM name.
        crate::microvm::pause_vm(&self.id.0)
    }

    fn resume(&self) -> Result<()> {
        crate::microvm::resume_vm(&self.id.0)
    }

    fn status(&self) -> Result<VmStatus> {
        // Firecracker is sudo-launched and runs as root, so the libkrun
        // running-VM's `libc::kill(pid, 0)` probe returns EPERM from a non-root
        // mvmctl and would misreport a live VM as Stopped. Probe ownership-
        // independently via /proc/<pid>/comm, reusing FC's own liveness helper.
        if crate::firecracker::is_vm_running(&self.pid_file.to_string_lossy())? {
            Ok(VmStatus::Running)
        } else {
            Ok(VmStatus::Stopped)
        }
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        // Firecracker multiplexes every host→guest connection over the single
        // vsock UDS, selecting the destination port via the `CONNECT <port>\n`
        // handshake. Restricted to the agent port and the dev-only console data
        // ports (a sealed prod boot registers no console listeners), mirroring
        // the other drivers' allow-list.
        if guest_port != GUEST_AGENT_PORT && !dev_console_data_ports().any(|p| p == guest_port) {
            bail!(
                "Firecracker driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}) and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        }
        let stream = connect_to_port(&self.vsock_uds, guest_port, VSOCK_CONNECT_TIMEOUT_SECS)
            .with_context(|| {
                format!(
                    "connect to Firecracker vsock port {guest_port} via {}",
                    self.vsock_uds
                )
            })?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{ConsoleCapture, VsockPort};
    use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT};

    fn host_dials(guest_port: u32, uds: &str) -> VsockPort {
        VsockPort {
            guest_port,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    fn guest_dials(guest_port: u32, uds: &str) -> VsockPort {
        VsockPort {
            guest_port,
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
            memory_mib: 512,
            mem_initial_mib: None,
            blocks,
            vsock,
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
        }
    }

    fn ro_block(source: &str, slot: u8) -> BlockDev {
        BlockDev {
            source: source.into(),
            read_only: true,
            ephemeral: false,
            slot,
        }
    }

    fn config_puts(spec: &VmmSpec) -> Vec<FcApiPut> {
        fc_config_api_puts(spec, "/img/vmlinux", "/state/w/runtime/v.sock", "/state/w")
    }

    fn body_for<'a>(puts: &'a [FcApiPut], path: &str) -> &'a str {
        puts.iter()
            .find(|p| p.path == path)
            .map(|p| p.body.as_str())
            .unwrap_or_else(|| panic!("no PUT for {path}"))
    }

    #[test]
    fn identity_and_capabilities_report_the_flipped_nic_less_profile() {
        let d = FcDriver::new();
        assert_eq!(d.name(), "firecracker");
        assert_eq!(d.kind(), BackendKind::Firecracker);
        let caps = d.capabilities();
        assert!(caps.vsock);
        // Flipped: no routable NIC + host vsock proxy, TAP off — the raw
        // FirecrackerBackend advertises the inverse (TAP on).
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert!(!caps.tap_networking);
        assert!(
            FirecrackerBackend.capabilities().tap_networking,
            "sanity: the raw backend still advertises TAP, so caps are not delegated"
        );
        assert_eq!(d.snapshot_capability(), SnapshotCapability::DiskOnly);
        // Security tier still delegates to the raw backend (same claims).
        assert_eq!(
            d.security_profile().tier,
            FirecrackerBackend.security_profile().tier
        );
    }

    #[test]
    fn workload_base_bootargs_uses_ttys0_and_carries_no_nic_or_other_console() {
        let d = FcDriver::new();
        let disk = d.workload_base_bootargs(false, true);
        assert!(disk.contains("console=ttyS0"), "got: {disk}");
        assert!(disk.contains("root=/dev/vda"), "got: {disk}");
        // No NIC tokens, and not another VMM's console.
        assert!(!disk.contains("mvm.ip="), "got: {disk}");
        assert!(!disk.contains("mvm.gw="), "got: {disk}");
        assert!(!disk.contains("hvc0"), "got: {disk}");
        assert!(!disk.contains("ttyAMA0"), "got: {disk}");

        // Verity / initramfs base: serial console only, no root/init token.
        let verity = d.workload_base_bootargs(false, false);
        assert_eq!(verity, "console=ttyS0 reboot=k panic=1 net.ifnames=0");
        assert!(!verity.contains("root="), "got: {verity}");

        // The virtiofs-root variant still uses ttyS0, not another VMM's console.
        let virtiofs = d.workload_base_bootargs(true, false);
        assert!(virtiofs.contains("console=ttyS0"), "got: {virtiofs}");
        assert!(virtiofs.contains("rootfstype=virtiofs"), "got: {virtiofs}");
        assert!(!virtiofs.contains("mvm.ip="), "got: {virtiofs}");
    }

    #[test]
    fn guest_channel_info_delegates_to_the_firecracker_backend() {
        let d = FcDriver::new();
        let id = VmId("fc-guest-channel-info-test-vm".into());
        assert_eq!(
            format!("{:?}", d.guest_channel_info(&id).map_err(|e| e.to_string())),
            format!(
                "{:?}",
                FirecrackerBackend
                    .guest_channel_info(&id)
                    .map_err(|e| e.to_string())
            )
        );
    }

    #[test]
    fn resolve_kernel_rejects_a_bundled_kernel() {
        // Firecracker has no bundled kernel; a bundled-kernel spec must not reach
        // the API.
        let spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        assert!(resolve_fc_kernel_path(&spec).is_err());
        assert!(
            resolve_fc_kernel_path(&spec_with(
                KernelImage::Path("/img/vmlinux".into()),
                vec![],
                vec![]
            ))
            .is_ok()
        );
    }

    #[test]
    fn drives_map_slot_ordered_blocks_to_vda_vdb_vdc_in_order() {
        // Out of slot order to prove sorting: the PUT order (== FC device-letter
        // order) must follow slot order, so slot 0 → first PUT (/dev/vda).
        let blocks = vec![
            ro_block("/img/overlay.ext4", 2),
            ro_block("/img/rootfs.verity", 1),
            ro_block("/img/rootfs.ext4", 0),
        ];
        let puts = fc_drive_puts(&blocks);
        let paths: Vec<&str> = puts.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["/drives/blk0", "/drives/blk1", "/drives/blk2"]);
        // The device-letter order the guest sees lines up with BlockDev::device_node.
        assert_eq!(blocks[2].device_node(), "/dev/vda");
        assert_eq!(blocks[1].device_node(), "/dev/vdb");
        assert_eq!(blocks[0].device_node(), "/dev/vdc");
        // Only the first PUT (slot 0) is the root device; all read-only.
        assert!(puts[0].body.contains("\"is_root_device\": true"));
        assert!(puts[1].body.contains("\"is_root_device\": false"));
        assert!(puts[0].body.contains("/img/rootfs.ext4"));
        assert!(puts[1].body.contains("/img/rootfs.verity"));
        assert!(puts[2].body.contains("/img/overlay.ext4"));
        assert!(
            puts.iter()
                .all(|p| p.body.contains("\"is_read_only\": true"))
        );
    }

    #[test]
    fn config_threads_cmdline_verbatim_and_configures_no_nic() {
        let mut spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![guest_dials(EGRESS_PORT, "/run/egress.sock")],
            vec![ro_block("/img/rootfs.ext4", 0)],
        );
        spec.cmdline = "  console=ttyS0 root=/dev/vda mvm.roothash=abc mvm.vsock_egress=1  ".into();
        let puts = config_puts(&spec);

        // The already-assembled cmdline is threaded verbatim (trimmed) — no
        // re-derivation of verity/egress tokens.
        let boot = body_for(&puts, "/boot-source");
        assert!(
            boot.contains(
                r#""boot_args": "console=ttyS0 root=/dev/vda mvm.roothash=abc mvm.vsock_egress=1""#
            ),
            "boot-source did not thread the cmdline verbatim: {boot}"
        );
        assert!(
            boot.contains(r#""kernel_image_path": "/img/vmlinux""#),
            "{boot}"
        );

        // Machine config carries the resources.
        let machine = body_for(&puts, "/machine-config");
        assert!(machine.contains("\"vcpu_count\": 2"), "{machine}");
        assert!(machine.contains("\"mem_size_mib\": 512"), "{machine}");

        // vsock device carries the guest CID + the mux uds.
        let vsock = body_for(&puts, "/vsock");
        assert!(
            vsock.contains(&format!("\"guest_cid\": {GUEST_CID}")),
            "{vsock}"
        );
        assert!(vsock.contains("/state/w/runtime/v.sock"), "{vsock}");

        // No NIC anywhere: no /network-interfaces PUT and no NIC JSON fields.
        assert!(
            puts.iter()
                .all(|p| !p.path.starts_with("/network-interfaces")),
            "a NIC device was configured: {:?}",
            puts.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert!(
            puts.iter()
                .all(|p| !p.body.contains("iface_id") && !p.body.contains("host_dev_name")),
            "a NIC JSON field leaked into the config"
        );
    }

    #[test]
    fn config_defaults_an_empty_cmdline_and_threads_the_initramfs() {
        let mut spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![],
            vec![ro_block("/img/rootfs.ext4", 0)],
        );
        // Empty + a disk ⇒ the driver's default disk base.
        let puts = config_puts(&spec);
        let boot = body_for(&puts, "/boot-source");
        assert!(
            boot.contains(&fc_base_bootargs(false, true)),
            "empty cmdline should default to the disk base: {boot}"
        );
        assert!(
            !boot.contains("initrd_path"),
            "no initramfs ⇒ no initrd_path"
        );

        // An initramfs boot threads the initrd path and defaults to the
        // console-only base (initramfs PID 1 owns root/init).
        spec.initramfs = Some("/img/initrd.cpio".into());
        spec.blocks.clear();
        let puts = config_puts(&spec);
        let boot = body_for(&puts, "/boot-source");
        assert!(
            boot.contains(r#""initrd_path": "/img/initrd.cpio""#),
            "{boot}"
        );
        assert!(
            boot.contains(r#""boot_args": "console=ttyS0 reboot=k panic=1 net.ifnames=0""#),
            "{boot}"
        );
    }

    #[test]
    fn balloon_is_configured_only_when_mem_initial_is_set() {
        let mut spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![],
            vec![ro_block("/img/rootfs.ext4", 0)],
        );
        assert!(
            config_puts(&spec).iter().all(|p| p.path != "/balloon"),
            "no balloon without mem_initial"
        );
        spec.mem_initial_mib = Some(128);
        let puts = config_puts(&spec);
        let balloon = body_for(&puts, "/balloon");
        // memory 512 - initial 128 = 384 MiB pre-inflated.
        assert!(balloon.contains("\"amount_mib\": 384"), "{balloon}");
        assert!(balloon.contains("\"deflate_on_oom\": true"), "{balloon}");
    }

    #[test]
    fn wire_guest_dial_bridges_links_egress_and_broker_but_not_exit_or_agent() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path();
        let spec = spec_with(
            KernelImage::Path("/img/vmlinux".into()),
            vec![
                host_dials(GUEST_AGENT_PORT, "/run/agent.sock"),
                guest_dials(EGRESS_PORT, "/run/egress.sock"),
                guest_dials(BROKER_PORT, "/run/broker.sock"),
                guest_dials(WORKLOAD_EXIT_PORT, "/state/w/workload.exit"),
            ],
            vec![],
        );
        let created = wire_guest_dial_bridges(&spec, runtime).unwrap();
        assert_eq!(created.len(), 2, "only egress + broker are bridged");

        // Egress: v.sock_5253 → the runner's endpoint socket.
        let egress_link = fc_guest_dial_socket(runtime, EGRESS_PORT);
        assert_eq!(
            std::fs::read_link(&egress_link).unwrap(),
            PathBuf::from("/run/egress.sock")
        );
        // Broker similarly.
        let broker_link = fc_guest_dial_socket(runtime, BROKER_PORT);
        assert_eq!(
            std::fs::read_link(&broker_link).unwrap(),
            PathBuf::from("/run/broker.sock")
        );
        // The exit port is driver-bound, not bridged — no symlink for it.
        assert!(
            !fc_guest_dial_socket(runtime, WORKLOAD_EXIT_PORT).exists(),
            "the workload-exit port must not be symlinked; the driver binds it"
        );
        // The host-dialed agent port is never bridged here.
        assert!(!fc_guest_dial_socket(runtime, GUEST_AGENT_PORT).exists());
    }

    #[test]
    fn workload_exit_capture_binds_and_persists_the_guest_exit_code() {
        use std::io::{Read, Write};

        let state_dir = tempfile::tempdir().unwrap();
        let runtime = state_dir.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();

        // The driver binds the exit socket synchronously before returning, so a
        // guest dial (here: a plain UnixStream, as Firecracker forwards it) lands.
        spawn_workload_exit_capture(&runtime, state_dir.path());

        let sock = fc_guest_dial_socket(&runtime, WORKLOAD_EXIT_PORT);
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        client.write_all(&3i32.to_le_bytes()).unwrap();
        // capture acks after the file is durably written.
        let mut ack = [0u8; 1];
        let _ = client.read_exact(&mut ack);

        // wait_for_workload_exit reads the persisted code from the state dir.
        let status = crate::workload_wait::wait_for_workload_exit(state_dir.path());
        assert_eq!(status.code, Some(3));
        assert!(!status.success);
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // status probes /proc/<pid>/comm through the Linux shell env; mock it so
        // the probe is deterministic on every host (a missing VM ⇒ "no").
        let _guard = crate::base::shell_mock::install_handler(|_| {
            crate::base::shell_mock::MockResponse::ok("no")
        });
        let vm = FcDriver::new()
            .attach(&VmId("fc-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "fc-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn status_uses_the_ownership_independent_probe_not_libc_kill() {
        // A sudo-launched Firecracker runs as root, so libc::kill(pid, 0) from a
        // non-root mvmctl returns EPERM and would misreport a live VM as Stopped.
        // status must instead honour the /proc/<pid>/comm probe: "yes" ⇒ Running.
        let vm = FcRunningVm {
            id: VmId("root-vm".into()),
            state_dir: PathBuf::from("/state/root-vm"),
            pid_file: PathBuf::from("/state/root-vm/fc.pid"),
            vsock_uds: "/state/root-vm/runtime/v.sock".into(),
        };
        let running = crate::base::shell_mock::install_handler(|_| {
            crate::base::shell_mock::MockResponse::ok("yes")
        });
        assert_eq!(vm.status().unwrap(), VmStatus::Running);
        drop(running);

        let stopped = crate::base::shell_mock::install_handler(|_| {
            crate::base::shell_mock::MockResponse::ok("no")
        });
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
        drop(stopped);
    }

    #[test]
    fn kill_removes_the_pid_file_when_the_vm_is_already_gone() {
        // A "no" liveness probe short-circuits the escalation: no signals sent,
        // the pid marker cleaned up, Ok returned.
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        let vm = FcRunningVm {
            id: VmId("gone-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: pid_file.clone(),
            vsock_uds: "/state/gone-vm/runtime/v.sock".into(),
        };
        let _guard = crate::base::shell_mock::install_handler(|_| {
            crate::base::shell_mock::MockResponse::ok("no")
        });
        vm.kill().unwrap();
        assert!(!pid_file.exists(), "pid marker must be removed on kill");
    }

    #[test]
    fn escalate_kill_returns_already_stopped_without_signalling() {
        let mut signals = Vec::new();
        let outcome = escalate_kill(
            Duration::from_secs(2),
            Duration::from_millis(10),
            || Ok(false),
            |s| signals.push(s),
            Instant::now,
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome, KillOutcome::AlreadyStopped);
        assert!(signals.is_empty(), "a dead process must not be signalled");
    }

    #[test]
    fn escalate_kill_stops_after_sigterm_within_the_grace_window() {
        use std::cell::Cell;
        // Alive on the pre-check, gone on the first grace-loop probe.
        let probes = Cell::new(0u32);
        let is_running = || {
            let n = probes.get();
            probes.set(n + 1);
            Ok(n < 1)
        };
        let mut signals = Vec::new();
        // A large grace + fixed clock so the loop runs (and sees the exit) rather
        // than the deadline being the reason it ends.
        let base = Instant::now();
        let outcome = escalate_kill(
            Duration::from_secs(10),
            Duration::from_millis(10),
            is_running,
            |s| signals.push(s),
            || base,
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome, KillOutcome::Stopped);
        assert_eq!(
            signals,
            vec![FcStopSignal::Terminate],
            "a graceful exit must not escalate to SIGKILL"
        );
    }

    #[test]
    fn escalate_kill_fails_closed_when_the_signal_never_lands() {
        // The process ignores both signals (a non-root kill of a root process
        // that never reaches it): SIGTERM, then SIGKILL, then StillRunning.
        let mut signals = Vec::new();
        let base = Instant::now();
        let tick = std::cell::Cell::new(0u64);
        let now = || {
            let n = tick.get();
            tick.set(n + 1);
            base + Duration::from_millis(n)
        };
        let outcome = escalate_kill(
            Duration::from_millis(1),
            Duration::from_millis(10),
            || Ok(true),
            |s| signals.push(s),
            now,
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome, KillOutcome::StillRunning);
        assert_eq!(
            signals,
            vec![FcStopSignal::Terminate, FcStopSignal::ForceKill],
            "an unresponsive process must be escalated to SIGKILL"
        );
    }

    #[test]
    fn kill_fails_closed_and_keeps_the_pid_file_when_the_signal_cannot_land() {
        // A liveness probe that always reports alive models a root VM a non-root
        // mvmctl can't signal. kill_with (the injectable seam kill delegates to)
        // must surface the failure and NOT remove the pid file — removing it
        // would orphan a live root VM silently. Injected clock so no 2s wait.
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        let vm = FcRunningVm {
            id: VmId("wedged-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: pid_file.clone(),
            vsock_uds: "/state/wedged-vm/runtime/v.sock".into(),
        };
        let base = Instant::now();
        let tick = std::cell::Cell::new(0u64);
        let now = || {
            let n = tick.get();
            tick.set(n + 1);
            base + Duration::from_millis(n)
        };
        let err = vm
            .kill_with(
                Duration::from_millis(1),
                Duration::from_millis(10),
                || Ok(true),
                |_| {},
                now,
                |_| {},
            )
            .expect_err("kill must fail closed when the signal can't land");
        assert!(
            err.to_string().contains("still running"),
            "unexpected error: {err}"
        );
        assert!(
            pid_file.exists(),
            "pid marker must survive a failed kill so the live VM isn't orphaned silently"
        );
    }

    #[test]
    fn fc_sudo_signal_routes_terminate_and_forcekill_through_sudo() {
        use std::sync::{Arc, Mutex};
        // Capture the emitted shell script to prove SIGTERM omits -9 and the
        // force kill adds it — and that both go through sudo (root reach).
        let scripts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = scripts.clone();
        let _guard = crate::base::shell_mock::install_handler(move |s: &str| {
            sink.lock().unwrap().push(s.to_string());
            crate::base::shell_mock::MockResponse::empty()
        });
        fc_sudo_signal("/state/vm/fc.pid", FcStopSignal::Terminate);
        fc_sudo_signal("/state/vm/fc.pid", FcStopSignal::ForceKill);
        let captured = scripts.lock().unwrap();
        assert!(
            captured[0].contains("sudo kill "),
            "SIGTERM: {}",
            captured[0]
        );
        assert!(
            !captured[0].contains("kill -9"),
            "SIGTERM must not force: {}",
            captured[0]
        );
        assert!(
            captured[1].contains("sudo kill -9"),
            "ForceKill: {}",
            captured[1]
        );
    }

    #[test]
    fn vsock_connect_reaches_the_agent_over_the_connect_handshake_and_rejects_other_ports() {
        use crate::test_support::bind_unix_listener;
        use std::io::{BufRead, BufReader, Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let vsock = runtime.join("v.sock");
        let Some(listener) = bind_unix_listener(&vsock) else {
            return;
        };
        // Firecracker's mux: read `CONNECT <port>`, reply `OK <port>`, then echo.
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let mut w = stream;
                    let port = line.trim().trim_start_matches("CONNECT ").trim();
                    let _ = writeln!(w, "OK {port}");
                    let _ = w.flush();
                    let mut b = [0u8; 1];
                    if reader.read_exact(&mut b).is_ok() {
                        let _ = w.write_all(&b);
                    }
                }
            }
        });

        let vm = FcRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join("fc.pid"),
            vsock_uds: vsock.to_string_lossy().into_owned(),
        };

        // The agent port connects through the CONNECT handshake + round-trips.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // Ports outside the agent + console data range are not host-dialable
        // (rejected before any connect attempt).
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
        assert!(vm.vsock_connect(9999).is_err());
    }

    #[test]
    fn vsock_connect_allows_a_dev_console_data_port() {
        // The allow-list admits the dev console data range; one past the top is
        // rejected. Proven at the boundary without a live socket, since the
        // reject path returns before connecting.
        let vm = FcRunningVm {
            id: VmId("console-vm".into()),
            state_dir: PathBuf::from("/state/console-vm"),
            pid_file: PathBuf::from("/state/console-vm/fc.pid"),
            vsock_uds: "/nonexistent/runtime/v.sock".into(),
        };
        // In range but no listener ⇒ a connect error (not an allow-list refusal).
        let in_range = vm
            .vsock_connect(CONSOLE_PORT_BASE + 1)
            .err()
            .unwrap()
            .to_string();
        assert!(
            in_range.contains("connect to Firecracker vsock port"),
            "an in-range port must pass the allow-list and fail at connect: {in_range}"
        );
        // One past the top of the range is refused by the allow-list itself.
        let refused = vm
            .vsock_connect(CONSOLE_PORT_BASE + 129)
            .err()
            .unwrap()
            .to_string();
        assert!(
            refused.contains("supports only the agent port"),
            "an out-of-range port must be refused by the allow-list: {refused}"
        );
    }
}
