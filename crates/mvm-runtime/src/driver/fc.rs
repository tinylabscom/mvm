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
    CONSOLE_PORT_BASE, GUEST_AGENT_PORT, GUEST_CID, GuestRequest, GuestResponse,
    WORKLOAD_EXIT_PORT, connect_to_port, dev_console_data_ports, send_request_stream,
};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, SnapshotCapability, StandbyError,
    StandbyHandle, StandbyState, VmBackend, VmCapabilities, VmExitStatus, VmId, VmStatus,
};

use crate::backend::FirecrackerBackend;
use crate::driver::spec::KernelImage;
use crate::driver::{
    BlockDev, ChildForkRequest, DuplexStream, RunningVm, StandbyParentSpawn, VmmDriver, VmmSpec,
    VsockDirection, VsockPort,
};
use crate::microvm::{
    FirecrackerGuard, api_put_socket, balloon_body, boot_source_body, drive_body, fc_pid_path,
    firecracker_vsock_uds_path, logger_body, machine_config_body, read_firecracker_pid,
    start_vm_firecracker, vsock_body,
};
use crate::standby_pool::now_unix_secs;

/// Host→guest dial timeout (seconds) for `vsock_connect`. The underlying
/// `connect_to_port` retries the CONNECT handshake internally within this bound.
const VSOCK_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Overall deadline for the guest agent to answer its first CONNECT after
/// `InstanceStart` — the boot-confirmation signal that the guest is up.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound the guest's stop-time filesystem drain. A clean stop refuses to tear
/// down Firecracker until the guest confirms its filesystems are durable.
const GUEST_STOP_DRAIN_TIMEOUT_SECS: u64 = 10;

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
        // No `root=` declaration here: Firecracker itself appends the
        // authoritative `root=/dev/vda ro|rw` to the boot args from the root
        // drive's `is_root_device`/`is_read_only` flags, so emitting our own
        // would put two contradictory root declarations on the cmdline and
        // leave the winner to kernel parsing order.
        format!("{console} rootwait init=/init")
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
///
/// Takes the channel list rather than a whole `VmmSpec` because both start
/// paths need it and only one of them has a spec: a cold boot passes the spec it
/// is about to boot, and a warm claim passes the channels the role layer
/// resolved for a child whose device model comes from restored memory.
fn wire_guest_dial_bridges(
    channels: &[VsockPort],
    runtime_dir: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut created = Vec::new();
    for port in channels {
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

/// Put the host end of every channel the guest dials in place, then arm the
/// workload-exit capture — the whole host-side channel set a Firecracker guest
/// needs before it is able to dial anything.
///
/// Both start paths run this, and both run it before the guest's vCPUs do
/// anything: a cold boot before `InstanceStart`, a warm claim before the restore
/// resumes the child. The claim's window is the tighter of the two, because a
/// restored guest is already past its own boot — it can dial its egress
/// endpoint, its broker, and its exit reporter the instant it resumes, whereas a
/// cold-booted guest spends a kernel boot getting there.
///
/// A prior run's captured exit code is cleared first, so a reader observes this
/// launch's exit status and never a stale one.
fn arm_host_channels(channels: &[VsockPort], state_dir: &Path, runtime_dir: &Path) -> Result<()> {
    let _ = std::fs::remove_file(mvm_core::exit_capture::exit_file_path(state_dir));
    wire_guest_dial_bridges(channels, runtime_dir)?;
    spawn_workload_exit_capture(runtime_dir, state_dir);
    Ok(())
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

#[cfg(target_os = "linux")]
fn fc_linux_signal_args(pid: u32, signal: FcStopSignal) -> Vec<String> {
    let signal_arg = match signal {
        FcStopSignal::Terminate => "-TERM",
        FcStopSignal::ForceKill => "-KILL",
    };
    vec![
        "-n".to_string(),
        "kill".to_string(),
        signal_arg.to_string(),
        pid.to_string(),
    ]
}

/// Deliver `signal` to an already-captured, identity-checked Firecracker PID.
/// Firecracker is started under `sudo` and runs as **root**, so a
/// non-root `mvmctl` cannot signal it directly — a plain `libc::kill` returns
/// `EPERM` and silently no-ops. The signal therefore goes through `sudo kill`,
/// the same mechanism the raw stop path uses. Best-effort: a delivery failure
/// is logged, and the caller's liveness probe is the authority on whether the
/// process actually stopped (so a lost race with a self-exiting process is not
/// mistaken for a failure).
fn fc_sudo_signal(pid: u32, signal: FcStopSignal) {
    #[cfg(target_os = "linux")]
    {
        let args = fc_linux_signal_args(pid, signal);
        match std::process::Command::new("sudo").args(&args).output() {
            Ok(output) if output.status.success() => {}
            Ok(_) | Err(_) => tracing::warn!(
                "Firecracker stop signal {signal:?} to pid {pid} did not report success \
                 (the process may have already exited)"
            ),
        }
    }

    #[cfg(not(target_os = "linux"))]
    let flag = match signal {
        FcStopSignal::Terminate => "",
        FcStopSignal::ForceKill => " -9",
    };
    #[cfg(not(target_os = "linux"))]
    let script = format!(
        r#"[ -f "/proc/{pid}/comm" ] && [ "$(cat /proc/{pid}/comm)" = "firecracker" ] && sudo kill{flag} {pid}"#
    );
    #[cfg(not(target_os = "linux"))]
    match crate::base::shell::run_in_vm(&script) {
        Ok(out) if out.status.success() => {}
        Ok(_) | Err(_) => tracing::warn!(
            "Firecracker stop signal {signal:?} to pid {pid} did not report success \
             (the process may have already exited)"
        ),
    }
}

/// Read the pid `boot` recorded for the VM whose state dir is `vm_state_dir`.
/// `boot` only returns once the guest agent has answered, so the pid file is
/// already on disk by the time a caller reaches for it.
fn read_fc_pid(vm_state_dir: &str) -> Option<u32> {
    read_firecracker_pid(vm_state_dir).ok()
}

/// Resolve the pid a just-completed `boot` recorded, via the injected
/// `read_pid` closure, failing closed rather than defaulting to 0 on a read
/// miss. `boot` only returns once the guest agent has answered, so by this
/// point the pid file is on disk and a read failure is a real defect, not
/// "no live process" — `StandbyHandle::pid == 0` is the sentinel
/// `is_saved_state()` keys off, and both the pool's eviction (which only
/// SIGTERMs a non-saved-state handle) and its stale reaper (which routes
/// saved-state handles through TTL/park logic instead of a liveness probe)
/// would silently skip a live Firecracker process wearing that sentinel.
/// The closure is injected so this is unit-testable without booting anything.
fn resolve_standby_parent_pid(
    vm_id: &str,
    read_pid: impl FnOnce() -> Option<u32>,
) -> std::result::Result<u32, StandbyError> {
    read_pid().ok_or_else(|| {
        StandbyError::SpawnFailed(format!(
            "standby parent '{vm_id}' booted but its Firecracker pid could not be read"
        ))
    })
}

/// Clear a dead process's stale marker before a new launch. A live marker is
/// retained and the launch is refused: replacing it would make the existing
/// Firecracker invisible to every normal list, stop, and orphan-reap path.
fn clear_stale_pid_marker_for_start(
    pid_file: &Path,
    is_running: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if !pid_file.exists() {
        return Ok(());
    }
    if is_running()? {
        bail!(
            "Firecracker recorded by {} is already running; refusing to replace its pid marker",
            pid_file.display()
        );
    }
    std::fs::remove_file(pid_file)
        .with_context(|| format!("remove stale Firecracker pid marker {}", pid_file.display()))
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

fn remove_pid_marker_if_matches(pid_file: &Path, pid: u32) {
    let marker_matches = std::fs::read_to_string(pid_file)
        .map(|recorded| recorded.trim() == pid.to_string())
        .unwrap_or(false);
    if marker_matches {
        let _ = std::fs::remove_file(pid_file);
    }
}

/// Terminate one already-captured Firecracker process and remove its marker
/// only after that exact PID is proven gone. The caller must capture `pid`
/// while `pid_file` is still trusted; this function never rereads the marker
/// for liveness or signal delivery.
pub(crate) fn terminate_firecracker_pid(name: &str, pid: u32, pid_file: &Path) -> Result<()> {
    let outcome = escalate_kill(
        crate::libkrun::STOP_TIMEOUT,
        Duration::from_millis(100),
        || crate::firecracker::is_firecracker_pid_running(pid),
        |signal| fc_sudo_signal(pid, signal),
        Instant::now,
        std::thread::sleep,
    )?;
    finish_firecracker_kill(name, pid, pid_file, outcome)
}

fn finish_firecracker_kill(
    name: &str,
    pid: u32,
    pid_file: &Path,
    outcome: KillOutcome,
) -> Result<()> {
    match outcome {
        KillOutcome::AlreadyStopped | KillOutcome::Stopped => {
            remove_pid_marker_if_matches(pid_file, pid);
            Ok(())
        }
        KillOutcome::StillRunning => bail!(
            "Firecracker VM '{name}' is still running after SIGTERM and SIGKILL; \
             the stop signal could not be delivered"
        ),
    }
}

/// Resolve the externally visible state from a captured Firecracker PID and
/// an ownership-independent liveness probe. Keeping the probe injectable makes
/// the root-owned-process behavior deterministic on hosts without Firecracker.
fn firecracker_status_with(
    pid: Option<u32>,
    is_running: impl FnOnce(u32) -> Result<bool>,
) -> Result<VmStatus> {
    if let Some(pid) = pid
        && is_running(pid)?
    {
        Ok(VmStatus::Running)
    } else {
        Ok(VmStatus::Stopped)
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
        // The runner-backed, NIC-less profile.
        // (which advertise a routable TAP). The converged Firecracker driver
        // carries no guest NIC and routes egress solely over the vsock proxy,
        // matching libkrun and hvf. Pause/resume and balloon stay true (both are
        // wired through this driver's boot + running-VM handle); live-memory
        // snapshots are dropped, since the runner path is cold-boot only.
        //
        // `standby_pool` stays off. The spawn/capture/fork/handshake code is
        // all here — `spawn_standby_parent` boots a clean factory parent and
        // `vm_full_control` captures its whole {rootfs, memory, vmstate} — and
        // validation on real KVM hardware has since shown that half working:
        // the parent boots the workload's verified shape, reaches its guest
        // agent, and the capture writes a memory-carrying checkpoint. But the
        // capability means "can actually spawn AND claim a warm parent on this
        // host", and the claim half has never been exercised live: the
        // transient run path mints no verb-grant sidecar, so a restored child
        // has no host-signer anchor to authenticate against and every claim
        // falls back to a cold boot. Advertising it would cost every launch a
        // parent boot for a claim that cannot yet land, so it stays false until
        // a live run is green end to end. That capture/restore pair is a
        // distinct seam from the coarse `snapshots`/`snapshot_capability` tier
        // below — it captures one specific parent shape for the standby pool,
        // not an arbitrary named VM's live memory on demand, so those two
        // fields stay unchanged either way.
        VmCapabilities {
            pause_resume: true,
            snapshots: false,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            vsock: true,
            tap_networking: false,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            // Firecracker workload VMs are configured with vsock and no
            // network-interfaces entry at all, so the L3 tunnel's
            // no-NIC precondition holds structurally.
            l3_vsock: true,
            balloon: true,
            fs_quick_checkpoint: false,
            ..VmCapabilities::default()
        }
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.backend.security_profile()
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        fc_base_bootargs(virtiofs_root, has_disk)
    }

    fn spawn_standby_parent(
        &self,
        req: &StandbyParentSpawn<'_>,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let spec = req.spec;

        // The boot inputs arrive fully assembled from the role layer, which
        // derives them from the launch this parent will serve using the same
        // mappers a workload boot uses. The driver adds nothing: a parent that
        // boots a shape of this driver's own invention would hand that shape to
        // every child restored from it.
        //
        // `boot` returns only once the guest agent answered over vsock, so the
        // memory captured next is of a fully-booted, ready guest — that is what
        // lets a restored child skip boot entirely.
        let vm = self
            .boot(req.boot)
            .map_err(|e| StandbyError::SpawnFailed(format!("boot standby parent: {e}")))?;

        // Deliberately left running: the caller captures its live memory, and
        // Firecracker outlives this handle. A pid we can't read is a real
        // failure at this point (see `resolve_standby_parent_pid`), so the
        // just-booted process is killed rather than handed back as an
        // untracked "saved state" standby.
        let pid = match resolve_standby_parent_pid(&spec.id, || read_fc_pid(&spec.vm_state_dir)) {
            Ok(pid) => pid,
            Err(e) => {
                let _ = vm.kill();
                return Err(e);
            }
        };
        drop(vm);

        Ok(StandbyHandle {
            id: spec.id.clone(),
            // Propagate the template identity: a parent bound to one template
            // must never be claimable by a launch of another.
            template_id: spec.template_id.clone(),
            control_socket: spec.control_socket.clone(),
            pid,
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
            vsock_egress: spec.vsock_egress,
            // The caller captures the parent and stamps this.
            parent_checkpoint: None,
        })
    }

    fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
        Some(Box::new(crate::firecracker::FcVmFullControl::new(vm_name)))
    }

    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        if !req.child_dir.exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': child dir {} was never materialized",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }
        // The restorer renames `memory.bin` to Firecracker's canonical load
        // name, so accept either — but require one. Without saved memory this
        // would quietly become a cold boot, losing the whole point of the pool.
        if !req.child_dir.join("memory.bin").exists() && !req.child_dir.join("mem.bin").exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': clone at {} carries no saved memory image",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }

        // Arm the child's host channel set before anything resumes it. The
        // restore below brings the guest back already booted, so the moment its
        // vCPUs run it can dial its egress endpoint, its broker and its exit
        // reporter; a cold boot gets the same wiring, just with a whole kernel
        // boot of slack. Wiring after the restore would leave a live guest
        // dialing sockets that do not exist — egress dark, host services
        // silently unavailable, and no exit code recorded.
        let runtime_dir = req.child_dir.join("runtime");
        std::fs::create_dir_all(&runtime_dir).map_err(|e| {
            StandbyError::ClaimFailed(format!(
                "fork child '{}': create runtime dir {}: {e}",
                req.child_vm_name,
                runtime_dir.display()
            ))
        })?;
        arm_host_channels(req.channels, req.child_dir, &runtime_dir).map_err(|e| {
            StandbyError::ClaimFailed(format!(
                "fork child '{}': wiring its host channels: {e}",
                req.child_vm_name
            ))
        })?;

        // Restore the parent's saved memory into a fresh VMM under the child's
        // own identity. The device-model guard between load and resume refuses
        // any snapshot carrying a network interface, so a restored child cannot
        // reintroduce a path off the box that bypasses vsock.
        crate::checkpoint::ForkVmFullRestorer::restore_fork(
            &crate::firecracker::FcForkRestorer,
            req.child_vm_name,
            req.child_dir,
        )
        .map_err(|e| StandbyError::ClaimFailed(format!("restore forked child: {e}")))?;
        Ok(())
    }

    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        let kernel_path = resolve_fc_kernel_path(spec)?;

        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        let pid_file = fc_pid_path(&spec.name)
            .ok_or_else(|| anyhow!("resolve Firecracker pid path for '{}'", spec.name))?;
        // Clear only a marker proven stale. Removing a live process's marker
        // would orphan that Firecracker as soon as this launch overwrote the
        // rest of its state directory.
        let pid_file_str = pid_file.to_string_lossy().into_owned();
        clear_stale_pid_marker_for_start(&pid_file, || {
            crate::firecracker::is_vm_running(&pid_file_str)
        })?;

        let runtime_dir = state_dir.join("runtime");
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| anyhow!("create runtime dir {}: {e}", runtime_dir.display()))?;
        let abs_dir = state_dir.to_string_lossy().into_owned();

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
        let mut firecracker_guard = FirecrackerGuard::new(&abs_dir);
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
        crate::microvm::secure_vsock_socket_for_caller(&vsock_uds)
            .context("restrict Firecracker vsock socket to the invoking user")?;

        // Wire the guest-dial egress/broker bridges and bind the workload-exit
        // capture — the whole host channel set must be in place before the guest
        // boots and dials out.
        arm_host_channels(&spec.vsock, &state_dir, &runtime_dir)?;

        // Boot the configured instance.
        api_put_socket(&socket, "/actions", r#"{"action_type": "InstanceStart"}"#)
            .context("Firecracker API PUT /actions InstanceStart")?;

        // Confirm the guest is up: a successful agent CONNECT over the vsock mux
        // means userspace booted and the agent is listening. Bounded so a guest
        // that never comes up fails closed rather than hanging forever.
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

        let vm = Box::new(FcRunningVm {
            id: VmId(spec.name.clone()),
            state_dir,
            pid_file,
            pid: Some(read_firecracker_pid(&abs_dir).with_context(|| {
                format!("capture Firecracker pid for '{}' after boot", spec.name)
            })?),
            vsock_uds,
        });
        firecracker_guard.defuse();
        Ok(vm)
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the fc.pid marker + the persisted
        // workload-exit code under the VM's state dir), so reattaching is just
        // re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        let vsock_uds = firecracker_vsock_uds_path(&state_dir.to_string_lossy());
        let pid_file = fc_pid_path(&id.0)
            .ok_or_else(|| anyhow!("resolve Firecracker pid path for '{}'", id.0))?;
        let pid = if pid_file.exists() {
            Some(
                read_firecracker_pid(&state_dir.to_string_lossy()).with_context(|| {
                    format!("capture Firecracker pid for '{}' while attaching", id.0)
                })?,
            )
        } else {
            None
        };
        Ok(Box::new(FcRunningVm {
            pid_file,
            pid,
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
    /// Process identity captured while attaching, before any sidecar teardown
    /// can remove the recovery marker. `None` represents an already-stopped VM.
    pid: Option<u32>,
    /// The single host-side vsock mux UDS (`<state_dir>/runtime/v.sock`); the
    /// host dials guest ports through the CONNECT handshake on this socket.
    vsock_uds: String,
}

fn require_guest_filesystem_flush(response: GuestResponse) -> Result<()> {
    match response {
        GuestResponse::SleepPrepAck { success: true, .. } => Ok(()),
        GuestResponse::SleepPrepAck {
            success: false,
            detail,
        } => bail!(
            "guest refused the stop-time filesystem flush: {}",
            detail.unwrap_or_else(|| "no detail supplied".to_string())
        ),
        other => bail!("guest returned an unexpected stop-time flush response: {other:?}"),
    }
}

fn prepare_guest_filesystems_for_stop(vsock_uds: &str) -> Result<()> {
    let mut stream = connect_to_port(vsock_uds, GUEST_AGENT_PORT, GUEST_STOP_DRAIN_TIMEOUT_SECS)
        .with_context(|| format!("connect to guest agent for filesystem flush via {vsock_uds}"))?;
    let response = send_request_stream(
        &mut stream,
        &GuestRequest::SleepPrep {
            drain_timeout_secs: GUEST_STOP_DRAIN_TIMEOUT_SECS,
        },
    )
    .context("request guest filesystem flush before Firecracker stop")?;
    require_guest_filesystem_flush(response)
}

fn stop_after_guest_flush(
    prepare: impl FnOnce() -> Result<()>,
    terminate: impl FnOnce() -> Result<()>,
) -> Result<()> {
    prepare()?;
    terminate()
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
        let Some(pid) = self.pid else {
            return Ok(());
        };
        if !crate::firecracker::is_firecracker_pid_running(pid)? {
            remove_pid_marker_if_matches(&self.pid_file, pid);
            return Ok(());
        }
        stop_after_guest_flush(
            || prepare_guest_filesystems_for_stop(&self.vsock_uds),
            || terminate_firecracker_pid(&self.id.0, pid, &self.pid_file),
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
        firecracker_status_with(self.pid, crate::firecracker::is_firecracker_pid_running)
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
    use crate::driver::ConsoleCapture;
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

    /// The four standing channels a workload VM carries: the agent RPC the host
    /// dials, and the egress, broker and exit ports the guest dials.
    fn workload_channels() -> Vec<VsockPort> {
        vec![
            host_dials(GUEST_AGENT_PORT, "/run/agent.sock"),
            guest_dials(EGRESS_PORT, "/run/egress.sock"),
            guest_dials(BROKER_PORT, "/run/broker.sock"),
            guest_dials(WORKLOAD_EXIT_PORT, "/state/w/workload.exit"),
        ]
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
    fn guest_filesystem_flush_requires_a_positive_sleep_prep_ack() {
        assert!(
            require_guest_filesystem_flush(GuestResponse::SleepPrepAck {
                success: true,
                detail: Some("synced".into()),
            })
            .is_ok()
        );

        let refused = require_guest_filesystem_flush(GuestResponse::SleepPrepAck {
            success: false,
            detail: Some("sync failed".into()),
        })
        .unwrap_err()
        .to_string();
        assert!(refused.contains("sync failed"), "got: {refused}");

        let unexpected = require_guest_filesystem_flush(GuestResponse::Pong)
            .unwrap_err()
            .to_string();
        assert!(unexpected.contains("unexpected"), "got: {unexpected}");
    }

    #[test]
    fn firecracker_stop_is_ordered_after_a_successful_guest_flush() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        stop_after_guest_flush(
            || {
                events.borrow_mut().push("flush");
                Ok(())
            },
            || {
                events.borrow_mut().push("terminate");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(events.into_inner(), ["flush", "terminate"]);
    }

    #[test]
    fn firecracker_stop_refuses_termination_when_guest_flush_fails() {
        use std::cell::Cell;

        let terminated = Cell::new(false);
        let err = stop_after_guest_flush(
            || anyhow::bail!("guest flush unavailable"),
            || {
                terminated.set(true);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("guest flush unavailable"), "got: {err}");
        assert!(!terminated.get());
    }

    #[test]
    fn identity_and_capabilities_report_the_flipped_nic_less_profile() {
        let d = FcDriver::new();
        assert_eq!(d.name(), "firecracker");
        assert_eq!(d.kind(), BackendKind::Firecracker);
        let caps = d.capabilities();
        assert!(caps.vsock);
        // No routable NIC + host vsock proxy, TAP off.
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert!(!caps.tap_networking);
        assert!(!FirecrackerBackend.capabilities().tap_networking);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
        // Security tier still delegates to the raw backend (same claims).
        assert_eq!(
            d.security_profile().tier,
            FirecrackerBackend.security_profile().tier
        );
    }

    /// No selectable driver advertises the standby (warm) pool. The capability
    /// means "can actually spawn AND claim a warm parent on this host", so it
    /// flips per-backend only once a live run proves that backend's spawn and
    /// claim both work — a capability nobody can service costs every launch a
    /// parent boot for nothing. Firecracker's spawn+capture half is live-proven;
    /// its claim half is not, so it stays off with the rest. (The in-memory
    /// `MockBackend` opts into it explicitly via `with_standby()` for the
    /// hermetic claim tests; the `MockDriver` seam here does not.)
    #[test]
    fn no_selectable_driver_advertises_the_standby_pool() {
        use crate::driver::{HvfDriver, LibkrunDriver, MockDriver};
        use crate::qemu::QemuBackend;
        use crate::wasm_backend::WasmBackend;

        assert!(!FcDriver::new().capabilities().standby_pool);
        assert!(!LibkrunDriver::new().capabilities().standby_pool);
        assert!(!HvfDriver::new().capabilities().standby_pool);
        assert!(!MockDriver::default().capabilities().standby_pool);
        assert!(!QemuBackend.capabilities().standby_pool);
        assert!(!WasmBackend::new().capabilities().standby_pool);
    }

    #[test]
    fn workload_base_bootargs_uses_ttys0_and_carries_no_nic_or_other_console() {
        let d = FcDriver::new();
        let disk = d.workload_base_bootargs(false, true);
        assert!(disk.contains("console=ttyS0"), "got: {disk}");
        // The disk base carries rootwait+init but NO `root=` declaration:
        // Firecracker appends the authoritative `root=/dev/vda ro|rw` from the
        // root drive's flags, and a second declaration here would contradict
        // it (exactly one root declaration reaches the guest).
        assert!(disk.contains("rootwait init=/init"), "got: {disk}");
        assert!(!disk.contains("root="), "got: {disk}");
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

        assert_eq!(
            puts.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec![
                "/logger",
                "/boot-source",
                "/machine-config",
                "/drives/blk0",
                "/vsock"
            ]
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
        let created = wire_guest_dial_bridges(&workload_channels(), runtime).unwrap();
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
        assert_eq!(
            firecracker_status_with(Some(4242), |pid| {
                assert_eq!(pid, 4242);
                Ok(true)
            })
            .unwrap(),
            VmStatus::Running
        );
        assert_eq!(
            firecracker_status_with(Some(4242), |_| Ok(false)).unwrap(),
            VmStatus::Stopped
        );
        assert_eq!(
            firecracker_status_with(None, |_| unreachable!("no PID must skip the probe")).unwrap(),
            VmStatus::Stopped
        );

        let err = firecracker_status_with(Some(4242), |_| anyhow::bail!("probe failed"))
            .expect_err("probe failures must remain visible");
        assert!(err.to_string().contains("probe failed"));
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
            pid: Some(4242),
            vsock_uds: "/state/gone-vm/runtime/v.sock".into(),
        };
        let _guard = crate::base::shell_mock::install_handler(|script| {
            if script.starts_with("cat ") {
                crate::base::shell_mock::MockResponse::ok("4242")
            } else {
                crate::base::shell_mock::MockResponse::ok("no")
            }
        });
        vm.kill().unwrap();
        assert!(!pid_file.exists(), "pid marker must be removed on kill");
    }

    #[test]
    fn kill_tracks_the_captured_pid_after_the_marker_disappears() {
        use std::cell::{Cell, RefCell};

        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();
        let captured_pid = 4242;
        let probes = Cell::new(0usize);
        let signals = RefCell::new(Vec::new());
        let base = Instant::now();
        let outcome = escalate_kill(
            Duration::from_secs(10),
            Duration::from_millis(10),
            || {
                assert_eq!(captured_pid, 4242);
                let probe = probes.get();
                probes.set(probe + 1);
                Ok(probe == 0)
            },
            |signal| {
                assert_eq!(captured_pid, 4242);
                std::fs::remove_file(&pid_file).unwrap();
                signals.borrow_mut().push(signal);
            },
            || base,
            |_| {},
        )
        .unwrap();
        finish_firecracker_kill("marker-race-vm", captured_pid, &pid_file, outcome)
            .expect("marker loss must not lose the captured process identity");

        assert_eq!(probes.get(), 2);
        assert_eq!(*signals.borrow(), vec![FcStopSignal::Terminate]);
        assert!(!pid_file.exists());
    }

    #[test]
    fn start_refuses_to_replace_the_pid_marker_of_a_live_firecracker() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();

        let err = clear_stale_pid_marker_for_start(&pid_file, || Ok(true))
            .expect_err("a second start must refuse a live Firecracker");

        assert!(
            err.to_string().contains("already running"),
            "unexpected error: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&pid_file).unwrap(),
            "4242",
            "the only handle to the live process must remain intact"
        );
    }

    #[test]
    fn start_removes_a_stale_pid_marker_after_proving_the_process_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("fc.pid");
        std::fs::write(&pid_file, "4242").unwrap();

        clear_stale_pid_marker_for_start(&pid_file, || Ok(false))
            .expect("a dead process leaves a removable stale marker");

        assert!(!pid_file.exists());
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
        let err = finish_firecracker_kill("wedged-vm", 4242, &pid_file, KillOutcome::StillRunning)
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
    #[cfg(not(target_os = "linux"))]
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
        fc_sudo_signal(4242, FcStopSignal::Terminate);
        fc_sudo_signal(4242, FcStopSignal::ForceKill);
        let captured = scripts.lock().unwrap();
        assert!(
            captured[0].contains("sudo kill "),
            "SIGTERM: {}",
            captured[0]
        );
        assert!(captured[0].contains("/proc/4242/comm"));
        assert!(captured[0].ends_with("sudo kill 4242"));
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
        assert!(captured[1].ends_with("sudo kill -9 4242"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fc_signal_arguments_are_noninteractive_and_explicit() {
        assert_eq!(
            fc_linux_signal_args(4242, FcStopSignal::Terminate),
            ["-n", "kill", "-TERM", "4242"]
        );
        assert_eq!(
            fc_linux_signal_args(4242, FcStopSignal::ForceKill),
            ["-n", "kill", "-KILL", "4242"]
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
            pid: None,
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
            pid: None,
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

    /// Capturing a parent's memory needs a backend-specific control; Firecracker
    /// has one, so it must offer it rather than falling through to the default.
    #[test]
    fn fc_offers_a_vm_full_capture_control() {
        assert!(FcDriver::new().vm_full_control("any-vm").is_some());
    }

    /// The metadata the spawn path writes for a factory parent must be exactly
    /// what `FcVmFullControl::rootfs_path()` reads back, or a live capture
    /// fails closed for want of a resolvable rootfs. Proven by running the real
    /// derivation (launch config → parent config → recorded metadata) and then
    /// resolving it through the real capture control — no boot, no KVM.
    #[test]
    fn the_parent_metadata_the_spawn_path_writes_resolves_through_the_capture_control() {
        use crate::checkpoint::VmFullControl as _;
        use crate::workload_runner::standby_boot::factory_parent_config;
        use mvm_core::util::test_env::TestEnv;
        use mvm_core::vm_backend::{StandbySpec, StartMode, VmStartConfig};

        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let image = tmp.path().join("rootfs.ext4");
        std::fs::write(&image, b"fake-rootfs").unwrap();

        let launch = VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: image.display().to_string(),
            kernel_path: Some("/img/vmlinux".into()),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };
        let spec = StandbySpec {
            id: "standby-parent-1".into(),
            template_id: None,
            kernel_path: "/img/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: tmp.path().join("control.sock").display().to_string(),
            vm_state_dir: tmp.path().join("standby-parent-1").display().to_string(),
            image_path: Some(image.display().to_string()),
            image_sha256: Some("c".repeat(64)),
            vsock_egress: crate::egress_shared::effective_vsock_egress(&launch),
        };

        let parent_cfg = factory_parent_config(&launch, &spec).unwrap();
        crate::base::runtime_meta::record_from_start_config(
            &spec.id,
            StartMode::Detached,
            &parent_cfg,
        )
        .unwrap();

        let control = crate::firecracker::FcVmFullControl::new(&spec.id);
        assert_eq!(control.rootfs_path().unwrap(), image);
    }

    /// A parent warmed for an egress-allowing launch boots the guest's egress
    /// client — and that is the *only* thing the enablement changes.
    ///
    /// The enablement reaches the parent as a policy that answers "egress
    /// allowed", because that is what the cmdline token is derived from. This
    /// pins that the policy buys the parent nothing else: flipping it leaves the
    /// device set the driver configures byte-identical, so an egress-enabled
    /// parent hands a restored child the same vsock-only machine a deny-all one
    /// does. (That the set itself carries no guest NIC is enforced structurally
    /// by the workspace's vsock-only-egress token gate over this file.)
    #[test]
    fn an_egress_enabled_parent_boots_the_token_and_nothing_else_changes() {
        use crate::workload_runner::{factory_parent_config, factory_parent_spec};
        use mvm_core::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::util::test_env::TestEnv;
        use mvm_core::vm_backend::{StandbySpec, VmStartConfig};

        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let image = tmp.path().join("rootfs.ext4");
        std::fs::write(&image, b"fake-rootfs").unwrap();

        let deny_all_launch = VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: image.display().to_string(),
            kernel_path: Some("/img/vmlinux".into()),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };
        let egress_launch = VmStartConfig {
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            ..deny_all_launch.clone()
        };
        let spec_for = |launch: &VmStartConfig| StandbySpec {
            id: "standby-egress-parent".into(),
            template_id: None,
            kernel_path: "/img/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: tmp.path().join("control.sock").display().to_string(),
            vm_state_dir: tmp
                .path()
                .join("standby-egress-parent")
                .display()
                .to_string(),
            image_path: Some(image.display().to_string()),
            image_sha256: Some("c".repeat(64)),
            vsock_egress: crate::egress_shared::effective_vsock_egress(launch),
        };
        let parent_boot = |launch: &VmStartConfig| {
            let spec = spec_for(launch);
            let cfg = factory_parent_config(launch, &spec).unwrap();
            let boot = factory_parent_spec(
                &cfg,
                std::path::Path::new(&spec.vm_state_dir),
                |virtiofs_root, has_disk| {
                    FcDriver::new().workload_base_bootargs(virtiofs_root, has_disk)
                },
            );
            (spec.vsock_egress, boot)
        };

        let (deny_enabled, deny_boot) = parent_boot(&deny_all_launch);
        let (egress_enabled, egress_boot) = parent_boot(&egress_launch);
        assert!(!deny_enabled);
        assert!(
            egress_enabled,
            "fixture must warm an egress-enabled parent, or it proves nothing"
        );

        assert!(
            egress_boot.cmdline.contains("mvm.vsock_egress=1"),
            "the parent must boot the guest egress client: {}",
            egress_boot.cmdline
        );
        assert!(
            !egress_boot.cmdline.contains("api.example.com"),
            "the parent's cmdline must name no destination: {}",
            egress_boot.cmdline
        );

        // Everything the driver would configure apart from the boot args is
        // identical between the two enablements. `/boot-source` is excluded
        // because it is where the cmdline lands, and that the cmdline matches the
        // workload's is asserted where both are assembled, not here.
        let device_set = |boot: &VmmSpec| {
            config_puts(boot)
                .into_iter()
                .filter(|p| p.path != "/boot-source")
                .map(|p| (p.path, p.body))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            device_set(&egress_boot),
            device_set(&deny_boot),
            "the egress enablement must add no device to a warm parent"
        );
    }

    /// A pid that can't be read after a successful boot is a real failure, not
    /// "no live process" — silently defaulting to 0 would leave a live
    /// Firecracker process wearing the sentinel that pool eviction and the
    /// stale reaper both treat as an already-quiesced saved state.
    #[test]
    fn resolve_standby_parent_pid_fails_closed_when_the_pid_read_fails() {
        let err = resolve_standby_parent_pid("standby-x", || None).unwrap_err();
        assert!(
            matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("pid")),
            "expected a SpawnFailed naming the unreadable pid, got: {err:?}"
        );
    }

    /// The success path: a readable pid passes straight through.
    #[test]
    fn resolve_standby_parent_pid_returns_the_read_pid() {
        assert_eq!(
            resolve_standby_parent_pid("standby-x", || Some(4242)).unwrap(),
            4242
        );
    }

    fn sample_generation_token() -> mvm_core::crypto::vmgenid::GenerationToken {
        mvm_core::crypto::vmgenid::GenerationToken {
            token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            content_hash: "test-content-hash".into(),
        }
    }

    /// The runner materializes the CoW clone before forking. An absent dir means
    /// the clone never landed, so restoring would load something other than the
    /// verified parent's content — refuse instead.
    #[test]
    fn fork_standby_child_refuses_an_unmaterialized_child_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("never-materialized");
        let req = ChildForkRequest {
            child_vm_name: "child-vm-1",
            child_dir: &missing,
            genid: sample_generation_token(),
            channels: &workload_channels(),
        };

        let err = FcDriver::new().fork_standby_child(&req).unwrap_err();

        assert!(
            matches!(err, StandbyError::ClaimFailed(ref m) if m.contains("child-vm-1")),
            "expected a ClaimFailed naming the child, got: {err:?}"
        );
    }

    /// A memory restore needs the parent's saved memory. A clone carrying only a
    /// rootfs would silently cold-boot instead of restoring, so it is refused.
    #[test]
    fn fork_standby_child_refuses_a_clone_without_saved_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let child_dir = tmp.path().join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(child_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        let req = ChildForkRequest {
            child_vm_name: "child-vm-2",
            child_dir: &child_dir,
            genid: sample_generation_token(),
            channels: &workload_channels(),
        };

        let err = FcDriver::new().fork_standby_child(&req).unwrap_err();

        assert!(
            matches!(err, StandbyError::ClaimFailed(ref m) if m.contains("memory")),
            "expected a ClaimFailed naming the missing memory image, got: {err:?}"
        );
    }

    /// A restore resumes a guest that is already booted, so the host end of
    /// every channel it dials has to exist before `restore_fork` runs — there is
    /// no kernel boot to cover the gap the way a cold boot's does.
    ///
    /// Driven by letting the restore itself fail (no hypervisor here, and the
    /// clone carries no device anchors): the bridges and the exit listener are
    /// still on disk afterwards, which they could not be if the wiring ran after
    /// the restore. The equality against the cold-boot wiring is asserted
    /// alongside, so a claim cannot come to wire a different set.
    #[test]
    fn fork_standby_child_wires_the_childs_host_channels_before_it_attempts_the_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let child_dir = tmp.path().join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(child_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(child_dir.join("memory.bin"), b"saved-memory").unwrap();

        let channels = workload_channels();
        let req = ChildForkRequest {
            child_vm_name: "child-vm-3",
            child_dir: &child_dir,
            genid: sample_generation_token(),
            channels: &channels,
        };

        // The restore has no Firecracker to talk to and no device anchors to
        // read, so it fails — the point is what survives on disk regardless.
        FcDriver::new()
            .fork_standby_child(&req)
            .expect_err("no hypervisor here: the restore itself must fail");

        let runtime = child_dir.join("runtime");
        // Exactly the bridge set a cold boot of the same channels produces.
        let cold = tempfile::tempdir().unwrap();
        for (cold_link, _) in wire_guest_dial_bridges(&channels, cold.path()).unwrap() {
            let name = cold_link.file_name().unwrap();
            assert_eq!(
                std::fs::read_link(runtime.join(name)).ok(),
                std::fs::read_link(&cold_link).ok(),
                "the fork must wire {} exactly as a cold boot does",
                name.to_string_lossy()
            );
        }
        // Named concretely too, so a failure says which channel went dark.
        assert_eq!(
            std::fs::read_link(fc_guest_dial_socket(&runtime, EGRESS_PORT)).unwrap(),
            PathBuf::from("/run/egress.sock"),
            "the child's egress endpoint must be reachable before it resumes"
        );
        assert_eq!(
            std::fs::read_link(fc_guest_dial_socket(&runtime, BROKER_PORT)).unwrap(),
            PathBuf::from("/run/broker.sock"),
            "host.audit.v1 / host.secrets.v1 must be reachable before it resumes"
        );
        // The exit port is bound by the driver, not symlinked: a real socket.
        let exit_sock = fc_guest_dial_socket(&runtime, WORKLOAD_EXIT_PORT);
        assert!(
            std::os::unix::net::UnixStream::connect(&exit_sock).is_ok(),
            "the workload-exit listener must be bound before the child resumes, \
             or the run reports UNKNOWN instead of the guest's exit code"
        );
    }

    /// A factory parent carries no channel at all — it has no gating endpoint
    /// and no broker to reach — so the same wiring call produces no bridge. The
    /// parent/workload namespace split is what this preserves: the driver does
    /// not invent a channel for a spec that names none.
    #[test]
    fn wiring_a_channel_less_boot_creates_no_bridge() {
        let dir = tempfile::tempdir().unwrap();
        assert!(wire_guest_dial_bridges(&[], dir.path()).unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "a parent with no channels must leave the runtime dir empty"
        );
    }
}
