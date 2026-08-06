//! `HvfDriver` — the `VmmDriver` for the first-party VMM (HVF on macOS, KVM
//! on Linux via the shared `vmm` device model). Identity and capabilities
//! delegate to the proven `HvfBackend`. `boot` maps a policy-free `VmmSpec` to a
//! relay supervisor config, spawns `mvm-hvf-supervisor`, and returns a live
//! handle. The claim-10 egress gate and secret substitution live in the
//! host-side endpoint the caller binds to the spec's `EGRESS_PORT` socket; the
//! driver only wires that socket through as the supervisor's egress relay — it
//! carries no policy and never sees a `NetworkPolicy`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use mvm_agentd::vsock::{CONSOLE_PORT_BASE, GUEST_AGENT_PORT, dev_console_data_ports};
use mvm_build::hvf_supervisor::{ConsoleDataSocket, HvfDisk, HvfSupervisorConfig};
use mvm_core::config::{vm_hvf_vsock_port_socket_at, vm_state_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, StandbyError, StandbyHandle,
    StandbyState, VmBackend, VmCapabilities, VmExitStatus, VmId, VmStatus,
};
use mvm_net::channel::GuestService;

use crate::driver::spec::KernelImage;
use crate::driver::{
    ChildForkRequest, DuplexStream, RunningVm, StandbyParentSpawn, VmmDriver, VmmSpec,
    VsockDirection,
};
use crate::hvf_backend::{
    self, HvfBackend, PID_FILE_NAME, PID_FILE_POLL_INTERVAL, PID_FILE_TIMEOUT,
    resolve_supervisor_path,
};

/// The first-party VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge, not
/// here.
pub struct HvfDriver {
    backend: HvfBackend,
}

impl HvfDriver {
    pub fn new() -> Self {
        Self {
            backend: HvfBackend,
        }
    }
}

impl Default for HvfDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The per-VM host paths the supervisor writes and reads, resolved from the VM's
/// state dir. Grouped so the pure config mapping takes one struct rather than a
/// fistful of positional paths.
struct SupervisorPaths {
    state_dir: PathBuf,
    pid_file: PathBuf,
    console_log: PathBuf,
    workload_exit: PathBuf,
    timeout_secs: u64,
}

impl SupervisorPaths {
    /// Resolve the standard per-VM paths under the VM's state dir. `timeout_secs`
    /// is a backstop cap (0 = none) against a guest that never reports its exit.
    fn resolve(state_dir: PathBuf, timeout_secs: u64) -> Self {
        let pid_file = state_dir.join(PID_FILE_NAME);
        let console_log = state_dir.join("console.log");
        let workload_exit = state_dir.join("workload.exit");
        Self {
            state_dir,
            pid_file,
            console_log,
            workload_exit,
            timeout_secs,
        }
    }
}

/// Map a policy-free `VmmSpec` to a relay `HvfSupervisorConfig`: the supervisor
/// wires the guest's `EGRESS_PORT` straight to the host-side endpoint bound at
/// `egress_relay_socket`, which owns the claim-10 gate and substitution. The
/// spec MUST carry that egress socket — an hvf workload has no other path
/// off the box, so a spec without it fails closed rather than booting ungated.
fn relay_supervisor_config(spec: &VmmSpec, paths: &SupervisorPaths) -> Result<HvfSupervisorConfig> {
    let kernel = match &spec.kernel {
        KernelImage::Path(p) => p.clone(),
        KernelImage::Bundled => {
            bail!("the hvf VMM requires an explicit kernel Image; VmmSpec.kernel is Bundled")
        }
    };

    // Every block in slot order becomes a virtio-blk device (`/dev/vda`…). Each
    // block carries its own read-only + ephemeral policy: a read-only block is
    // file-served with hypervisor-enforced RO; an ephemeral block is RAM-backed
    // (writes dropped on exit); a writable non-ephemeral block persists to the
    // host file (the builder's nix-store / output disks).
    let mut ordered: Vec<&crate::driver::BlockDev> = spec.blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    let disks = ordered
        .iter()
        .map(|b| HvfDisk {
            path: b.source.clone(),
            read_only: b.read_only,
            ephemeral: b.ephemeral,
        })
        .collect();

    // Every boot carries the substitution channel, including builder boots.
    // Requiring it here keeps a malformed spec from creating an ungated path.
    let egress_relay_socket = spec
        .host_socket_for_service(GuestService::Substitution)
        .ok_or_else(|| anyhow!("hvf spec is missing the EGRESS_PORT vsock relay socket"))?;

    // An empty spec cmdline means "use the supervisor's workload default"
    // (`init=/init`); a non-empty one (e.g. the builder rootfs's
    // `init=/sbin/mvm-host-vm-init`) is threaded through verbatim.
    let cmdline = {
        let c = spec.cmdline.trim();
        (!c.is_empty()).then(|| c.to_string())
    };

    // Collect dev-only console data sockets: the spec carries one HostDials entry
    // per pre-opened console data port (exact members of dev_console_data_ports()).
    // Sealed prod specs carry none, so this vec is empty in production.
    let console_data_sockets = spec
        .vsock
        .iter()
        .filter(|p| matches!(p.service, GuestService::ConsoleData { .. }))
        .map(|p| ConsoleDataSocket {
            guest_port: p.port(),
            host_socket: p.host_uds.clone(),
        })
        .collect();

    Ok(HvfSupervisorConfig {
        kernel,
        cmdline,
        memory_mib: spec.memory_mib,
        initramfs: spec.initramfs.clone(),
        disks,
        virtiofs_root: None,
        vsock: true,
        console_log: paths.console_log.clone(),
        pid_file: paths.pid_file.clone(),
        workload_exit: paths.workload_exit.clone(),
        timeout_secs: paths.timeout_secs,
        // Re-derive the agent bridge from the state dir rather than trusting the
        // spec's backend-neutral agent hint (`agent.sock`): the detached
        // supervisor binds this exact path, and the host resolver probes the same
        // `hvf-agent.sock`, so binder and resolver can't drift.
        agent_socket: Some(hvf_agent_socket(&paths.state_dir)),
        substitution_socket: None,
        egress_relay_socket: Some(egress_relay_socket),
        // An admitted workload carries a BROKER_PORT relay socket; the supervisor
        // splices the guest's BROKER_PORT dial to it so host.audit.v1 /
        // host.secrets.v1 reach the per-VM broker (or the per-tenant host-agent
        // daemon). Absent for a builder/dev VM, which runs no admitted workload.
        broker_socket: spec.host_socket_for_service(GuestService::Broker),
        console_data_sockets,
    })
}

impl VmmDriver for HvfDriver {
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
        let mut capabilities = self.backend.capabilities();
        // HVF uses a paused resident-parent handoff rather than advertising a
        // serialized fresh-VMM restore that the native API cannot provide.
        capabilities.pause_resume = true;
        capabilities.standby_pool = true;
        capabilities
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.backend.security_profile()
    }

    fn standby_parent_is_live(&self) -> bool {
        true
    }

    fn spawn_standby_parent(
        &self,
        req: &StandbyParentSpawn<'_>,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let vm = self
            .boot(req.boot)
            .map_err(|e| StandbyError::SpawnFailed(format!("boot HVF standby parent: {e}")))?;
        let state_dir = vm_state_dir(&req.spec.id);
        let agent = hvf_agent_socket(&state_dir);
        wait_for_socket(&agent).map_err(|e| {
            let _ = vm.kill();
            StandbyError::SpawnFailed(format!("wait for HVF standby agent: {e}"))
        })?;
        vm.pause().map_err(|e| {
            let _ = vm.kill();
            StandbyError::SpawnFailed(format!("pause HVF standby parent: {e}"))
        })?;
        let pid = hvf_backend::read_pid(&state_dir.join(PID_FILE_NAME)).ok_or_else(|| {
            StandbyError::SpawnFailed("HVF standby parent lost its PID marker".to_string())
        })?;
        let pid = u32::try_from(pid).map_err(|_| {
            StandbyError::SpawnFailed("HVF standby parent PID marker is invalid".to_string())
        })?;
        Ok(StandbyHandle {
            id: req.spec.id.clone(),
            template_id: req.spec.template_id.clone(),
            control_socket: req.spec.control_socket.clone(),
            pid,
            kernel_sha256: req.spec.kernel_sha256.clone(),
            vcpus: req.spec.vcpus,
            mem_mib: req.spec.mem_mib,
            binding_nonce: req.spec.binding_nonce.clone(),
            spawned_unix_secs: crate::standby_pool::now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: req.spec.image_sha256.clone(),
            vsock_egress: req.spec.vsock_egress,
            parent_checkpoint: None,
        })
    }

    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        let parent_dir = vm_state_dir(req.parent_vm_name);
        let parent_pid = parent_dir.join(PID_FILE_NAME);
        if hvf_backend::read_pid(&parent_pid).is_none() {
            return Err(StandbyError::ClaimFailed(format!(
                "live HVF standby parent '{}' is no longer running",
                req.parent_vm_name
            )));
        }

        let result = (|| {
            link_path(
                &hvf_agent_socket(&parent_dir),
                &hvf_agent_socket(req.child_dir),
            )?;
            link_path(&parent_pid, &req.child_dir.join(PID_FILE_NAME))?;
            link_path(
                &parent_dir.join("workload.exit"),
                &req.child_dir.join("workload.exit"),
            )?;
            link_path(
                &parent_dir.join("console.log"),
                &req.child_dir.join("console.log"),
            )?;

            let child_egress = channel_path(req, GuestService::Substitution)?;
            link_path(&child_egress, &parent_dir.join("standby-egress.sock"))?;
            if let Some(child_broker) = channel_path_optional(req, GuestService::Broker) {
                link_path(&child_broker, &parent_dir.join("standby-broker.sock"))?;
            }
            std::fs::write(req.child_dir.join("hvf-live-parent"), req.parent_vm_name)
                .map_err(|e| anyhow!("record live HVF parent: {e}"))?;

            self.attach(&VmId(req.parent_vm_name.to_string()))?
                .resume()
                .map_err(|e| anyhow!("resume live HVF child handoff: {e}"))
        })();

        result.map_err(|e| {
            let _ = self
                .attach(&VmId(req.parent_vm_name.to_string()))
                .and_then(|vm| vm.kill());
            StandbyError::ClaimFailed(format!("wire live HVF standby child: {e}"))
        })
    }

    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        let state_dir = vm_state_dir(&spec.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        // Create/truncate the console capture up front.
        let _ = crate::libkrun::open_console_capture(&state_dir.join("console.log"));

        // MVM_HVF_TIMEOUT is only a backstop cap (0 = none) — matches HvfBackend.
        let timeout_secs = std::env::var("MVM_HVF_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let paths = SupervisorPaths::resolve(state_dir, timeout_secs);

        // Clear any prior run's exit code so `wait` reads only this launch's.
        let _ = std::fs::remove_file(&paths.workload_exit);

        let cfg = relay_supervisor_config(spec, &paths)?;
        let json = serde_json::to_string(&cfg)
            .map_err(|e| anyhow!("serialize HvfSupervisorConfig: {e}"))?;

        let supervisor = resolve_supervisor_path()?;
        let mut child = Command::new(&supervisor)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file (boot confirmed). If the supervisor exits first,
        // surface that — its inherited stderr carries the actionable detail.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if paths.pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "hvf supervisor exited before writing its PID file (status: {status}); see {}",
                    paths.console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                    paths.console_log.display()
                );
            }
            std::thread::sleep(PID_FILE_POLL_INTERVAL);
        }

        // Detach: dropping the `Child` does not kill it, so the supervisor
        // outlives this call (reaped via its PID file by `kill`).
        drop(child);

        // The agent RPC socket the supervisor binds for this VM (host→guest agent
        // bridge on GUEST_AGENT_PORT). Re-derived from the state dir so it matches
        // the value handed to the supervisor above and the path a later `attach`
        // and the host resolver both probe.
        let agent_socket = hvf_agent_socket(&paths.state_dir);
        Ok(Box::new(HvfRunningVm {
            id: VmId(spec.name.clone()),
            state_dir: paths.state_dir,
            pid_file: paths.pid_file,
            agent_socket,
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the supervisor's pid file + the
        // persisted workload-exit code under the VM's state dir), so reattaching is
        // just re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(HvfRunningVm {
            pid_file: state_dir.join(PID_FILE_NAME),
            agent_socket: hvf_agent_socket(&state_dir),
            state_dir,
            id: id.clone(),
        }))
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.backend.guest_channel_info(id)
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        crate::hvf_bootargs::workload_bootargs(virtiofs_root, has_disk)
    }
}

/// The per-VM agent-RPC socket the detached `mvm-hvf-supervisor` binds
/// (host→guest agent bridge). The driver re-derives this from the state dir
/// rather than trusting the spec's generic agent hint — the same way the FC and
/// libkrun drivers ignore the spec's agent host_uds — so the value it hands the
/// supervisor is exactly the one the host resolver (`DevConsoleTransport` /
/// `for_vm` → `vm_hvf_agent_socket`) probes. A drift here silently makes the
/// guest agent unreachable and every RPC time out.
fn hvf_agent_socket(state_dir: &std::path::Path) -> PathBuf {
    mvm_core::config::vm_hvf_agent_socket_at(state_dir)
}

fn wait_for_socket(path: &std::path::Path) -> Result<()> {
    let timeout = PID_FILE_TIMEOUT;
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            bail!(
                "HVF supervisor did not bind {} within {timeout:?}",
                path.display()
            );
        }
        std::thread::sleep(PID_FILE_POLL_INTERVAL);
    }
    Ok(())
}

fn channel_path(req: &ChildForkRequest<'_>, service: GuestService) -> Result<PathBuf> {
    channel_path_optional(req, service).ok_or_else(|| {
        anyhow!(
            "live HVF child is missing its required guest-dialed channel {}",
            service.port()
        )
    })
}

fn channel_path_optional(req: &ChildForkRequest<'_>, service: GuestService) -> Option<PathBuf> {
    req.channels
        .iter()
        .find(|channel| {
            channel.service == service && channel.direction == VsockDirection::GuestDials
        })
        .map(|channel| channel.host_uds.clone())
}

fn link_path(target: &std::path::Path, link: &std::path::Path) -> Result<()> {
    if link.exists() || std::fs::symlink_metadata(link).is_ok() {
        bail!(
            "refusing to replace existing live-HVF handoff path {}",
            link.display()
        );
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("link {} -> {}", link.display(), target.display()))
}

fn signal_vm(pid_file: &std::path::Path, signal: libc::c_int) -> Result<()> {
    let pid = hvf_backend::read_pid(pid_file)
        .ok_or_else(|| anyhow!("HVF VM has no live PID marker at {}", pid_file.display()))?;
    // SAFETY: the PID comes from the backend-owned marker created for this VM;
    // the signal is limited to pause/resume/termination for that process.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("send signal {signal} to HVF supervisor pid {pid}"));
    }
    Ok(())
}

/// Resolve the host UDS for a console data port via the shared HVF-style socket
/// helper. Returns `None` when the port is outside `dev_console_data_ports()`.
fn console_socket_for_port(state_dir: &std::path::Path, guest_port: u32) -> Option<PathBuf> {
    if dev_console_data_ports().any(|p| p == guest_port) {
        Some(vm_hvf_vsock_port_socket_at(state_dir, guest_port))
    } else {
        None
    }
}

/// A live hvf VM: the detached `mvm-hvf-supervisor` tracked by its PID file,
/// with the workload's exit code persisted under its state dir.
struct HvfRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
    /// Host→guest agent RPC socket the supervisor bound for this VM.
    agent_socket: PathBuf,
}

impl RunningVm for HvfRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(crate::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        if let Some(pid) = hvf_backend::read_pid(&self.pid_file) {
            hvf_backend::terminate_pid(pid);
        }
        let _ = std::fs::remove_file(&self.pid_file);
        if let Ok(parent_name) = std::fs::read_to_string(self.state_dir.join("hvf-live-parent")) {
            let parent_name = parent_name.trim();
            if !parent_name.is_empty() {
                let parent_state = vm_state_dir(parent_name);
                let _ = std::fs::remove_dir_all(parent_state);
            }
        }
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        signal_vm(&self.pid_file, libc::SIGUSR1)
    }

    fn resume(&self) -> Result<()> {
        signal_vm(&self.pid_file, libc::SIGUSR2)
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(match hvf_backend::read_pid(&self.pid_file) {
            Some(pid) if hvf_backend::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        let socket_path = if guest_port == GUEST_AGENT_PORT {
            self.agent_socket.clone()
        } else if let Some(path) = console_socket_for_port(&self.state_dir, guest_port) {
            // Dev-only: pre-opened console data port in the CONSOLE_PORT_BASE+1..=+128
            // range. Claim 15: sealed prod specs carry no console sockets, so this
            // path is only reachable when the runner pre-bound these UDS at start.
            path
        } else {
            bail!(
                "hvf driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}) and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        };
        let stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .with_context(|| format!("connect to hvf vsock socket {}", socket_path.display()))?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BlockDev, ConsoleCapture, VsockDirection, VsockPort};
    use mvm_core::vm_backend::SnapshotCapability;

    fn egress_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::Substitution,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn agent_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::MachineControl,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    fn broker_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::Broker,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn spec_with(kernel: KernelImage, vsock: Vec<VsockPort>, blocks: Vec<BlockDev>) -> VmmSpec {
        VmmSpec {
            name: "w".into(),
            kernel,
            initramfs: Some("/img/initrd.cpio".into()),
            cmdline: String::new(),
            vcpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks,
            vsock,
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
        }
    }

    fn sample_paths() -> SupervisorPaths {
        SupervisorPaths::resolve(PathBuf::from("/state/w"), 0)
    }

    #[test]
    fn identity_and_capabilities_delegate_to_the_hvf_backend() {
        let d = HvfDriver::new();
        assert_eq!(d.name(), "hvf");
        assert_eq!(d.kind(), BackendKind::Hvf);
        assert!(d.capabilities().vsock);
        assert!(d.capabilities().pause_resume);
        assert!(d.capabilities().standby_pool);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
        assert_eq!(
            d.security_profile().tier,
            HvfBackend.security_profile().tier
        );
    }

    #[test]
    fn live_handoff_refuses_to_replace_an_existing_socket_path() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.sock");
        let link = tmp.path().join("link.sock");
        std::fs::write(&target, b"target").unwrap();
        std::fs::write(&link, b"existing").unwrap();

        let err = link_path(&target, &link).unwrap_err();

        assert!(err.to_string().contains("refusing to replace"));
        assert_eq!(std::fs::read(&link).unwrap(), b"existing");
    }

    #[test]
    fn live_handoff_only_accepts_guest_dialed_channels() {
        let channels = vec![VsockPort {
            service: GuestService::Substitution,
            host_uds: "/run/egress.sock".into(),
            direction: VsockDirection::HostDials,
        }];
        let child_dir = PathBuf::from("/tmp/child-vm");
        let req = ChildForkRequest {
            parent_vm_name: "parent-vm",
            child_vm_name: "child-vm",
            child_dir: &child_dir,
            genid: mvm_core::crypto::vmgenid::GenerationToken {
                token: [0; mvm_core::crypto::vmgenid::GENID_BYTES],
                content_hash: "content".into(),
            },
            channels: &channels,
        };

        assert!(channel_path_optional(&req, GuestService::Substitution).is_none());
    }

    #[test]
    fn workload_base_bootargs_delegates_to_hvf_bootargs() {
        let d = HvfDriver::new();
        assert_eq!(
            d.workload_base_bootargs(false, true),
            crate::hvf_bootargs::workload_bootargs(false, true)
        );
        assert_eq!(
            d.workload_base_bootargs(true, false),
            crate::hvf_bootargs::workload_bootargs(true, false)
        );
    }

    #[test]
    fn guest_channel_info_delegates_to_the_hvf_backend() {
        // HvfBackend declares no guest channel (the agent bridge is a fixed
        // vsock port, not a queryable per-VM channel) — the driver must relay
        // that same fail-closed answer rather than inventing one.
        let d = HvfDriver::new();
        let id = VmId("hvf-guest-channel-info-test-vm".into());
        assert!(d.guest_channel_info(&id).is_err());
        assert!(HvfBackend.guest_channel_info(&id).is_err());
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // Reattaching needs no boot state — it re-derives the state dir. A VM that
        // never ran (or has exited) reports Stopped rather than erroring.
        let vm = HvfDriver::new()
            .attach(&VmId("hvf-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "hvf-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn relay_config_wires_egress_relay_and_agent_leaves_substitution_none() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let paths = sample_paths();
        let cfg = relay_supervisor_config(&spec, &paths).unwrap();

        assert_eq!(cfg.kernel, PathBuf::from("/img/Image"));
        assert_eq!(cfg.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
        // The driver re-derives the agent bridge from the state dir (hvf-agent.sock)
        // and ignores the spec's backend-neutral agent hint (/run/agent.sock), so
        // the supervisor binds the exact path the host resolver probes.
        assert_eq!(cfg.agent_socket, Some(hvf_agent_socket(&paths.state_dir)));
        assert_ne!(cfg.agent_socket, Some(PathBuf::from("/run/agent.sock")));
        assert_eq!(cfg.substitution_socket, None);
        // No BROKER_PORT in this spec ⇒ no broker relay (unadmitted / builder).
        assert_eq!(cfg.broker_socket, None);
        assert!(cfg.vsock);
        // No blocks → no disks.
        assert!(cfg.disks.is_empty());
        // Empty spec cmdline ⇒ None (supervisor uses its workload default).
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn driver_agent_bind_path_equals_the_host_resolver_probe() {
        // The live regression this pins closed: the detached mvm-hvf-supervisor
        // binds the `agent_socket` the driver hands it, while the host reaches the
        // guest agent through DevConsoleTransport::for_vm / vm_hvf_agent_socket. If
        // those two ever name different sockets the guest agent is unreachable and
        // every RPC times out (the witness that caught the agent.sock/hvf-agent.sock
        // drift). Assert the exact bind path == the exact probe path for the same
        // VM so neither side can drift independently again.
        let name = "hvf-agent-socket-drift-guard-vm";
        let paths = SupervisorPaths::resolve(vm_state_dir(name), 0);
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );

        // What the supervisor binds: the agent socket the driver puts on the config.
        let cfg = relay_supervisor_config(&spec, &paths).unwrap();
        let binder = cfg
            .agent_socket
            .expect("hvf relay config must carry an agent socket");

        // What the host reaches the guest agent through.
        let resolver = mvm_core::config::vm_hvf_agent_socket(name);
        let transport =
            crate::vsock_transport::DevConsoleTransport::for_vm(name).socket_path(GUEST_AGENT_PORT);

        assert_eq!(
            binder, resolver,
            "supervisor bind path must equal the resolver"
        );
        assert_eq!(
            binder, transport,
            "supervisor bind path must equal the transport probe"
        );
        // The running-vm / attach handle re-derives via the same driver helper, so
        // vsock_connect(GUEST_AGENT_PORT) reaches the identical socket.
        assert_eq!(hvf_agent_socket(&paths.state_dir), resolver);
    }

    #[test]
    fn relay_config_wires_the_broker_relay_when_the_spec_carries_broker_port() {
        // An admitted workload's spec carries a BROKER_PORT channel; the
        // supervisor config must relay it so host.audit.v1 / host.secrets.v1
        // reach the broker. Absence ⇒ None (asserted above).
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
                broker_port("/run/broker.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.broker_socket, Some(PathBuf::from("/run/broker.sock")));
    }

    #[test]
    fn relay_config_threads_a_non_empty_cmdline_and_drops_an_empty_one() {
        // The builder rootfs boots a different PID 1 than the mkGuest workload
        // default, so its cmdline must reach the supervisor verbatim.
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        spec.cmdline = "  console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init  ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        // Trimmed, threaded verbatim.
        assert_eq!(
            cfg.cmdline.as_deref(),
            Some("console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init")
        );

        // A whitespace-only cmdline collapses to None (default applies).
        spec.cmdline = "   ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn relay_config_maps_blocks_to_disks_in_slot_order_carrying_ro_and_ephemeral() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![
                // Out of slot order, mixed flags — proves sorting + per-disk policy
                // pass through verbatim (a builder's persistent nix-store is
                // writable AND non-ephemeral).
                BlockDev {
                    source: "/img/nix-store.img".into(),
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
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.disks.len(), 2);
        // vda = slot 0: read-only rootfs, file-served.
        assert_eq!(cfg.disks[0].path, PathBuf::from("/img/rootfs.ext4"));
        assert!(cfg.disks[0].read_only);
        assert!(!cfg.disks[0].ephemeral);
        // vdb = slot 1: writable + persistent (not ephemeral) — writes hit the file.
        assert_eq!(cfg.disks[1].path, PathBuf::from("/img/nix-store.img"));
        assert!(!cfg.disks[1].read_only);
        assert!(!cfg.disks[1].ephemeral);
    }

    #[test]
    fn relay_config_requires_the_same_egress_relay_for_builder_boots() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                agent_port("/run/agent.sock"),
                egress_port("/run/egress.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
    }

    #[test]
    fn relay_config_missing_egress_port_fails_closed() {
        // No EGRESS_PORT: the hvf VMM has no other path off the box, so this
        // must not boot an ungated guest.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![agent_port("/run/agent.sock")],
            vec![],
        );
        let err = relay_supervisor_config(&spec, &sample_paths())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("EGRESS_PORT"), "unexpected error: {err}");
    }

    #[test]
    fn relay_config_rejects_a_bundled_kernel() {
        // HVF has no bundled kernel; the spec must name an explicit Image.
        let spec = spec_with(
            KernelImage::Bundled,
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        assert!(relay_supervisor_config(&spec, &sample_paths()).is_err());
    }

    #[test]
    fn vsock_connect_reaches_the_agent_socket_and_rejects_other_ports() {
        use crate::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("hvf-agent.sock");
        // Stand-in for the supervisor's agent bridge: echo one byte back.
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

        let vm = HvfRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(PID_FILE_NAME),
            agent_socket: sock,
        };

        // The agent port connects + round-trips through the socket.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // Ports outside the agent port and the console data range are not host-dialable.
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
    }

    // --- console_socket_for_port ---

    #[test]
    fn console_socket_for_port_resolves_first_console_port() {
        let state = PathBuf::from("/state/vm");
        let got = console_socket_for_port(&state, 20001).unwrap();
        assert_eq!(got, PathBuf::from("/state/vm/vsock/vsock-20001.sock"));
    }

    #[test]
    fn console_socket_for_port_resolves_last_console_port() {
        let state = PathBuf::from("/state/vm");
        let got = console_socket_for_port(&state, 20128).unwrap();
        assert_eq!(got, PathBuf::from("/state/vm/vsock/vsock-20128.sock"));
    }

    #[test]
    fn console_socket_for_port_returns_none_for_out_of_range_ports() {
        let state = PathBuf::from("/state/vm");
        // CONSOLE_PORT_BASE itself is not a data port (data ports start at +1).
        assert!(console_socket_for_port(&state, 20000).is_none());
        // Beyond the 128-port cap.
        assert!(console_socket_for_port(&state, 20129).is_none());
        // Arbitrary unrelated port.
        assert!(console_socket_for_port(&state, 9999).is_none());
    }

    #[test]
    fn vsock_connect_console_port_resolves_to_vsock_subdir() {
        use crate::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let vsock_dir = dir.path().join("vsock");
        std::fs::create_dir_all(&vsock_dir).unwrap();
        let sock = vsock_dir.join("vsock-20001.sock");
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

        let vm = HvfRunningVm {
            id: VmId("console-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(PID_FILE_NAME),
            agent_socket: dir.path().join("hvf-agent.sock"),
        };

        // Port 20001 (first console data port) connects via the vsock subdir.
        let mut s = vm.vsock_connect(20001).unwrap();
        s.write_all(b"y").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"y");
        server.join().unwrap();

        // A port outside both the agent and console ranges still bails.
        assert!(vm.vsock_connect(9999).is_err());
    }

    // --- relay_supervisor_config: console_data_sockets ---

    fn console_vsock_port(port: u32, uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::ConsoleData { port },
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    #[test]
    fn relay_config_copies_console_ports_into_console_data_sockets() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
                console_vsock_port(20001, "/state/vsock/vsock-20001.sock"),
                console_vsock_port(20002, "/state/vsock/vsock-20002.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.console_data_sockets.len(), 2);
        assert_eq!(cfg.console_data_sockets[0].guest_port, 20001);
        assert_eq!(
            cfg.console_data_sockets[0].host_socket,
            PathBuf::from("/state/vsock/vsock-20001.sock")
        );
        assert_eq!(cfg.console_data_sockets[1].guest_port, 20002);
    }

    #[test]
    fn relay_config_produces_empty_console_data_sockets_when_none_in_spec() {
        // Sealed prod: spec carries only the three standing ports, no console entries.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert!(cfg.console_data_sockets.is_empty());
    }
}
