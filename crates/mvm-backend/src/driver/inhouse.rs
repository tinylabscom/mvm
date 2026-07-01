//! `InHouseDriver` — the `VmmDriver` for the first-party VMM (HVF on macOS, KVM
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

use anyhow::{Result, anyhow, bail};
use mvm_build::hvf_supervisor::HvfSupervisorConfig;
use mvm_core::config::vm_state_dir;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{
    SnapshotCapability, VmBackend, VmCapabilities, VmExitStatus, VmId, VmStatus,
};
use mvm_guest::vsock::{EGRESS_PORT, GUEST_AGENT_PORT};

use crate::driver::spec::KernelImage;
use crate::driver::{DuplexStream, RunningVm, VmmDriver, VmmSpec};
use crate::hvf_backend::{
    self, HvfBackend, PID_FILE_NAME, PID_FILE_TIMEOUT, resolve_supervisor_path,
};

/// The first-party VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge, not
/// here.
pub struct InHouseDriver {
    backend: HvfBackend,
}

impl InHouseDriver {
    pub fn new() -> Self {
        Self {
            backend: HvfBackend,
        }
    }
}

impl Default for InHouseDriver {
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

/// Find the host socket for a standing vsock port by its guest-port number.
fn vsock_socket(spec: &VmmSpec, guest_port: u32) -> Option<PathBuf> {
    spec.vsock
        .iter()
        .find(|p| p.guest_port == guest_port)
        .map(|p| p.host_uds.clone())
}

/// Map a policy-free `VmmSpec` to a relay `HvfSupervisorConfig`: the supervisor
/// wires the guest's `EGRESS_PORT` straight to the host-side endpoint bound at
/// `egress_relay_socket`, which owns the claim-10 gate and substitution. The
/// spec MUST carry that egress socket — an in-house workload has no other path
/// off the box, so a spec without it fails closed rather than booting ungated.
fn relay_supervisor_config(spec: &VmmSpec, paths: &SupervisorPaths) -> Result<HvfSupervisorConfig> {
    let kernel = match &spec.kernel {
        KernelImage::Path(p) => p.clone(),
        KernelImage::Bundled => {
            bail!("the in-house VMM requires an explicit kernel Image; VmmSpec.kernel is Bundled")
        }
    };

    // The HVF supervisor takes a single virtio-blk device today; the sealed
    // rootfs is slot 0. Multi-disk (verity sidecar + overlay) is a follow-up.
    let disk = spec.blocks.first().map(|b| b.source.clone());

    let egress_relay_socket = vsock_socket(spec, EGRESS_PORT).ok_or_else(|| {
        anyhow!("in-house workload spec is missing the EGRESS_PORT vsock relay socket")
    })?;

    Ok(HvfSupervisorConfig {
        kernel,
        initramfs: spec.initramfs.clone(),
        disk,
        vsock: true,
        console_log: paths.console_log.clone(),
        pid_file: paths.pid_file.clone(),
        workload_exit: paths.workload_exit.clone(),
        // Unused in relay mode — the host endpoint gates — but the field is
        // non-optional, so deny-all is the fail-closed value.
        network_policy: NetworkPolicy::deny_all(),
        timeout_secs: paths.timeout_secs,
        agent_socket: vsock_socket(spec, GUEST_AGENT_PORT),
        substitution_socket: None,
        egress_relay_socket: Some(egress_relay_socket),
    })
}

impl VmmDriver for InHouseDriver {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn is_available(&self) -> Result<bool> {
        self.backend.is_available()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.backend.capabilities()
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        self.backend.snapshot_capability()
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
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Detach: dropping the `Child` does not kill it, so the supervisor
        // outlives this call (reaped via its PID file by `kill`).
        drop(child);

        Ok(Box::new(InHouseRunningVm {
            id: VmId(spec.name.clone()),
            state_dir: paths.state_dir,
            pid_file: paths.pid_file,
        }))
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the supervisor's pid file + the
        // persisted workload-exit code under the VM's state dir), so reattaching is
        // just re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(InHouseRunningVm {
            pid_file: state_dir.join(PID_FILE_NAME),
            state_dir,
            id: id.clone(),
        }))
    }
}

/// A live in-house VM: the detached `mvm-hvf-supervisor` tracked by its PID file,
/// with the workload's exit code persisted under its state dir.
struct InHouseRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
}

impl RunningVm for InHouseRunningVm {
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
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        bail!("in-house pause/resume is not yet implemented")
    }

    fn resume(&self) -> Result<()> {
        bail!("in-house pause/resume is not yet implemented")
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(match hvf_backend::read_pid(&self.pid_file) {
            Some(pid) if hvf_backend::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn vsock_connect(&self, _guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        bail!("in-house driver vsock_connect is not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{BlockDev, ConsoleCapture, VsockDirection, VsockPort};

    fn egress_port(uds: &str) -> VsockPort {
        VsockPort {
            guest_port: EGRESS_PORT,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn agent_port(uds: &str) -> VsockPort {
        VsockPort {
            guest_port: GUEST_AGENT_PORT,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
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
        let d = InHouseDriver::new();
        assert_eq!(d.name(), "hvf");
        assert!(d.capabilities().vsock);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // Reattaching needs no boot state — it re-derives the state dir. A VM that
        // never ran (or has exited) reports Stopped rather than erroring.
        let vm = InHouseDriver::new()
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
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();

        assert_eq!(cfg.kernel, PathBuf::from("/img/Image"));
        assert_eq!(cfg.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
        assert_eq!(cfg.agent_socket, Some(PathBuf::from("/run/agent.sock")));
        assert_eq!(cfg.substitution_socket, None);
        assert_eq!(cfg.network_policy, NetworkPolicy::deny_all());
        assert!(cfg.vsock);
        // No blocks → no disk.
        assert_eq!(cfg.disk, None);
    }

    #[test]
    fn relay_config_takes_the_first_block_as_the_single_disk() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![BlockDev {
                source: "/img/rootfs.ext4".into(),
                read_only: true,
                slot: 0,
            }],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.disk, Some(PathBuf::from("/img/rootfs.ext4")));
    }

    #[test]
    fn relay_config_missing_egress_port_fails_closed() {
        // No EGRESS_PORT: the in-house VMM has no other path off the box, so this
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
}
