//! The warm-standby parent spawn for the HVF driver: boot the parent through
//! the handoff path, wait for its guest agent, and describe it as a standby.

use mvm_vmm::driver::traits::RunningVm;
use mvm_vmm::host::process_liveness::read_pid_file;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{StandbyHandle, StandbyState};

use super::{
    HandoffConfig, PID_FILE_NAME, StandbyParentSpawn, boot_with_handoff, hvf_agent_socket,
};

pub(super) fn spawn_standby_parent(req: &StandbyParentSpawn<'_>) -> Result<StandbyHandle> {
    let handoff = handoff_config(&req.spec.id).context("prepare HVF handoff")?;
    let vm = boot_with_handoff(req.boot, Some(&handoff), None, None).context("boot HVF standby")?;
    let state_dir = vm_state_dir(&req.spec.id);
    let recorded = read_pid_file(&state_dir.join(PID_FILE_NAME));
    let pid = recorded_pid_or_stop(vm.as_ref(), recorded, &req.spec.id)?;
    if let Err(error) = wait_for_guest_agent(&state_dir) {
        let _ = vm.kill();
        bail!(
            "HVF standby '{}' guest agent did not become ready: {error}",
            req.spec.id
        );
    }
    drop(vm);
    Ok(StandbyHandle {
        id: req.spec.id.clone(),
        template_id: req.spec.template_id.clone(),
        control_socket: state_dir
            .join("hvf-control.sock")
            .to_string_lossy()
            .into_owned(),
        pid,
        kernel_sha256: req.spec.kernel_sha256.clone(),
        vcpus: req.spec.vcpus,
        mem_mib: req.spec.mem_mib,
        binding_nonce: req.spec.binding_nonce.clone(),
        spawned_unix_secs: mvm_core::time::now_unix_secs(),
        state: StandbyState::Idle,
        image_sha256: req.spec.image_sha256.clone(),
        root_strategy: req.spec.root_strategy,
        parent_checkpoint: None,
        preloaded_child_vm_name: None,
        vsock_egress: req.spec.vsock_egress,
    })
}

/// The supervisor pid a freshly booted standby parent must be trackable by,
/// stopping the VM on every refusal. `recorded` is what the shared pid-file
/// guard accepted; a record it filtered out, or a negative value that would
/// wrap into a process-group signal target, can never be torn down or reaped
/// later, so no refusal here may leave the parent running.
fn recorded_pid_or_stop(vm: &dyn RunningVm, recorded: Option<i32>, id: &str) -> Result<u32> {
    let Some(pid) = recorded else {
        let _ = vm.kill();
        bail!("HVF standby '{id}' did not publish a pid");
    };
    let Ok(pid) = u32::try_from(pid) else {
        let _ = vm.kill();
        bail!("HVF standby '{id}' pid is negative");
    };
    Ok(pid)
}

fn handoff_config(parent_vm_name: &str) -> Result<HandoffConfig> {
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
        .context("load host identity for HVF handoff")?;
    let state_dir = vm_state_dir(parent_vm_name);
    mvm_core::config::secure_fallback_socket_dir_at(&state_dir)
        .context("prepare HVF handoff socket directory")?;
    Ok(HandoffConfig {
        socket: mvm_core::config::vm_hvf_handoff_socket_at(&state_dir),
        root: mvm_core::config::vms_dir(),
        verify_key: hex::encode(identity.verifying.to_bytes()),
    })
}

/// How long a factory parent's guest agent has to start answering.
const STANDBY_AGENT_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Do not capture a factory parent until its guest agent has completed init.
/// The child resumes from the captured CPU/device state rather than rebooting,
/// so a parent captured before the agent listener is serving would make every
/// later post-restore identity handshake impossible.
fn wait_for_guest_agent(state_dir: &Path) -> Result<()> {
    wait_for_standby_agent(&hvf_agent_socket(state_dir), STANDBY_AGENT_READY_TIMEOUT)
}

/// Poll `socket` until a guest agent answers the authenticated readiness probe
/// in either serving state.
///
/// A parent booted with the universal initramfs is still waiting for
/// `ActivateEnvironment` here — the runner activates it only after this
/// returns — and that agent answers every `Ping` with `NotActivated`. That
/// answer is the agent serving, so it counts. Requiring `Pong` instead waits
/// for a reply the guest cannot give until the caller's next step, and fails
/// every such parent at the deadline.
pub(super) fn wait_for_standby_agent(socket: &Path, timeout: std::time::Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    let mut last_error: Option<anyhow::Error> = None;
    loop {
        if socket.exists() {
            // The HVF agent socket is the bridge's direct stream endpoint. It
            // is not a Firecracker-style CONNECT multiplexer, so sending the
            // `CONNECT <port>` preamble would be interpreted by the guest as
            // the first four bytes of an RPC frame. Probe the authenticated
            // RPC stream directly; this waits for a real guest response rather
            // than treating the host-side listener as readiness.
            match std::os::unix::net::UnixStream::connect(socket) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
                    match mvm_agentd::vsock::probe_agent_serving(&mut stream) {
                        Ok(_) => return Ok(()),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error.into()),
            }
        }
        // Probe first, then check the clock: an agent already serving is
        // ready whatever the budget, and the remaining time, not a comparison
        // against the deadline, decides whether to keep waiting.
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            break;
        }
        std::thread::sleep(mvm_core::poll_backoff::fine_poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
    let reason = last_error.map_or_else(
        || "the socket was never bound".to_string(),
        |error| format!("last probe: {error:#}"),
    );
    anyhow::bail!(
        "guest agent socket {} was not responsive within {timeout:?} ({reason})",
        socket.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::{VmExitStatus, VmId, VmStatus};
    use mvm_vmm::driver::DuplexStream;
    use std::sync::Mutex;

    /// Records kills so a test can prove a refused standby was stopped.
    struct FakeStandbyVm {
        id: VmId,
        kill_count: Mutex<u32>,
    }

    impl FakeStandbyVm {
        fn new() -> Self {
            Self {
                id: VmId("standby-test".into()),
                kill_count: Mutex::new(0),
            }
        }

        fn killed(&self) -> bool {
            *self.kill_count.lock().expect("kill count lock") > 0
        }
    }

    impl RunningVm for FakeStandbyVm {
        fn id(&self) -> &VmId {
            &self.id
        }

        fn wait(&self) -> Result<VmExitStatus> {
            Ok(VmExitStatus::SUCCESS)
        }

        fn kill(&self) -> Result<()> {
            *self.kill_count.lock().expect("kill count lock") += 1;
            Ok(())
        }

        fn pause(&self) -> Result<()> {
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            Ok(())
        }

        fn status(&self) -> Result<VmStatus> {
            Ok(VmStatus::Running)
        }

        fn vsock_connect(&self, _guest_port: u32) -> Result<Box<dyn DuplexStream>> {
            bail!("fake standby VM has no vsock")
        }
    }

    fn with_pid_file(dir: &Path, contents: &str) {
        std::fs::write(dir.join(PID_FILE_NAME), contents).unwrap();
    }

    /// The shared pid-file guard reads a record it cannot accept as `None`,
    /// so a file holding one is indistinguishable from a missing file here.
    #[test]
    fn an_unsignalable_recorded_pid_reads_as_none() {
        // 0 names the caller's whole process group, 1 is init, and a negative
        // value names a process group; none may ever reach a kill.
        for contents in ["0", "1", "-5"] {
            let dir = tempfile::tempdir().unwrap();
            with_pid_file(dir.path(), contents);
            assert_eq!(read_pid_file(&dir.path().join(PID_FILE_NAME)), None);
        }
    }

    #[test]
    fn a_negative_recorded_pid_stops_the_standby_and_is_refused() {
        let vm = FakeStandbyVm::new();
        let error = recorded_pid_or_stop(&vm, Some(-5), "standby-test")
            .expect_err("a negative recorded pid must be refused");
        assert!(
            format!("{error:#}").contains("pid is negative"),
            "{error:#}"
        );
        assert!(vm.killed(), "a refused standby must be stopped");
    }

    #[test]
    fn a_missing_or_unsignalable_recorded_pid_stops_the_standby_and_is_refused() {
        let vm = FakeStandbyVm::new();
        let error = recorded_pid_or_stop(&vm, None, "standby-test")
            .expect_err("no recorded pid must be refused");
        assert!(
            format!("{error:#}").contains("did not publish a pid"),
            "{error:#}"
        );
        assert!(vm.killed(), "a refused standby must be stopped");
    }

    #[test]
    fn a_signalable_recorded_pid_keeps_the_standby_running() {
        let vm = FakeStandbyVm::new();
        let pid = recorded_pid_or_stop(&vm, Some(4242), "standby-test")
            .expect("a signalable recorded pid is accepted");
        assert_eq!(pid, 4242);
        assert!(!vm.killed(), "an accepted standby must keep running");
    }
}
