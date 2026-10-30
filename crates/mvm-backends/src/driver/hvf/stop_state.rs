//! Deciding that a stop which could not reach the supervisor found nothing
//! running.

use mvm_vmm::driver::traits::RunningVm;

use super::{HvfRunningVm, hvf_backend};

impl HvfRunningVm {
    /// A stop that could not reach the control socket found nothing to stop
    /// only when the socket is refused or gone and the recorded supervisor
    /// process is provably not alive. A live process, or no recorded process,
    /// keeps the raw error.
    pub(super) fn stop_found_nothing_running(&self, error: &anyhow::Error) -> bool {
        control_socket_is_gone(error)
            && self
                .host_process_id()
                .and_then(|pid| libc::pid_t::try_from(pid).ok())
                .is_some_and(|pid| !hvf_backend::pid_alive(pid))
    }
}

/// Whether `error` carries a refused connection, which proves no listener
/// answers. A missing file is deliberately not enough: a missing operator key
/// or instance record fails the same way and is not evidence of a stop.
fn control_socket_is_gone(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
}

#[cfg(test)]
mod tests {
    use super::super::*;

    fn vm_with_pid_file(dir: &Path, pid: Option<&str>) -> HvfRunningVm {
        let pid_file = dir.join(PID_FILE_NAME);
        if let Some(pid) = pid {
            std::fs::write(&pid_file, pid).unwrap();
        }
        HvfRunningVm {
            id: VmId("stopped-vm".into()),
            instance: HvfInstance {
                vm_id: "stopped-vm".into(),
                boot_nonce: [3; 32],
            },
            owned: None,
            state_dir: dir.to_path_buf(),
            pid_file,
            agent_socket: dir.join("hvf-agent.sock"),
        }
    }

    fn refused() -> anyhow::Error {
        anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context("connect to HVF control socket")
    }

    fn reaped_child_pid() -> String {
        // Libtest's help exits without running tests or consulting PATH.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(child.wait().unwrap().success());
        pid.to_string()
    }

    #[test]
    fn dead_supervisor_fixture_does_not_require_path() {
        use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};
        use std::time::Duration;

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "driver::hvf::stop_state::tests::refused_socket_and_dead_supervisor_is_already_stopped",
                "--nocapture",
            ])
            .env("PATH", "")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let exited = ProcessExitObserver::arm(child.id().try_into().unwrap())
            .and_then(|observer| observer.wait_event(Instant::now() + Duration::from_secs(10)));
        if !matches!(exited, Ok(ProcessExitWait::Exited)) {
            let _ = child.kill();
            child.wait().unwrap();
            panic!("fixture exit was not observed: {exited:?}");
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("1 passed"), "{stdout}");
        assert!(output.status.success(), "{stdout}");
    }

    #[test]
    fn refused_socket_and_dead_supervisor_is_already_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let gone = vm_with_pid_file(dir.path(), Some(&reaped_child_pid()));
        assert!(gone.stop_found_nothing_running(&refused()));
    }

    #[test]
    fn a_missing_file_with_dead_supervisor_keeps_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let gone = vm_with_pid_file(dir.path(), Some(&reaped_child_pid()));
        let absent = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(!gone.stop_found_nothing_running(&absent));
    }

    #[test]
    fn refused_socket_with_no_recorded_supervisor_keeps_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let unknown = vm_with_pid_file(dir.path(), None);
        assert!(!unknown.stop_found_nothing_running(&refused()));
    }

    #[test]
    fn refused_socket_with_live_supervisor_keeps_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let live = vm_with_pid_file(dir.path(), Some(&std::process::id().to_string()));
        assert!(!live.stop_found_nothing_running(&refused()));
    }

    #[test]
    fn other_control_failures_are_not_already_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_with_pid_file(dir.path(), Some(&reaped_child_pid()));
        assert!(!vm.stop_found_nothing_running(&anyhow!("HVF ownership generation changed")));
        let denied =
            anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(!vm.stop_found_nothing_running(&denied));
    }
}
