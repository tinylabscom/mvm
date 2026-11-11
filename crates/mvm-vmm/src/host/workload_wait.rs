//! Shared one-shot workload-exit wait, used by every backend that captures a
//! guest exit code to `<vm_state_dir>/workload.exit`.
//!
//! The poll is state-dir based and therefore backend-agnostic: the supervisor
//! (libkrun or hvf) persists `workload.exit` BEFORE the guest powers off — the
//! ack handshake guarantees that ordering — so the file's presence is the
//! reliable "workload finished" signal. We deliberately do NOT poll supervisor
//! PID liveness: on a busy host a dead supervisor's PID can be reused by another
//! process, making a liveness check spin forever. Bounded so a guest that
//! crashes without reporting fails closed to UNKNOWN.

use mvm_core::vm_backend::VmExitStatus;
use std::path::Path;
use std::time::{Duration, Instant};

/// Max time to wait for a one-shot workload to report its exit code.
pub const WORKLOAD_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

/// Read the captured exit code from `<state_dir>/workload.exit`, or UNKNOWN when
/// absent (guest was killed / backend doesn't capture).
pub fn read_exit_status_from(state_dir: &Path) -> VmExitStatus {
    match mvm_core::exit_capture::read_captured(state_dir) {
        Some(code) => VmExitStatus {
            code: Some(code),
            success: code == 0,
        },
        None => VmExitStatus::UNKNOWN,
    }
}

/// Block until the captured exit code appears under `state_dir`, or the bounded
/// timeout elapses (→ UNKNOWN). Shared by the libkrun and hvf `VmBackend::wait`
/// impls — both supervisors write the same `workload.exit` file.
///
/// No production caller reaches this outside the wasm tier today: a foreground
/// run reads its exit from the guest's exec stream instead.
pub fn wait_for_workload_exit(state_dir: &Path) -> VmExitStatus {
    wait_for_workload_exit_within(state_dir, WORKLOAD_WAIT_TIMEOUT)
}

/// [`wait_for_workload_exit`] with the bound named by the caller, so one that
/// knows the workload's admitted wall clock can wait as long as that allows.
///
/// Giving up does not stop the VM: the answer is UNKNOWN, and the warning says
/// so rather than leaving a caller to read an exit it never got.
pub fn wait_for_workload_exit_within(state_dir: &Path, timeout: Duration) -> VmExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        let status = read_exit_status_from(state_dir);
        if status != VmExitStatus::UNKNOWN {
            return status;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                state_dir = %state_dir.display(),
                waited_secs = timeout.as_secs(),
                "no workload exit was reported in time; the exit status is unknown and the VM was not stopped"
            );
            return VmExitStatus::UNKNOWN;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_exit_status_nonzero_is_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), "3").unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status.code, Some(3));
        assert!(!status.success);
    }

    #[test]
    fn read_exit_status_zero_is_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), "0").unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status.code, Some(0));
        assert!(status.success);
    }

    #[test]
    fn read_exit_status_absent_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status, VmExitStatus::UNKNOWN);
    }

    #[test]
    fn wait_returns_staged_exit_immediately() {
        // A workload.exit already present returns at once (no timeout wait) —
        // the path every backend's `wait()` shares.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), "2").unwrap();
        let status = wait_for_workload_exit(dir.path());
        assert_eq!(status.code, Some(2));
        assert!(!status.success);
    }

    #[test]
    fn a_wait_that_runs_out_reports_unknown_at_its_own_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let status = wait_for_workload_exit_within(dir.path(), Duration::from_millis(250));
        assert_eq!(status, VmExitStatus::UNKNOWN);
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn a_wait_sees_an_exit_written_while_it_waits() {
        let dir = tempfile::tempdir().unwrap();
        let path = mvm_core::exit_capture::exit_file_path(dir.path());
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::write(path, "5").unwrap();
        });
        let status = wait_for_workload_exit_within(dir.path(), Duration::from_secs(30));
        writer.join().unwrap();
        assert_eq!(status.code, Some(5));
    }
}
