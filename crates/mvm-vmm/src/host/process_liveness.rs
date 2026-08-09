//! Cheap supervisor-process liveness helpers shared by backends and runtime.

use std::path::{Path, PathBuf};

/// Supervisor PID markers, one per workload backend plus the generic `pid`
/// fallback. This is the single list every liveness probe reads — a backend
/// missing here reads as stopped everywhere at once.
const PID_FILE_NAMES: &[&str] = &["libkrun.pid", "hvf.pid", "fc.pid", "qemu.pid", "pid"];

/// `kill(pid, 0)` existence probe — delivers no signal, just checks the
/// process is alive. `EPERM` is a positive existence result for a supervisor
/// owned by another uid (notably root-owned Firecracker); only `ESRCH` means
/// the process is absent. The cheap half of the live-vs-orphan discrimination
/// (see module docs); the heavier argv/ppid sweep stays in `cache prune`.
fn pid_is_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 performs only a permission/existence
    // check and never delivers a signal.
    let result = unsafe { libc::kill(pid, 0) };
    let error = (result != 0)
        .then(|| std::io::Error::last_os_error().raw_os_error())
        .flatten();
    kill_zero_reports_alive(result, error)
}

fn kill_zero_reports_alive(result: i32, error: Option<i32>) -> bool {
    result == 0 || error == Some(libc::EPERM)
}

fn read_pid_file(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 1)
}

/// Whether one supervisor PID file identifies a live process.
pub fn pid_file_has_live_process(path: &Path) -> bool {
    read_pid_file(path).is_some_and(pid_is_alive)
}

/// Resolve the first known supervisor PID file in `dir` that points at a live
/// process.
pub fn live_process_pid_file(dir: &Path) -> Option<PathBuf> {
    PID_FILE_NAMES
        .iter()
        .map(|file| dir.join(file))
        .find(|path| pid_file_has_live_process(path))
}

/// Whether a VM state directory carries a supervisor PID file pointing at a
/// live process.
pub fn state_dir_has_live_process(dir: &Path) -> bool {
    live_process_pid_file(dir).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_zero_treats_permission_denied_as_a_live_process() {
        assert!(kill_zero_reports_alive(0, None));
        assert!(kill_zero_reports_alive(-1, Some(libc::EPERM)));
        assert!(!kill_zero_reports_alive(-1, Some(libc::ESRCH)));
        assert!(!kill_zero_reports_alive(-1, Some(libc::EINVAL)));
    }
}
