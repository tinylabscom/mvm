//! Cheap supervisor-process liveness helpers shared by backends and runtime.

use std::path::{Path, PathBuf};

/// Supervisor PID markers, one per workload backend plus the generic `pid`
/// fallback. This is the single list every liveness probe reads — a backend
/// missing here reads as stopped everywhere at once.
///
/// Public because the orphan-helper reaper in the CLI has to answer the same
/// "is this VM still alive" question before it kills anything, and a second
/// copy of the list there would drift into reaping a live guest.
pub const PID_FILE_NAMES: &[&str] = &["libkrun.pid", "hvf.pid", "fc.pid", "qemu.pid", "pid"];

/// `kill(pid, 0)` existence probe — delivers no signal, just checks the
/// process is alive. `EPERM` is a positive existence result for a supervisor
/// owned by another uid (notably root-owned Firecracker); only `ESRCH` means
/// the process is absent. The cheap half of the live-vs-orphan discrimination
/// (see module docs); the heavier argv/ppid sweep stays in `cache prune`.
/// Whether a process ID currently identifies a live or permission-protected
/// process.
pub fn pid_is_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    #[cfg(target_os = "macos")]
    if macos_process_is_zombie(pid) {
        return false;
    }
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

#[cfg(target_os = "macos")]
fn macos_process_is_zombie(pid: i32) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `proc_pidinfo` fills the initialized buffer when the returned
    // byte count matches its size. The PID was validated by the caller.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<libc::proc_bsdinfo>() as i32,
        )
    };
    if bytes != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
        return false;
    }
    // SAFETY: The size check above proves that the kernel populated `info`.
    unsafe { info.assume_init().pbi_status == libc::SZOMB }
}

/// Parse a supervisor PID marker. `None` when the file is absent, unparseable,
/// or names a PID no supervisor can have — `0` addresses the caller's whole
/// process group and `1` is init, so neither may reach a `kill`.
pub fn read_pid_file(path: &Path) -> Option<i32> {
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
