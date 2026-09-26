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

/// The executable a live process is running, read from the kernel rather than
/// from its argv, which a process may rewrite. `None` when the process is gone,
/// when it belongs to a user this process may not inspect, or on a platform
/// with no way to ask. Callers that would signal a recorded PID use this to
/// confirm the PID still names the process they recorded.
pub fn process_executable(pid: i32) -> Option<PathBuf> {
    if pid <= 1 {
        return None;
    }
    platform_process_executable(pid)
}

#[cfg(target_os = "linux")]
fn platform_process_executable(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(without_deleted_marker)
}

/// Linux reports an executable whose file was unlinked after exec as
/// `<path> (deleted)`. The process still runs that binary, so the marker is not
/// part of its identity — an upgrade that removed an old release directory
/// leaves exactly this behind.
#[cfg(any(target_os = "linux", test))]
fn without_deleted_marker(path: PathBuf) -> PathBuf {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    const MARKER: &[u8] = b" (deleted)";
    let bytes = path.as_os_str().as_bytes();
    match bytes.strip_suffix(MARKER) {
        Some(stripped) => PathBuf::from(std::ffi::OsString::from_vec(stripped.to_vec())),
        None => path,
    }
}

#[cfg(target_os = "macos")]
fn platform_process_executable(pid: i32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let capacity = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).ok()?;
    let mut buffer = vec![0u8; capacity];
    let buffer_len = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `proc_pidpath` writes at most `buffer_len` bytes into the buffer,
    // which is exactly that long, and returns how many it wrote. The PID was
    // validated by the caller.
    let written = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer_len) };
    let written = usize::try_from(written).ok().filter(|&n| n > 0)?;
    buffer.truncate(written);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buffer)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_process_executable(_pid: i32) -> Option<PathBuf> {
    None
}

/// What [`signal_if_executable`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardedSignal {
    /// The process was running an accepted executable and was sent the signal.
    Sent,
    /// No live process holds the PID, so there was nothing to signal.
    Exited,
    /// The process is live, but its executable could not be read (`None`) or
    /// was not accepted. Nothing was sent.
    Refused(Option<PathBuf>),
}

/// Send `signal` to `pid` only if the process holding it runs an executable
/// `accept` approves.
///
/// On Linux the check and the signal go through one pidfd, so the signal
/// reaches exactly the process whose executable was read: a PID recycled
/// between the two steps is refused rather than signalled. Where pidfds are
/// unavailable the executable is read and the PID signalled separately, which
/// leaves the recycling window a pidfd closes.
pub fn signal_if_executable(
    pid: i32,
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
) -> std::io::Result<GuardedSignal> {
    if pid <= 1 {
        return Ok(GuardedSignal::Refused(None));
    }
    platform_signal_if_executable(pid, signal, accept)
}

#[cfg(target_os = "linux")]
fn platform_signal_if_executable(
    pid: i32,
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
) -> std::io::Result<GuardedSignal> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: `pidfd_open` takes a PID and flags and returns a new descriptor
    // or -1; it reads and writes no memory of ours.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(GuardedSignal::Exited),
            Some(libc::ENOSYS) | Some(libc::EINVAL) => inspect_then_kill(pid, signal, accept),
            _ => Err(error),
        };
    }
    let raw = i32::try_from(raw).map_err(|_| std::io::Error::other("pidfd out of range"))?;
    // SAFETY: `raw` is a descriptor `pidfd_open` just returned and nothing else
    // owns; `OwnedFd` closes it exactly once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };

    let executable = process_executable(pid);
    // A pidfd names one process for its whole life, and a PID cannot be reused
    // while that process is alive. So if the process is still there after the
    // executable was read, the read described it and not a successor.
    if !pidfd_send_signal(&pidfd, 0)? {
        return Ok(GuardedSignal::Exited);
    }
    match executable {
        Some(path) if accept(&path) => {
            if pidfd_send_signal(&pidfd, signal)? {
                Ok(GuardedSignal::Sent)
            } else {
                Ok(GuardedSignal::Exited)
            }
        }
        other => Ok(GuardedSignal::Refused(other)),
    }
}

/// Signal the process a pidfd names. `Ok(false)` when it has exited.
#[cfg(target_os = "linux")]
fn pidfd_send_signal(pidfd: &std::os::fd::OwnedFd, signal: libc::c_int) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is a live pidfd; a null siginfo asks the kernel to
    // fill in the default sender details, and no flags are defined.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(error)
}

#[cfg(not(target_os = "linux"))]
fn platform_signal_if_executable(
    pid: i32,
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
) -> std::io::Result<GuardedSignal> {
    inspect_then_kill(pid, signal, accept)
}

fn inspect_then_kill(
    pid: i32,
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
) -> std::io::Result<GuardedSignal> {
    if !pid_is_alive(pid) {
        return Ok(GuardedSignal::Exited);
    }
    match process_executable(pid) {
        Some(path) if accept(&path) => {}
        other => return Ok(GuardedSignal::Refused(other)),
    }
    // SAFETY: `kill` has no memory-safety preconditions; the PID was checked
    // above to be greater than 1 and to run an accepted executable.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(GuardedSignal::Sent);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(GuardedSignal::Exited);
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_executable_names_this_process_binary() {
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        let reported = process_executable(pid).expect("own executable is readable");
        let expected = std::env::current_exe().expect("current exe");
        assert_eq!(
            std::fs::canonicalize(&reported).expect("reported path exists"),
            std::fs::canonicalize(&expected).expect("current exe exists"),
        );
    }

    #[test]
    fn process_executable_refuses_pids_no_daemon_can_have() {
        assert_eq!(process_executable(0), None);
        assert_eq!(process_executable(1), None);
        assert_eq!(process_executable(-7), None);
    }

    #[test]
    fn process_executable_is_none_for_an_exited_process() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = i32::try_from(child.id()).expect("pid fits in i32");
        child.wait().expect("reap true");
        assert_eq!(process_executable(pid), None);
    }

    /// A child running `sleep`, returned only once it has exec'd.
    ///
    /// `spawn` returns after the fork, while the child can still be running
    /// this test binary. A check made in that window sees the wrong
    /// executable and is refused, which is correct behaviour and a flaky test.
    fn spawn_sleep() -> (std::process::Child, i32) {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = i32::try_from(child.id()).expect("pid fits in i32");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while process_executable(pid)
            .is_none_or(|path| path.file_name() != Some(std::ffi::OsStr::new("sleep")))
        {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sleep child {pid} never reported running sleep");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        (child, pid)
    }

    #[test]
    fn a_process_running_an_unaccepted_executable_is_not_signalled() {
        let (mut child, pid) = spawn_sleep();
        let outcome = signal_if_executable(pid, libc::SIGTERM, &|_| false).unwrap();
        let still_running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            matches!(outcome, GuardedSignal::Refused(Some(ref path)) if path.file_name().is_some()),
            "{outcome:?}"
        );
        assert!(still_running, "a refused process must not be signalled");
    }

    #[test]
    fn a_process_running_an_accepted_executable_is_signalled() {
        use std::os::unix::process::ExitStatusExt;
        let (mut child, pid) = spawn_sleep();
        let outcome = signal_if_executable(pid, libc::SIGTERM, &|path| {
            path.file_name() == Some(std::ffi::OsStr::new("sleep"))
        })
        .unwrap();
        if outcome != GuardedSignal::Sent {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        assert_eq!(outcome, GuardedSignal::Sent);
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn an_exited_or_reserved_pid_is_never_signalled() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = i32::try_from(child.id()).expect("pid fits in i32");
        child.wait().expect("reap true");
        assert_eq!(
            signal_if_executable(pid, libc::SIGTERM, &|_| true).unwrap(),
            GuardedSignal::Exited
        );
        for reserved in [0, 1, -1] {
            assert_eq!(
                signal_if_executable(reserved, libc::SIGTERM, &|_| true).unwrap(),
                GuardedSignal::Refused(None)
            );
        }
    }

    #[test]
    fn deleted_marker_is_stripped_and_other_paths_are_kept() {
        assert_eq!(
            without_deleted_marker(PathBuf::from("/opt/mvm/1-v1/mvm-host-agent (deleted)")),
            PathBuf::from("/opt/mvm/1-v1/mvm-host-agent"),
        );
        assert_eq!(
            without_deleted_marker(PathBuf::from("/usr/bin/mvm-host-agent")),
            PathBuf::from("/usr/bin/mvm-host-agent"),
        );
    }

    #[test]
    fn kill_zero_treats_permission_denied_as_a_live_process() {
        assert!(kill_zero_reports_alive(0, None));
        assert!(kill_zero_reports_alive(-1, Some(libc::EPERM)));
        assert!(!kill_zero_reports_alive(-1, Some(libc::ESRCH)));
        assert!(!kill_zero_reports_alive(-1, Some(libc::EINVAL)));
    }
}
