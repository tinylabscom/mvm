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
    pid_is_alive_with_probes(
        pid,
        |pid| {
            #[cfg(target_os = "macos")]
            {
                macos_process_is_zombie(pid)
            }
            #[cfg(target_os = "linux")]
            {
                linux_process_is_zombie(pid)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = pid;
                false
            }
        },
        |pid| {
            // SAFETY: kill with signal 0 performs only a permission/existence
            // check and never delivers a signal.
            let result = unsafe { libc::kill(pid, 0) };
            let error = (result != 0)
                .then(|| std::io::Error::last_os_error().raw_os_error())
                .flatten();
            (result, error)
        },
    )
}

fn pid_is_alive_with_probes(
    pid: i32,
    is_zombie: impl FnOnce(i32) -> bool,
    signal_zero: impl FnOnce(i32) -> (i32, Option<i32>),
) -> bool {
    if pid <= 1 {
        return false;
    }
    if is_zombie(pid) {
        return false;
    }
    let (result, error) = signal_zero(pid);
    kill_zero_reports_alive(result, error)
}

fn kill_zero_reports_alive(result: i32, error: Option<i32>) -> bool {
    result == 0 || error == Some(libc::EPERM)
}

/// `kill(pid, 0)` also succeeds for an exited, unreaped child, so Linux reads
/// the state field of `/proc/<pid>/stat` instead.
#[cfg(target_os = "linux")]
fn linux_process_is_zombie(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| stat_state_is_zombie(&stat))
}

/// The state is the first field after the parenthesised command name, which
/// may itself contain spaces and parentheses, so split at the last `)`.
#[cfg(any(target_os = "linux", test))]
fn stat_state_is_zombie(stat: &str) -> bool {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z")
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
    // The kernel still answers `kill(pid, 0)` for a zombie but refuses its
    // process info with ESRCH, so an empty answer with that error is how an
    // exited, unreaped child shows up here. A pid that is gone entirely gives
    // the same answer and is just as dead; any other failure (EPERM for
    // another user's process) proves nothing.
    if bytes == 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    if bytes != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
        // The kernel reports a zombie as `ESRCH` here, with no info, while
        // `kill(pid, 0)` still succeeds. A process that is gone also answers
        // `ESRCH`; both are "not a live process", which is all the caller asks.
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
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

/// What [`signal_if_executable`] or [`signal_if_identity`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardedSignal {
    /// The process was running an accepted executable and was sent the signal.
    Sent,
    /// No live process holds the PID, so there was nothing to signal.
    Exited,
    /// The process is live, but its executable could not be read (`None`) or
    /// was not accepted (including identity rejection). Nothing was sent.
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

/// Signal a recorded Linux process identity without a numeric-PID fallback.
///
/// `accept` runs only after opening a pidfd and receiving the executable. It
/// must validate the recorded identity, including an exact raw `/proc/PID/stat`
/// field-22 starttime (reject missing evidence), and any endpoint/socket checks.
/// The starttime is re-read after the callback and the pidfd is probed last:
/// validation of a replacement PID cannot authorize signalling the old process.
///
/// `Refused` means identity validation failed, `Exited` means the process vanished.
/// Unsupported pidfds/platforms return `ErrorKind::Unsupported`; inspection or
/// signal permission failures return `PermissionDenied`. No privileges are
/// elevated. Signal zero is rejected: `Sent` always means a signal was delivered.
/// Unlike [`signal_if_executable`], this API never calls `kill`.
pub fn signal_if_identity(
    pid: i32,
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
) -> std::io::Result<GuardedSignal> {
    if pid <= 1 {
        return Ok(GuardedSignal::Refused(None));
    }
    if signal == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "identity signalling requires a nonzero signal",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        identity_signal_with(
            signal,
            accept,
            || open_identity_pidfd(pid),
            || {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
                parse_proc_starttime(&stat)
            },
            || std::fs::read_link(format!("/proc/{pid}/exe")).map(without_deleted_marker),
            pidfd_send_signal,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = accept;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "identity signalling requires Linux pidfds",
        ))
    }
}

/// One original Linux process handle, retained across multiple identity checks.
/// There is deliberately no fallback on kernels without pidfds.
#[cfg(target_os = "linux")]
pub struct RetainedProcess {
    pid: i32,
    start_ticks: u64,
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl RetainedProcess {
    /// Open before collecting any registration evidence.
    pub fn open(pid: i32) -> std::io::Result<Self> {
        if pid <= 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid PID",
            ));
        }
        let fd = open_identity_pidfd(pid)?;
        let start_ticks =
            parse_proc_starttime(&std::fs::read_to_string(format!("/proc/{pid}/stat"))?)?;
        if !pidfd_send_signal(&fd, 0)? {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        Ok(Self {
            pid,
            start_ticks,
            fd,
        })
    }

    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }

    /// Check the retained handle without delivering a signal.
    pub fn check(&self, accept: &dyn Fn(&Path) -> bool) -> std::io::Result<GuardedSignal> {
        self.checked_signal(0, accept)
    }

    /// Validate and signal through this exact handle, never a newly opened one.
    /// The callback must check all additional recorded identity bindings.
    pub fn signal(
        &self,
        signal: libc::c_int,
        accept: &dyn Fn(&Path) -> bool,
    ) -> std::io::Result<GuardedSignal> {
        if signal <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid signal",
            ));
        }
        self.checked_signal(signal, accept)
    }

    fn checked_signal(
        &self,
        signal: libc::c_int,
        accept: &dyn Fn(&Path) -> bool,
    ) -> std::io::Result<GuardedSignal> {
        identity_signal_with(
            signal,
            accept,
            || Ok(&self.fd),
            || {
                let ticks = parse_proc_starttime(&std::fs::read_to_string(format!(
                    "/proc/{}/stat",
                    self.pid
                ))?)?;
                if ticks != self.start_ticks {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "process identity changed",
                    ));
                }
                Ok(ticks)
            },
            || std::fs::read_link(format!("/proc/{}/exe", self.pid)),
            |fd, signal| pidfd_send_signal(fd, signal),
        )
    }
}

#[cfg(target_os = "linux")]
fn open_identity_pidfd(pid: i32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: pidfd_open takes scalar arguments and returns a new descriptor.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) => {
                std::io::Error::new(std::io::ErrorKind::Unsupported, error)
            }
            _ => error,
        });
    }
    let raw = i32::try_from(raw).map_err(|_| std::io::Error::other("pidfd out of range"))?;
    // SAFETY: only this owner closes the newly opened pidfd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_proc_starttime(stat: &str) -> std::io::Result<u64> {
    // comm can contain spaces and ')' characters. Fields after its final ')'
    // begin at field 3; field 22 is therefore index 19.
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid process starttime")
        })
}

#[cfg(any(target_os = "linux", test))]
fn identity_signal_with<H>(
    signal: libc::c_int,
    accept: &dyn Fn(&Path) -> bool,
    open: impl FnOnce() -> std::io::Result<H>,
    starttime: impl Fn() -> std::io::Result<u64>,
    executable: impl FnOnce() -> std::io::Result<PathBuf>,
    send: impl Fn(&H, libc::c_int) -> std::io::Result<bool>,
) -> std::io::Result<GuardedSignal> {
    let attempt = || {
        // Keep the owned handle in scope through every check and both sends.
        let handle = open().map_err(|error| match error.raw_os_error() {
            Some(libc::EINVAL) => std::io::Error::new(std::io::ErrorKind::Unsupported, error),
            _ => error,
        })?;
        let before = starttime()?;
        let path = executable()?;
        let accepted = accept(&path);
        let after = starttime()?;
        if !send(&handle, 0)? {
            return Ok(GuardedSignal::Exited);
        }
        if !accepted || before != after {
            return Ok(GuardedSignal::Refused(Some(path)));
        }
        if send(&handle, signal)? {
            Ok(GuardedSignal::Sent)
        } else {
            Ok(GuardedSignal::Exited)
        }
    };
    attempt().or_else(|error: std::io::Error| match error.raw_os_error() {
        Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(GuardedSignal::Exited),
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, error))
        }
        _ => Err(error),
    })
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

    /// A stopped supervisor whose parent has not reaped it still answers
    /// `kill(pid, 0)`. It is not a live process, and a pool or a state-dir
    /// sweep that believes otherwise keeps a dead VM's records forever.
    #[test]
    fn an_exited_but_unreaped_child_is_not_alive() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        // `true` has exited once it is a zombie; poll for that without
        // waiting on it, which would reap it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while pid_is_alive(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY: signal 0 only probes existence.
        let still_there = unsafe { libc::kill(pid, 0) } == 0;
        let alive = pid_is_alive(pid);
        child.wait().unwrap();
        assert!(still_there, "the unreaped child must still be a zombie");
        assert!(!alive, "a zombie must not count as alive");
    }

    #[test]
    fn stat_state_z_is_a_zombie_even_with_a_tricky_command_name() {
        assert!(stat_state_is_zombie("42 (true) Z 1 2 3"));
        assert!(stat_state_is_zombie("42 (a) Z (b) Z 1"));
        assert!(!stat_state_is_zombie("42 (a) Z) S 1 2"));
        assert!(!stat_state_is_zombie("42 (sleep) S 1 2 3"));
        assert!(!stat_state_is_zombie("garbage"));
    }

    #[test]
    fn identity_starttime_is_raw_field_22_even_with_complex_comm() {
        let fields = std::iter::repeat_n("0", 19).collect::<Vec<_>>().join(" ");
        let stat = format!("42 (name ) with spaces) {fields} 18446744073709551615 9");
        assert_eq!(parse_proc_starttime(&stat).unwrap(), u64::MAX);
        for invalid in ["", "42 (name) 0", "42 (name) malformed"] {
            assert_eq!(
                parse_proc_starttime(invalid).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn identity_open_errors_never_inspect_or_signal_a_numeric_pid() {
        for (errno, kind) in [
            (libc::ENOSYS, std::io::ErrorKind::Unsupported),
            (libc::EINVAL, std::io::ErrorKind::Unsupported),
            (libc::EPERM, std::io::ErrorKind::PermissionDenied),
        ] {
            let result = identity_signal_with::<()>(
                libc::SIGTERM,
                &|_| panic!("must not accept without a pidfd"),
                || Err(std::io::Error::from_raw_os_error(errno)),
                || panic!("must not inspect without a pidfd"),
                || panic!("must not inspect without a pidfd"),
                |_, _| panic!("must not signal without a pidfd"),
            );
            assert_eq!(result.unwrap_err().kind(), kind);
        }
        assert_eq!(
            identity_signal_with::<()>(
                libc::SIGTERM,
                &|_| panic!("missing PID"),
                || Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
                || panic!("missing PID"),
                || panic!("missing PID"),
                |_, _| panic!("missing PID"),
            )
            .unwrap(),
            GuardedSignal::Exited
        );
    }

    #[test]
    fn identity_validation_and_signalling_retain_the_handle_in_order() {
        use std::cell::{Cell, RefCell};
        let held = Cell::new(false);
        struct Handle<'a>(&'a Cell<bool>);
        impl Drop for Handle<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        // Accepted identity, callback rejecting absent/mismatched evidence,
        // changed starttime, and replacement identity while old pidfd is dead.
        for (accepted, changed, alive, expected) in [
            (true, false, true, GuardedSignal::Sent),
            (
                false,
                false,
                true,
                GuardedSignal::Refused(Some("/fc".into())),
            ),
            (true, true, true, GuardedSignal::Refused(Some("/fc".into()))),
            (true, false, false, GuardedSignal::Exited),
        ] {
            let reads = Cell::new(0);
            let signals = RefCell::new(Vec::new());
            let result = identity_signal_with(
                libc::SIGTERM,
                &|path| {
                    assert!(held.get());
                    assert_eq!(path, Path::new("/fc"));
                    assert_eq!(reads.get(), 1);
                    accepted
                },
                || {
                    held.set(true);
                    Ok(Handle(&held))
                },
                || {
                    assert!(held.get());
                    let n = reads.get();
                    reads.set(n + 1);
                    Ok(if changed && n > 0 { 23 } else { 22 })
                },
                || {
                    assert!(held.get());
                    Ok("/fc".into())
                },
                |_, signal| {
                    assert!(held.get());
                    assert_eq!(reads.get(), 2);
                    signals.borrow_mut().push(signal);
                    Ok(alive)
                },
            );
            assert_eq!(result.unwrap(), expected);
            assert!(!held.get(), "owned handle closes after operation");
            assert_eq!(
                *signals.borrow(),
                if expected == GuardedSignal::Sent {
                    vec![0, libc::SIGTERM]
                } else {
                    vec![0]
                }
            );
        }
    }

    #[test]
    fn identity_signal_permission_and_exit_are_not_success() {
        for errno in [libc::EPERM, libc::EACCES, libc::ESRCH] {
            let result = identity_signal_with(
                libc::SIGTERM,
                &|_| true,
                || Ok(()),
                || Ok(22),
                || Ok("/fc".into()),
                |_, signal| {
                    if signal == 0 {
                        Ok(true)
                    } else {
                        Err(std::io::Error::from_raw_os_error(errno))
                    }
                },
            );
            if errno == libc::ESRCH {
                assert_eq!(result.unwrap(), GuardedSignal::Exited);
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        }
        assert_eq!(
            signal_if_identity(42, 0, &|_| true).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn identity_callback_rejects_missing_or_mismatched_recorded_starttime() {
        for expected in [None, Some(21), Some(22)] {
            let sent = std::cell::Cell::new(false);
            let result = identity_signal_with(
                libc::SIGTERM,
                &|exe| exe == Path::new("/fc") && expected == Some(22),
                || Ok(()),
                || Ok(22),
                || Ok("/fc".into()),
                |_, signal| {
                    if signal != 0 {
                        sent.set(true);
                    }
                    Ok(true)
                },
            )
            .unwrap();
            assert_eq!(sent.get(), expected == Some(22));
            assert_eq!(
                result,
                if expected == Some(22) {
                    GuardedSignal::Sent
                } else {
                    GuardedSignal::Refused(Some("/fc".into()))
                }
            );
        }
    }

    #[test]
    fn identity_inspection_failure_is_not_silent_success() {
        for errno in [libc::ENOENT, libc::EACCES] {
            let result = identity_signal_with(
                libc::SIGTERM,
                &|_| panic!("inspection failed"),
                || Ok(()),
                || Err(std::io::Error::from_raw_os_error(errno)),
                || panic!("inspection failed"),
                |_, _| panic!("inspection failed"),
            );
            if errno == libc::ENOENT {
                assert_eq!(result.unwrap(), GuardedSignal::Exited);
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn identity_signal_is_unsupported_without_linux_pidfds() {
        assert_eq!(
            signal_if_identity(42, libc::SIGTERM, &|_| panic!("no pidfd"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }

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

    #[test]
    fn pid_liveness_reserved_pids_never_reach_probes() {
        for pid in [-1, 0, 1] {
            assert!(!pid_is_alive_with_probes(
                pid,
                |_| panic!("reserved PID reached zombie probe"),
                |_| panic!("reserved PID reached signal probe"),
            ));
        }
    }

    #[test]
    fn pid_liveness_known_zombie_never_reaches_signal_probe() {
        assert!(!pid_is_alive_with_probes(
            42,
            |pid| {
                assert_eq!(pid, 42);
                true
            },
            |_| panic!("known zombie reached signal probe"),
        ));
    }

    #[test]
    fn pid_liveness_successful_probe_reports_alive() {
        let calls = std::cell::RefCell::new(Vec::new());
        assert!(pid_is_alive_with_probes(
            42,
            |_| {
                calls.borrow_mut().push("zombie");
                false
            },
            |_| {
                calls.borrow_mut().push("signal");
                (0, None)
            },
        ));
        assert_eq!(calls.into_inner(), vec!["zombie", "signal"]);
    }

    #[test]
    fn pid_liveness_permission_protected_process_is_alive_with_ordered_probes() {
        let calls = std::cell::RefCell::new(Vec::new());
        assert!(pid_is_alive_with_probes(
            42,
            |pid| {
                assert_eq!(pid, 42);
                calls.borrow_mut().push("zombie");
                false
            },
            |pid| {
                assert_eq!(pid, 42);
                calls.borrow_mut().push("signal");
                (-1, Some(libc::EPERM))
            },
        ));
        assert_eq!(calls.into_inner(), vec!["zombie", "signal"]);
    }

    #[test]
    fn pid_liveness_missing_and_other_errors_preserve_policy() {
        for error in [
            Some(libc::ESRCH),
            Some(libc::EINVAL),
            Some(libc::EACCES),
            Some(libc::EIO),
            None,
        ] {
            let calls = std::cell::RefCell::new(Vec::new());
            assert!(!pid_is_alive_with_probes(
                42,
                |_| {
                    calls.borrow_mut().push("zombie");
                    false
                },
                |_| {
                    calls.borrow_mut().push("signal");
                    (-1, error)
                },
            ));
            assert_eq!(calls.into_inner(), vec!["zombie", "signal"]);
        }
    }
}
