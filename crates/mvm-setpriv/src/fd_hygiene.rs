//! Preventing inherited descriptors from surviving a child exec.
//!
//! Close-on-exec is a property each descriptor has to be given when it is
//! created, and one that is missed anywhere leaks into every child spawned
//! afterwards. A child that should hold a known set of descriptors therefore
//! marks everything else close-on-exec in `pre_exec`, rather than trusting
//! every open call in the parent to have set the flag. Marking instead of
//! closing preserves the standard library's private exec-error pipe until the
//! exec attempt has either succeeded or reported its error to the parent.

use std::process::Command;

/// Configure a child command so every unintended descriptor closes atomically
/// when `execve(2)` succeeds.
///
/// The registered hook uses only raw syscalls, so callers do not have to
/// duplicate the `pre_exec` safety boundary at every spawn site. Hooks run in
/// registration order, so a hook registered after this one may still hand a
/// named descriptor on by `dup2` or by clearing its flag. Hosts other than
/// Linux and macOS leave the command unchanged.
pub fn configure_close_fds(command: &mut Command, first: u32, keep: Option<u32>) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        // SAFETY: the closure runs after fork and before exec, calls only the
        // async-signal-safe raw-syscall implementation below, and captures
        // only plain integers.
        unsafe {
            command.pre_exec(move || mark_descriptors_close_on_exec_from(first, keep));
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::CommandExt;

        // Allocated here, before the fork, because the child may not allocate.
        let mut open = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            LISTED_DESCRIPTORS
        ];
        // SAFETY: the closure runs after fork and before exec, calls only raw
        // syscalls, and writes only into the buffer it owns, allocated above.
        unsafe {
            command.pre_exec(move || mark_listed_close_on_exec(&mut open, first, keep));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (command, first, keep);
}

/// The inclusive descriptor ranges to close so that everything from `first`
/// upwards is closed except `keep`. Pure, so the arithmetic is tested on any
/// host.
pub fn ranges_to_close(first: u32, keep: Option<u32>) -> [Option<(u32, u32)>; 2] {
    match keep {
        Some(keep) if keep > first => [
            Some((first, keep - 1)),
            keep.checked_add(1).map(|n| (n, u32::MAX)),
        ],
        Some(keep) if keep == first => [keep.checked_add(1).map(|n| (n, u32::MAX)), None],
        _ => [Some((first, u32::MAX)), None],
    }
}

/// Close every descriptor from `first` upwards except `keep`.
///
/// Async-signal-safe: raw syscalls only, no allocation, so it may run in
/// `pre_exec`. Uses `close_range(2)`, and on kernels before 5.9, which lack it,
/// closes each descriptor up to the process's open-file limit.
#[cfg(target_os = "linux")]
pub fn close_descriptors_from(first: u32, keep: Option<u32>) -> std::io::Result<()> {
    for (low, high) in ranges_to_close(first, keep).into_iter().flatten() {
        close_range(low, high)?;
    }
    Ok(())
}

/// Mark every descriptor from `first` upwards close-on-exec except `keep`.
///
/// Async-signal-safe: raw syscalls only, no allocation, so it may run in
/// `pre_exec`. The descriptors remain open long enough for Rust's hidden
/// exec-error pipe to report a failed exec, but none survive a successful
/// image replacement.
#[cfg(unix)]
pub fn mark_descriptors_close_on_exec_from(first: u32, keep: Option<u32>) -> std::io::Result<()> {
    for (low, high) in ranges_to_close(first, keep).into_iter().flatten() {
        mark_range_close_on_exec(low, high)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_range(low: u32, high: u32) -> std::io::Result<()> {
    // SAFETY: `close_range` takes plain integers and touches no memory.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, low, high, 0u32) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOSYS) {
        return Err(error);
    }
    let end = descriptor_ceiling()?.min(u64::from(high) + 1);
    for fd in u64::from(low)..end {
        // SAFETY: closing a descriptor number; EBADF for an unused one is
        // expected and ignored.
        unsafe {
            libc::close(fd as libc::c_int);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn mark_range_close_on_exec(low: u32, high: u32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `close_range` takes plain integers and touches no memory.
        // With `CLOSE_RANGE_CLOEXEC`, it updates descriptor flags without
        // closing the descriptors in the pre-exec process.
        let rc =
            unsafe { libc::syscall(libc::SYS_close_range, low, high, libc::CLOSE_RANGE_CLOEXEC) };
        if rc == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL)
        ) {
            return Err(error);
        }
    }
    let end = descriptor_ceiling()?.min(u64::from(high) + 1);
    for fd in u64::from(low)..end {
        mark_close_on_exec(fd as libc::c_int)?;
    }
    Ok(())
}

/// Mark one descriptor close-on-exec; an unused number is not an error.
#[cfg(unix)]
fn mark_close_on_exec(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: both operations take a descriptor number and integer flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(());
        }
        return Err(error);
    }
    // SAFETY: `flags` came from F_GETFD for this same descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How many open descriptors the macOS fast path lists in one call. A process
/// holding more takes the complete walk instead.
#[cfg(target_os = "macos")]
const LISTED_DESCRIPTORS: usize = 1024;

/// [`mark_descriptors_close_on_exec_from`] for macOS, which has no
/// `close_range`: walking every number below the descriptor table size costs
/// hundreds of thousands of `fcntl` calls once the open-file limit is raised,
/// so this marks only the descriptors the kernel lists as open, into `open`.
/// A list that may have been cut short falls back to the complete walk.
///
/// Async-signal-safe: `proc_pidinfo` is a direct wrapper over the
/// `proc_info` system call, and nothing here allocates.
#[cfg(target_os = "macos")]
fn mark_listed_close_on_exec(
    open: &mut [libc::proc_fdinfo],
    first: u32,
    keep: Option<u32>,
) -> std::io::Result<()> {
    let capacity = libc::c_int::try_from(std::mem::size_of_val(open)).unwrap_or(0);
    // SAFETY: `open` is a writable buffer of exactly `capacity` bytes; the
    // kernel writes at most that many.
    let listed = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            open.as_mut_ptr().cast(),
            capacity,
        )
    };
    if listed <= 0 || listed >= capacity {
        return mark_descriptors_close_on_exec_from(first, keep);
    }
    let count = usize::try_from(listed).unwrap_or(0) / std::mem::size_of::<libc::proc_fdinfo>();
    for info in open.iter().take(count) {
        let Ok(fd) = u32::try_from(info.proc_fd) else {
            continue;
        };
        if fd >= first && Some(fd) != keep {
            mark_close_on_exec(info.proc_fd)?;
        }
    }
    Ok(())
}

/// One past the highest descriptor number this process can hold, capped so an
/// unlimited setting is still a bounded walk.
#[cfg(unix)]
fn descriptor_ceiling() -> std::io::Result<u64> {
    // On macOS the table is also bounded by the per-process kernel maximum,
    // which the soft limit alone may exceed.
    #[cfg(target_os = "macos")]
    // SAFETY: `getdtablesize` takes no arguments and cannot fail.
    let ceiling = u64::try_from(unsafe { libc::getdtablesize() }).unwrap_or(0);
    #[cfg(not(target_os = "macos"))]
    let ceiling = {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable `rlimit`.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // A descriptor cannot be numbered at or above the soft limit.
        limit.rlim_cur
    };
    Ok(ceiling.min(1 << 20))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_from_the_first_descriptor_is_closed_when_nothing_is_kept() {
        assert_eq!(ranges_to_close(4, None), [Some((4, u32::MAX)), None]);
    }

    #[test]
    fn a_kept_descriptor_splits_the_range_around_itself() {
        assert_eq!(
            ranges_to_close(4, Some(9)),
            [Some((4, 8)), Some((10, u32::MAX))]
        );
        assert_eq!(ranges_to_close(4, Some(4)), [Some((5, u32::MAX)), None]);
    }

    #[test]
    fn a_kept_descriptor_below_the_range_changes_nothing() {
        assert_eq!(ranges_to_close(4, Some(2)), [Some((4, u32::MAX)), None]);
    }

    #[test]
    fn the_highest_descriptor_can_be_kept() {
        assert_eq!(
            ranges_to_close(4, Some(u32::MAX)),
            [Some((4, u32::MAX - 1)), None]
        );
    }

    /// A descriptor the parent left inheritable, as a shell's `flock 9` is.
    #[cfg(unix)]
    fn inheritable_descriptor() -> std::fs::File {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: changes only the descriptor flags of a file this test owns.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        file
    }

    /// Whether a `/bin/sh` child built by `configure` holds `fd` open.
    #[cfg(unix)]
    fn child_holds(fd: &std::fs::File, configure: impl FnOnce(&mut Command)) -> bool {
        use std::os::fd::AsRawFd;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "[ -e /dev/fd/$1 ]", "sh", &fd.as_raw_fd().to_string()]);
        configure(&mut command);
        command.status().unwrap().success()
    }

    #[cfg(unix)]
    #[test]
    fn an_inheritable_descriptor_does_not_reach_a_configured_child() {
        let leaked = inheritable_descriptor();
        assert!(
            child_holds(&leaked, |_| {}),
            "control: an unconfigured child inherits it"
        );
        assert!(!child_holds(&leaked, |command| {
            configure_close_fds(command, 3, None)
        }));
    }

    /// A listing too large for its buffer may be cut short, so the macOS path
    /// takes the complete walk instead and still misses nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_overflowing_listing_falls_back_to_the_complete_walk() {
        use std::os::unix::process::CommandExt;
        let leaked = inheritable_descriptor();
        assert!(!child_holds(&leaked, |command| {
            let mut one = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                };
                1
            ];
            // SAFETY: the same async-signal-safe hook `configure_close_fds`
            // registers, over a buffer allocated before the fork.
            unsafe {
                command.pre_exec(move || mark_listed_close_on_exec(&mut one, 3, None));
            }
        }));
    }

    #[cfg(unix)]
    #[test]
    fn the_kept_descriptor_still_reaches_a_configured_child() {
        use std::os::fd::AsRawFd;
        let kept = inheritable_descriptor();
        let fd = u32::try_from(kept.as_raw_fd()).unwrap();
        assert!(child_holds(&kept, |command| {
            configure_close_fds(command, 3, Some(fd))
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_executable_is_reported_without_losing_the_exec_error_pipe() {
        let mut command = Command::new("/definitely/not/a/real/executable");
        configure_close_fds(&mut command, 3, None);

        let error = command.status().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
