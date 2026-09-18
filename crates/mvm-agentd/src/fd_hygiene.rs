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
/// duplicate the `pre_exec` safety boundary at every spawn site. Non-Linux
/// development hosts leave the command unchanged; workload guests are Linux.
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
    #[cfg(not(target_os = "linux"))]
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
#[cfg(target_os = "linux")]
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
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A descriptor cannot be numbered at or above the soft limit, so nothing
    // past it can be open. Capped so an unlimited setting is still a bounded
    // walk.
    let end = limit.rlim_cur.min(1 << 20).min(u64::from(high) + 1);
    for fd in u64::from(low)..end {
        // SAFETY: closing a descriptor number; EBADF for an unused one is
        // expected and ignored.
        unsafe {
            libc::close(fd as libc::c_int);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mark_range_close_on_exec(low: u32, high: u32) -> std::io::Result<()> {
    // SAFETY: `close_range` takes plain integers and touches no memory. With
    // `CLOSE_RANGE_CLOEXEC`, it updates descriptor flags without closing the
    // descriptors in the pre-exec process.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, low, high, libc::CLOSE_RANGE_CLOEXEC) };
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
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = limit.rlim_cur.min(1 << 20).min(u64::from(high) + 1);
    for fd in u64::from(low)..end {
        let fd = fd as libc::c_int;
        // SAFETY: both operations take a descriptor number and integer flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: `flags` came from F_GETFD for this same descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_executable_is_reported_without_losing_the_exec_error_pipe() {
        let mut command = Command::new("/definitely/not/a/real/executable");
        configure_close_fds(&mut command, 3, None);

        let error = command.status().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
