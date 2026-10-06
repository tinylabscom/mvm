//! How a host helper process ended, worded for the operator who has to act on
//! it.
//!
//! The helpers that confine themselves with seccomp die by `SIGSYS` when their
//! filter refuses a system call. Reported as a bare status, or not reported at
//! all because the launcher only noticed a closed socket, that reads as a
//! transport failure two layers away from the cause. Naming the signal, and
//! what it means for a confined helper, is what turns it back into the
//! allowlist gap it is.

use std::fmt;
use std::time::{Duration, Instant};

/// The terminal state of a helper process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExit {
    /// The process called `exit` with this status.
    Code(i32),
    /// The process was terminated by this signal.
    Signal(i32),
}

impl HelperExit {
    /// Decode a `waitpid`-style status word.
    #[must_use]
    pub fn from_wait_status(status: libc::c_int) -> Self {
        if libc::WIFSIGNALED(status) {
            Self::Signal(libc::WTERMSIG(status))
        } else {
            Self::Code(libc::WEXITSTATUS(status))
        }
    }

    /// Decode a status `std::process::Child::wait` returned. `None` only for
    /// a status that is neither an exit nor a terminating signal, which a
    /// reaped process cannot have.
    #[must_use]
    pub fn from_exit_status(status: &std::process::ExitStatus) -> Option<Self> {
        use std::os::unix::process::ExitStatusExt as _;
        match (status.code(), status.signal()) {
            (Some(code), _) => Some(Self::Code(code)),
            (None, Some(signal)) => Some(Self::Signal(signal)),
            (None, None) => None,
        }
    }

    /// Whether this is the death a seccomp filter's trap action causes.
    #[must_use]
    pub fn is_seccomp_kill(&self) -> bool {
        *self == Self::Signal(libc::SIGSYS)
    }
}

impl fmt::Display for HelperExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Code(code) => write!(f, "exited with status {code}"),
            Self::Signal(signal) if signal == libc::SIGSYS => f.write_str(
                "was killed by SIGSYS: its seccomp filter refused a system call it made. \
                 The helper writes the refused call's number to its stderr before it dies; \
                 a legitimate call needs a reviewed allowlist entry",
            ),
            Self::Signal(signal) => match signal_name(signal) {
                Some(name) => write!(f, "was killed by signal {signal} ({name})"),
                None => write!(f, "was killed by signal {signal}"),
            },
        }
    }
}

fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGHUP => "SIGHUP",
        libc::SIGILL => "SIGILL",
        libc::SIGINT => "SIGINT",
        libc::SIGKILL => "SIGKILL",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGSYS => "SIGSYS",
        libc::SIGTERM => "SIGTERM",
        _ => return None,
    })
}

/// How a child of this process ended, if it has, read without reaping it.
///
/// `waitid(WNOWAIT)` leaves the zombie in place, so whoever owns the child's
/// handle can still wait for it, and a `kill(pid, 0)` liveness probe keeps
/// answering for it. That probe on its own is why a dead helper used to look
/// alive: a zombie answers `kill(pid, 0)`.
///
/// `None` when the child is still running, when `pid` is not a child of this
/// process (only a parent can read the status), or off Linux.
#[must_use]
pub fn peek_child_exit(pid: libc::pid_t) -> Option<HelperExit> {
    peek_child_exit_impl(pid)
}

#[cfg(target_os = "linux")]
fn peek_child_exit_impl(pid: libc::pid_t) -> Option<HelperExit> {
    if pid <= 0 {
        return None;
    }
    // SAFETY: an all-zero `siginfo_t` is a valid value; `waitid` fills it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-pointer for the duration of the call, and
    // WNOWAIT leaves the child waitable by its owner.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: `si_pid` is the field `waitid` sets for a child state change; it
    // stays zero when WNOHANG found the child still running.
    if rc != 0 || unsafe { info.si_pid() } != pid {
        return None;
    }
    // SAFETY: for a `waitid` result, `si_status` holds the exit status or the
    // terminating signal, as `si_code` says.
    let status = unsafe { info.si_status() };
    Some(match info.si_code {
        libc::CLD_EXITED => HelperExit::Code(status),
        _ => HelperExit::Signal(status),
    })
}

#[cfg(not(target_os = "linux"))]
fn peek_child_exit_impl(_pid: libc::pid_t) -> Option<HelperExit> {
    None
}

/// [`peek_child_exit`], retried for up to `within`.
///
/// For a caller that has just seen a helper's pipe close: the kernel closes
/// the descriptors before it marks the process exited, so the status may
/// trail the EOF by a moment.
#[must_use]
pub fn await_child_exit(pid: libc::pid_t, within: Duration) -> Option<HelperExit> {
    if !cfg!(target_os = "linux") {
        // Nothing to wait for: the status cannot be read on this host.
        return None;
    }
    let deadline = Instant::now() + within;
    loop {
        if let Some(exit) = peek_child_exit(pid) {
            return Some(exit);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seccomp_kill_names_the_filter_and_the_fix() {
        let exit = HelperExit::Signal(libc::SIGSYS);
        assert!(exit.is_seccomp_kill());
        let text = exit.to_string();
        assert!(text.contains("SIGSYS"), "{text}");
        assert!(text.contains("seccomp filter refused"), "{text}");
        assert!(text.contains("stderr"), "{text}");
    }

    #[test]
    fn other_endings_are_described_plainly() {
        assert_eq!(HelperExit::Code(3).to_string(), "exited with status 3");
        assert_eq!(
            HelperExit::Signal(libc::SIGKILL).to_string(),
            format!("was killed by signal {} (SIGKILL)", libc::SIGKILL)
        );
        assert!(!HelperExit::Signal(libc::SIGKILL).is_seccomp_kill());
        assert!(!HelperExit::Code(libc::SIGSYS).is_seccomp_kill());
    }

    #[test]
    fn wait_and_exit_statuses_decode_alike() {
        use std::os::unix::process::ExitStatusExt as _;
        let signalled = std::process::ExitStatus::from_raw(libc::SIGSYS);
        let exited = std::process::ExitStatus::from_raw(7 << 8);
        assert_eq!(
            HelperExit::from_exit_status(&signalled),
            Some(HelperExit::Signal(libc::SIGSYS))
        );
        assert_eq!(
            HelperExit::from_exit_status(&exited),
            Some(HelperExit::Code(7))
        );
        assert_eq!(
            HelperExit::from_wait_status(libc::SIGSYS),
            HelperExit::Signal(libc::SIGSYS)
        );
        assert_eq!(HelperExit::from_wait_status(7 << 8), HelperExit::Code(7));
    }

    #[test]
    fn a_process_that_is_not_our_child_has_no_status_to_read() {
        assert_eq!(peek_child_exit(std::process::id() as libc::pid_t), None);
        assert_eq!(peek_child_exit(0), None);
    }

    /// The case the launcher used to misread: a child killed by SIGSYS and
    /// never reaped still answers `kill(pid, 0)`, but its status is readable,
    /// and reading it leaves it for its owner to reap.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreaped_child_killed_by_sigsys_is_reported_without_being_reaped() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "kill -SYS $$"])
            .spawn()
            .expect("spawn sh");
        let pid = child.id() as libc::pid_t;
        let exit = await_child_exit(pid, Duration::from_secs(10));
        assert_eq!(exit, Some(HelperExit::Signal(libc::SIGSYS)));
        // SAFETY: signal 0 only probes existence.
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "still a zombie");
        let status = child.wait().expect("the owner can still reap it");
        assert_eq!(
            HelperExit::from_exit_status(&status),
            Some(HelperExit::Signal(libc::SIGSYS))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_child_has_no_exit_yet() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        assert_eq!(peek_child_exit(child.id() as libc::pid_t), None);
        let _ = child.kill();
        let _ = child.wait();
    }
}
