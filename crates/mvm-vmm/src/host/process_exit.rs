//! Event-driven observation of a host process exiting.
//!
//! The observer is only an observation primitive. Callers still own signal
//! delivery, deadlines, process identity checks, and final cleanup. When the
//! platform cannot provide a safe process-exit handle, callers must retain
//! their bounded polling fallback.

use std::fmt::{Display, Formatter};
use std::io;
use std::time::Instant;

/// Result of waiting for an armed process-exit observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExitWait {
    /// The operating system reported that the watched process exited.
    Exited,
    /// The deadline elapsed without an exit event.
    TimedOut,
}

/// Why an exit observer could not be armed or waited.
#[derive(Debug)]
pub enum ProcessExitError {
    /// This platform or kernel does not expose the required primitive.
    Unsupported,
    /// The operating system rejected an observer operation.
    Io(io::Error),
    /// An exit event arrived, but final liveness verification did not prove
    /// that the recorded process ID is gone.
    VerificationFailed,
    /// The supplied PID is not a valid supervisor PID.
    InvalidPid(libc::pid_t),
}

impl Display for ProcessExitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("process exit observation is unsupported"),
            Self::Io(error) => write!(formatter, "process exit observation failed: {error}"),
            Self::VerificationFailed => {
                formatter.write_str("process exit observation failed verification")
            }
            Self::InvalidPid(pid) => {
                write!(formatter, "invalid process id for exit observation: {pid}")
            }
        }
    }
}

impl std::error::Error for ProcessExitError {}

/// A process-exit observer armed before a termination signal is delivered.
#[derive(Debug)]
pub struct ProcessExitObserver {
    pid: libc::pid_t,
    kind: ObserverKind,
}

#[derive(Debug)]
enum ObserverKind {
    AlreadyExited,
    #[cfg(target_os = "macos")]
    Kqueue {
        fd: libc::c_int,
    },
    #[cfg(target_os = "linux")]
    PidFd {
        fd: libc::c_int,
    },
}

impl ProcessExitObserver {
    /// Arm an observer for `pid`.
    ///
    /// The registration happens before the caller sends SIGTERM, closing the
    /// race where a short-lived supervisor exits between signal delivery and
    /// observer setup. An already-dead PID returns an observer that reports
    /// [`ProcessExitWait::Exited`] immediately.
    pub fn arm(pid: libc::pid_t) -> Result<Self, ProcessExitError> {
        if pid <= 1 {
            return Err(ProcessExitError::InvalidPid(pid));
        }

        #[cfg(target_os = "macos")]
        {
            Self::arm_kqueue(pid)
        }

        #[cfg(target_os = "linux")]
        {
            Self::arm_pidfd(pid)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = pid;
            Err(ProcessExitError::Unsupported)
        }
    }

    /// Wait until the process-exit event arrives or `deadline` passes.
    pub fn wait(&self, deadline: Instant) -> Result<ProcessExitWait, ProcessExitError> {
        let outcome = match &self.kind {
            ObserverKind::AlreadyExited => ProcessExitWait::Exited,
            #[cfg(target_os = "macos")]
            ObserverKind::Kqueue { fd } => wait_kqueue(*fd, deadline)?,
            #[cfg(target_os = "linux")]
            ObserverKind::PidFd { fd } => wait_pidfd(*fd, deadline)?,
        };
        if outcome == ProcessExitWait::Exited && !process_is_dead(self.pid) {
            return Err(ProcessExitError::VerificationFailed);
        }
        Ok(outcome)
    }

    #[cfg(target_os = "macos")]
    fn arm_kqueue(pid: libc::pid_t) -> Result<Self, ProcessExitError> {
        // SAFETY: kqueue returns an owned descriptor and the kevent is fully
        // initialized before registration.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(ProcessExitError::Io(io::Error::last_os_error()));
        }

        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let mut receipt = std::mem::MaybeUninit::<libc::kevent>::uninit();
        // SAFETY: `fd` is a valid kqueue descriptor and the change/receipt
        // buffers are valid for the requested counts.
        let result =
            unsafe { libc::kevent(fd, &change, 1, receipt.as_mut_ptr(), 1, std::ptr::null()) };
        if result < 0 {
            close_fd(fd);
            return Err(ProcessExitError::Io(io::Error::last_os_error()));
        }
        // EV_RECEIPT returns one EV_ERROR record. ESRCH closes the registration
        // race by telling us the process exited before it could be watched.
        let receipt = unsafe { receipt.assume_init() };
        if receipt.flags & libc::EV_ERROR != 0 && receipt.data != 0 {
            let error = io::Error::from_raw_os_error(receipt.data as i32);
            close_fd(fd);
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(Self {
                    pid,
                    kind: ObserverKind::AlreadyExited,
                })
            } else {
                Err(ProcessExitError::Io(error))
            };
        }
        Ok(Self {
            pid,
            kind: ObserverKind::Kqueue { fd },
        })
    }

    #[cfg(target_os = "linux")]
    fn arm_pidfd(pid: libc::pid_t) -> Result<Self, ProcessExitError> {
        // SAFETY: pidfd_open is invoked with a validated PID and no flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return classify_pidfd_open_error(pid, io::Error::last_os_error());
        }
        let fd = libc::c_int::try_from(fd).map_err(|_| ProcessExitError::Unsupported)?;
        Ok(Self {
            pid,
            kind: ObserverKind::PidFd { fd },
        })
    }
}

#[cfg(target_os = "linux")]
fn classify_pidfd_open_error(
    pid: libc::pid_t,
    error: io::Error,
) -> Result<ProcessExitObserver, ProcessExitError> {
    match error.raw_os_error() {
        Some(error) if error == libc::ENOSYS || error == libc::EINVAL => {
            Err(ProcessExitError::Unsupported)
        }
        Some(libc::ESRCH) => Ok(ProcessExitObserver {
            pid,
            kind: ObserverKind::AlreadyExited,
        }),
        _ => Err(ProcessExitError::Io(error)),
    }
}

impl Drop for ProcessExitObserver {
    fn drop(&mut self) {
        match &self.kind {
            ObserverKind::AlreadyExited => {}
            #[cfg(target_os = "macos")]
            ObserverKind::Kqueue { fd } => close_fd(*fd),
            #[cfg(target_os = "linux")]
            ObserverKind::PidFd { fd } => close_fd(*fd),
        }
    }
}

/// Wait for a process-exit event, falling back to bounded adaptive polling when
/// the platform observer is unavailable or cannot verify the event.
///
/// The final liveness check is performed for both paths. A `true` result means
/// the recorded PID is no longer a live process; it does not merely mean that
/// an event or timeout occurred.
pub fn wait_for_pid_exit(
    pid: libc::pid_t,
    deadline: Instant,
    observer: Option<&ProcessExitObserver>,
) -> bool {
    if let Some(observer) = observer {
        match observer.wait(deadline) {
            Ok(ProcessExitWait::Exited) => return process_is_dead(pid),
            Ok(ProcessExitWait::TimedOut)
            | Err(ProcessExitError::Unsupported)
            | Err(ProcessExitError::Io(_))
            | Err(ProcessExitError::VerificationFailed)
            | Err(ProcessExitError::InvalidPid(_)) => {}
        }
    }

    let mut attempt = 0_u32;
    loop {
        if process_is_dead(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
}

#[cfg(target_os = "macos")]
fn wait_kqueue(fd: libc::c_int, deadline: Instant) -> Result<ProcessExitWait, ProcessExitError> {
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let timeout = libc::timespec {
            tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
            tv_nsec: timeout.subsec_nanos().into(),
        };
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        // SAFETY: `fd` is owned by the observer and the event buffer is valid.
        let result =
            unsafe { libc::kevent(fd, std::ptr::null(), 0, event.as_mut_ptr(), 1, &timeout) };
        if result > 0 {
            return Ok(ProcessExitWait::Exited);
        }
        if result == 0 {
            return Ok(ProcessExitWait::TimedOut);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline {
            continue;
        }
        return Err(ProcessExitError::Io(error));
    }
}

#[cfg(target_os = "linux")]
fn wait_pidfd(fd: libc::c_int, deadline: Instant) -> Result<ProcessExitWait, ProcessExitError> {
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pollfd points to one initialized descriptor and the
        // timeout is bounded to the platform's integer range.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            return Ok(ProcessExitWait::Exited);
        }
        if result == 0 {
            return Ok(ProcessExitWait::TimedOut);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline {
            continue;
        }
        return Err(ProcessExitError::Io(error));
    }
}

fn close_fd(fd: libc::c_int) {
    // SAFETY: every descriptor passed here was returned by kqueue or
    // pidfd_open and is owned by this observer.
    unsafe {
        libc::close(fd);
    }
}

fn process_is_dead(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: WNOHANG only reaps this process's child if it has exited. A
    // non-child PID falls through to the shared permission-aware liveness
    // probe, which is the correct path for detached supervisors.
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if waited == pid {
        return true;
    }
    if waited == 0 {
        return false;
    }
    !super::process_liveness::pid_is_alive(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn invalid_pid_is_rejected() {
        assert!(matches!(
            ProcessExitObserver::arm(1),
            Err(ProcessExitError::InvalidPid(1))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_maps_unsupported_kernel_errors() {
        for raw_error in [libc::ENOSYS, libc::EINVAL] {
            assert!(matches!(
                classify_pidfd_open_error(4242, io::Error::from_raw_os_error(raw_error)),
                Err(ProcessExitError::Unsupported)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_maps_a_missing_process_to_already_exited() {
        let observer = classify_pidfd_open_error(4242, io::Error::from_raw_os_error(libc::ESRCH))
            .expect("map a missing process");

        assert_eq!(observer.pid, 4242);
        assert!(matches!(observer.kind, ObserverKind::AlreadyExited));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_preserves_permission_failures() {
        let error = classify_pidfd_open_error(4242, io::Error::from_raw_os_error(libc::EPERM))
            .expect_err("permission denial must remain an I/O error");

        assert!(matches!(
            error,
            ProcessExitError::Io(error) if error.raw_os_error() == Some(libc::EPERM)
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn observer_reports_a_child_exit() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.05"])
            .spawn()
            .expect("spawn short-lived child");
        let observer = match ProcessExitObserver::arm(child.id() as libc::pid_t) {
            Ok(observer) => observer,
            Err(ProcessExitError::Unsupported) => {
                let _ = child.wait();
                return;
            }
            Err(error) => panic!("arm process observer: {error}"),
        };
        let outcome = observer
            .wait(Instant::now() + Duration::from_secs(2))
            .expect("wait for child exit");
        let _ = child.wait();
        assert_eq!(outcome, ProcessExitWait::Exited);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn observer_reports_an_already_dead_child() {
        let mut child = Command::new("true").spawn().expect("spawn child");
        child.wait().expect("reap child");
        match ProcessExitObserver::arm(child.id() as libc::pid_t) {
            Ok(observer) => assert_eq!(
                observer
                    .wait(Instant::now() + Duration::from_millis(1))
                    .expect("wait for dead child"),
                ProcessExitWait::Exited
            ),
            Err(ProcessExitError::Unsupported) => {}
            Err(error) => panic!("arm dead-child observer: {error}"),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn observer_reports_a_deadline_without_claiming_exit() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.2"])
            .spawn()
            .expect("spawn child");
        let observer =
            ProcessExitObserver::arm(child.id() as libc::pid_t).expect("arm child observer");
        let outcome = observer
            .wait(Instant::now() + Duration::from_millis(1))
            .expect("wait for timeout");
        assert_eq!(outcome, ProcessExitWait::TimedOut);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn observer_rejects_an_exit_event_that_fails_liveness_verification() {
        let observer = ProcessExitObserver {
            pid: std::process::id() as libc::pid_t,
            kind: ObserverKind::AlreadyExited,
        };
        assert!(matches!(
            observer.wait(Instant::now()),
            Err(ProcessExitError::VerificationFailed)
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn shared_wait_fallback_reports_a_child_exit() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.05"])
            .spawn()
            .expect("spawn short-lived child");
        let exited = wait_for_pid_exit(
            child.id() as libc::pid_t,
            Instant::now() + Duration::from_secs(2),
            None,
        );
        let _ = child.wait();
        assert!(exited);
    }
}
