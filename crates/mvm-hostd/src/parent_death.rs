//! Child-side parent-death watchdog for the host-side subprocess moat.
//!
//! The leaf moat bins (broker, host-signer, audit-signer, signer-helper,
//! substitution-endpoint) are each spawned by a supervisor and are useless the
//! instant that supervisor is gone. (`mvm-host-agent` deliberately opts out:
//! its worker is built to outlive a wrapper restart, so a getppid-based
//! self-reap would kill it mid-restart; instead the worker self-terminates via
//! the idle-registration watcher once it has had no VM registrations for the
//! configured timeout, with the age-based reaper as the long-tail backstop.)
//! The
//! supervisor attaches a parent-death signal on Linux at spawn time
//! (`PR_SET_PDEATHSIG`, see `supervisor::services::spawn`), but two gaps let a
//! helper leak as an orphan re-parented to init/launchd:
//!
//! - **macOS has no parent-side primitive.** A `Command` can only carry a
//!   `pre_exec` hook, and there is no Apple equivalent of `PR_SET_PDEATHSIG`,
//!   so the spawn-side attach is a documented no-op there. macOS is precisely
//!   where these orphans accumulate.
//! - **Abnormal supervisor death runs no teardown.** A `SIGKILL` (e.g. the
//!   `amfid` codesign kill that fells test binaries) or a panic-abort skips
//!   every `Drop`/atexit path the supervisor would use to reap its children.
//!
//! The fix is to make each helper defend *itself*: arm a watchdog inside its
//! own `main` that exits the moment its parent dies, regardless of how the
//! parent died. On Linux that re-arms `PR_SET_PDEATHSIG` (belt-and-suspenders
//! with the spawn-side attach, and the only attach at all when a test harness
//! spawns the bin directly). On macOS it runs a `kqueue` `NOTE_EXIT` watcher
//! thread, falling back to a `getppid` poll if `kqueue` setup fails.

/// Pid of init/launchd. A parent pid of `1` (or `0`) means this process has
/// been re-parented — its real parent is gone and it should exit.
const INIT_PID: libc::pid_t = 1;

/// Exit status used when the watchdog reaps an orphaned helper. Zero: the
/// supervisor that would observe a code is, by definition, already gone, and a
/// clean status keeps an in-between waiter (e.g. the host-agent worker-restart
/// loop) from treating an orphan exit as a crash to back off on.
const ORPHAN_EXIT_CODE: libc::c_int = 0;

/// Decide, from a parent pid, whether this process has been orphaned.
///
/// Pure so the orphan rule is unit-testable without forking.
fn orphaned(parent_pid: libc::pid_t) -> bool {
    parent_pid <= INIT_PID
}

/// Terminate immediately because the parent is gone.
///
/// Uses `_exit` rather than `std::process::exit` to skip Rust/atexit and tokio
/// teardown that could block on sockets whose far end (the dead supervisor) is
/// never coming back.
fn orphan_exit() -> ! {
    // SAFETY: `_exit` is async-signal-safe and never returns.
    unsafe { libc::_exit(ORPHAN_EXIT_CODE) }
}

/// Install the child-side parent-death watchdog. Call once, first thing in a
/// helper's `main`, before it blocks on stdin or binds its socket.
///
/// Idempotent in effect and best-effort: a watchdog that cannot arm leaves the
/// age-based reaper (`just reap-helpers`) as the backstop rather than failing
/// the helper.
pub fn exit_when_orphaned() {
    // SAFETY: `getppid` is async-signal-safe and infallible.
    let parent = unsafe { libc::getppid() };
    if orphaned(parent) {
        orphan_exit();
    }
    #[cfg(target_os = "linux")]
    arm_pdeathsig();
    #[cfg(not(target_os = "linux"))]
    spawn_parent_watcher(parent);
}

/// Linux: ask the kernel to signal us the instant our parent dies, then close
/// the fork/exec race where the parent died before we could arm.
#[cfg(target_os = "linux")]
fn arm_pdeathsig() {
    // SAFETY: `prctl`/`getppid` are infallible for these arguments; a failed
    // `prctl` only means we fall through to the orphan re-check.
    unsafe {
        let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong);
        if orphaned(libc::getppid()) {
            orphan_exit();
        }
    }
}

/// Non-Linux: watch the parent on a dedicated thread so the helper's tokio
/// runtime is untouched. If the thread cannot spawn, the reaper is the
/// backstop.
#[cfg(not(target_os = "linux"))]
fn spawn_parent_watcher(parent_pid: libc::pid_t) {
    let _ = std::thread::Builder::new()
        .name("parent-death".into())
        .spawn(move || watch_parent(parent_pid));
}

/// Block until the parent dies, then exit. Prefers `kqueue` `NOTE_EXIT` (no
/// idle wakeups for these long-lived helpers) and falls back to polling
/// `getppid` if `kqueue` setup fails.
#[cfg(not(target_os = "linux"))]
fn watch_parent(parent_pid: libc::pid_t) {
    #[cfg(target_os = "macos")]
    match block_until_parent_exit(parent_pid) {
        // The parent is gone (or was already gone): reap ourselves.
        ParentExit::Died => orphan_exit(),
        // kqueue could not arm; drop through to the portable poll.
        ParentExit::SetupFailed => {}
    }
    watch_parent_poll();
}

/// Outcome of the macOS `kqueue` watch, separated from the exit so the FFI is
/// testable without terminating the test process.
#[cfg(target_os = "macos")]
enum ParentExit {
    /// The parent exited (or had already exited before we could register).
    Died,
    /// `kqueue`/`kevent` setup failed; caller should fall back to polling.
    SetupFailed,
}

/// macOS: register `EVFILT_PROC`/`NOTE_EXIT` on the parent pid and block until
/// it fires. The `EV_RECEIPT` flag forces the registration to report its status
/// in-band, so a parent that died between `getppid` and here (errno `ESRCH`) is
/// reported as `Died` instead of blocking forever on a dead pid.
#[cfg(target_os = "macos")]
fn block_until_parent_exit(parent_pid: libc::pid_t) -> ParentExit {
    // SAFETY: textbook `kqueue`/`kevent` FFI; `kq` is closed before every
    // return and the `kevent` structs are fully initialised.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            return ParentExit::SetupFailed;
        }
        let change = libc::kevent {
            ident: parent_pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let mut receipt: libc::kevent = std::mem::zeroed();
        let n = libc::kevent(kq, &change, 1, &mut receipt, 1, std::ptr::null());
        if n < 0 {
            libc::close(kq);
            return ParentExit::SetupFailed;
        }
        // EV_RECEIPT always returns one EV_ERROR event; `data` is the errno
        // (0 = registered cleanly). A non-zero errno — ESRCH most likely —
        // means the parent is already gone.
        if n == 1 && (receipt.flags & libc::EV_ERROR) != 0 && receipt.data != 0 {
            libc::close(kq);
            return ParentExit::Died;
        }
        let mut event: libc::kevent = std::mem::zeroed();
        let n = libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null());
        libc::close(kq);
        if n < 0 {
            return ParentExit::SetupFailed;
        }
        ParentExit::Died
    }
}

/// Portable fallback: re-read `getppid` once a second and exit on reparent.
/// Latency to reap is bounded by the poll interval, which is irrelevant for
/// cleanup.
#[cfg(not(target_os = "linux"))]
fn watch_parent_poll() -> ! {
    loop {
        // SAFETY: `getppid` is infallible.
        if orphaned(unsafe { libc::getppid() }) {
            orphan_exit();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::orphaned;

    #[test]
    fn init_pid_is_orphaned() {
        assert!(orphaned(1));
    }

    #[test]
    fn zero_parent_is_orphaned() {
        // Defensive: a 0 from a surprising libc should fail safe to "orphaned".
        assert!(orphaned(0));
    }

    #[test]
    fn live_parent_is_not_orphaned() {
        assert!(!orphaned(2));
        assert!(!orphaned(42_000));
    }

    #[test]
    fn arming_with_a_live_parent_returns_without_exiting() {
        // The test runner is our live parent, so this must arm and return
        // (Linux prctl path / non-Linux watcher-thread spawn) without reaping
        // the test process. Reaching the assert proves it did not _exit.
        super::exit_when_orphaned();
        assert!(!orphaned(unsafe { libc::getppid() }));
    }

    // The macOS kqueue path is the one that actually closes the leak on this
    // platform, so exercise the real `EVFILT_PROC`/`NOTE_EXIT` FFI directly.
    // `block_until_parent_exit` returns its verdict instead of `_exit`ing, so
    // these run without killing the test process.
    #[cfg(target_os = "macos")]
    #[test]
    fn kqueue_detects_a_live_child_exiting() {
        use super::{ParentExit, block_until_parent_exit};
        use std::process::Command;

        let mut child = Command::new("sleep")
            .arg("0.3")
            .spawn()
            .expect("spawn `sleep`");
        let pid = child.id() as libc::pid_t;
        // Blocks on NOTE_EXIT until the short-lived child exits (~0.3s).
        let outcome = block_until_parent_exit(pid);
        let _ = child.wait();
        assert!(matches!(outcome, ParentExit::Died));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kqueue_treats_already_dead_pid_as_died() {
        use super::{ParentExit, block_until_parent_exit};
        use std::process::Command;

        let mut child = Command::new("true").spawn().expect("spawn `true`");
        let pid = child.id() as libc::pid_t;
        child.wait().expect("reap `true`"); // pid is now dead
        // Registering NOTE_EXIT on a dead pid yields ESRCH via EV_RECEIPT,
        // which must read as Died — never an infinite block on a stale pid.
        assert!(matches!(block_until_parent_exit(pid), ParentExit::Died));
    }
}
