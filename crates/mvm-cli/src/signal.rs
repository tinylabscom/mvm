//! Ctrl-C (SIGINT) and termination (SIGTERM, SIGHUP) handling without the
//! `ctrlc` crate.
//!
//! `ctrlc` pulled a small subtree (`nix`, `dispatch2`, `block2`, …) for what is
//! two call-sites here. The handlers do real teardown (kill child pids, stop the
//! transient VM) — work that is **not** async-signal-safe — so we use the
//! standard self-pipe trick: the installed signal handler does nothing but
//! `write()` one byte to a pipe (async-signal-safe), and a dedicated thread
//! reads the pipe and runs the caller's closure in normal context. Only the
//! first install wins, mirroring `ctrlc::set_handler`'s single-handler contract.
//!
//! SIGTERM and SIGHUP (a closed terminal) go through the same handler as
//! SIGINT, so the cleanup an interrupt runs also runs when `mvmctl` is asked to
//! terminate. The byte written to the pipe is the signal number, so the closure
//! can tell them apart. SIGKILL cannot be caught, and neither can an
//! out-of-memory kill.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Write end of the self-pipe, read by the servicing thread. Set once at install.
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Enforces the single-handler contract (second install returns `AlreadyExists`).
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// The signals routed through the handler.
pub const HANDLED_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The installed disposition: only ever writes one byte, the signal number, to
/// the self-pipe. Everything here must be async-signal-safe — `write` is;
/// nothing else runs.
extern "C" fn on_signal(signal: libc::c_int) {
    let fd = WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // Every handled signal number fits in a byte.
        let byte = signal as u8;
        // SAFETY: `write` is async-signal-safe; a partial/failed write has
        // nothing safe to recover to inside a signal handler, so ignore it.
        unsafe {
            libc::write(fd, std::ptr::addr_of!(byte) as *const libc::c_void, 1);
        }
    }
}

/// Run `handler` with the signal number on each SIGINT, SIGTERM or SIGHUP.
/// The first call installs; later calls return `io::ErrorKind::AlreadyExists`.
pub fn set_ctrlc_handler<F>(handler: F) -> io::Result<()>
where
    F: FnMut(libc::c_int) + Send + 'static,
{
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a Ctrl-C handler is already installed",
        ));
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe` writes two fds into the 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    WRITE_FD.store(write_fd, Ordering::SeqCst);
    install_dispositions()?;
    spawn_servicer(read_fd, handler)
}

/// Point every signal in [`HANDLED_SIGNALS`] at [`on_signal`].
fn install_dispositions() -> io::Result<()> {
    for signal in HANDLED_SIGNALS {
        // SAFETY: installs the minimal, async-signal-safe handler above.
        unsafe {
            let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            if libc::signal(signal, h) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Spawn the thread that turns self-pipe bytes into `handler` calls in normal
/// context. Split out from signal installation so the mechanism is testable
/// without raising signals: write a byte to the pipe, assert `handler` runs.
fn spawn_servicer<F>(read_fd: libc::c_int, mut handler: F) -> io::Result<()>
where
    F: FnMut(libc::c_int) + Send + 'static,
{
    std::thread::Builder::new()
        .name("ctrlc".into())
        .spawn(move || {
            let mut buf = [0u8; 1];
            loop {
                // SAFETY: blocking read on the pipe's read end.
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
                if n > 0 {
                    handler(libc::c_int::from(buf[0]));
                } else if n == 0 {
                    break; // write end closed
                } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break; // real error, stop servicing
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn servicer_runs_handler_per_pipe_byte() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let hits = Arc::new(AtomicI32::new(0));
        let h = hits.clone();
        spawn_servicer(read_fd, move |_| {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        for _ in 0..3 {
            let b = 1u8;
            assert_eq!(
                unsafe { libc::write(write_fd, std::ptr::addr_of!(b) as *const _, 1) },
                1
            );
        }
        // give the servicing thread time to drain the three bytes
        for _ in 0..100 {
            if hits.load(Ordering::SeqCst) == 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 3, "handler runs once per byte");
    }

    /// The servicing thread hands the handler the signal that arrived.
    #[test]
    fn servicer_passes_the_signal_number() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let seen = Arc::new(AtomicI32::new(0));
        let s = seen.clone();
        spawn_servicer(read_fd, move |signal| {
            s.store(signal, Ordering::SeqCst);
        })
        .unwrap();
        let byte = libc::SIGTERM as u8;
        assert_eq!(
            unsafe { libc::write(write_fd, std::ptr::addr_of!(byte) as *const _, 1) },
            1
        );
        for _ in 0..100 {
            if seen.load(Ordering::SeqCst) != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(seen.load(Ordering::SeqCst), libc::SIGTERM);
    }

    /// SIGTERM and SIGHUP are routed through the same handler as SIGINT. Run
    /// in a forked child, so the test process keeps its own dispositions.
    #[test]
    fn termination_signals_share_the_interrupt_handler() {
        // SAFETY: the child only installs dispositions, queries them, and
        // leaves with `_exit`; it never returns into the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            let installed = install_dispositions().is_ok()
                && HANDLED_SIGNALS.iter().all(|&signal| {
                    let mut current = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
                    // SAFETY: queries the disposition into a zeroed sigaction.
                    let ok =
                        unsafe { libc::sigaction(signal, std::ptr::null(), current.as_mut_ptr()) }
                            == 0;
                    // SAFETY: filled by the successful sigaction above.
                    ok && unsafe { current.assume_init() }.sa_sigaction
                        == on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t
                });
            // SAFETY: ends the forked child without running inherited handlers.
            unsafe { libc::_exit(if installed { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert_eq!(HANDLED_SIGNALS, [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
    }
}
