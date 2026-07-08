//! Ctrl-C (SIGINT) handling without the `ctrlc` crate.
//!
//! `ctrlc` pulled a small subtree (`nix`, `dispatch2`, `block2`, …) for what is
//! two call-sites here. The handlers do real teardown (kill child pids, stop the
//! transient VM) — work that is **not** async-signal-safe — so we use the
//! standard self-pipe trick: the installed signal handler does nothing but
//! `write()` one byte to a pipe (async-signal-safe), and a dedicated thread
//! reads the pipe and runs the caller's closure in normal context. Only the
//! first install wins, mirroring `ctrlc::set_handler`'s single-handler contract.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Write end of the self-pipe, read by the servicing thread. Set once at install.
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Enforces the single-handler contract (second install returns `AlreadyExists`).
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// The installed SIGINT disposition: only ever writes one byte to the self-pipe.
/// Everything here must be async-signal-safe — `write` is; nothing else runs.
extern "C" fn on_sigint(_: libc::c_int) {
    let fd = WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: `write` is async-signal-safe; a partial/failed write has
        // nothing safe to recover to inside a signal handler, so ignore it.
        unsafe {
            libc::write(fd, std::ptr::addr_of!(byte) as *const libc::c_void, 1);
        }
    }
}

/// Run `handler` on each Ctrl-C (SIGINT). Drop-in for `ctrlc::set_handler`:
/// the first call installs; later calls return `io::ErrorKind::AlreadyExists`.
pub fn set_ctrlc_handler<F>(handler: F) -> io::Result<()>
where
    F: FnMut() + Send + 'static,
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
    // SAFETY: install the minimal, async-signal-safe handler above for SIGINT.
    unsafe {
        let h = on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t;
        if libc::signal(libc::SIGINT, h) == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    spawn_servicer(read_fd, handler)
}

/// Spawn the thread that turns self-pipe bytes into `handler` calls in normal
/// context. Split out from signal installation so the mechanism is testable
/// without raising signals: write a byte to the pipe, assert `handler` runs.
fn spawn_servicer<F>(read_fd: libc::c_int, mut handler: F) -> io::Result<()>
where
    F: FnMut() + Send + 'static,
{
    std::thread::Builder::new()
        .name("ctrlc".into())
        .spawn(move || {
            let mut buf = [0u8; 1];
            loop {
                // SAFETY: blocking read on the pipe's read end.
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
                if n > 0 {
                    handler();
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
        spawn_servicer(read_fd, move || {
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
}
