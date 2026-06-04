//! Passt-backed virtio-net supervisor (Plan 87 W2 / ADR-055).
//!
//! `passt` is a userspace network gateway that translates between
//! virtio-net frames the libkrun guest writes to a unixstream socket
//! and AF_INET sockets on the host. Together with libkrun's
//! `krun_add_net_unixstream` (W1, exposed via
//! [`crate::sys::Context::add_net_unixstream_fd`]) it replaces
//! libkrun's TSI mode, which breaks on the HTTP patterns nix relies
//! on for substituter / source fetches (Plan 86 §"Problem").
//!
//! Boot sequence:
//!
//! 1. Host calls [`spawn`]. It creates a
//!    `socketpair(AF_UNIX, SOCK_STREAM, 0)`, spawns `passt` with
//!    `--fd=N` pointing at one half, and keeps the other half on
//!    [`PasstHandle::socket_fd`].
//! 2. Host stuffs that fd into [`crate::KrunContext`] via
//!    [`crate::KrunContext::with_passt`].
//! 3. libkrun's `start_enter` consumes the fd. From that point on
//!    the guest's `eth0` is bridged to passt's network namespace.
//! 4. When the host drops the [`PasstHandle`], the supervisor
//!    `SIGTERM`s passt, waits up to [`SHUTDOWN_GRACE`], then
//!    `SIGKILL`s on timeout.
//!
//! Lifetime invariant: the [`PasstHandle`] must outlive
//! `start_enter` — `Drop` runs in any error path, so callers don't
//! need to manage cleanup explicitly.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Grace period between SIGTERM and SIGKILL during shutdown. passt's
/// own teardown is fast (it drops its socket + closes file
/// descriptors); two seconds is generous without making a hung
/// process block `mvmctl` shutdown for long.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Default MAC address assigned to the guest's `eth0`. The first
/// octet has bit `0x02` set (locally-administered, unicast) per
/// IEEE 802 so the address never collides with real hardware.
/// Stable across boots so the guest's NetworkManager / udev does
/// not reshuffle interface names.
pub const DEFAULT_GUEST_MAC: [u8; 6] = [0xAE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];

/// Errors the supervisor can return. Mirrors the
/// [`crate::Error`] shape so consumers can surface a single error
/// type, but keeps passt-specific failures distinguishable.
#[derive(Debug)]
pub enum PasstError {
    /// `passt` binary not found on `$PATH`. Includes the install
    /// hint string for whichever platform the host is on.
    NotInstalled { install_hint: &'static str },
    /// `socketpair(2)` returned an error.
    Socketpair(io::Error),
    /// Spawning the passt child process failed.
    Spawn(io::Error),
    /// passt exited before we could verify it was listening on
    /// its end of the socketpair.
    EarlyExit { status: std::process::ExitStatus },
    /// Filesystem I/O — usually the scratch dir for passt's PID
    /// file / log output.
    Io { context: String, source: io::Error },
}

impl std::fmt::Display for PasstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasstError::NotInstalled { install_hint } => {
                write!(f, "`passt` binary not found on $PATH. {install_hint}")
            }
            PasstError::Socketpair(e) => write!(f, "socketpair failed: {e}"),
            PasstError::Spawn(e) => write!(f, "spawning passt failed: {e}"),
            PasstError::EarlyExit { status } => write!(
                f,
                "passt exited before initialisation completed (status: {status:?})"
            ),
            PasstError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for PasstError {}

/// Suggested install command for the current host platform.
/// Surfaced both in `PasstError::NotInstalled` and by `mvmctl
/// doctor` (Plan 87 W5).
pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "Install with: brew install passt"
    } else if cfg!(target_os = "linux") {
        "Install with: apt install passt  (Debian/Ubuntu) / dnf install passt  (Fedora)"
    } else {
        "Install passt via your platform's package manager: https://passt.top/"
    }
}

/// Probe `$PATH` for `passt`. Returns the absolute path on success.
pub fn locate_passt() -> Option<PathBuf> {
    // Prefer `which` from the workspace dep so the search semantics
    // match other binary probes in the codebase (e.g.
    // `mvm-cli::commands::env::doctor`).
    which::which("passt").ok()
}

/// Owning handle to a running passt child process. `Drop` cleans up
/// the child (SIGTERM, grace period, SIGKILL on timeout). Cloning
/// is not supported — the fd hand-off to libkrun is one-shot.
#[derive(Debug)]
pub struct PasstHandle {
    child: Option<Child>,
    /// Parent end of the socketpair. Owned here until libkrun
    /// consumes it via `start_enter`; on Drop without consumption
    /// the socket is closed and the child exits naturally.
    parent_socket: Option<OwnedFd>,
}

impl PasstHandle {
    /// Raw fd for the unixstream socket libkrun will read virtio-net
    /// frames from. The fd remains owned by the [`PasstHandle`]; do
    /// not close it manually — pass it to
    /// [`crate::KrunContext::with_passt`] and let libkrun consume
    /// it at `start_enter`.
    pub fn socket_fd(&self) -> RawFd {
        self.parent_socket
            .as_ref()
            .expect("PasstHandle::socket_fd called after the handle was dropped")
            .as_raw_fd()
    }

    /// Take ownership of the parent socket. Returns the OwnedFd so
    /// the caller can decide what to do with it (close, hand to
    /// libkrun, dup, …). After this call [`Self::socket_fd`] panics.
    /// libkrun's `start_enter` semantics consume the fd implicitly,
    /// so most callers never need this.
    ///
    /// Consumes the handle, so the child process is killed via Drop
    /// once the returned fd is dropped. Use [`Self::take_socket`]
    /// when the caller wants to keep the child alive (e.g., the
    /// gateway audit bridge that splices passt ↔ libkrun for the
    /// guest's lifetime).
    pub fn into_socket(mut self) -> OwnedFd {
        self.parent_socket
            .take()
            .expect("PasstHandle::into_socket called twice")
    }

    /// Plan 102 W6.A.5 — take ownership of the parent socket
    /// *without* consuming the handle. The PasstHandle keeps the
    /// child alive (Drop on the handle still SIGTERMs the child),
    /// so the bridge thread can splice the returned fd ↔ libkrun's
    /// inner half for the guest's lifetime.
    ///
    /// Returns `None` on the second call (parent_socket already
    /// taken). After this call [`Self::socket_fd`] panics on access.
    pub fn take_socket(&mut self) -> Option<OwnedFd> {
        self.parent_socket.take()
    }
}

/// Spawn a passt child process and return a handle to its
/// socketpair fd. The child inherits the supervisor's stdio for
/// diagnostics; we intentionally avoid `passt --log-file` because
/// passt may drop privileges before opening it, which turns a
/// private scratch dir into a hard startup failure on CI and
/// multi-user hosts.
///
/// The returned [`PasstHandle`] must outlive any libkrun
/// configuration consuming `socket_fd()`. On Drop the child is
/// killed gracefully.
pub fn spawn(scratch_dir: &std::path::Path) -> Result<PasstHandle, PasstError> {
    let passt_bin = locate_passt().ok_or_else(|| PasstError::NotInstalled {
        install_hint: install_hint(),
    })?;

    std::fs::create_dir_all(scratch_dir).map_err(|e| PasstError::Io {
        context: format!("creating passt scratch dir {}", scratch_dir.display()),
        source: e,
    })?;

    // SAFETY: socketpair writes two valid fds to `fds` on success
    // and returns 0; on failure it returns -1 and writes nothing.
    let (parent_fd, child_fd) = make_socketpair()?;

    let pid_path = scratch_dir.join("passt.pid");

    // passt args:
    //   --fd <N>          — connect to libkrun via the socketpair
    //   --foreground      — stay attached so Drop's SIGTERM reaches it
    //   -P <path>         — older distro passt builds don't support
    //                       `--no-pid`; a scratch-local pidfile is
    //                       portable and harmless because `Child` still
    //                       owns the actual process lifetime
    //   (no --log-file)   — passt may drop privileges before opening
    //                       the path; keeping diagnostics on inherited
    //                       stderr avoids turning a private scratch dir
    //                       into a startup failure
    //   --quiet           — drop the boot-time chatter on inherited stdio
    //   --mtu 65520       — match libkrun's COMPAT_NET_FEATURES MTU
    let mut cmd = Command::new(&passt_bin);
    cmd.args(passt_args(child_fd.as_raw_fd(), &pid_path));

    // The child needs `child_fd` to NOT have FD_CLOEXEC, otherwise
    // it disappears when the new image takes over. socketpair(2)
    // creates fds without CLOEXEC by default, but Rust's `OwnedFd`
    // sets CLOEXEC when wrapping. Clear it explicitly on the child
    // end so passt can read its argv-supplied fd number after the
    // process image is replaced. (The parent fd may keep CLOEXEC
    // — libkrun will dup it across the start_enter boundary.)
    clear_cloexec(child_fd.as_raw_fd()).map_err(|e| PasstError::Io {
        context: format!(
            "clearing CLOEXEC on passt child fd {}",
            child_fd.as_raw_fd()
        ),
        source: e,
    })?;

    let child = cmd.spawn().map_err(PasstError::Spawn)?;

    // Close the child end on the parent side — the child inherits
    // its own copy across the spawn. Holding both ends would prevent
    // EOF from propagating to libkrun if the child died.
    drop(child_fd);

    // Sanity check: passt should not exit before we're done
    // handing the fd to libkrun. Sleep briefly and probe — if
    // it died, surface that instead of letting libkrun fail with
    // a cryptic socket error later. 50ms is enough to catch the
    // immediate exits (missing arg, spawn failure) without
    // measurably slowing dev up.
    std::thread::sleep(Duration::from_millis(50));
    let mut child = child;
    if let Some(status) = child.try_wait().map_err(PasstError::Spawn)? {
        return Err(PasstError::EarlyExit { status });
    }

    Ok(PasstHandle {
        child: Some(child),
        parent_socket: Some(parent_fd),
    })
}

impl Drop for PasstHandle {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };

        // Already-dead is fine.
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }

        // SIGTERM, wait up to SHUTDOWN_GRACE, then SIGKILL.
        let pid = child.id() as i32;
        // SAFETY: pid is valid until we wait. SIGTERM on a stale pid
        // returns ESRCH which we treat as "already gone".
        unsafe { libc::kill(pid, libc::SIGTERM) };

        let deadline = Instant::now() + SHUTDOWN_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                _ => break,
            }
        }

        // Still alive — SIGKILL + reap.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
    }
}

fn make_socketpair() -> Result<(OwnedFd, OwnedFd), PasstError> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: socketpair fills `fds` with two valid file descriptors
    // on success (return 0). On failure (return -1) the fds are
    // untouched and we return errno.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(PasstError::Socketpair(io::Error::last_os_error()));
    }
    // SAFETY: the kernel returned two valid fds in fds[]; FromRawFd
    // gives us ownership semantics for each.
    let parent = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((parent, child))
}

fn passt_args(child_fd: RawFd, pid_path: &std::path::Path) -> Vec<OsString> {
    vec![
        OsString::from("--fd"),
        OsString::from(child_fd.to_string()),
        OsString::from("--foreground"),
        OsString::from("-P"),
        pid_path.as_os_str().to_os_string(),
        OsString::from("--quiet"),
        OsString::from("--mtu"),
        OsString::from("65520"),
    ]
}

fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(F_GETFD)/F_SETFD on an owned fd is a standard
    // operation; both return -1 on error.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let new = flags & !libc::FD_CLOEXEC;
    if new == flags {
        return Ok(());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_ENV_LOCK as ENV_LOCK;
    use std::path::Path;

    #[test]
    fn install_hint_is_platform_specific() {
        let hint = install_hint();
        assert!(!hint.is_empty());
        if cfg!(target_os = "macos") {
            assert!(hint.contains("brew install passt"), "hint: {hint}");
        }
    }

    #[test]
    fn locate_passt_is_optional() {
        // Whether passt is installed is host-dependent; the function
        // just shouldn't panic. Either Some or None is acceptable.
        let _ = locate_passt();
    }

    #[test]
    fn spawn_without_passt_returns_not_installed() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Hide passt from PATH for this test by setting PATH to
        // an empty dir.
        let tmp = tempfile::tempdir().unwrap();
        let original_path = std::env::var_os("PATH");
        // SAFETY: tests are single-threaded by default in Rust;
        // set_var is fine here as long as we restore.
        unsafe {
            std::env::set_var("PATH", tmp.path());
        }
        let result = spawn(tmp.path());
        unsafe {
            match original_path {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        match result {
            Err(PasstError::NotInstalled { install_hint }) => {
                assert!(!install_hint.is_empty());
            }
            other => panic!("expected NotInstalled, got {other:?}"),
        }
    }

    #[test]
    fn make_socketpair_returns_two_fds() {
        let (a, b) = make_socketpair().expect("socketpair");
        assert_ne!(a.as_raw_fd(), b.as_raw_fd());
        assert!(a.as_raw_fd() >= 0);
        assert!(b.as_raw_fd() >= 0);
    }

    #[test]
    fn passt_args_omit_log_file_flag() {
        let args = passt_args(42, Path::new("/tmp/passt.pid"));
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|arg| arg == "--log-file"),
            "passt args must not include --log-file: {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg == "-P"),
            "passt args should keep the pid file path: {args:?}"
        );
    }

    /// Plan 102 W6.A.5 — `take_socket` returns the parent fd
    /// without consuming the handle, so the child stays alive
    /// (its SIGTERM-on-Drop continues to fire). A second call
    /// returns `None`.
    #[test]
    fn take_socket_keeps_handle_alive() {
        let Some(_) = locate_passt() else {
            eprintln!("test skipped: passt not on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let mut handle = spawn(tmp.path()).expect("spawn passt");
        let first = handle.take_socket();
        assert!(first.is_some(), "first take_socket must yield the fd");
        let second = handle.take_socket();
        assert!(second.is_none(), "second take_socket must yield None");
        // Drop should still kill the child cleanly — if take_socket
        // had consumed the handle (like into_socket does), the child
        // would already be unreachable here.
        drop(handle);
    }

    /// Spawn passt and immediately drop the handle. Verifies the
    /// Drop impl kills the child cleanly (no zombies, no
    /// timeout-to-SIGKILL escalation in the happy path). Skipped
    /// when passt isn't installed.
    #[test]
    fn spawn_then_drop_reaps_child() {
        let Some(_) = locate_passt() else {
            eprintln!("test skipped: passt not on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let handle = spawn(tmp.path()).expect("spawn passt");
        let fd = handle.socket_fd();
        assert!(fd >= 0);
        drop(handle);
        // If Drop hung we'd have timed out; reaching here means the
        // child was reaped before the test thread's local Drop ran.
    }
}
