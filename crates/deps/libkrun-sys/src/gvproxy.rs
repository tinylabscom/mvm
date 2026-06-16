//! Gvproxy-backed virtio-net supervisor.
//!
//! `gvproxy` is a userspace network gateway (containers/gvisor-tap-vsock
//! project, Apache-2.0, single statically-linked binary) that translates
//! between virtio-net frames the libkrun guest writes to a unix-domain
//! socket and AF_INET sockets on the host. The slp/krun Homebrew tap
//! ships it as the canonical macOS networking backend for libkrun,
//! filling the role passt fills on Linux (passt itself doesn't build on
//! macOS).
//!
//! The integration model differs from passt:
//!
//! - passt: parent creates a socketpair, hands one end to passt via
//!   `--fd=N`, keeps the other end; libkrun consumes the parent end.
//! - gvproxy: gvproxy itself creates a listening unix-domain socket
//!   when invoked with `--listen-vfkit <path>`; libkrun connects to
//!   that path via `krun_add_net_unixgram(ctx, c_path, fd=-1, …)`.
//!
//! Boot sequence:
//!
//! 1. Host calls [`spawn`]. It picks a socket path under the
//!    scratch dir, spawns `gvproxy --listen-vfkit <socket>
//!    --log-file <log>`, then polls for the socket file to appear
//!    (gvproxy creates it ~tens of ms after spawn).
//! 2. Host stuffs the socket path into [`crate::KrunContext`] via
//!    [`crate::KrunContext::with_gvproxy`].
//! 3. libkrun's `start_enter` opens the socket and consumes the
//!    virtio-net frames.
//! 4. When the host drops the [`GvproxyHandle`], the supervisor
//!    `SIGTERM`s gvproxy, waits up to [`SHUTDOWN_GRACE`], then
//!    `SIGKILL`s.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// File name of gvproxy's PID sidecar under the per-VM scratch dir.
/// Lets [`reap_by_pid_file`] (and `mvmctl cache prune`) reap a gvproxy
/// the in-process [`GvproxyHandle::drop`] missed — which is the common
/// case on the libkrun lane, where `krun_start_enter` calls `exit()`
/// on guest shutdown and the stack never unwinds (so Drop never runs).
pub const PID_FILE_NAME: &str = "gvproxy.pid";

/// PID of the gvproxy this process most recently spawned, or 0 if
/// none. Set by [`spawn`], cleared by [`GvproxyHandle::drop`]. Read by
/// the libkrun supervisor's `SIGTERM` handler (an `extern "C"` signal
/// handler that can't capture state) so it can SIGTERM gvproxy before
/// `_exit` — otherwise `mvmctl stop` / `kill` orphans it. One gvproxy
/// per supervisor process (one VM per supervisor), so a single slot is
/// enough.
pub static RUNNING_GVPROXY_PID: AtomicI32 = AtomicI32::new(0);

/// Grace period between SIGTERM and SIGKILL during shutdown. Matches
/// the [`crate::passt::SHUTDOWN_GRACE`] knob so both backends behave
/// the same way under cleanup pressure.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How long [`spawn`] waits for gvproxy's listener socket to appear
/// on disk. gvproxy creates the file within ~tens of milliseconds on
/// macOS Apple Silicon (no `bind(2)` blocking). 500ms is generous
/// without measurably slowing `dev up`.
pub const SOCKET_READY_TIMEOUT: Duration = Duration::from_millis(500);

/// Default MAC for the guest's `eth0`. Locally-administered (bit
/// `0x02` set), unicast, stable across boots. Matches
/// [`crate::passt::DEFAULT_GUEST_MAC`] so the in-guest udev rules
/// don't reshuffle the interface name when a contributor switches
/// between backends.
pub const DEFAULT_GUEST_MAC: [u8; 6] = [0xAE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];

/// Errors the supervisor can return.
#[derive(Debug)]
pub enum GvproxyError {
    /// `gvproxy` binary not found on `$PATH`.
    NotInstalled { install_hint: &'static str },
    /// Spawning the gvproxy child process failed.
    Spawn(io::Error),
    /// gvproxy exited before the listener socket appeared on disk.
    /// `stdio_log` is the capture file holding gvproxy's pre-listener
    /// stdout/stderr (the reason it bailed lives there, not in
    /// `-log-file`, which gvproxy opens only after arg-parse).
    EarlyExit {
        status: std::process::ExitStatus,
        stdio_log: PathBuf,
    },
    /// `SOCKET_READY_TIMEOUT` elapsed without gvproxy creating its
    /// listener socket. Typically a permission issue on the scratch
    /// dir or a fatal error gvproxy logged before listening.
    SocketTimeout { socket_path: PathBuf },
    /// Filesystem I/O failure (scratch dir create, etc.).
    Io { context: String, source: io::Error },
}

impl std::fmt::Display for GvproxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GvproxyError::NotInstalled { install_hint } => {
                write!(f, "`gvproxy` binary not found on $PATH. {install_hint}")
            }
            GvproxyError::Spawn(e) => write!(f, "spawning gvproxy failed: {e}"),
            GvproxyError::EarlyExit { status, stdio_log } => write!(
                f,
                "gvproxy exited before its listener socket appeared (status: {status:?}); \
                 see {}",
                stdio_log.display()
            ),
            GvproxyError::SocketTimeout { socket_path } => write!(
                f,
                "gvproxy did not create its listener socket at {} within {} ms",
                socket_path.display(),
                SOCKET_READY_TIMEOUT.as_millis()
            ),
            GvproxyError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for GvproxyError {}

/// Suggested install command for the current host platform. Surfaced
/// both in `GvproxyError::NotInstalled` and `mvmctl doctor`.
pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        // slp/krun is the same tap that ships libkrun + libkrunfw, so
        // pointing at it keeps the doc story consistent.
        "Install with: brew install slp/krun/gvproxy"
    } else if cfg!(target_os = "linux") {
        // Most distros don't package gvproxy. Building from source is
        // a single `go build` against
        // github.com/containers/gvisor-tap-vsock.
        "Install from source: https://github.com/containers/gvisor-tap-vsock"
    } else {
        "Install gvproxy: https://github.com/containers/gvisor-tap-vsock"
    }
}

/// Locate the host-side vfkit gateway binary to spawn.
///
/// `MVM_GATEWAY_BIN`, when set to a non-empty value, overrides the
/// default — the seam for running an alternate gateway that speaks the
/// same `-listen-vfkit` unixgram protocol gvproxy does (the in-house
/// native gateway, selected via `MVM_NETWORKING=native`). The path is
/// used verbatim; a bad path surfaces as a clear spawn error rather
/// than silently falling back to `gvproxy`. Unset → probe `$PATH` for
/// `gvproxy`.
pub fn locate_gvproxy() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("MVM_GATEWAY_BIN")
        && !bin.is_empty()
    {
        return Some(PathBuf::from(bin));
    }
    which::which("gvproxy").ok()
}

/// Reserve a free TCP port on loopback for gvproxy's mandatory
/// SSH-forward listener by letting the OS assign one.
///
/// gvproxy's `-ssh-port` arg is *mandatory* (default 2222) and
/// gvproxy binds it on every start. mvm never uses the SSH forward
/// (no SSH in microVMs, ever) but gvproxy refuses to disable it
/// (`-ssh-port` validates to 1024..=65535), so we have to hand it a
/// port we don't care about.
///
/// We bind `127.0.0.1:0`, read back the ephemeral port the kernel
/// picked, and immediately drop the listener so gvproxy can claim
/// it. This is collision-proof in the way a deterministic
/// scratch-dir hash is *not*: the OS never hands out a port already
/// in `LISTEN`, so a leaked gvproxy from a prior run (libkrun's
/// `krun_start_enter` `exit()`s on guest shutdown and skips
/// `GvproxyHandle::Drop`, so daemons routinely outlive their VM) or
/// a concurrent VM reusing the same scratch dir can't steal the
/// port out from under us. An earlier deterministic-hash scheme
/// collided exactly this way — a re-run reusing `~/.mvm/vms/<name>/`
/// derived the same port a still-bound leaked daemon already held,
/// and gvproxy bailed with `bind: address already in use`.
///
/// The bind→read→close → gvproxy-bind window is a microsecond-scale
/// TOCTOU that another process could in principle race, but a closed
/// listener that never accepted a connection frees its port
/// immediately (no `TIME_WAIT`), so in practice gvproxy reclaims it
/// before anything else does.
pub fn free_loopback_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    // Listener drops here, freeing the port for gvproxy to bind.
    Ok(port)
}

/// Owning handle to a running gvproxy child process. `Drop` cleans up
/// the child the same way [`crate::passt::PasstHandle::drop`] does:
/// SIGTERM → grace period → SIGKILL → reap.
#[derive(Debug)]
pub struct GvproxyHandle {
    child: Option<Child>,
    socket_path: PathBuf,
    pid_path: PathBuf,
}

impl GvproxyHandle {
    /// Path to the unix-domain socket gvproxy listens on. Hand this
    /// to [`crate::KrunContext::with_gvproxy`] (or directly to
    /// `crate::sys::Context::add_net_unixgram_path` for advanced
    /// callers).
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Spawn a gvproxy child process and return a handle to its listener
/// socket path. The child logs to `scratch_dir/gvproxy.log`.
///
/// The returned [`GvproxyHandle`] must outlive any libkrun
/// configuration referencing `socket_path()`. On Drop the child is
/// killed gracefully and the socket file is deleted (best-effort —
/// libkrun may have already consumed it).
pub fn spawn(scratch_dir: &Path) -> Result<GvproxyHandle, GvproxyError> {
    let gvproxy_bin = locate_gvproxy().ok_or_else(|| GvproxyError::NotInstalled {
        install_hint: install_hint(),
    })?;

    std::fs::create_dir_all(scratch_dir).map_err(|e| GvproxyError::Io {
        context: format!("creating gvproxy scratch dir {}", scratch_dir.display()),
        source: e,
    })?;

    let socket_path = scratch_dir.join("gvproxy.sock");
    let log_path = scratch_dir.join("gvproxy.log");

    // Reap a gvproxy leaked into this exact scratch dir by a prior run
    // before we touch its socket/pid files. Persistent dirs (`dev` /
    // named VMs) get reused, so a leaked daemon could still be bound
    // here; ephemeral builder-VM dirs are timestamped so this is
    // usually a no-op. Either way it keeps the socket pre-unlink below
    // honest.
    reap_by_pid_file(scratch_dir);

    // Remove a stale socket from a previous run before spawning —
    // gvproxy refuses to bind if the file exists.
    let _ = std::fs::remove_file(&socket_path);

    // gvproxy args we care about:
    //   -listen-vfkit <path> — unix-domain socket libkrun connects to
    //                          via `krun_add_net_unixgram`. "vfkit"
    //                          mode is the libkrun-compatible one.
    //   -log-file <path>     — diagnostic log; absent → stderr (lost
    //                          when we redirect to /dev/null).
    //   -ssh-port <port>     — gvproxy always binds a TCP listener for
    //                          guest-SSH forwarding (default 2222). On
    //                          a host running more than one gvproxy
    //                          (concurrent dev VMs, parallel tests,
    //                          debugging cycles), instance N+1 fails
    //                          to bind 2222 and exits immediately
    //                          with `address already in use`. Hand it
    //                          a fresh OS-assigned free port so no two
    //                          instances — including leaked daemons —
    //                          collide (see `free_loopback_port`).
    //   -debug               — verbose logging. Not set by default;
    //                          if a future MVM_GVPROXY_DEBUG=1 env
    //                          var trips this we'd flip it here.
    // gvproxy expects the `-listen-vfkit` arg as a URL —
    // `unixgram://<path>`. A bare path errors out with
    // "vfkit listen address must be unixgram:// address" before the
    // listener is created. The libkrun-end of the socket connects
    // to the absolute path; the URL prefix only carries the scheme.
    let listen_url = {
        let mut s = OsString::from("unixgram://");
        s.push(socket_path.as_os_str());
        s
    };
    let ssh_port = free_loopback_port().map_err(|e| GvproxyError::Io {
        context: "reserving a free port for gvproxy's ssh-forward listener".to_string(),
        source: e,
    })?;

    // NEVER inherit the spawner's stdout/stderr. gvproxy is a long-lived
    // daemon; if it holds a write end of the parent's stdout/stderr pipe,
    // any ancestor reading that pipe to EOF (e.g. a test driving `mvmctl`
    // via `Command::output()`) blocks forever — gvproxy keeps the pipe
    // open for the life of the VM (and beyond, since libkrun's exit() on
    // guest shutdown skips `GvproxyHandle::Drop`, orphaning it). That fd
    // inheritance is exactly what hung `core_demo_e2e`: `dev up`'s build
    // VM powered down, mvmctl exited, but the orphaned gvproxy held the
    // pipe so `output()` never saw EOF.
    //
    // Redirect both streams to a per-VM capture file instead. This still
    // preserves the visibility that motivated the old `inherit()`:
    // gvproxy's pre-listener failures (arg-parse, "bind: address already
    // in use" on the SSH-forward port) go to stderr *before* `-log-file`
    // is opened, so they'd be lost to /dev/null — the capture file keeps
    // them on disk next to the listener log.
    let stdio_log_path = scratch_dir.join("gvproxy-stdio.log");
    let stdio_log = std::fs::File::create(&stdio_log_path).map_err(|e| GvproxyError::Io {
        context: format!(
            "creating gvproxy stdio capture {}",
            stdio_log_path.display()
        ),
        source: e,
    })?;
    let stdio_log_err = stdio_log.try_clone().map_err(|e| GvproxyError::Io {
        context: format!("cloning gvproxy stdio capture {}", stdio_log_path.display()),
        source: e,
    })?;
    let mut cmd = Command::new(&gvproxy_bin);
    cmd.arg("-listen-vfkit")
        .arg(listen_url)
        .arg("-log-file")
        .arg(OsString::from(&log_path))
        .arg("-ssh-port")
        .arg(ssh_port.to_string())
        .stdout(std::process::Stdio::from(stdio_log))
        .stderr(std::process::Stdio::from(stdio_log_err));

    let mut child = cmd.spawn().map_err(GvproxyError::Spawn)?;

    // Record the pid before the poll loop: the SIGTERM handler reaps
    // whatever `RUNNING_GVPROXY_PID` names, and `reap_by_pid_file`
    // needs the sidecar even if we die mid-poll.
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    RUNNING_GVPROXY_PID.store(child.id() as i32, Ordering::SeqCst);
    let _ = std::fs::write(&pid_path, child.id().to_string());

    // Poll for the socket to appear, with a bounded budget. gvproxy
    // creates the file synchronously inside its main loop on startup,
    // so this should resolve within ~tens of ms. We also re-check
    // `try_wait()` every iteration so an early exit (missing arg,
    // permission denied, etc.) surfaces immediately instead of as
    // a SocketTimeout.
    let deadline = Instant::now() + SOCKET_READY_TIMEOUT;
    loop {
        if socket_path.exists() {
            return Ok(GvproxyHandle {
                child: Some(child),
                socket_path,
                pid_path,
            });
        }
        if let Some(status) = child.try_wait().map_err(GvproxyError::Spawn)? {
            // gvproxy is gone; clear the records so a later reaper / the
            // next spawn doesn't chase a dead (or recycled) pid.
            RUNNING_GVPROXY_PID.store(0, Ordering::SeqCst);
            let _ = std::fs::remove_file(&pid_path);
            return Err(GvproxyError::EarlyExit {
                status,
                stdio_log: stdio_log_path,
            });
        }
        if Instant::now() >= deadline {
            // Kill the still-running child before bailing — leaking it
            // would block whatever the caller does next.
            let _ = child.kill();
            let _ = child.wait();
            RUNNING_GVPROXY_PID.store(0, Ordering::SeqCst);
            let _ = std::fs::remove_file(&pid_path);
            return Err(GvproxyError::SocketTimeout { socket_path });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl Drop for GvproxyHandle {
    fn drop(&mut self) {
        // Clear the global slot first — whether or not the child is
        // still alive, this handle is going away, so the SIGTERM
        // handler must stop referencing its pid.
        RUNNING_GVPROXY_PID.store(0, Ordering::SeqCst);

        let Some(mut child) = self.child.take() else {
            let _ = std::fs::remove_file(&self.pid_path);
            return;
        };

        // Already-dead is fine.
        if matches!(child.try_wait(), Ok(Some(_))) {
            let _ = std::fs::remove_file(&self.socket_path);
            let _ = std::fs::remove_file(&self.pid_path);
            return;
        }

        // SIGTERM → wait → SIGKILL.
        let pid = child.id() as i32;
        // SAFETY: pid is valid until we wait; SIGTERM on a stale pid
        // returns ESRCH which we treat as "already gone".
        unsafe { libc::kill(pid, libc::SIGTERM) };

        let deadline = Instant::now() + SHUTDOWN_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                _ => break,
            }
        }

        if matches!(child.try_wait(), Ok(None)) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = child.wait();
        }

        // Best-effort socket cleanup — if libkrun was holding the fd
        // open, the inode goes away when the last fd closes, but the
        // path entry remains. Removing it explicitly keeps
        // `~/.cache/mvm/builder-vm/vms/<vm>/` tidy.
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

/// SIGTERM (then SIGKILL) a gvproxy named by `<scratch_dir>/gvproxy.pid`,
/// then remove the sidecar + listener socket. Idempotent: a missing
/// or stale pid file, or an already-dead pid, is a clean no-op. This is
/// the reaper for gvproxy daemons the in-process [`GvproxyHandle::drop`]
/// never got to — the common libkrun case, where `krun_start_enter`
/// `exit()`s on guest shutdown without unwinding. Called pre-spawn (to
/// clear a dir's leftover) and by `mvmctl cache prune`.
pub fn reap_by_pid_file(scratch_dir: &Path) {
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    let pid: i32 = match std::fs::read_to_string(&pid_path) {
        Ok(s) => match s.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                let _ = std::fs::remove_file(&pid_path);
                return;
            }
        },
        Err(_) => return,
    };

    if pid_alive(pid) {
        // SAFETY: pid probed alive; SIGTERM on a since-exited pid races
        // to ESRCH, which is benign.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while pid_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        if pid_alive(pid) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(scratch_dir.join("gvproxy.sock"));
}

/// True if `pid` names a live process we can signal (`kill(pid, 0)`).
fn pid_alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn install_hint_is_platform_specific() {
        let hint = install_hint();
        assert!(!hint.is_empty());
        if cfg!(target_os = "macos") {
            assert!(hint.contains("brew install"), "hint: {hint}");
        }
    }

    #[test]
    fn locate_gvproxy_is_optional() {
        let _ = locate_gvproxy();
    }

    /// `MVM_GATEWAY_BIN` overrides the default `gvproxy` lookup — the seam an
    /// alternate vfkit gateway (the native gateway) is spawned through. An
    /// empty value is ignored so it falls back to the `$PATH` probe.
    #[test]
    fn locate_gvproxy_honors_gateway_bin_override() {
        let mut env = TestEnv::new();
        env.set("MVM_GATEWAY_BIN", "/opt/mvm/native-gateway");
        assert_eq!(
            locate_gvproxy(),
            Some(PathBuf::from("/opt/mvm/native-gateway")),
            "MVM_GATEWAY_BIN must override the default gvproxy lookup"
        );
        env.set("MVM_GATEWAY_BIN", "");
        // Empty → ignored; must not return an empty path.
        assert_ne!(locate_gvproxy(), Some(PathBuf::new()));
        env.remove("MVM_GATEWAY_BIN");
    }

    /// A reserved port is in gvproxy's accepted `-ssh-port` range
    /// (1024..=65535) and is actually free — we can rebind it after
    /// the reservation drops, which is exactly what gvproxy does.
    #[test]
    fn free_loopback_port_is_in_range_and_bindable() {
        let port = free_loopback_port().expect("reserve a free port");
        assert!(port >= 1024, "port {port} below gvproxy's 1024 floor");
        // The reservation listener is already dropped, so this rebind
        // models gvproxy claiming the port we handed it.
        let rebound = std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("reserved port is free to bind");
        drop(rebound);
    }

    #[test]
    fn spawn_without_gvproxy_returns_not_installed() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("PATH", tmp.path());
        let result = spawn(tmp.path());
        match result {
            Err(GvproxyError::NotInstalled { install_hint }) => {
                assert!(!install_hint.is_empty());
            }
            other => panic!("expected NotInstalled, got {other:?}"),
        }
    }

    /// Spawn gvproxy, verify the socket + pid sidecar + stdio capture
    /// exist and the global pid slot is set, then drop the handle and
    /// confirm everything is cleaned up. Skipped when gvproxy isn't
    /// installed.
    #[test]
    fn spawn_then_drop_reaps_child() {
        let Some(_) = locate_gvproxy() else {
            eprintln!("test skipped: gvproxy not on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let handle = spawn(tmp.path()).expect("spawn gvproxy");
        let socket = handle.socket_path().to_path_buf();
        let pid_file = tmp.path().join(PID_FILE_NAME);
        assert!(socket.exists(), "socket missing: {}", socket.display());
        assert!(pid_file.exists(), "pid sidecar missing");
        assert!(
            tmp.path().join("gvproxy-stdio.log").exists(),
            "stdio capture file missing — stdout/stderr were not redirected to it"
        );
        assert!(
            RUNNING_GVPROXY_PID.load(Ordering::SeqCst) > 0,
            "global gvproxy pid slot not set"
        );
        drop(handle);
        // After Drop: socket + pid sidecar removed, global slot cleared.
        assert!(!socket.exists(), "socket lingered after Drop");
        assert!(!pid_file.exists(), "pid sidecar lingered after Drop");
        assert_eq!(
            RUNNING_GVPROXY_PID.load(Ordering::SeqCst),
            0,
            "global gvproxy pid slot not cleared on Drop"
        );
    }

    /// `reap_by_pid_file` SIGTERMs the pid named in the sidecar and
    /// removes the sidecar + socket. Uses a real `sleep` child as the
    /// stand-in daemon — no gvproxy needed. Holds the shared `TestEnv` guard
    /// so the PATH-mutating `spawn_without_gvproxy_*` test can't make our
    /// `sleep` lookup miss.
    #[test]
    fn reap_by_pid_file_kills_live_pid_and_cleans_files() {
        use std::os::unix::process::ExitStatusExt;
        let _env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep stand-in");
        let pid = child.id() as i32;
        std::fs::write(tmp.path().join(PID_FILE_NAME), pid.to_string()).unwrap();
        std::fs::write(tmp.path().join("gvproxy.sock"), b"").unwrap();
        assert!(pid_alive(pid), "stand-in should be alive pre-reap");

        reap_by_pid_file(tmp.path());

        // We're the stand-in's parent, so a SIGTERM'd `sleep` lingers as
        // a zombie (kill(pid,0) still succeeds) until we wait() — in
        // production gvproxy is reparented to init, which auto-reaps.
        // So prove the kill via the wait status, not a liveness poll.
        let status = child.wait().expect("wait stand-in");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "stand-in was not SIGTERM'd by reap (status: {status:?})"
        );
        assert!(
            !tmp.path().join(PID_FILE_NAME).exists(),
            "pid file not removed"
        );
        assert!(
            !tmp.path().join("gvproxy.sock").exists(),
            "socket not removed"
        );
    }

    /// Missing, unparseable, and dead-pid sidecars are all clean no-ops
    /// (no panic, stale files swept).
    #[test]
    fn reap_by_pid_file_missing_or_stale_is_noop() {
        // No env mutation here, but hold the shared guard so a PATH-mutating
        // test can't hide `sleep` from this test's `Command::new` mid-run.
        let _env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        // Missing sidecar — must not panic.
        reap_by_pid_file(tmp.path());

        // Garbage sidecar — swept, no panic.
        std::fs::write(tmp.path().join(PID_FILE_NAME), b"not-a-pid").unwrap();
        reap_by_pid_file(tmp.path());
        assert!(!tmp.path().join(PID_FILE_NAME).exists());

        // Dead pid — swept. Spawn+reap a child to get a guaranteed-dead pid.
        let mut throwaway = Command::new("sleep").arg("0").spawn().unwrap();
        let dead = throwaway.id() as i32;
        throwaway.wait().unwrap();
        std::fs::write(tmp.path().join(PID_FILE_NAME), dead.to_string()).unwrap();
        reap_by_pid_file(tmp.path());
        assert!(!tmp.path().join(PID_FILE_NAME).exists());
    }
}
