//! Native-gateway-backed virtio-net supervisor.
//!
//! The legacy vfkit gateway contract is a userspace network transport
//! implemented by containers/gvisor-tap-vsock and drop-in replacements. It
//! translates
//! between virtio-net frames the libkrun guest writes to a unix-domain
//! socket and AF_INET sockets on the host. mvm treats this as a native gateway
//! contract, filling the role passt fills on Linux (passt itself doesn't build
//! on macOS).
//!
//! The integration model differs from passt:
//!
//! - passt: parent creates a socketpair, hands one end to passt via
//!   `--fd=N`, keeps the other end; libkrun consumes the parent end.
//! - native gateway: the gateway itself creates a listening unix-domain socket
//!   when invoked with `--listen-vfkit <path>`; libkrun connects to
//!   that path via `krun_add_net_unixgram(ctx, c_path, fd=-1, …)`.
//!
//! Boot sequence:
//!
//! 1. Host calls [`spawn`]. It picks a socket path under the
//!    scratch dir, spawns the configured gateway with `--listen-vfkit <socket>
//!    --log-file <log>`, then polls for the socket file to appear
//!    (the gateway creates it ~tens of ms after spawn).
//! 2. Host stuffs the socket path into [`crate::KrunContext`] via
//!    [`crate::KrunContext::with_native_gateway`].
//! 3. libkrun's `start_enter` opens the socket and consumes the
//!    virtio-net frames.
//! 4. When the host drops the [`NativeGatewayHandle`], the supervisor
//!    `SIGTERM`s the gateway, waits up to [`SHUTDOWN_GRACE`], then
//!    `SIGKILL`s.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// File name of the native gateway's PID sidecar under the per-VM scratch dir.
/// Lets [`reap_by_pid_file`] (and `mvmctl cache prune`) reap a gateway
/// the in-process [`NativeGatewayHandle::drop`] missed — which is the common
/// case on the libkrun lane, where `krun_start_enter` calls `exit()`
/// on guest shutdown and the stack never unwinds (so Drop never runs).
pub const PID_FILE_NAME: &str = "native-gateway.pid";

/// PID of the native gateway this process most recently spawned, or 0 if
/// none. Set by [`spawn`], cleared by [`NativeGatewayHandle::drop`]. Read by
/// the libkrun supervisor's `SIGTERM` handler (an `extern "C"` signal
/// handler that can't capture state) so it can SIGTERM the gateway before
/// `_exit` — otherwise `mvmctl stop` / `kill` orphans it. One gateway
/// per supervisor process (one VM per supervisor), so a single slot is
/// enough.
pub static RUNNING_NATIVE_GATEWAY_PID: AtomicI32 = AtomicI32::new(0);

/// Grace period between SIGTERM and SIGKILL during shutdown. Matches
/// the [`crate::passt::SHUTDOWN_GRACE`] knob so both backends behave
/// the same way under cleanup pressure.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How long [`spawn`] waits for the native gateway's listener socket to appear
/// on disk. The gateway creates the file within ~tens of milliseconds on
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
pub enum NativeGatewayError {
    /// Native gateway binary not found on `$PATH`.
    NotInstalled { install_hint: &'static str },
    /// Spawning the native gateway child process failed.
    Spawn(io::Error),
    /// Native gateway exited before the listener socket appeared on disk.
    /// `stdio_log` is the capture file holding the gateway's pre-listener
    /// stdout/stderr (the reason it bailed lives there, not in
    /// `-log-file`, which the compat CLI opens only after arg-parse).
    EarlyExit {
        status: std::process::ExitStatus,
        stdio_log: PathBuf,
    },
    /// `SOCKET_READY_TIMEOUT` elapsed without the native gateway creating its
    /// listener socket. Typically a permission issue on the scratch
    /// dir or a fatal error the gateway logged before listening.
    SocketTimeout { socket_path: PathBuf },
    /// Filesystem I/O failure (scratch dir create, etc.).
    Io { context: String, source: io::Error },
}

impl std::fmt::Display for NativeGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeGatewayError::NotInstalled { install_hint } => {
                write!(
                    f,
                    "native gateway binary not found on $PATH. {install_hint}"
                )
            }
            NativeGatewayError::Spawn(e) => write!(f, "spawning native gateway failed: {e}"),
            NativeGatewayError::EarlyExit { status, stdio_log } => write!(
                f,
                "native gateway exited before its listener socket appeared (status: {status:?}); \
                 see {}",
                stdio_log.display()
            ),
            NativeGatewayError::SocketTimeout { socket_path } => write!(
                f,
                "native gateway did not create its listener socket at {} within {} ms",
                socket_path.display(),
                SOCKET_READY_TIMEOUT.as_millis()
            ),
            NativeGatewayError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for NativeGatewayError {}

/// Suggested install/config hint for the current host platform. Surfaced
/// both in `NativeGatewayError::NotInstalled` and `mvmctl doctor`.
pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "Set MVM_GATEWAY_BIN to an rvproxy binary that supports -listen-vfkit"
    } else if cfg!(target_os = "linux") {
        // Most distros don't package the legacy vfkit gateway. Building from source is
        // a single `go build` against
        // github.com/containers/gvisor-tap-vsock.
        "Install from source: https://github.com/containers/gvisor-tap-vsock"
    } else {
        "Install a vfkit-compatible native gateway: https://github.com/containers/gvisor-tap-vsock"
    }
}

/// Locate the host-side vfkit gateway binary to spawn.
///
/// `MVM_GATEWAY_BIN`, when set to a non-empty value, names the gateway
/// directly. The path is used verbatim; a bad path surfaces as a clear spawn
/// error rather than silently falling back to a legacy helper name.
pub fn locate_gateway() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("MVM_GATEWAY_BIN")
        && !bin.is_empty()
    {
        return Some(PathBuf::from(bin));
    }
    None
}

/// Reserve a free TCP port on loopback for the compat gateway's mandatory
/// SSH-forward listener by letting the OS assign one.
///
/// The compat CLI's `-ssh-port` arg is *mandatory* (default 2222) and
/// the gateway binds it on every start. mvm never uses the SSH forward
/// (no SSH in microVMs, ever) but that compat mode refuses to disable it
/// (`-ssh-port` validates to 1024..=65535), so we have to hand it a
/// port we don't care about.
///
/// We bind `127.0.0.1:0`, read back the ephemeral port the kernel
/// picked, and immediately drop the listener so the gateway can claim
/// it. This is collision-proof in the way a deterministic
/// scratch-dir hash is *not*: the OS never hands out a port already
/// in `LISTEN`, so a leaked gateway from a prior run (libkrun's
/// `krun_start_enter` `exit()`s on guest shutdown and skips
/// `NativeGatewayHandle::Drop`, so daemons routinely outlive their VM) or
/// a concurrent VM reusing the same scratch dir can't steal the
/// port out from under us. An earlier deterministic-hash scheme
/// collided exactly this way — a re-run reusing `~/.mvm/vms/<name>/`
/// derived the same port a still-bound leaked daemon already held,
/// and the gateway bailed with `bind: address already in use`.
///
/// The bind→read→close → gateway-bind window is a microsecond-scale
/// TOCTOU that another process could in principle race, but a closed
/// listener that never accepted a connection frees its port
/// immediately (no `TIME_WAIT`), so in practice the gateway reclaims it
/// before anything else does.
pub fn free_loopback_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    // Listener drops here, freeing the port for the gateway to bind.
    Ok(port)
}

/// Owning handle to a running native gateway child process. `Drop` cleans up
/// the child the same way [`crate::passt::PasstHandle::drop`] does:
/// SIGTERM → grace period → SIGKILL → reap.
#[derive(Debug)]
pub struct NativeGatewayHandle {
    child: Option<Child>,
    socket_path: PathBuf,
    pid_path: PathBuf,
}

impl NativeGatewayHandle {
    /// Path to the unix-domain socket the native gateway listens on. Hand this
    /// to [`crate::KrunContext::with_native_gateway`] (or directly to
    /// `crate::sys::Context::add_net_unixgram_path` for advanced
    /// callers).
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Spawn a native gateway child process and return a handle to its listener
/// socket path. The child logs to `scratch_dir/native-gateway.log`.
///
/// The returned [`NativeGatewayHandle`] must outlive any libkrun
/// configuration referencing `socket_path()`. On Drop the child is
/// killed gracefully and the socket file is deleted (best-effort —
/// libkrun may have already consumed it).
pub fn spawn(
    scratch_dir: &Path,
    native_config: Option<&Path>,
) -> Result<NativeGatewayHandle, NativeGatewayError> {
    let gateway_bin = locate_gateway().ok_or_else(|| NativeGatewayError::NotInstalled {
        install_hint: install_hint(),
    })?;

    std::fs::create_dir_all(scratch_dir).map_err(|e| NativeGatewayError::Io {
        context: format!(
            "creating native gateway scratch dir {}",
            scratch_dir.display()
        ),
        source: e,
    })?;

    let socket_path = scratch_dir.join("native-gateway.sock");
    let log_path = scratch_dir.join("native-gateway.log");

    // Reap a gateway leaked into this exact scratch dir by a prior run
    // before we touch its socket/pid files. Persistent dirs (`dev` /
    // named VMs) get reused, so a leaked daemon could still be bound
    // here; ephemeral builder-VM dirs are timestamped so this is
    // usually a no-op. Either way it keeps the socket pre-unlink below
    // honest.
    reap_by_pid_file(scratch_dir);

    // Remove a stale socket from a previous run before spawning —
    // the compat gateway refuses to bind if the file exists.
    let _ = std::fs::remove_file(&socket_path);

    // Native-gateway compat args we care about:
    //   -listen-vfkit <path> — unix-domain socket libkrun connects to
    //                          via `krun_add_net_unixgram`. "vfkit"
    //                          mode is the libkrun-compatible one.
    //   -log-file <path>     — diagnostic log; absent → stderr (lost
    //                          when we redirect to /dev/null).
    //   -ssh-port <port>     — the compat helper always binds a TCP listener for
    //                          guest-SSH forwarding (default 2222). On
    //                          a host running more than one gateway
    //                          (concurrent dev VMs, parallel tests,
    //                          debugging cycles), instance N+1 fails
    //                          to bind 2222 and exits immediately
    //                          with `address already in use`. Hand it
    //                          a fresh OS-assigned free port so no two
    //                          instances — including leaked daemons —
    //                          collide (see `free_loopback_port`).
    //   -debug               — verbose logging. Not set by default;
    //                          if a future MVM_GATEWAY_DEBUG=1 env
    //                          var trips this we'd flip it here.
    // (Native rvproxy mode skips all of the above: `run --config <path>`
    // carries the transport socket, log, and policy in its config file.)

    // NEVER inherit the spawner's stdout/stderr. The compat gateway is a long-lived
    // daemon; if it holds a write end of the parent's stdout/stderr pipe,
    // any ancestor reading that pipe to EOF (e.g. a test driving `mvmctl`
    // via `Command::output()`) blocks forever — the gateway keeps the pipe
    // open for the life of the VM (and beyond, since libkrun's exit() on
    // guest shutdown skips `NativeGatewayHandle::Drop`, orphaning it). That fd
    // inheritance is exactly what hung `core_demo_e2e`: `dev up`'s build
    // VM powered down, mvmctl exited, but the orphaned gateway held the
    // pipe so `output()` never saw EOF.
    //
    // Redirect both streams to a per-VM capture file instead. This still
    // preserves the visibility that motivated the old `inherit()`:
    // the gateway's pre-listener failures (arg-parse, "bind: address already
    // in use" on the SSH-forward port) go to stderr *before* `-log-file`
    // is opened, so they'd be lost to /dev/null — the capture file keeps
    // them on disk next to the listener log.
    let stdio_log_path = scratch_dir.join("native-gateway-stdio.log");
    let stdio_log = std::fs::File::create(&stdio_log_path).map_err(|e| NativeGatewayError::Io {
        context: format!(
            "creating native gateway stdio capture {}",
            stdio_log_path.display()
        ),
        source: e,
    })?;
    let stdio_log_err = stdio_log.try_clone().map_err(|e| NativeGatewayError::Io {
        context: format!(
            "cloning native gateway stdio capture {}",
            stdio_log_path.display()
        ),
        source: e,
    })?;
    let mut cmd = Command::new(&gateway_bin);
    match native_config {
        // Native rvproxy: `run --config <path>`. The config's
        // `[transport].path` is `<scratch_dir>/native-gateway.sock` (the same
        // `socket_path` the poll loop waits on), so libkrun connects to the
        // socket rvproxy binds. Logging + listener config live in the file,
        // so none of the compat `-listen-vfkit`/`-log-file`/`-ssh-port`
        // flags apply.
        Some(config_path) => {
            cmd.arg("run").arg("--config").arg(config_path.as_os_str());
        }
        // Gateway-compat: `-listen-vfkit` wants the socket as a
        // `unixgram://<path>` URL — a bare path errors with "vfkit listen
        // address must be unixgram:// address" before the listener is
        // created. The libkrun-end connects to the absolute path; the URL
        // prefix only carries the scheme. `-ssh-port` gets a fresh free
        // port so two gateway instances (concurrent VMs, leaked daemons)
        // never collide on the default 2222.
        None => {
            let listen_url = {
                let mut s = OsString::from("unixgram://");
                s.push(socket_path.as_os_str());
                s
            };
            let ssh_port = free_loopback_port().map_err(|e| NativeGatewayError::Io {
                context: "reserving a free port for the native gateway ssh-forward listener"
                    .to_string(),
                source: e,
            })?;
            cmd.arg("-listen-vfkit")
                .arg(listen_url)
                .arg("-log-file")
                .arg(OsString::from(&log_path))
                .arg("-ssh-port")
                .arg(ssh_port.to_string());
        }
    }
    cmd.stdout(std::process::Stdio::from(stdio_log))
        .stderr(std::process::Stdio::from(stdio_log_err));

    // Tie the native gateway to the supervisor's lifetime: a SIGKILL'd / panicked
    // supervisor (which the SIGTERM handler can't catch) must not orphan it.
    crate::child_lifecycle::tie_to_parent_death(&mut cmd);
    let mut child = cmd.spawn().map_err(NativeGatewayError::Spawn)?;

    // Record the pid before the poll loop: the SIGTERM handler reaps
    // whatever `RUNNING_NATIVE_GATEWAY_PID` names, and `reap_by_pid_file`
    // needs the sidecar even if we die mid-poll.
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    RUNNING_NATIVE_GATEWAY_PID.store(child.id() as i32, Ordering::SeqCst);
    let _ = std::fs::write(&pid_path, child.id().to_string());

    // Poll for the socket to appear, with a bounded budget. The gateway
    // creates the file synchronously inside its main loop on startup,
    // so this should resolve within ~tens of ms. We also re-check
    // `try_wait()` every iteration so an early exit (missing arg,
    // permission denied, etc.) surfaces immediately instead of as
    // a SocketTimeout.
    let deadline = Instant::now() + SOCKET_READY_TIMEOUT;
    loop {
        if socket_path.exists() {
            return Ok(NativeGatewayHandle {
                child: Some(child),
                socket_path,
                pid_path,
            });
        }
        if let Some(status) = child.try_wait().map_err(NativeGatewayError::Spawn)? {
            // The gateway is gone; clear the records so a later reaper / the
            // next spawn doesn't chase a dead (or recycled) pid.
            RUNNING_NATIVE_GATEWAY_PID.store(0, Ordering::SeqCst);
            let _ = std::fs::remove_file(&pid_path);
            return Err(NativeGatewayError::EarlyExit {
                status,
                stdio_log: stdio_log_path,
            });
        }
        if Instant::now() >= deadline {
            // Kill the still-running child before bailing — leaking it
            // would block whatever the caller does next.
            let _ = child.kill();
            let _ = child.wait();
            RUNNING_NATIVE_GATEWAY_PID.store(0, Ordering::SeqCst);
            let _ = std::fs::remove_file(&pid_path);
            return Err(NativeGatewayError::SocketTimeout { socket_path });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl Drop for NativeGatewayHandle {
    fn drop(&mut self) {
        // Clear the global slot first — whether or not the child is
        // still alive, this handle is going away, so the SIGTERM
        // handler must stop referencing its pid.
        RUNNING_NATIVE_GATEWAY_PID.store(0, Ordering::SeqCst);

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

/// SIGTERM (then SIGKILL) a native gateway named by `<scratch_dir>/native-gateway.pid`,
/// then remove the sidecar + listener socket. Idempotent: a missing
/// or stale pid file, or an already-dead pid, is a clean no-op. This is
/// the reaper for gateway daemons the in-process [`NativeGatewayHandle::drop`]
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
    let _ = std::fs::remove_file(scratch_dir.join("native-gateway.sock"));
}

/// Backstop reaper that kills a native gateway still bound to
/// `<scratch_dir>/native-gateway.sock` even when no `native-gateway.pid` sidecar exists —
/// the case a supervisor binary predating the sidecar leaves behind (it spawns
/// the gateway without writing the pid file, so [`reap_by_pid_file`] finds nothing
/// to reap and the daemon reparents to the init process). Scans the process
/// table for whatever gateway is bound to this VM's socket (the compat helper, or the
/// native gateway swapped in via `MVM_GATEWAY_BIN` — both carry the socket path
/// in argv) and `SIGKILL`s it, then unlinks the socket. The compat helper ignores
/// `SIGTERM`, so a graceful window buys nothing here.
///
/// Idempotent: a missing socket or no argv match is a clean no-op. Keyed on the
/// per-VM socket path, which is unique to this VM's scratch dir, so it never
/// touches another VM's gateway. The parent-aware sweep behind `mvmctl cache
/// prune` supersedes this for cross-VM cleanup; this is the per-teardown
/// guarantee the spawning host makes for the one VM it just waited on.
pub fn reap_by_socket_path(scratch_dir: &Path) {
    let socket_path = scratch_dir.join("native-gateway.sock");
    if !socket_path.exists() {
        return;
    }
    let self_pid = std::process::id() as i32;
    for pid in pids_bound_to_socket(&socket_path) {
        if pid == self_pid || pid <= 1 {
            continue;
        }
        // SAFETY: kill on a since-exited pid races to ESRCH, which is benign.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let _ = std::fs::remove_file(&socket_path);
}

/// PIDs whose argv references `socket_path` — the gateway daemon(s) bound to
/// this VM's native-gateway socket. Reads one process-table snapshot: `/proc` on
/// Linux, a single `ps` on macOS/BSD (no `/proc`). The far richer, parent-aware
/// process sweep behind `mvmctl cache prune` lives in the CLI layer; this crate
/// can't reach up to it, so this stays a minimal self-contained probe scoped to
/// a single known socket path.
fn pids_bound_to_socket(socket_path: &Path) -> Vec<i32> {
    let needle = socket_path.to_string_lossy();

    #[cfg(target_os = "linux")]
    {
        let mut pids = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return pids;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            // cmdline is NUL-separated argv; a lossy join preserves the path
            // substring across argument boundaries.
            if let Ok(bytes) = std::fs::read(entry.path().join("cmdline"))
                && String::from_utf8_lossy(&bytes).contains(needle.as_ref())
            {
                pids.push(pid);
            }
        }
        pids
    }

    #[cfg(not(target_os = "linux"))]
    {
        let Ok(output) = Command::new("ps").args(["-Ao", "pid=,command="]).output() else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let (pid, cmd) = line.trim_start().split_once(char::is_whitespace)?;
                cmd.contains(needle.as_ref())
                    .then(|| pid.parse::<i32>().ok())
                    .flatten()
            })
            .collect()
    }
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
            assert!(hint.contains("MVM_GATEWAY_BIN"), "hint: {hint}");
        }
    }

    #[test]
    fn locate_gateway_is_optional() {
        let _ = locate_gateway();
    }

    /// `MVM_GATEWAY_BIN` overrides the default gateway lookup — the seam an
    /// alternate vfkit gateway (the native gateway) is spawned through. An
    /// empty value is ignored so it falls back to the `$PATH` probe.
    #[test]
    fn locate_gateway_honors_gateway_bin_override() {
        let mut env = TestEnv::new();
        env.set("MVM_GATEWAY_BIN", "/opt/mvm/native-gateway");
        assert_eq!(
            locate_gateway(),
            Some(PathBuf::from("/opt/mvm/native-gateway")),
            "MVM_GATEWAY_BIN must override the default gateway lookup"
        );
        env.set("MVM_GATEWAY_BIN", "");
        // Empty → ignored; must not return an empty path.
        assert_ne!(locate_gateway(), Some(PathBuf::new()));
        env.remove("MVM_GATEWAY_BIN");
    }

    /// A reserved port is in the compat helper's accepted `-ssh-port` range
    /// (1024..=65535) and is actually free — we can rebind it after
    /// the reservation drops, which is exactly what the helper does.
    #[test]
    fn free_loopback_port_is_in_range_and_bindable() {
        for _ in 0..20 {
            let port = match free_loopback_port() {
                Ok(port) => port,
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!("test skipped: loopback bind is not permitted on this host: {err}");
                    return;
                }
                Err(err) => panic!("reserve a free port: {err}"),
            };
            assert!(
                port >= 1024,
                "port {port} below the compat helper's 1024 floor"
            );
            // The reservation listener is already dropped, so this rebind
            // models the helper claiming the port we handed it. Another parallel
            // test/process can win the intentionally-open TOCTOU window; retry
            // that specific race and fail all other bind errors.
            match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Ok(rebound) => {
                    drop(rebound);
                    return;
                }
                Err(err) if err.kind() == io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("reserved port {port} was not bindable: {err}"),
            }
        }
        panic!("reserved port was repeatedly claimed before the test could bind it");
    }

    #[test]
    fn spawn_without_native_gateway_returns_not_installed() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("PATH", tmp.path());
        let result = spawn(tmp.path(), None);
        match result {
            Err(NativeGatewayError::NotInstalled { install_hint }) => {
                assert!(!install_hint.is_empty());
            }
            other => panic!("expected NotInstalled, got {other:?}"),
        }
    }

    /// Spawn the configured vfkit gateway, verify the socket + pid sidecar +
    /// stdio capture exist and the global pid slot is set, then drop the
    /// handle and confirm everything is cleaned up. Skipped unless a real
    /// gateway binary is provided through `MVM_TEST_RVPROXY_BIN`.
    #[test]
    fn spawn_then_drop_reaps_child() {
        let Some(bin) = std::env::var_os("MVM_TEST_RVPROXY_BIN") else {
            eprintln!("test skipped: set MVM_TEST_RVPROXY_BIN to a vfkit gateway binary");
            return;
        };
        let mut env = TestEnv::new();
        env.set("MVM_GATEWAY_BIN", &bin);
        let tmp = tempfile::tempdir().unwrap();
        let handle = spawn(tmp.path(), None).expect("spawn native gateway");
        let socket = handle.socket_path().to_path_buf();
        let pid_file = tmp.path().join(PID_FILE_NAME);
        assert!(socket.exists(), "socket missing: {}", socket.display());
        assert!(pid_file.exists(), "pid sidecar missing");
        assert!(
            tmp.path().join("native-gateway-stdio.log").exists(),
            "stdio capture file missing — stdout/stderr were not redirected to it"
        );
        assert!(
            RUNNING_NATIVE_GATEWAY_PID.load(Ordering::SeqCst) > 0,
            "global native-gateway pid slot not set"
        );
        drop(handle);
        // After Drop: socket + pid sidecar removed, global slot cleared.
        assert!(!socket.exists(), "socket lingered after Drop");
        assert!(!pid_file.exists(), "pid sidecar lingered after Drop");
        assert_eq!(
            RUNNING_NATIVE_GATEWAY_PID.load(Ordering::SeqCst),
            0,
            "global native-gateway pid slot not cleared on Drop"
        );
    }

    /// Native rvproxy path: given a real `rvproxy` binary (via
    /// `MVM_TEST_RVPROXY_BIN`) and a rendered config, `spawn(.., Some(cfg))`
    /// launches `rvproxy run --config`, which binds the vfkit transport
    /// socket libkrun would connect to. Confirms the socket + pid sidecar
    /// appear and Drop reaps cleanly — the same handle contract as the
    /// gateway-compat path. Skipped unless the binary is provided.
    #[test]
    fn native_spawn_then_drop_reaps_child() {
        let Some(bin) = std::env::var_os("MVM_TEST_RVPROXY_BIN") else {
            eprintln!("test skipped: set MVM_TEST_RVPROXY_BIN to a real rvproxy binary");
            return;
        };
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("native-gateway.sock");
        // The config's [transport].path must equal the socket the poll loop
        // waits on, so libkrun connects to the one rvproxy binds.
        let config_path = tmp.path().join("rvproxy.toml");
        let api_sock = tmp.path().join("rvproxy-api.sock");
        let audit_path = tmp.path().join("flow-audit.jsonl");
        std::fs::write(
            &config_path,
            format!(
                "id = \"vm-test\"\n\
                 mode = \"single-vm\"\n\
                 [network]\n\
                 cidr = \"192.168.127.0/24\"\n\
                 gateway_ip = \"192.168.127.1\"\n\
                 guest_ip = \"192.168.127.2\"\n\
                 mtu = 1500\n\
                 [backend]\n\
                 kind = \"vfkit\"\n\
                 [transport]\n\
                 kind = \"vfkit\"\n\
                 path = \"{sock}\"\n\
                 [api]\n\
                 listen = \"unix:{api}\"\n\
                 [dns]\n\
                 enabled = true\n\
                 upstream = [\"1.1.1.1\"]\n\
                 [audit]\n\
                 dataplane_audit_jsonl_path = \"{audit}\"\n\
                 [policy]\n\
                 allow_transport_ingress = true\n\
                 allow_transport_egress = true\n\
                 allow_guest_egress = true\n\
                 default_egress_deny = true\n",
                sock = socket.display(),
                api = api_sock.display(),
                audit = audit_path.display(),
            ),
        )
        .unwrap();

        env.set("MVM_GATEWAY_BIN", &bin);
        let handle = spawn(tmp.path(), Some(&config_path)).expect("spawn rvproxy run --config");

        assert!(
            handle.socket_path().exists(),
            "rvproxy did not bind the vfkit transport socket: {}",
            handle.socket_path().display()
        );
        assert!(
            tmp.path().join(PID_FILE_NAME).exists(),
            "pid sidecar missing"
        );
        drop(handle);
        assert!(!socket.exists(), "socket lingered after Drop");
    }

    /// `reap_by_pid_file` SIGTERMs the pid named in the sidecar and
    /// removes the sidecar + socket. Uses a real `sleep` child as the
    /// stand-in daemon — no native gateway needed. Holds the shared `TestEnv` guard
    /// so the PATH-mutating `spawn_without_native_gateway_*` test can't make our
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
        std::fs::write(tmp.path().join("native-gateway.sock"), b"").unwrap();
        assert!(pid_alive(pid), "stand-in should be alive pre-reap");

        reap_by_pid_file(tmp.path());

        // We're the stand-in's parent, so a SIGTERM'd `sleep` lingers as
        // a zombie (kill(pid,0) still succeeds) until we wait() — in
        // production native gateways are reparented to init, which auto-reaps.
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
            !tmp.path().join("native-gateway.sock").exists(),
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

    /// `reap_by_socket_path` SIGKILLs a gateway bound to `<dir>/native-gateway.sock`
    /// found by its argv alone — the pid-file-less case a supervisor predating
    /// the sidecar leaves behind. Stand-in is a `sh` sleeper carrying the socket
    /// path in argv, exactly as the compat helper's `-listen-vfkit unixgram://<path>` does.
    #[test]
    fn reap_by_socket_path_kills_gateway_found_by_argv() {
        use std::os::unix::process::ExitStatusExt;
        let _env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("native-gateway.sock");
        std::fs::write(&socket, b"").unwrap();

        // Stand-in gateway: `sh` blocking on the `read` builtin, so it stays in
        // one process (no forked child to leak) with the socket path in its argv
        // — exactly where the compat helper's `-listen-vfkit unixgram://<path>` carries it.
        // The held-open stdin pipe keeps `read` blocking until we SIGKILL it.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("read _")
            .arg(socket.display().to_string())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh stand-in carrying the socket path in argv");
        let pid = child.id() as i32;

        // The process table can lag the spawn; poll until the scan sees it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pids_bound_to_socket(&socket).contains(&pid) {
            if Instant::now() >= deadline {
                eprintln!(
                    "test skipped: process table does not expose the stand-in gateway argv for pid {pid}"
                );
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        reap_by_socket_path(tmp.path());

        // We're the stand-in's parent, so a SIGKILL'd child lingers as a zombie
        // until we wait() — prove the kill via the wait status, mirroring the
        // pid-file reap test.
        let status = child.wait().expect("wait stand-in");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "stand-in gateway was not SIGKILL'd by the socket reap (status: {status:?})"
        );
        assert!(!socket.exists(), "socket not removed by the socket reap");
    }

    /// No socket file → nothing bound → clean no-op (no scan, no panic).
    #[test]
    fn reap_by_socket_path_is_noop_without_socket() {
        let tmp = tempfile::tempdir().unwrap();
        reap_by_socket_path(tmp.path());
        assert!(!tmp.path().join("native-gateway.sock").exists());
    }
}
