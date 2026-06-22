//! Host-side gvproxy lifecycle for the Vz backend.
//!
//! VzBackend is stateless (no per-VM in-memory ownership), so
//! `gvproxy` must outlive `VzBackend::start`'s
//! return. We can't use [`libkrun_sys::gvproxy::spawn`] directly:
//! it returns a `GvproxyHandle` whose Drop SIGTERMs the child the
//! moment the handle goes out of scope — perfect for the in-libkrun-
//! supervisor model (which holds the handle on the supervisor
//! process's stack until `krun_start_enter` exit()s), wrong for the
//! Vz parent-spawn model.
//!
//! This module spawns gvproxy without owning its `Child`, records
//! the PID in a sidecar file under the per-VM scratch dir, and
//! exposes a tear-down helper for `VzBackend::stop` to call.
//! `std::process::Child::drop` does NOT kill the child — it just
//! closes stdio handles — so dropping the Child immediately is
//! safe and leaves gvproxy running as a normal child of the
//! original parent (and re-parented to init when the parent
//! eventually exits).
//!
//! The libkrun lane keeps using `libkrun_sys::gvproxy::spawn` —
//! that model is in-process and the Drop semantics fit it. We
//! deliberately don't refactor the libkrun lane to share this
//! module: the trade-offs are different (in-process vs detached).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};

/// File name used for the host-gvproxy PID sidecar under the per-VM
/// state dir. Picked to not collide with the existing `libkrun.pid`
/// or `mvm-vz-supervisor.pid` markers in the same directory.
pub const PID_FILE_NAME: &str = "host-gvproxy.pid";

/// File name of the host-gvproxy listener socket. Lives under the
/// per-VM bridge scratch dir alongside the supervisor-side bridge
/// listener (when claim-10 bridge mode is on).
pub const SOCKET_FILE_NAME: &str = "gvproxy.sock";

/// Size of an `AF_UNIX` `sun_path` buffer, *including* the NUL terminator:
/// 104 on Darwin, 108 on Linux. A path of `L` bytes needs `L + 1` (path + NUL)
/// to fit, so it binds iff `L < SUN_PATH_MAX`. `bind()` of a longer path fails
/// `EINVAL`; gvproxy surfaces it as `vfkit listen error: ... bind: invalid
/// argument` and exits before its listener socket appears.
#[cfg(target_os = "macos")]
pub(crate) const SUN_PATH_MAX: usize = 104;
#[cfg(not(target_os = "macos"))]
pub(crate) const SUN_PATH_MAX: usize = 108;

/// Short, deterministic, filesystem-safe hex token derived from `input`
/// (first `bytes` bytes of its SHA-256). Used to keep `AF_UNIX` socket paths
/// short: as a relocated-socket filename here, and as the Vz persistent
/// builder's session id (so its `<state_dir>/vsock/*` paths stay under
/// [`SUN_PATH_MAX`]). Collision-resistant across a host's per-VM dirs.
pub(crate) fn short_token(input: &str, bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(bytes)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Resolve the host-gvproxy listener socket path for a VM rooted at
/// `scratch_dir`.
///
/// Normally `<scratch_dir>/gvproxy.sock`. But the per-VM state-dir name can be
/// long (e.g. `mvm-persistent-builder-vz-<session>`), and under a long
/// `MVM_CACHE_DIR`/`MVM_DATA_DIR` or a long `$HOME` the natural path can exceed
/// the `AF_UNIX` `sun_path` limit — gvproxy then fails to `bind()` and exits
/// before listening. When the natural path wouldn't fit, relocate the socket to
/// a short, deterministic path under `<cache>/gv/` (the mvm cache root is 0700
/// and isolation-respecting). Only the bind-limited socket moves; the PID file
/// and logs stay in `scratch_dir`. `spawn_detached` and `stop_by_pid_file` both
/// call this so they always agree on the path.
fn gvproxy_socket_path(scratch_dir: &Path) -> PathBuf {
    gvproxy_socket_path_in(scratch_dir, Path::new(&mvm_core::config::mvm_cache_dir()))
}

/// Pure core of [`gvproxy_socket_path`] with the relocation root injected, so
/// the natural-vs-relocated decision is unit-testable without touching the
/// process environment.
fn gvproxy_socket_path_in(scratch_dir: &Path, cache_root: &Path) -> PathBuf {
    let natural = scratch_dir.join(SOCKET_FILE_NAME);
    // Fits iff path bytes < buffer size (one byte reserved for the NUL).
    if natural.as_os_str().len() < SUN_PATH_MAX {
        return natural;
    }
    // 12 hex chars (48 bits) keyed on the full scratch dir — collision-resistant
    // across a host's per-VM dirs, and short enough to stay well under the limit.
    let token = short_token(&scratch_dir.to_string_lossy(), 6);
    cache_root.join("gv").join(format!("{token}.sock"))
}

/// How long we wait for gvproxy's listen-vfkit socket to appear
/// before declaring the spawn failed.
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// How long [`stop_by_pid_file`] gives the child to exit after
/// `SIGTERM` before escalating to `SIGKILL`.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Spawned host gvproxy's externally-observable identity. Returned
/// from [`spawn_detached`] for the caller to feed into the per-VM
/// supervisor config + PID-file tear-down later.
#[derive(Debug, Clone)]
pub struct HostGvproxyInfo {
    /// Absolute path to gvproxy's `-listen-vfkit` SOCK_DGRAM
    /// listener. Vz supervisor connects here.
    pub socket_path: PathBuf,
    /// gvproxy's PID. Also written to `<scratch_dir>/host-gvproxy.pid`
    /// so [`stop_by_pid_file`] can rediscover it after VzBackend::start
    /// has returned.
    pub pid: u32,
}

/// Spawn gvproxy as a detached child of the current process.
/// Writes the PID to `<scratch_dir>/host-gvproxy.pid`, polls for
/// the listener socket to appear, then returns. Drops the
/// `std::process::Child` — gvproxy keeps running as a normal child
/// (re-parented to init when mvmctl exits).
///
/// `scratch_dir` is the per-VM state dir (typically
/// `~/.mvm/vms/<name>/`). Created if missing. Stale PID + socket
/// files from a prior run are pre-cleaned.
pub fn spawn_detached(scratch_dir: &Path) -> Result<HostGvproxyInfo> {
    let gvproxy_bin = libkrun_sys::gvproxy::locate_gvproxy().ok_or_else(|| {
        anyhow!(
            "gvproxy binary not found on PATH. {}",
            libkrun_sys::gvproxy::install_hint()
        )
    })?;

    std::fs::create_dir_all(scratch_dir)
        .map_err(|e| anyhow!("create scratch dir {}: {e}", scratch_dir.display()))?;

    let socket_path = gvproxy_socket_path(scratch_dir);
    // The relocated path lives under <cache>/gv/, which may not exist yet.
    // (For the natural path the parent is `scratch_dir`, just created above.)
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create gvproxy socket dir {}: {e}", parent.display()))?;
    }
    // Defense in depth: if even the (possibly relocated) socket path can't fit
    // sun_path, fail with an actionable error instead of gvproxy's cryptic
    // bind-failure-then-exit.
    if socket_path.as_os_str().len() >= SUN_PATH_MAX {
        bail!(
            "gvproxy socket path {} is {} bytes, at/over the {SUN_PATH_MAX}-byte AF_UNIX \
             sun_path buffer (path + NUL); use a shorter MVM_CACHE_DIR",
            socket_path.display(),
            socket_path.as_os_str().len(),
        );
    }
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    let log_path = scratch_dir.join("host-gvproxy.log");

    // Defensive cleanup — a previous mvmctl crash may have left a
    // stale socket file in place; gvproxy refuses to bind in that
    // case. The PID file is also stale-cleared; if a previous
    // gvproxy is still running its PID is unrelated to ours and
    // would be misleading.
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&pid_path);

    // gvproxy args (mirror mvm-libkrun::gvproxy::spawn):
    //   -listen-vfkit unixgram://<path>  — Vz connects here
    //   -log-file <path>                 — diagnostic log
    //   -ssh-port <port>                 — fresh OS-assigned free port
    //                                      so concurrent gvproxies (and
    //                                      leaked daemons) never collide
    let listen_url = {
        let mut s = OsString::from("unixgram://");
        s.push(socket_path.as_os_str());
        s
    };
    let ssh_port = libkrun_sys::gvproxy::free_loopback_port()
        .map_err(|e| anyhow!("reserve a free gvproxy ssh-forward port: {e}"))?;

    // NEVER inherit the parent's stderr. gvproxy is detached and
    // re-parented to init; an inherited stderr write end keeps the
    // parent's stderr pipe open for gvproxy's whole lifetime, so any
    // ancestor reading it to EOF (a test driving `mvmctl` via
    // `Command::output()`) hangs forever. Capture pre-listener errors
    // (port-in-use, etc. — emitted before `-log-file` opens) to a file
    // instead, preserving the operator visibility the old inherit gave.
    let stdio_log_path = scratch_dir.join("host-gvproxy-stdio.log");
    let stdio_log = std::fs::File::create(&stdio_log_path).map_err(|e| {
        anyhow!(
            "create gvproxy stdio capture {}: {e}",
            stdio_log_path.display()
        )
    })?;
    let stdio_log_err = stdio_log.try_clone().map_err(|e| {
        anyhow!(
            "clone gvproxy stdio capture {}: {e}",
            stdio_log_path.display()
        )
    })?;
    let mut cmd = Command::new(&gvproxy_bin);
    cmd.arg("-listen-vfkit")
        .arg(listen_url)
        .arg("-log-file")
        .arg(OsString::from(&log_path))
        .arg("-ssh-port")
        .arg(ssh_port.to_string())
        .stdout(Stdio::from(stdio_log))
        .stderr(Stdio::from(stdio_log_err));

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn gvproxy {}: {e}", gvproxy_bin.display()))?;
    let pid = child.id();

    // Persist the PID so VzBackend::stop can find this child later.
    // VzBackend::start returns shortly after this, dropping `child`
    // (which doesn't kill the process — std::process::Child::drop
    // is a no-op WRT process lifetime). The kernel reparents
    // gvproxy to init when mvmctl eventually exits.
    std::fs::write(&pid_path, pid.to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_path.display()))?;

    // Poll for the listener socket to appear. If gvproxy exits
    // early (missing arg, port already in use, etc.), surface the
    // status immediately rather than as a generic timeout.
    let deadline = Instant::now() + SOCKET_READY_TIMEOUT;
    loop {
        if socket_path.exists() {
            // Intentional: drop the Child without killing.
            // std::process::Child::drop just closes pipe handles.
            drop(child);
            return Ok(HostGvproxyInfo { socket_path, pid });
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("poll gvproxy child: {e}"))?
        {
            let _ = std::fs::remove_file(&pid_path);
            bail!(
                "gvproxy exited before listener appeared (status: {status}). \
                 Log: {}",
                log_path.display()
            );
        }
        if Instant::now() >= deadline {
            // Bound the leak: kill the still-running child before
            // bailing so it doesn't survive the failed start.
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&pid_path);
            bail!(
                "gvproxy did not create {} within {SOCKET_READY_TIMEOUT:?}. \
                 Log: {}",
                socket_path.display(),
                log_path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// SIGTERM the gvproxy process named by the PID file under `scratch_dir`,
/// wait up to `STOP_TIMEOUT` for it to exit, and fall back to SIGKILL.
/// Removes the PID + socket files. Idempotent — no-op when the PID file is
/// missing or the named process is already gone.
pub fn stop_by_pid_file(scratch_dir: &Path) -> Result<()> {
    stop_by_pid_file_with_grace(scratch_dir, Some(STOP_TIMEOUT))
}

/// Like [`stop_by_pid_file`] but skips the graceful SIGTERM window and
/// SIGKILLs the gvproxy process immediately — for ephemeral transient
/// teardown (`mvmctl run` / `machine run`) where the userspace gateway has
/// nothing to flush. gvproxy ignores SIGTERM, so the graceful path always
/// burns the full `STOP_TIMEOUT`; this path returns at once.
pub fn kill_by_pid_file(scratch_dir: &Path) -> Result<()> {
    stop_by_pid_file_with_grace(scratch_dir, None)
}

/// Shared teardown. With `grace == None` the process is SIGKILLed
/// immediately; with `Some(d)` it is SIGTERMed, polled up to `d`, then
/// SIGKILLed. Removes the PID + socket files on every terminal path.
fn stop_by_pid_file_with_grace(scratch_dir: &Path, grace: Option<Duration>) -> Result<()> {
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    let socket_path = gvproxy_socket_path(scratch_dir);

    let pid: i32 = match std::fs::read_to_string(&pid_path) {
        Ok(s) => match s.trim().parse() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %pid_path.display(),
                    error = %e,
                    "host_gvproxy: PID file content invalid; cleaning up"
                );
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&socket_path);
                return Ok(());
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No PID file = nothing to stop. Mirror the libkrun /
            // Vz supervisor stop semantics.
            return Ok(());
        }
        Err(e) => return Err(anyhow!("read {}: {e}", pid_path.display())),
    };

    if !pid_alive(pid) {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&socket_path);
        return Ok(());
    }

    match grace {
        // No flush needed for an ephemeral gateway — kill at once.
        None => unsafe {
            libc::kill(pid, libc::SIGKILL);
        },
        Some(d) => {
            // SAFETY: pid was just probed alive; SIGTERM on a stale pid
            // returns ESRCH which we treat as a benign race.
            unsafe { libc::kill(pid, libc::SIGTERM) };
            let deadline = Instant::now() + d;
            while Instant::now() < deadline {
                if !pid_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if pid_alive(pid) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Derive a MAC address from a VM name. Stable across runs (same
/// name → same MAC), collision-resistant via SHA-256 truncation,
/// and locally-administered (first octet has `0x02` set) per the
/// MacAddress invariant in `mvm-vz`. Renders as
/// `"aa:bb:cc:dd:ee:ff"` (lowercase) suitable for the
/// `NetworkConfig::Gvproxy.mac` field.
pub fn derive_mac(vm_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vm_name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&digest[..6]);
    // Force locally-administered + clear multicast bit.
    bytes[0] = (bytes[0] | 0x02) & !0x01;
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_mac_is_locally_administered_lowercase_and_stable() {
        let mac = derive_mac("vm-alpha");
        assert_eq!(mac.len(), 17, "AA:BB:CC:DD:EE:FF shape");
        let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(
            first_byte & 0x02,
            0x02,
            "locally-administered bit must be set: {mac}"
        );
        assert_eq!(first_byte & 0x01, 0, "multicast bit must be clear: {mac}");
        // Lowercase hex digits + colons only.
        assert!(
            mac.chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f' | ':')),
            "lowercase hex digits + colons only: {mac}"
        );
        // Stability across calls.
        assert_eq!(mac, derive_mac("vm-alpha"));
    }

    #[test]
    fn derive_mac_differs_for_different_names() {
        let a = derive_mac("vm-alpha");
        let b = derive_mac("vm-beta");
        assert_ne!(a, b);
    }

    #[test]
    fn socket_path_keeps_natural_path_when_it_fits() {
        let scratch = Path::new("/Users/u/.cache/mvm/builder-vm/vms/mvm-builder-vz-123");
        let cache = Path::new("/Users/u/.cache/mvm");
        let got = gvproxy_socket_path_in(scratch, cache);
        // Fits → unchanged behaviour: socket sits in the scratch dir.
        assert_eq!(got, scratch.join(SOCKET_FILE_NAME));
        assert!(got.as_os_str().len() < SUN_PATH_MAX);
    }

    #[test]
    fn socket_path_relocates_when_natural_path_exceeds_sun_path() {
        // A long cache root + the long persistent state-dir name pushes the
        // natural socket path over the AF_UNIX limit (the proof4 failure mode).
        let cache = Path::new("/Users/somebody/some-long-isolated-cache-dir/mvm");
        let scratch = cache
            .join("builder-vm/vms")
            .join("mvm-persistent-builder-vz-1782091841495-85253");
        let natural = scratch.join(SOCKET_FILE_NAME);
        assert!(
            natural.as_os_str().len() >= SUN_PATH_MAX,
            "fixture must exceed the limit: {} bytes",
            natural.as_os_str().len()
        );
        let got = gvproxy_socket_path_in(&scratch, cache);
        // Relocated: not the natural path, lives under <cache>/gv/, ends .sock,
        // and now fits the limit so gvproxy can bind it.
        assert_ne!(got, natural);
        assert_eq!(got.parent().unwrap(), cache.join("gv"));
        assert_eq!(got.extension().and_then(|e| e.to_str()), Some("sock"));
        assert!(
            got.as_os_str().len() < SUN_PATH_MAX,
            "relocated path must fit: {} bytes",
            got.as_os_str().len()
        );
    }

    #[test]
    fn socket_path_is_deterministic_and_collision_free() {
        let cache = Path::new("/Users/somebody/some-long-isolated-cache-dir/mvm");
        let a = cache.join("builder-vm/vms/mvm-persistent-builder-vz-1111111111111-11111");
        let b = cache.join("builder-vm/vms/mvm-persistent-builder-vz-2222222222222-22222");
        // Same input → same path (so spawn_detached and stop_by_pid_file agree).
        assert_eq!(
            gvproxy_socket_path_in(&a, cache),
            gvproxy_socket_path_in(&a, cache)
        );
        // Different VMs → different relocated sockets (no collision).
        assert_ne!(
            gvproxy_socket_path_in(&a, cache),
            gvproxy_socket_path_in(&b, cache)
        );
    }

    #[test]
    fn short_token_is_deterministic_fixed_length_and_distinct() {
        let a = short_token("scratch-a", 4);
        assert_eq!(a.len(), 8, "4 bytes → 8 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, short_token("scratch-a", 4)); // deterministic
        assert_ne!(a, short_token("scratch-b", 4)); // distinct inputs differ
        assert_eq!(short_token("x", 6).len(), 12); // 6 bytes → 12 hex
    }

    #[test]
    fn ssh_port_uses_a_free_os_assigned_port() {
        // The Vz lane reserves its gvproxy ssh-forward port the same
        // way the libkrun lane does — a fresh OS-assigned free port,
        // never a deterministic scratch-dir hash that could collide
        // with a leaked daemon.
        let port = libkrun_sys::gvproxy::free_loopback_port().expect("reserve a free port");
        assert!(port >= 1024, "port {port} below gvproxy's 1024 floor");
    }

    #[test]
    fn stop_by_pid_file_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        stop_by_pid_file(tmp.path()).expect("missing PID file is benign");
    }

    #[test]
    fn kill_by_pid_file_idempotent_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        kill_by_pid_file(tmp.path()).expect("missing PID file is benign");
    }

    #[test]
    fn kill_by_pid_file_sigkills_without_graceful_wait() {
        // A child that ignores SIGTERM: the graceful path would block the
        // full 2 s STOP_TIMEOUT, so a sub-second stop proves the fast path
        // SIGKILLed immediately.
        let tmp = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .spawn()
            .expect("spawn sleeper");
        std::fs::write(tmp.path().join(PID_FILE_NAME), child.id().to_string()).unwrap();
        let start = Instant::now();
        kill_by_pid_file(tmp.path()).expect("kill fast path");
        let elapsed = start.elapsed();
        let _ = child.wait();
        assert!(
            elapsed < Duration::from_millis(500),
            "fast teardown must not wait the graceful window; took {elapsed:?}"
        );
        assert!(!tmp.path().join(PID_FILE_NAME).exists());
    }

    #[test]
    fn stop_by_pid_file_cleans_up_stale_dead_pid() {
        // Use PID 1 only as a heuristic — pid 1 is always alive on
        // a Unix host, so this test would mis-fire. Use a high PID
        // that's almost certainly free (gvproxy doesn't run here
        // either).
        let tmp = tempfile::tempdir().unwrap();
        let pid_path = tmp.path().join(PID_FILE_NAME);
        // Pick a PID very unlikely to be alive on the test host.
        std::fs::write(&pid_path, "999999").unwrap();
        stop_by_pid_file(tmp.path()).expect("dead pid is cleaned up");
        assert!(!pid_path.exists(), "PID file should be removed");
    }
}
