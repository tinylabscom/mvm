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

    let socket_path = scratch_dir.join(SOCKET_FILE_NAME);
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

/// Read the PID file under `scratch_dir`, SIGTERM the gvproxy
/// process, wait up to `STOP_TIMEOUT` for it to exit, and fall
/// back to SIGKILL. Removes the PID file + socket file on success
/// or on a clean already-gone state. Idempotent — no-op when the
/// PID file is missing or the named process is already gone.
pub fn stop_by_pid_file(scratch_dir: &Path) -> Result<()> {
    let pid_path = scratch_dir.join(PID_FILE_NAME);
    let socket_path = scratch_dir.join(SOCKET_FILE_NAME);

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

    // SAFETY: pid was just probed alive; SIGTERM on a stale pid
    // returns ESRCH which we treat as a benign race.
    unsafe { libc::kill(pid, libc::SIGTERM) };

    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if pid_alive(pid) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
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
