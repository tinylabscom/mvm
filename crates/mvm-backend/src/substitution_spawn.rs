//! Plan 129 — shared per-VM substitution-endpoint spawn/reap helpers.
//!
//! One implementation behind the two workload backends that need it (QEMU
//! slirp + Firecracker TAP), so the moat-spawn logic can't drift between
//! copies. The endpoint is `mvm-substitution-endpoint` (an `mvm-hostd` bin):
//! when the admitted plan carries secret bindings it runs as a per-VM host
//! process that resolves placeholders for the guest's egress so the real
//! secret never enters the guest. The QEMU caller passes `terminator_listen:
//! None` (slirp has no TAP to redirect); the FC caller passes `Some(addr)` to
//! turn on the transparent HTTP terminator that the nft TAP REDIRECT feeds.

use anyhow::{Result, anyhow, bail};
use mvm_core::plan::SecretBinding;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Plan 129 — PID of the per-VM `mvm-substitution-endpoint` moat, and the JSON
/// file holding the `(guest var, placeholder)` env pairs it minted (the invoke
/// path reads this to inject `HTTP_PROXY` + placeholder vars). Spawned only when
/// the admitted plan carries secret bindings.
pub const SUBST_PID_FILE: &str = "substitution.pid";
/// How long the endpoint gets to bind its listener + write the ready handshake
/// line before the caller declares the spawn failed.
pub const SUBST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Locate the `mvm-substitution-endpoint` binary: `MVM_SUBSTITUTION_ENDPOINT_PATH`
/// override → sibling of the current exe → workspace `target/{release,debug}`.
/// Mirrors `resolve_vz_drainer_path`.
fn resolve_substitution_endpoint_path() -> Result<PathBuf> {
    const BIN: &str = "mvm-substitution-endpoint";
    if let Some(p) = std::env::var_os("MVM_SUBSTITUTION_ENDPOINT_PATH").map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "MVM_SUBSTITUTION_ENDPOINT_PATH points at {} which is not a file",
            p.display()
        );
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let candidate = dir.join(BIN);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root.join("target").join(variant).join(BIN);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("could not locate the {BIN} binary (set MVM_SUBSTITUTION_ENDPOINT_PATH)")
}

/// Plan 129 — spawn the per-VM `mvm-substitution-endpoint` moat. Hands it the
/// plan's secret bindings on stdin, reads back the minted `(guest var,
/// placeholder)` handshake line, and persists it to the per-VM substitution env
/// file for the invoke path to inject (`HTTP_PROXY` + placeholder vars). The
/// endpoint binds a host AF_VSOCK listener on `SUBSTITUTION_PORT` (the guest→
/// host substitution channel); when `terminator_listen` is `Some`, it *also*
/// runs the transparent HTTP terminator on that host TCP addr (Task 4) — the FC
/// nft TAP REDIRECT steers guest :80 there. Detached via `setsid` so it
/// outlives `mvmctl up`; the stop path reaps it via [`SUBST_PID_FILE`]. The real
/// secret values never leave the endpoint's address space — only the opaque
/// placeholders are persisted/handed out.
pub fn spawn_substitution_endpoint(
    vm_name: &str,
    state_dir: &Path,
    tenant: &str,
    secrets: &[SecretBinding],
    terminator_listen: Option<SocketAddr>,
) -> Result<()> {
    use std::io::Write;

    let bin = resolve_substitution_endpoint_path()?;
    let mut cfg = serde_json::json!({
        "tenant_id": tenant,
        "secrets": secrets,
        "transport": { "kind": "vsock", "port": mvm_guest::vsock::SUBSTITUTION_PORT },
    });
    if let Some(addr) = terminator_listen {
        // `EndpointConfig.terminator_listen: Option<SocketAddr>` (Task 4):
        // present ⇒ the endpoint runs the host TCP terminator concurrently with
        // the vsock substitution transport. `SocketAddr`'s Display ("ip:port")
        // is the wire form `serde(SocketAddr)` round-trips.
        cfg["terminator_listen"] = serde_json::Value::String(addr.to_string());
    }

    let mut cmd = Command::new(&bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // Detach into its own session so it survives this `mvmctl` process.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn substitution endpoint ({}): {e}", bin.display()))?;

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("substitution endpoint stdin was not piped"))?
        .write_all(cfg.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe EndpointConfig to substitution endpoint: {e}"))?;
    // (stdin writer dropped here → EOF, so the endpoint stops reading config.)

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("substitution endpoint stdout was not piped"))?;
    let handshake = read_handshake_line(stdout, child.id(), SUBST_HANDSHAKE_TIMEOUT)?;

    let pid_file = state_dir.join(SUBST_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    let env_path = mvm_core::config::vm_substitution_env_path(vm_name);
    std::fs::write(&env_path, handshake.trim().as_bytes())
        .map_err(|e| anyhow!("write {}: {e}", env_path.display()))?;
    // Detach: drop the child handle without killing. The endpoint runs
    // daemonized (setsid) and is reaped by the stop path via SUBST_PID_FILE.
    Ok(())
}

/// Read the endpoint's one-line ready handshake from its stdout within
/// `timeout`. A blocking pipe read can't be timed directly, so read on a
/// helper thread and bound the wait; on timeout / EOF-without-line, SIGKILL
/// the endpoint and fail (the caller rolls back the VM — fail closed).
fn read_handshake_line(
    stdout: std::process::ChildStdout,
    pid: u32,
    timeout: Duration,
) -> Result<String> {
    use std::io::{BufRead, BufReader};
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.trim().is_empty() => Ok(line),
        Ok(Ok(_)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("substitution endpoint closed stdout without a ready handshake")
        }
        Ok(Err(e)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("read substitution endpoint handshake: {e}")
        }
        Err(_) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("substitution endpoint handshake timed out after {timeout:?}")
        }
    }
}

/// Reap the per-VM substitution endpoint (if this VM spawned one) so its
/// decrypted secrets don't outlive the guest, and drop the pid + env sidecars.
/// Best-effort + idempotent: a VM with no endpoint (no secrets) is a no-op. The
/// liveness guard prevents signalling a recycled PID from a stale pidfile.
pub fn reap_substitution_endpoint(state_dir: &Path, vm_name: &str) {
    if let Some(spid) = read_pid(&state_dir.join(SUBST_PID_FILE))
        && pid_alive(spid)
    {
        kill(spid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(state_dir.join(SUBST_PID_FILE));
    let _ = std::fs::remove_file(mvm_core::config::vm_substitution_env_path(vm_name));
}

// ── pid helpers (local copies — backend modules keep theirs private) ──

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn kill(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(pid, sig);
    }
}
