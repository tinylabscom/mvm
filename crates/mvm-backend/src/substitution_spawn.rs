//! Shared per-VM substitution-endpoint spawn/reap helpers.
//!
//! One implementation behind the two workload backends that need it (QEMU
//! slirp + Firecracker TAP), so the moat-spawn logic can't drift between
//! copies. The endpoint is `mvm-substitution-endpoint` (an `mvm-hostd` bin):
//! when the admitted plan carries secret bindings it runs as a per-VM host
//! process that resolves placeholders for the guest's egress so the real
//! secret never enters the guest. The QEMU caller passes `terminator_listen:
//! None` (slirp has no TAP to redirect); the FC caller passes `Some(addr)` to
//! turn on the transparent HTTP terminator that the nft TAP REDIRECT feeds.

use crate::microvm::DriveFile;
use anyhow::{Result, anyhow, bail};
use mvm_core::crypto::egress_ca::EgressCa;
use mvm_core::plan::SecretBinding;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// The per-VM egress intermediate cert lands in the guest's `mvm-secrets`
/// drive under this filename; the mkGuest boot step appends it to the guest
/// trust bundle before the entrypoint runs.
pub const EGRESS_CERT_DRIVE_NAME: &str = "mvm-egress.crt";

/// The cert/key split the egress CA exists to enforce. The guest receives
/// only `guest_cert` (the intermediate's PEM **cert**, so it can
/// trust host-terminated bound-host TLS); the terminator endpoint receives the
/// cert **and** key (`endpoint_cert_pem` / `endpoint_key_pem`) to mint per-SNI
/// leaves. The intermediate key never enters the guest secrets drive — the same
/// claim-13 "no key on the guest" invariant the substitution channel upholds.
pub struct EgressTlsDelivery {
    /// Cert-only file injected into the guest `mvm-secrets` drive.
    pub guest_cert: DriveFile,
    /// The intermediate cert PEM the endpoint terminates under (== guest cert).
    pub endpoint_cert_pem: String,
    /// The intermediate key PEM — terminator-side only, NEVER to a guest.
    pub endpoint_key_pem: String,
}

// Manual redacted Debug: this struct carries the intermediate private key, so
// its `Debug` must never print key bytes (xtask check-no-display-on-secret-types
// parity with `VmIntermediate`).
impl std::fmt::Debug for EgressTlsDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressTlsDelivery")
            .field("guest_cert", &self.guest_cert.name)
            .field("endpoint_cert_pem", &"<intermediate cert>")
            .field("endpoint_key_pem", &"<redacted>")
            .finish()
    }
}

/// Mint the per-VM name-constrained intermediate (loading/initialising the
/// long-lived host egress CA under `ca_dir`) and split
/// it: cert to the guest secrets drive, cert+key to the terminator endpoint. A
/// pure, unit-testable helper; the boot path calls it when the admitted plan
/// carries secrets and threads the result into `create_dev_secrets_drive` (guest)
/// and the `EndpointConfig` (host). `bound_hosts` are the plan's allowed egress
/// hosts — the intermediate's `nameConstraints permitted` is exactly this set.
pub fn build_egress_tls_delivery(bound_hosts: &[&str], ca_dir: &Path) -> Result<EgressTlsDelivery> {
    let ca = EgressCa::load_or_init_at(ca_dir)
        .map_err(|e| anyhow!("load/init egress CA at {}: {e}", ca_dir.display()))?;
    let inter = ca
        .mint_vm_intermediate(bound_hosts)
        .map_err(|e| anyhow!("mint per-VM egress intermediate: {e}"))?;
    let cert_pem = inter.cert_pem().to_string();
    let key_pem = inter.key_pem();
    Ok(EgressTlsDelivery {
        guest_cert: DriveFile {
            name: EGRESS_CERT_DRIVE_NAME.to_string(),
            content: cert_pem.clone(),
            mode: 0o444,
        },
        endpoint_cert_pem: cert_pem,
        endpoint_key_pem: key_pem,
    })
}

/// PID of the per-VM `mvm-substitution-endpoint` moat, and the JSON
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

/// Spawn the per-VM `mvm-substitution-endpoint` moat. Hands it the
/// plan's secret bindings on stdin, reads back the minted `(guest var,
/// placeholder)` handshake line, and persists it to the per-VM substitution env
/// file for the invoke path to inject (`HTTP_PROXY` + placeholder vars). The
/// endpoint binds a host AF_VSOCK listener on `SUBSTITUTION_PORT` (the guest→
/// host substitution channel); when `terminator_listen` is `Some`, it *also*
/// runs the transparent HTTP terminator on that host TCP addr — the FC
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
    tls_intermediate: Option<(String, String)>,
) -> Result<()> {
    use std::io::Write;

    let bin = resolve_substitution_endpoint_path()?;
    let mut cfg = serde_json::json!({
        "tenant_id": tenant,
        "secrets": secrets,
        "transport": { "kind": "vsock", "port": mvm_guest::vsock::SUBSTITUTION_PORT },
    });
    if let Some(addr) = terminator_listen {
        // `EndpointConfig.terminator_listen: Option<SocketAddr>`:
        // present ⇒ the endpoint runs the host TCP terminator concurrently with
        // the vsock substitution transport. `SocketAddr`'s Display ("ip:port")
        // is the wire form `serde(SocketAddr)` round-trips.
        cfg["terminator_listen"] = serde_json::Value::String(addr.to_string());
    }
    if let Some((cert_pem, key_pem)) = tls_intermediate {
        // `EndpointConfig.tls_intermediate`: the per-VM name-constrained
        // intermediate the `https` terminator mints per-SNI leaves under. The
        // KEY only ever reaches this host endpoint — never the guest.
        cfg["tls_intermediate"] = serde_json::json!({
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    // `stop_vm` reaps the moat BEFORE its not-running early return (so a crashed
    // VM's decrypted-secret endpoint can't outlive the guest). That ordering is
    // only safe because reap is a no-op when nothing exists — assert it here.
    #[test]
    fn reap_is_noop_when_nothing_exists() {
        let dir = std::env::temp_dir().join(format!("mvm-reap-noop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        reap_substitution_endpoint(&dir, "nonexistent-vm");
        // Idempotent: a second call on the same empty dir is still clean.
        reap_substitution_endpoint(&dir, "nonexistent-vm");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── the cert-to-guest / key-to-endpoint split ──

    // The whole point of the egress CA: the guest may trust the per-VM
    // intermediate cert (to accept host-terminated bound-host TLS), but the
    // intermediate KEY must never reach the guest — same claim-13 "no key on the
    // guest" invariant the substitution channel already upholds. Assert the
    // split holds by construction.
    #[test]
    fn egress_tls_delivery_gives_cert_to_guest_key_to_endpoint() {
        let dir = std::env::temp_dir().join(format!("mvm-egress-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let d = build_egress_tls_delivery(&["api.openai.com"], &dir).unwrap();

        // The guest file is a cert at the fixed drive filename, world-readable.
        assert_eq!(d.guest_cert.name, EGRESS_CERT_DRIVE_NAME);
        assert_eq!(d.guest_cert.mode, 0o444);
        assert!(d.guest_cert.content.contains("BEGIN CERTIFICATE"));

        // The endpoint gets BOTH halves (it serves leaves under this intermediate).
        assert!(d.endpoint_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(d.endpoint_key_pem.contains("PRIVATE KEY"));

        // INVARIANT: no private-key material reaches the guest-delivered file.
        assert!(
            !d.guest_cert.content.contains("PRIVATE KEY"),
            "intermediate key leaked into the guest cert file"
        );
        // The guest must trust exactly the cert the endpoint terminates under.
        assert_eq!(d.guest_cert.content.trim(), d.endpoint_cert_pem.trim());

        std::fs::remove_dir_all(&dir).ok();
    }

    // The key-carrying delivery struct must not expose secret bytes via Debug
    // (xtask check-no-display-on-secret-types parity).
    #[test]
    fn egress_tls_delivery_debug_is_redacted() {
        let dir = std::env::temp_dir().join(format!("mvm-egress-ca-dbg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = build_egress_tls_delivery(&["api.openai.com"], &dir).unwrap();
        let dbg = format!("{d:?}");
        assert!(
            !dbg.contains("PRIVATE KEY"),
            "key bytes leaked via Debug: {dbg}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
