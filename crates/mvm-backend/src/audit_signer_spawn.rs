//! Per-VM `mvm-audit-signer` subprocess spawn — the host-side moat that holds
//! the workload audit chain-signing key and is the sole writer of a VM's
//! `<tenant>.<vm>.workload.jsonl` chain.
//!
//! Mirrors [`crate::substitution_spawn`]: resolve the binary, hand it a JSON
//! config on stdin, detach via `setsid` so it outlives `mvmctl`, wait for it to
//! bind its UDS, persist a PID for the stop path to reap. Unlike the
//! substitution endpoint there are no backend-shaped fields (the audit-signer
//! always speaks a host UDS), so one spawn path serves both libkrun and vz.
//!
//! Spawned only for an admitted plan (a tenant is present) — the same gate the
//! audit substrate uses, so the signer comes up exactly where the chain it
//! writes is already active. Fail-closed: a spawn failure rolls the launch back
//! (an admitted workload must not run unaudited), and the [`AuditSignerGuard`]
//! reaps the process if `start` errors before the VM is up.
//!
//! The chain key is the host signer key (`compute_audit_substrate`'s
//! `signing_key_path`) so the workload chain shares one trust root with the
//! claim-8 lifecycle chain and `mvmctl audit verify` verifies both under the
//! same public key. Nothing dials the signer until the broker lands (the next
//! slice); this slice just stands it up.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::audit_substrate::compute_audit_substrate;

/// Per-VM PID file for the audit-signer, under the VM state dir.
pub const AUDIT_SIGNER_PID_FILE: &str = "audit-signer.pid";

/// How long the signer gets to bind its UDS before the spawn is declared failed.
const AUDIT_SIGNER_BIND_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval while waiting for the UDS to appear.
const AUDIT_SIGNER_POLL: Duration = Duration::from_millis(25);

/// The per-VM UDS the audit-signer binds and the broker dials (next slice).
/// Grouped under the VM state dir's `services/` with the other per-VM broker
/// sockets; the parent is created mode 0700.
pub fn audit_signer_uds_path(state_dir: &Path) -> PathBuf {
    state_dir.join("services").join("audit-signer.sock")
}

/// Secondary chain-head persistence file (the signer writes the latest head
/// here after every append; a verify path can cross-check it).
fn audit_signer_head_path(state_dir: &Path) -> PathBuf {
    state_dir.join("services").join("audit-signer.head")
}

/// Locate the `mvm-audit-signer` binary: `MVM_AUDIT_SIGNER_PATH` override →
/// sibling of the current exe → workspace `target/{release,debug}`. Mirrors
/// [`crate::substitution_spawn`]'s resolver.
fn resolve_audit_signer_path() -> Result<PathBuf> {
    const BIN: &str = "mvm-audit-signer";
    if let Some(p) = std::env::var_os("MVM_AUDIT_SIGNER_PATH").map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "MVM_AUDIT_SIGNER_PATH points at {} which is not a file",
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
    bail!("could not locate the {BIN} binary (set MVM_AUDIT_SIGNER_PATH)")
}

/// Build the `mvm-audit-signer` `SubprocessConfig` JSON. Hand-built (not the
/// typed struct) because `mvm-backend` sits below `mvm-hostd` and can't import
/// it — same pattern the substitution spawn uses. The shape must match
/// `mvm_hostd::audit_signer::config::SubprocessConfig` (`#[serde(deny_unknown_fields)]`):
/// a drift surfaces as an early signer exit, caught fail-closed by the bind wait.
///
/// `workload_id` is the signer's identity label (used in its logs); the
/// authoritative per-entry `workload_id` is stamped by the broker's
/// `ServiceCallCtx` on each append (next slice), not taken from here.
fn build_audit_signer_config(
    vm_name: &str,
    tenant: &str,
    uds_path: &Path,
    audit_jsonl_path: &Path,
    head_path: &Path,
    signing_key_path: &Path,
) -> serde_json::Value {
    serde_json::json!({
        "workload_id": vm_name,
        "tenant_id": tenant,
        "uds_path": uds_path,
        "audit_jsonl_path": audit_jsonl_path,
        "chain_head_secondary_path": head_path,
        "software_chain_key_path": signing_key_path,
    })
}

/// Spawn the per-VM audit-signer when the plan is admitted (a tenant is
/// present). Returns an armed [`AuditSignerGuard`]; a no-tenant VM yields a
/// defused no-op guard. Fail-closed: any spawn error propagates so the backend
/// rolls the launch back.
pub fn spawn_audit_signer_if_needed(
    vm_name: &str,
    state_dir: &Path,
    tenant_id: Option<&str>,
) -> Result<AuditSignerGuard> {
    let Some(tenant) = tenant_id else {
        return Ok(AuditSignerGuard::defused());
    };
    let substrate = compute_audit_substrate(vm_name, Some(tenant))
        .context("computing audit substrate for the audit-signer")?;
    // Both are Some whenever a tenant is present; bail rather than spawn a
    // keyless signer (it would mint a throwaway key the verifier can't trust).
    let signing_key_path = substrate
        .signing_key_path
        .ok_or_else(|| anyhow!("audit substrate has no signing key path for tenant '{tenant}'"))?;
    let audit_dir = substrate
        .audit_dir
        .ok_or_else(|| anyhow!("audit substrate has no audit dir for tenant '{tenant}'"))?;

    spawn_audit_signer(AuditSignerSpawnParams {
        vm_name,
        state_dir,
        tenant,
        audit_dir: &audit_dir,
        signing_key_path: &signing_key_path,
    })?;
    Ok(AuditSignerGuard::new(vm_name))
}

/// Inputs to [`spawn_audit_signer`].
struct AuditSignerSpawnParams<'a> {
    vm_name: &'a str,
    state_dir: &'a Path,
    tenant: &'a str,
    /// The chain dir (`~/.mvm/audit/`); created if absent so the signer can
    /// open the JSONL.
    audit_dir: &'a Path,
    /// Host signer key the signer signs the chain with.
    signing_key_path: &'a Path,
}

/// Spawn the signer: prepare the dirs, hand it the config on stdin, detach, wait
/// for the UDS bind, persist the PID. Fail-closed on every step.
fn spawn_audit_signer(params: AuditSignerSpawnParams<'_>) -> Result<()> {
    use std::io::Write;
    let AuditSignerSpawnParams {
        vm_name,
        state_dir,
        tenant,
        audit_dir,
        signing_key_path,
    } = params;

    // The chain dir must exist for the signer to create the JSONL; the services
    // dir holds the per-VM UDS + secondary head. Both mode 0700.
    ensure_private_dir(audit_dir)?;
    let services_dir = state_dir.join("services");
    ensure_private_dir(&services_dir)?;

    let uds_path = audit_signer_uds_path(state_dir);
    // A stale socket from a prior run would fail the new bind; clear it.
    let _ = std::fs::remove_file(&uds_path);
    let head_path = audit_signer_head_path(state_dir);
    let jsonl_path = mvm_core::config::workload_audit_path(tenant, vm_name);

    let cfg = build_audit_signer_config(
        vm_name,
        tenant,
        &uds_path,
        &jsonl_path,
        &head_path,
        signing_key_path,
    );

    let bin = resolve_audit_signer_path()?;
    let mut cmd = Command::new(&bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
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
        .map_err(|e| anyhow!("spawn audit-signer ({}): {e}", bin.display()))?;

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("audit-signer stdin was not piped"))?
        .write_all(cfg.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe SubprocessConfig to audit-signer: {e}"))?;
    // (stdin writer dropped here → EOF, so the signer stops reading config.)

    // The signer writes no stdout handshake; readiness is the UDS appearing.
    wait_for_uds_bind(&mut child, &uds_path)?;

    let pid_file = state_dir.join(AUDIT_SIGNER_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    // Detach: drop the child handle without killing. The signer is daemonized
    // (setsid) and is reaped by the stop path via AUDIT_SIGNER_PID_FILE.
    Ok(())
}

/// Poll until `uds_path` exists (the signer bound its listener) or the bind
/// times out / the child exits early. SIGKILL + bail on failure — the caller
/// rolls the VM back (fail closed).
fn wait_for_uds_bind(child: &mut std::process::Child, uds_path: &Path) -> Result<()> {
    let start = Instant::now();
    loop {
        if uds_path.exists() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("waiting on audit-signer: {e}"))?
        {
            bail!("audit-signer exited before binding its UDS (status {status})");
        }
        if start.elapsed() > AUDIT_SIGNER_BIND_TIMEOUT {
            let _ = child.kill();
            bail!(
                "audit-signer did not bind {} within {:?}",
                uds_path.display(),
                AUDIT_SIGNER_BIND_TIMEOUT
            );
        }
        std::thread::sleep(AUDIT_SIGNER_POLL);
    }
}

/// Reap the per-VM audit-signer (if this VM spawned one) and drop its PID +
/// socket sidecars. Best-effort + idempotent: a VM with no signer is a no-op.
/// The liveness check prevents signalling a recycled PID from a stale pidfile.
pub fn reap_audit_signer(state_dir: &Path) {
    if let Some(pid) = read_pid(&state_dir.join(AUDIT_SIGNER_PID_FILE))
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(state_dir.join(AUDIT_SIGNER_PID_FILE));
    let _ = std::fs::remove_file(audit_signer_uds_path(state_dir));
}

/// RAII reaper for the per-VM audit-signer, armed while a backend's `start` is
/// wiring the VM and dropped on any early-return so the signer can't outlive a
/// failed launch. Defused once the VM is fully up (the `stop` path then owns
/// teardown). Shared by libkrun + vz so the spawn/reap moat can't drift.
pub struct AuditSignerGuard {
    /// `Some(name)` while armed; `None` once defused.
    vm_name: Option<String>,
}

impl AuditSignerGuard {
    fn new(vm_name: &str) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
        }
    }
    /// A guard for a VM that spawned no signer (no tenant) — Drop is a no-op.
    fn defused() -> Self {
        Self { vm_name: None }
    }
    pub fn defuse(&mut self) {
        self.vm_name = None;
    }
}

impl Drop for AuditSignerGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            tracing::warn!(vm = %name, "AuditSignerGuard: reaping orphaned audit-signer");
            reap_audit_signer(&mvm_core::config::vm_state_dir(name));
        }
    }
}

// ── dir + pid helpers (local copies — backend modules keep theirs private) ──

/// Create `dir` (and parents) at mode 0700, idempotently.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut perms = std::fs::metadata(dir)
        .with_context(|| format!("stat {}", dir.display()))?
        .permissions();
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

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

    #[test]
    fn no_tenant_yields_defused_noop_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let mut guard =
            spawn_audit_signer_if_needed("no-tenant-vm", tmp.path(), None).expect("no-op");
        // No PID file written, nothing to reap.
        assert!(!tmp.path().join(AUDIT_SIGNER_PID_FILE).exists());
        guard.defuse(); // defusing a defused guard is harmless
    }

    #[test]
    fn config_has_exactly_the_subprocess_config_fields() {
        let cfg = build_audit_signer_config(
            "vm-1",
            "tenant-a",
            Path::new("/s/audit-signer.sock"),
            Path::new("/a/tenant-a.vm-1.workload.jsonl"),
            Path::new("/s/audit-signer.head"),
            Path::new("/k/host-signer.ed25519"),
        );
        let obj = cfg.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "audit_jsonl_path",
                "chain_head_secondary_path",
                "software_chain_key_path",
                "tenant_id",
                "uds_path",
                "workload_id",
            ]
        );
        assert_eq!(obj["workload_id"], "vm-1");
        assert_eq!(obj["tenant_id"], "tenant-a");
        assert_eq!(obj["audit_jsonl_path"], "/a/tenant-a.vm-1.workload.jsonl");
        assert_eq!(obj["software_chain_key_path"], "/k/host-signer.ed25519");
    }

    #[test]
    fn uds_and_head_live_under_services_dir() {
        let sd = Path::new("/state/myvm");
        assert_eq!(
            audit_signer_uds_path(sd),
            Path::new("/state/myvm/services/audit-signer.sock")
        );
        assert_eq!(
            audit_signer_head_path(sd),
            Path::new("/state/myvm/services/audit-signer.head")
        );
    }

    #[test]
    fn resolve_rejects_bad_env_override() {
        // SAFETY: single-threaded test; restored before return.
        unsafe { std::env::set_var("MVM_AUDIT_SIGNER_PATH", "/nonexistent/mvm-audit-signer") };
        let err = resolve_audit_signer_path().unwrap_err();
        unsafe { std::env::remove_var("MVM_AUDIT_SIGNER_PATH") };
        assert!(err.to_string().contains("is not a file"), "{err}");
    }

    #[test]
    fn reap_is_idempotent_noop_without_pidfile() {
        let tmp = tempfile::tempdir().unwrap();
        // No PID file → no panic, no error.
        reap_audit_signer(tmp.path());
        reap_audit_signer(tmp.path());
    }
}
