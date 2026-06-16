//! Per-VM `mvm-audit-signer` subprocess spawn — the host-side moat that holds
//! the workload audit chain-signing key and is the sole writer of a VM's
//! `<tenant>.<vm>.workload.jsonl` chain.
//!
//! Builds on [`crate::service_spawn`] (resolve binary → `setsid`-detach → pipe
//! config → wait for the UDS bind → PID → reap). Unlike the broker the
//! audit-signer's UDS is host-internal (the broker dials it; the guest never
//! does), so it lives under the VM state dir's `services/`.
//!
//! Spawned only for an admitted plan (a tenant is present) — the same gate the
//! audit substrate uses, so the signer comes up exactly where the chain it
//! writes is already active. Fail-closed: a spawn failure rolls the launch back
//! (an admitted workload must not run unaudited), and the [`ServiceGuard`] reaps
//! the process if `start` errors before the VM is up.
//!
//! The chain key is the host signer key (`compute_audit_substrate`'s
//! `signing_key_path`) so the workload chain shares one trust root with the
//! claim-8 lifecycle chain and `mvmctl audit verify` verifies both under the
//! same public key.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::audit_substrate::compute_audit_substrate;
use crate::service_spawn::{
    ServiceGuard, UdsServiceSpec, ensure_private_dir, reap_service, resolve_service_binary,
    spawn_detached_uds_service,
};

/// Per-VM PID file for the audit-signer, under the VM state dir.
pub const AUDIT_SIGNER_PID_FILE: &str = "audit-signer.pid";

const AUDIT_SIGNER_BIN: &str = "mvm-audit-signer";
const AUDIT_SIGNER_PATH_ENV: &str = "MVM_AUDIT_SIGNER_PATH";

/// The per-VM UDS the audit-signer binds and the broker dials. Grouped under the
/// VM state dir's `services/` (created mode 0700).
pub fn audit_signer_uds_path(state_dir: &Path) -> PathBuf {
    state_dir.join("services").join("audit-signer.sock")
}

/// Secondary chain-head persistence file (the signer writes the latest head
/// here after every append; a verify path can cross-check it).
fn audit_signer_head_path(state_dir: &Path) -> PathBuf {
    state_dir.join("services").join("audit-signer.head")
}

/// Build the `mvm-audit-signer` `SubprocessConfig` JSON. Hand-built (not the
/// typed struct) because `mvm-backend` sits below `mvm-hostd` and can't import
/// it — same pattern the substitution spawn uses. The shape must match
/// `mvm_hostd::audit_signer::config::SubprocessConfig` (`#[serde(deny_unknown_fields)]`):
/// a drift surfaces as an early signer exit, caught fail-closed by the bind wait.
///
/// `workload_id` is the signer's identity label (used in its logs); the
/// authoritative per-entry `workload_id` is stamped by the broker's
/// `ServiceCallCtx` on each append, not taken from here.
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
/// present). Returns an armed [`ServiceGuard`]; a no-tenant VM yields a defused
/// no-op guard. Fail-closed: any spawn error propagates so the backend rolls the
/// launch back.
pub fn spawn_audit_signer_if_needed(
    vm_name: &str,
    state_dir: &Path,
    tenant_id: Option<&str>,
) -> Result<ServiceGuard> {
    let Some(tenant) = tenant_id else {
        return Ok(ServiceGuard::defused(reap_audit_signer));
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

    // The chain dir must exist for the signer to create the JSONL; the services
    // dir holds the per-VM UDS + secondary head. Both mode 0700.
    ensure_private_dir(&audit_dir)?;
    ensure_private_dir(&state_dir.join("services"))?;

    let uds_path = audit_signer_uds_path(state_dir);
    let config = build_audit_signer_config(
        vm_name,
        tenant,
        &uds_path,
        &mvm_core::config::workload_audit_path(tenant, vm_name),
        &audit_signer_head_path(state_dir),
        &signing_key_path,
    );
    let bin = resolve_service_binary(AUDIT_SIGNER_BIN, AUDIT_SIGNER_PATH_ENV)?;
    spawn_detached_uds_service(UdsServiceSpec {
        bin: &bin,
        config_json: &config,
        listen_uds: &uds_path,
        pid_file: &state_dir.join(AUDIT_SIGNER_PID_FILE),
    })?;
    Ok(ServiceGuard::armed(vm_name, reap_audit_signer))
}

/// Reap the per-VM audit-signer (if this VM spawned one). Best-effort +
/// idempotent: a VM with no signer is a no-op.
pub fn reap_audit_signer(state_dir: &Path) {
    reap_service(
        &state_dir.join(AUDIT_SIGNER_PID_FILE),
        &[audit_signer_uds_path(state_dir)],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tenant_yields_defused_noop_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let mut guard =
            spawn_audit_signer_if_needed("no-tenant-vm", tmp.path(), None).expect("no-op");
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
    fn reap_is_idempotent_noop_without_pidfile() {
        let tmp = tempfile::tempdir().unwrap();
        reap_audit_signer(tmp.path());
        reap_audit_signer(tmp.path());
    }
}
