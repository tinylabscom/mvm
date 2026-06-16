//! Per-VM `mvm-broker` subprocess spawn — the host-services broker the guest
//! reaches over vsock `BROKER_PORT`. Forwards `host.audit.v1` to the per-VM
//! audit-signer ([`crate::audit_signer_spawn`]); `host.time.v1`/`host.cost.v1`
//! handlers land later.
//!
//! Builds on [`crate::service_spawn`]. The broker's listener is the per-VM
//! vsock-port socket the VMM bridges the guest's `connect_host_vsock(BROKER_PORT)`
//! to — that path is **backend-shaped** (libkrun `vm_vsock_port_socket`, vz
//! `vm_vz_vsock_port_socket`), so the caller passes it. Everything else is
//! backend-agnostic.
//!
//! Spawned only for an admitted plan (a tenant is present), after the
//! audit-signer (the broker forwards audit to its UDS). Fail-closed via a
//! [`ServiceGuard`].

use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::audit_signer_spawn::audit_signer_uds_path;
use crate::audit_substrate::compute_audit_substrate;
use crate::service_spawn::{
    ServiceGuard, UdsServiceSpec, reap_service, resolve_service_binary, spawn_detached_uds_service,
};

/// Per-VM PID file for the broker, under the VM state dir.
pub const BROKER_PID_FILE: &str = "broker.pid";

const BROKER_BIN: &str = "mvm-broker";
const BROKER_PATH_ENV: &str = "MVM_BROKER_PATH";

/// Build the `mvm-broker` `SubprocessConfig` JSON. Hand-built (mvm-backend sits
/// below mvm-hostd; same pattern the substitution + audit-signer spawns use).
/// The shape must match `mvm_hostd::broker::config::SubprocessConfig`
/// (`#[serde(deny_unknown_fields)]`); `max_frame_bytes`/`parse_timeout` are left
/// to the type's serde defaults. A drift surfaces fail-closed as an early broker
/// exit caught by the bind wait.
fn build_broker_config(
    vm_name: &str,
    tenant: &str,
    listen_uds: &Path,
    host_signer_public_key_path: &Path,
    audit_signer_uds: &Path,
) -> serde_json::Value {
    serde_json::json!({
        "workload_id": vm_name,
        "tenant_id": tenant,
        "uds_path": listen_uds,
        "host_signer_public_key_path": host_signer_public_key_path,
        "audit_signer_uds_path": audit_signer_uds,
    })
}

/// Spawn the per-VM broker when the plan is admitted (a tenant is present),
/// binding `listen_uds` (the backend's vsock-port socket for `BROKER_PORT`).
/// Returns an armed [`ServiceGuard`]; a no-tenant VM yields a defused no-op.
/// Fail-closed.
pub fn spawn_broker_if_needed(
    vm_name: &str,
    state_dir: &Path,
    tenant_id: Option<&str>,
    listen_uds: &Path,
) -> Result<ServiceGuard> {
    let Some(tenant) = tenant_id else {
        return Ok(ServiceGuard::defused(reap_broker));
    };
    let substrate = compute_audit_substrate(vm_name, Some(tenant))
        .context("computing audit substrate for the broker")?;
    let signing_key_path = substrate
        .signing_key_path
        .ok_or_else(|| anyhow!("audit substrate has no signing key path for tenant '{tenant}'"))?;
    // The broker takes the host signer *public* key (sibling of the secret:
    // host-signer.ed25519 → host-signer.pub) for secrets-dispatcher response
    // verification; carried now so the config shape is stable.
    let pub_key_path = signing_key_path.with_extension("pub");

    let config = build_broker_config(
        vm_name,
        tenant,
        listen_uds,
        &pub_key_path,
        &audit_signer_uds_path(state_dir),
    );
    let bin = resolve_service_binary(BROKER_BIN, BROKER_PATH_ENV)?;
    spawn_detached_uds_service(UdsServiceSpec {
        bin: &bin,
        config_json: &config,
        listen_uds,
        pid_file: &state_dir.join(BROKER_PID_FILE),
    })?;
    Ok(ServiceGuard::armed(vm_name, reap_broker))
}

/// Reap the per-VM broker (if this VM spawned one). Best-effort + idempotent.
/// The vsock-port listen socket is backend-shaped (not derivable from the state
/// dir alone) and is cleared by the next spawn's stale-socket sweep, so reap
/// only signals the process + drops the PID file.
pub fn reap_broker(state_dir: &Path) {
    reap_service(&state_dir.join(BROKER_PID_FILE), &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tenant_yields_defused_noop_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let mut guard = spawn_broker_if_needed(
            "no-tenant-vm",
            tmp.path(),
            None,
            &tmp.path().join("vsock-5300.sock"),
        )
        .expect("no-op");
        assert!(!tmp.path().join(BROKER_PID_FILE).exists());
        guard.defuse();
    }

    #[test]
    fn config_has_the_required_broker_fields() {
        let cfg = build_broker_config(
            "vm-1",
            "tenant-a",
            Path::new("/state/vm-1/vsock-5300.sock"),
            Path::new("/k/host-signer.pub"),
            Path::new("/state/vm-1/services/audit-signer.sock"),
        );
        let obj = cfg.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "audit_signer_uds_path",
                "host_signer_public_key_path",
                "tenant_id",
                "uds_path",
                "workload_id",
            ]
        );
        assert_eq!(obj["workload_id"], "vm-1");
        assert_eq!(obj["tenant_id"], "tenant-a");
        assert_eq!(obj["uds_path"], "/state/vm-1/vsock-5300.sock");
        assert_eq!(
            obj["audit_signer_uds_path"],
            "/state/vm-1/services/audit-signer.sock"
        );
        assert_eq!(obj["host_signer_public_key_path"], "/k/host-signer.pub");
    }

    #[test]
    fn reap_is_idempotent_noop_without_pidfile() {
        let tmp = tempfile::tempdir().unwrap();
        reap_broker(tmp.path());
        reap_broker(tmp.path());
    }
}
