//! Tenant-scoped audit signer helper core.
//!
//! The per-VM `mvm-audit-signer` binary owns exactly one [`Chain`]. The resident
//! helper owns the same signing key but keeps one chain head per registered VM,
//! so a tenant can run many VMs without spawning one key-holding process per VM.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::naming::{validate_id, validate_vm_name};
use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, AuditSignerErrorCode,
};

use crate::audit_signer::chain::Chain;
use crate::audit_signer::server::dispatch_on_chain;

/// A VM chain the tenant helper should open and own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperVmRegistration {
    /// Server-derived VM id. Used only for routing inside the helper.
    pub vm_id: String,
    /// Tenant this VM belongs to. Must match the helper's tenant.
    pub tenant_id: String,
    /// Workload id stamped by the host-agent path before forwarding appends.
    pub workload_id: String,
    /// Per-VM workload audit JSONL path.
    pub workload_chain_path: PathBuf,
    /// Per-VM secondary chain-head path.
    pub chain_head_secondary_path: PathBuf,
}

struct VmChain {
    workload_id: String,
    chain: Chain,
}

/// One key-holding helper per tenant, with one in-memory chain head per VM.
pub struct TenantSignerHelper {
    tenant_id: String,
    software_chain_key_path: Option<PathBuf>,
    vms: HashMap<String, VmChain>,
}

impl TenantSignerHelper {
    /// Create an empty helper for one tenant.
    pub fn new(tenant_id: impl Into<String>, software_chain_key_path: Option<PathBuf>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            software_chain_key_path,
            vms: HashMap::new(),
        }
    }

    /// Number of registered VM chains currently owned by this helper.
    pub fn registration_count(&self) -> usize {
        self.vms.len()
    }

    /// Whether this helper currently owns a chain for `vm_id`.
    pub fn is_registered(&self, vm_id: &str) -> bool {
        self.vms.contains_key(vm_id)
    }

    /// Current chain head for a registered VM.
    pub fn chain_head(&self, vm_id: &str) -> Option<&str> {
        self.vms.get(vm_id).map(|vm| vm.chain.head())
    }

    /// Register or replace a VM chain. The helper opens the chain and owns the
    /// file descriptor until deregistration or process exit.
    pub fn register_vm(&mut self, reg: HelperVmRegistration) -> Result<()> {
        validate_id(&self.tenant_id, "tenant")?;
        validate_id(&reg.tenant_id, "tenant")?;
        if reg.tenant_id != self.tenant_id {
            bail!(
                "register for tenant {:?} on helper for tenant {:?}",
                reg.tenant_id,
                self.tenant_id
            );
        }
        validate_vm_name(&reg.vm_id)?;
        ensure_parent(&reg.workload_chain_path, "workload audit chain")?;
        ensure_parent(&reg.chain_head_secondary_path, "secondary chain head")?;

        let chain = Chain::open(
            &reg.workload_chain_path,
            &reg.chain_head_secondary_path,
            self.software_chain_key_path.as_deref(),
        )
        .with_context(|| format!("open workload audit chain for vm {}", reg.vm_id))?;

        self.vms.insert(
            reg.vm_id,
            VmChain {
                workload_id: reg.workload_id,
                chain,
            },
        );
        Ok(())
    }

    /// Deregister a VM. Dropping the owned [`Chain`] closes the append fd.
    pub fn deregister_vm(&mut self, vm_id: &str) {
        self.vms.remove(vm_id);
    }

    /// Append a request to the chain selected by the server-derived `vm_id`.
    pub fn append_for_vm(&mut self, vm_id: &str, req: AppendEntryRequest) -> AppendEntryResponse {
        let request_id = req.request_id().to_string();
        let Some(registered_workload_id) = self.vms.get(vm_id).map(|vm| vm.workload_id.clone())
        else {
            return AppendEntryResponse::Err {
                request_id,
                code: AuditSignerErrorCode::NotReady,
                message: "vm is not registered with the tenant signer helper".into(),
            };
        };
        if let Err(message) =
            validate_append_identity(&self.tenant_id, &req, &registered_workload_id)
        {
            return AppendEntryResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message,
            };
        }
        let vm = self
            .vms
            .get_mut(vm_id)
            .expect("registered vm chain must exist after preflight lookup");
        dispatch_on_chain(req, &mut vm.chain)
    }
}

fn validate_append_identity(
    helper_tenant_id: &str,
    req: &AppendEntryRequest,
    registered_workload_id: &str,
) -> std::result::Result<(), String> {
    match req {
        AppendEntryRequest::Probe { .. } => Ok(()),
        AppendEntryRequest::AppendEntry {
            tenant_id,
            workload_id,
            ..
        } => {
            if tenant_id != helper_tenant_id {
                return Err(format!(
                    "append tenant {:?} does not match helper tenant {:?}",
                    tenant_id, helper_tenant_id
                ));
            }
            if workload_id != registered_workload_id {
                return Err(format!(
                    "append workload {:?} does not match registered workload {:?}",
                    workload_id, registered_workload_id
                ));
            }
            Ok(())
        }
    }
}

fn ensure_parent(path: &Path, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{label} path {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create {label} parent {}", parent.display()))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use tempfile::tempdir;

    use super::*;
    use crate::audit_signer::canonical::CanonicalEntry;
    use crate::audit_signer::verify::verify_workload_chain;

    fn write_key(dir: &Path) -> (PathBuf, VerifyingKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let path = dir.join("host-signer.ed25519");
        std::fs::write(&path, key.to_bytes()).unwrap();
        (path, key.verifying_key())
    }

    fn registration(dir: &Path, tenant: &str, vm: &str, workload: &str) -> HelperVmRegistration {
        HelperVmRegistration {
            vm_id: vm.into(),
            tenant_id: tenant.into(),
            workload_id: workload.into(),
            workload_chain_path: dir.join(format!("{tenant}.{vm}.workload.jsonl")),
            chain_head_secondary_path: dir.join(format!("{tenant}.{vm}.head")),
        }
    }

    fn append_request(req: &str, tenant: &str, workload: &str) -> AppendEntryRequest {
        AppendEntryRequest::AppendEntry {
            request_id: req.into(),
            category: "workload_audit".into(),
            ts: "2026-06-17T00:00:00Z".into(),
            workload_id: workload.into(),
            tenant_id: tenant.into(),
            session_id: "sess-001".into(),
            correlation_id: format!("corr-{req}"),
            fields: serde_json::json!({"message": req}),
        }
    }

    fn ok_head(resp: AppendEntryResponse) -> String {
        match resp {
            AppendEntryResponse::Ok { chain_head, .. } => chain_head,
            other => panic!("expected ok response, got {other:?}"),
        }
    }

    #[test]
    fn register_vm_opens_independent_per_vm_chains() {
        let dir = tempdir().unwrap();
        let (key_path, verify_key) = write_key(dir.path());
        let mut helper = TenantSignerHelper::new("local", Some(key_path));
        let vm_a = registration(dir.path(), "local", "vm-a", "wl-a");
        let vm_b = registration(dir.path(), "local", "vm-b", "wl-b");
        let path_a = vm_a.workload_chain_path.clone();
        let path_b = vm_b.workload_chain_path.clone();

        helper.register_vm(vm_a).unwrap();
        helper.register_vm(vm_b).unwrap();

        let head_a = ok_head(helper.append_for_vm("vm-a", append_request("a", "local", "wl-a")));
        let head_b = ok_head(helper.append_for_vm("vm-b", append_request("b", "local", "wl-b")));

        assert_eq!(helper.registration_count(), 2);
        assert_eq!(helper.chain_head("vm-a"), Some(head_a.as_str()));
        assert_eq!(helper.chain_head("vm-b"), Some(head_b.as_str()));
        assert_ne!(
            helper.chain_head("vm-a"),
            Some(CanonicalEntry::genesis_prev_hash().as_str())
        );
        assert_eq!(verify_workload_chain(&path_a, &verify_key).unwrap(), 1);
        assert_eq!(verify_workload_chain(&path_b, &verify_key).unwrap(), 1);
    }

    #[test]
    fn deregister_vm_closes_the_owned_chain_slot() {
        let dir = tempdir().unwrap();
        let (key_path, _verify_key) = write_key(dir.path());
        let mut helper = TenantSignerHelper::new("local", Some(key_path));
        helper
            .register_vm(registration(dir.path(), "local", "vm-a", "wl-a"))
            .unwrap();
        assert!(helper.is_registered("vm-a"));

        helper.deregister_vm("vm-a");

        assert!(!helper.is_registered("vm-a"));
        let resp = helper.append_for_vm("vm-a", append_request("a", "local", "wl-a"));
        match resp {
            AppendEntryResponse::Err { code, .. } => {
                assert_eq!(code, AuditSignerErrorCode::NotReady);
            }
            other => panic!("expected NotReady, got {other:?}"),
        }
    }

    #[test]
    fn register_vm_refuses_other_tenant_and_unsafe_vm_id() {
        let dir = tempdir().unwrap();
        let (key_path, _verify_key) = write_key(dir.path());
        let mut helper = TenantSignerHelper::new("local", Some(key_path));

        assert!(
            helper
                .register_vm(registration(dir.path(), "other", "vm-a", "wl-a"))
                .is_err()
        );
        let mut bad = registration(dir.path(), "local", "vm-a", "wl-a");
        bad.vm_id = "../escape".into();
        assert!(helper.register_vm(bad).is_err());
        assert_eq!(helper.registration_count(), 0);
    }

    #[test]
    fn append_identity_must_match_registered_tenant_and_workload() {
        let dir = tempdir().unwrap();
        let (key_path, _verify_key) = write_key(dir.path());
        let mut helper = TenantSignerHelper::new("local", Some(key_path));
        helper
            .register_vm(registration(dir.path(), "local", "vm-a", "wl-a"))
            .unwrap();

        let tenant_resp = helper.append_for_vm("vm-a", append_request("a", "other", "wl-a"));
        let workload_resp = helper.append_for_vm("vm-a", append_request("b", "local", "wl-b"));

        for resp in [tenant_resp, workload_resp] {
            match resp {
                AppendEntryResponse::Err { code, .. } => {
                    assert_eq!(code, AuditSignerErrorCode::InvalidRequest);
                }
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        }
    }
}
