//! Resident per-tenant signer helper.
//!
//! Phase 2a of Plan 202 moves the audit signer from one process per VM to one
//! helper per tenant. The helper owns a `vm_id -> Chain` map: `RegisterVm`
//! opens a VM's workload chain, `AppendEntry` routes through the server-derived
//! `vm_id`, and `DeregisterVm` drops the chain handle so the file is closed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mvm_core::protocol::audit_signer::{
    AuditSignerErrorCode, SignerHelperAppendEntry, SignerHelperDeregisterVm,
    SignerHelperRegisterVm, SignerHelperRequest, SignerHelperResponse,
};
use mvm_core::security::SIG_ALG_ED25519;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::audit_signer::canonical::CanonicalEntry;
use crate::audit_signer::chain::Chain;
use crate::audit_signer::server::format_code_message;

const WORKLOAD_AUDIT_CATEGORY: &str = "workload_audit";

/// Shared helper state for the async UDS server.
pub type SharedSignerHelper = Arc<Mutex<SignerHelper>>;

struct VmChain {
    workload_id: String,
    chain: Chain,
}

/// The one key-holding signer helper for a tenant.
pub struct SignerHelper {
    tenant_id: String,
    software_chain_key_path: Option<PathBuf>,
    chains: HashMap<String, VmChain>,
}

impl SignerHelper {
    /// Create an empty helper for one tenant. Chains are opened by
    /// `RegisterVm`, not at helper boot.
    pub fn new(tenant_id: impl Into<String>, software_chain_key_path: Option<PathBuf>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            software_chain_key_path,
            chains: HashMap::new(),
        }
    }

    /// Number of currently registered VM chains.
    pub fn registration_count(&self) -> usize {
        self.chains.len()
    }

    /// Current chain head for a registered VM.
    pub fn chain_head(&self, vm_id: &str) -> Option<&str> {
        self.chains.get(vm_id).map(|vm| vm.chain.head())
    }

    /// Apply one helper request.
    pub fn dispatch(&mut self, req: SignerHelperRequest) -> SignerHelperResponse {
        match req {
            SignerHelperRequest::RegisterVm(req) => self.register(req),
            SignerHelperRequest::DeregisterVm(req) => self.deregister(req),
            SignerHelperRequest::AppendEntry(req) => self.append(req),
            SignerHelperRequest::Probe { request_id } => SignerHelperResponse::Pong { request_id },
        }
    }

    fn register(&mut self, req: SignerHelperRegisterVm) -> SignerHelperResponse {
        let request_id = req.request_id.clone();
        match self.open_chain(&req) {
            Ok(chain) => {
                let chain_head = chain.head().to_string();
                self.chains.insert(
                    req.vm_id.clone(),
                    VmChain {
                        workload_id: req.workload_id,
                        chain,
                    },
                );
                SignerHelperResponse::Registered {
                    request_id,
                    vm_id: req.vm_id,
                    chain_head,
                }
            }
            Err(e) => SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: e.to_string(),
            },
        }
    }

    fn open_chain(&mut self, req: &SignerHelperRegisterVm) -> Result<Chain> {
        if req.tenant_id != self.tenant_id {
            bail!(
                "register for tenant {:?} on signer helper for tenant {:?}",
                req.tenant_id,
                self.tenant_id
            );
        }
        validate_vm_id(&req.vm_id)?;
        ensure_parent(&req.workload_chain_path)?;
        ensure_parent(&req.chain_head_secondary_path)?;
        Chain::open(
            &req.workload_chain_path,
            &req.chain_head_secondary_path,
            self.software_chain_key_path.as_deref(),
        )
    }

    fn deregister(&mut self, req: SignerHelperDeregisterVm) -> SignerHelperResponse {
        self.chains.remove(&req.vm_id);
        SignerHelperResponse::Deregistered {
            request_id: req.request_id,
            vm_id: req.vm_id,
        }
    }

    fn append(&mut self, req: SignerHelperAppendEntry) -> SignerHelperResponse {
        let request_id = req.request_id.clone();
        if req.tenant_id != self.tenant_id {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::InvalidRequest,
                message: "append tenant does not match signer helper tenant".into(),
            };
        }
        let Some(vm) = self.chains.get_mut(&req.vm_id) else {
            return SignerHelperResponse::Err {
                request_id,
                code: AuditSignerErrorCode::NotReady,
                message: "vm is not registered with signer helper".into(),
            };
        };
        debug!(
            vm_id = %req.vm_id,
            workload_id = %vm.workload_id,
            request_id = %request_id,
            "signer helper appending entry"
        );
        let entry = CanonicalEntry {
            category: WORKLOAD_AUDIT_CATEGORY.into(),
            correlation_id: req.correlation_id,
            fields: req.fields,
            prev_hash: vm.chain.head().to_string(),
            session_id: req.session_id,
            tenant_id: req.tenant_id,
            ts: req.ts,
            workload_id: req.workload_id,
        };
        match vm.chain.append(entry) {
            Ok(new_head) => SignerHelperResponse::Ok {
                request_id,
                chain_head: new_head.clone(),
                entry_hash: new_head,
                sig_alg: SIG_ALG_ED25519,
            },
            Err(code) => SignerHelperResponse::Err {
                request_id,
                code,
                message: format_code_message(code),
            },
        }
    }
}

/// Accept loop for the resident helper UDS.
pub async fn serve(
    listener: UnixListener,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(max_frame_bytes, "mvm-signer-helper accept loop started");
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-signer-helper UDS accept failed")?;
        let helper = helper.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, helper, max_frame_bytes).await {
                warn!(error = %e, "mvm-signer-helper connection terminated with error");
            }
        });
    }
}

pub async fn serve_on_listener(
    listener: UnixListener,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, helper, max_frame_bytes).await
}

async fn handle_connection(
    mut stream: UnixStream,
    helper: SharedSignerHelper,
    max_frame_bytes: usize,
) -> Result<()> {
    let req = read_frame::<SignerHelperRequest>(&mut stream, max_frame_bytes).await?;
    let response = {
        let mut helper = helper.lock().await;
        helper.dispatch(req)
    };
    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-signer-helper UDS shutdown failed")?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-signer-helper frame read failed")
}

async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-signer-helper frame write failed")
}

fn validate_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty() || vm_id.len() > 63 {
        bail!("vm_id must be 1..=63 chars, got {}", vm_id.len());
    }
    if !vm_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("vm_id {:?} has characters outside [A-Za-z0-9_-]", vm_id);
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key_path(dir: &Path) -> PathBuf {
        let path = dir.join("tenant-key.ed25519");
        std::fs::write(&path, [9u8; 32]).unwrap();
        path
    }

    fn register_req(dir: &Path, vm_id: &str, tenant_id: &str) -> SignerHelperRequest {
        SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: format!("reg-{vm_id}"),
            vm_id: vm_id.into(),
            tenant_id: tenant_id.into(),
            workload_id: format!("wl-{vm_id}"),
            workload_chain_path: dir.join(format!("{tenant_id}.{vm_id}.workload.jsonl")),
            chain_head_secondary_path: dir.join(format!("{tenant_id}.{vm_id}.head")),
        })
    }

    fn append_req(vm_id: &str, request_id: &str) -> SignerHelperRequest {
        SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: request_id.into(),
            vm_id: vm_id.into(),
            category: "workload_audit".into(),
            ts: "2026-06-17T00:00:00Z".into(),
            workload_id: format!("wl-{vm_id}"),
            tenant_id: "local".into(),
            session_id: "sess-1".into(),
            correlation_id: format!("brk-{request_id}"),
            fields: serde_json::json!({"event": request_id}),
        })
    }

    #[test]
    fn register_opens_per_vm_chain_and_deregister_closes_it() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));

        let registered = helper.dispatch(register_req(dir.path(), "vm-1", "local"));
        match registered {
            SignerHelperResponse::Registered {
                vm_id, chain_head, ..
            } => {
                assert_eq!(vm_id, "vm-1");
                assert_eq!(Some(chain_head.as_str()), helper.chain_head("vm-1"));
            }
            other => panic!("expected Registered, got {other:?}"),
        }
        assert_eq!(helper.registration_count(), 1);

        let deregistered = helper.dispatch(SignerHelperRequest::DeregisterVm(
            SignerHelperDeregisterVm {
                request_id: "dereg-1".into(),
                vm_id: "vm-1".into(),
            },
        ));
        assert!(matches!(
            deregistered,
            SignerHelperResponse::Deregistered { .. }
        ));
        assert_eq!(helper.registration_count(), 0);

        let append_after_drop = helper.dispatch(append_req("vm-1", "append-after-drop"));
        assert!(matches!(
            append_after_drop,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::NotReady,
                ..
            }
        ));
    }

    #[test]
    fn append_routes_to_the_selected_vm_chain() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));
        helper.dispatch(register_req(dir.path(), "vm-a", "local"));
        helper.dispatch(register_req(dir.path(), "vm-b", "local"));

        let a_head = match helper.dispatch(append_req("vm-a", "append-a")) {
            SignerHelperResponse::Ok { chain_head, .. } => chain_head,
            other => panic!("expected vm-a append Ok, got {other:?}"),
        };
        let b_head = match helper.dispatch(append_req("vm-b", "append-b")) {
            SignerHelperResponse::Ok { chain_head, .. } => chain_head,
            other => panic!("expected vm-b append Ok, got {other:?}"),
        };

        assert_eq!(Some(a_head.as_str()), helper.chain_head("vm-a"));
        assert_eq!(Some(b_head.as_str()), helper.chain_head("vm-b"));
        assert_ne!(a_head, b_head);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("local.vm-a.workload.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("local.vm-b.workload.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn register_rejects_cross_tenant_and_unsafe_vm_id() {
        let dir = tempdir().unwrap();
        let mut helper = SignerHelper::new("local", Some(key_path(dir.path())));

        let cross_tenant = helper.dispatch(register_req(dir.path(), "vm-1", "other"));
        assert!(matches!(
            cross_tenant,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::InvalidRequest,
                ..
            }
        ));

        let unsafe_id = helper.dispatch(register_req(dir.path(), "../escape", "local"));
        assert!(matches!(
            unsafe_id,
            SignerHelperResponse::Err {
                code: AuditSignerErrorCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(helper.registration_count(), 0);
    }
}
