//! Resident per-tenant host-agent daemon.
//!
//! One daemon per tenant, not one process per VM. VMs register with it over
//! the host-signed control plane ([`super::control`]); on each `RegisterVm` it
//! binds that VM's `BROKER_PORT` socket and serves host-services on it, and on
//! `DeregisterVm` it unbinds and drops the VM. A tenant's many microVMs are
//! *registrations* in the `vm_id` map, not processes — `O(active tenants)`
//! daemons, not `O(VMs)`.
//!
//! Identity is **server-derived**: each VM's socket has its own serve task with
//! its own `Registry` (its `host.audit.v1` handler points at *its own*
//! audit-signer / chain). The `vm_id` a dispatched call is attributed to comes
//! from *which socket accepted it* — established at `RegisterVm` time — never
//! from a field in the guest frame. So one guest cannot reach another VM's
//! bindings or write another VM's chain, even though they share this daemon.
//!
//! The daemon holds **no keys** (the moat): it parses untrusted guest frames
//! but only forwards audit entries to the per-VM audit-signer that holds the
//! signing key. This slice is the daemon + its register/deregister core; the
//! `mvm-backend` `ensure_daemon`/`register_vm` seam that replaces the per-VM
//! `spawn_broker` fork is the next slice.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use tokio::net::UnixListener;
use tracing::warn;

use super::audit_client::AuditClient;
use super::control::{ControlRequest, ControlResponse, RegisterVm, SignedControl};
use super::handlers::host_audit_v1::HostAuditV1Handler;
use super::registry::Registry;
use super::server::{read_frame, serve_on_listener, write_frame};

/// Default control-frame cap — Register/Deregister are tiny; this bounds a
/// hostile/garbled control message.
const CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;

/// Default per-VM guest dispatch frame cap.
fn default_max_frame_bytes() -> usize {
    64 * 1024
}

/// Startup config the `mvm-host-agent` daemon reads on stdin: which tenant it
/// serves, where to bind its control socket, and the host signer public key it
/// verifies control messages against. The supervisor writes this once at spawn.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAgentConfig {
    /// The single tenant this daemon serves (it is per-tenant).
    pub tenant_id: String,
    /// The per-tenant control UDS to bind (mode 0700, host-only).
    pub control_socket: PathBuf,
    /// Path to the host signer's 32-byte Ed25519 public key, used to verify
    /// every control message.
    pub host_signer_public_key_path: PathBuf,
    /// Per-VM guest dispatch frame cap.
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl HostAgentConfig {
    /// Load the verifying key from `host_signer_public_key_path`.
    pub fn load_verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = std::fs::read(&self.host_signer_public_key_path).with_context(|| {
            format!(
                "read host signer pubkey {}",
                self.host_signer_public_key_path.display()
            )
        })?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("host signer pubkey must be 32 bytes, got {}", bytes.len())
        })?;
        VerifyingKey::from_bytes(&arr).context("host signer pubkey is not a valid Ed25519 key")
    }
}

/// Per-VM live state: the bound listen socket and the serve task. Dropping it
/// aborts the task and removes the socket — so `deregister` (and daemon
/// teardown) unbind cleanly.
struct VmHandle {
    listen_socket: PathBuf,
    serve_task: tokio::task::JoinHandle<()>,
}

impl Drop for VmHandle {
    fn drop(&mut self) {
        self.serve_task.abort();
        let _ = std::fs::remove_file(&self.listen_socket);
    }
}

/// The resident per-tenant host-agent daemon.
pub struct HostAgentDaemon {
    tenant_id: String,
    verifying_key: VerifyingKey,
    max_frame_bytes: usize,
    vms: HashMap<String, VmHandle>,
}

impl HostAgentDaemon {
    /// New daemon for `tenant_id`, verifying control messages against
    /// `verifying_key` (the host signer's public key). `max_frame_bytes` caps
    /// the per-VM guest dispatch frames.
    pub fn new(
        tenant_id: impl Into<String>,
        verifying_key: VerifyingKey,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            verifying_key,
            max_frame_bytes,
            vms: HashMap::new(),
        }
    }

    /// Whether `vm_id` is currently registered (bound + serving).
    pub fn is_registered(&self, vm_id: &str) -> bool {
        self.vms.contains_key(vm_id)
    }

    /// Number of live VM registrations.
    pub fn registration_count(&self) -> usize {
        self.vms.len()
    }

    /// Apply a verified control request. Must run inside a tokio runtime (it
    /// spawns the per-VM serve task). The control loop calls this after the
    /// signature verifies.
    pub fn apply(&mut self, req: &ControlRequest) -> Result<()> {
        match req {
            ControlRequest::Register(r) => self.register(r),
            ControlRequest::Deregister(d) => {
                // Drop = abort + unbind; idempotent on an unknown id.
                self.vms.remove(&d.vm_id);
                Ok(())
            }
        }
    }

    fn register(&mut self, r: &RegisterVm) -> Result<()> {
        // The daemon is per-tenant: refuse a registration for another tenant.
        if r.tenant_id != self.tenant_id {
            bail!(
                "register for tenant {:?} on a daemon for tenant {:?}",
                r.tenant_id,
                self.tenant_id
            );
        }
        // `vm_id` names the per-VM chain file; even though the register message
        // is host-signed, validate it as a defense-in-depth path-injection
        // guard before it reaches any filesystem path.
        validate_vm_id(&r.vm_id)?;

        // Re-register replaces: drop the prior handle first so its socket is
        // unbound before we rebind (idempotent rebind, fail-closed).
        self.vms.remove(&r.vm_id);

        // Per-VM registry: its own `host.audit.v1` handler points at this VM's
        // audit-signer, so the handler's rate-limiter + the forwarded chain are
        // both per-VM. Absent signer ⇒ `host.audit.v1` returns `NotBound`.
        let mut registry = Registry::new();
        if let Some(signer) = &r.audit_signer_uds_path {
            registry.register(Arc::new(HostAuditV1Handler::new(AuditClient::new(
                signer.clone(),
            ))));
        }
        let registry = Arc::new(registry);

        if let Some(parent) = r.broker_listen_socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create broker socket dir {}", parent.display()))?;
        }
        // Clear a stale socket so bind doesn't fail with EADDRINUSE.
        let _ = std::fs::remove_file(&r.broker_listen_socket);
        let listener = UnixListener::bind(&r.broker_listen_socket).with_context(|| {
            format!(
                "bind broker listen socket {}",
                r.broker_listen_socket.display()
            )
        })?;

        let vm_id = r.vm_id.clone();
        let tenant = self.tenant_id.clone();
        let mfb = self.max_frame_bytes;
        // `vm_id` is the server-derived identity threaded into dispatch — the
        // guest frame carries none, and this socket only ever serves this VM.
        let serve_task = tokio::spawn(async move {
            if let Err(e) = serve_on_listener(listener, registry, vm_id, tenant, mfb).await {
                warn!(error = %e, "host-agent per-VM serve loop exited");
            }
        });

        self.vms.insert(
            r.vm_id.clone(),
            VmHandle {
                listen_socket: r.broker_listen_socket.clone(),
                serve_task,
            },
        );
        Ok(())
    }

    /// Bind the per-tenant control UDS (mode 0700, host-only) and process
    /// host-signed Register/Deregister messages until the listener errors.
    pub async fn run(mut self, control_socket: &Path) -> Result<()> {
        if let Some(parent) = control_socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create control socket dir {}", parent.display()))?;
        }
        let _ = std::fs::remove_file(control_socket);
        let listener = UnixListener::bind(control_socket)
            .with_context(|| format!("bind control socket {}", control_socket.display()))?;
        // Host-only: no group/other access to the control plane.
        std::fs::set_permissions(control_socket, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", control_socket.display()))?;

        loop {
            let (mut stream, _addr) = listener
                .accept()
                .await
                .context("host-agent control accept failed")?;
            let resp = match read_frame::<SignedControl>(&mut stream, CONTROL_MAX_FRAME_BYTES).await
            {
                Ok(signed) => match signed.verify(&self.verifying_key) {
                    Ok(req) => {
                        let req = req.clone();
                        match self.apply(&req) {
                            Ok(()) => ControlResponse::Ok,
                            Err(e) => ControlResponse::Err {
                                message: e.to_string(),
                            },
                        }
                    }
                    Err(e) => ControlResponse::Err {
                        message: format!("control signature rejected: {e}"),
                    },
                },
                Err(e) => {
                    warn!(error = %e, "host-agent control frame read failed");
                    continue;
                }
            };
            if let Err(e) = write_frame(&mut stream, &resp).await {
                warn!(error = %e, "host-agent control reply failed");
            }
        }
    }
}

/// Validate a `vm_id` is safe to embed in a filesystem path: a non-empty DNS-
/// label-shaped token (alphanumeric plus `-`/`_`), no separators, no traversal.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::control::DeregisterVm;
    use ed25519_dalek::SigningKey;
    use mvm_core::protocol::broker::{ServiceCall, ServiceId, ServiceResponse};
    use std::time::Duration;
    use tokio::net::UnixStream;

    fn daemon(tenant: &str) -> HostAgentDaemon {
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        HostAgentDaemon::new(tenant, vk, 64 * 1024)
    }

    fn register(dir: &Path, vm: &str, tenant: &str, signer: Option<PathBuf>) -> RegisterVm {
        RegisterVm {
            vm_id: vm.into(),
            tenant_id: tenant.into(),
            broker_listen_socket: dir.join(format!("{vm}.sock")),
            workload_chain_path: dir.join(format!("{tenant}.{vm}.workload.jsonl")),
            audit_signer_uds_path: signer,
            services_bindings: vec![],
        }
    }

    #[test]
    fn validate_vm_id_rejects_traversal_and_separators() {
        assert!(validate_vm_id("vm-1").is_ok());
        assert!(validate_vm_id("e53b4probe").is_ok());
        assert!(validate_vm_id("").is_err());
        assert!(validate_vm_id("../escape").is_err());
        assert!(validate_vm_id("a/b").is_err());
        assert!(validate_vm_id("a.b").is_err());
        assert!(validate_vm_id(&"x".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn register_binds_socket_then_deregister_unbinds() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = reg.broker_listen_socket.clone();

        d.apply(&ControlRequest::Register(reg)).unwrap();
        assert!(d.is_registered("vm-1"));
        assert!(sock.exists(), "broker socket bound");

        d.apply(&ControlRequest::Deregister(DeregisterVm {
            vm_id: "vm-1".into(),
        }))
        .unwrap();
        assert!(!d.is_registered("vm-1"));
        // Drop runs synchronously on remove → socket file gone.
        assert!(!sock.exists(), "broker socket unbound");
    }

    #[tokio::test]
    async fn register_refuses_other_tenant_and_unsafe_vm_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        assert!(
            d.apply(&ControlRequest::Register(register(
                dir.path(),
                "vm-1",
                "acme",
                None
            )))
            .is_err(),
            "cross-tenant register refused"
        );
        let mut bad = register(dir.path(), "ok", "local", None);
        bad.vm_id = "../escape".into();
        assert!(
            d.apply(&ControlRequest::Register(bad)).is_err(),
            "unsafe vm_id refused"
        );
        assert_eq!(d.registration_count(), 0);
    }

    #[tokio::test]
    async fn registered_vm_dispatches_through_its_own_registry_with_server_correlation() {
        // No audit-signer registered ⇒ `host.audit.v1` is `NotBound`. The point
        // is that the call still *routes through the daemon's per-VM registry*
        // and comes back as a typed response with a server-reassigned
        // correlation id — i.e. bind + dispatch + server-derived identity work,
        // without depending on the audit-signer wire (covered elsewhere).
        let dir = tempfile::tempdir().unwrap();
        let mut d = daemon("local");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = reg.broker_listen_socket.clone();
        d.apply(&ControlRequest::Register(reg)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A guest dials the VM's broker socket. Its `correlation_id` is its own
        // choosing — the server must not echo it back.
        let mut client = UnixStream::connect(&sock).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({"ts": "2026-06-16T00:00:00Z", "fields": {"a": 1}}),
        };
        write_frame(&mut client, &call).await.unwrap();
        let resp: ServiceResponse = read_frame(&mut client, 64 * 1024).await.unwrap();
        let correlation_id = match resp {
            ServiceResponse::Ok { correlation_id, .. }
            | ServiceResponse::Err { correlation_id, .. } => correlation_id,
        };
        // Server-authoritative id (brk-*), never the guest's — even within a
        // shared daemon a guest can't choose its audit-chain correlation id.
        assert!(
            correlation_id.as_str().starts_with("brk-"),
            "server-derived correlation id, got {correlation_id:?}"
        );
        assert_ne!(correlation_id.as_str(), "guest-picked-id");
    }
}
