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
use mvm_core::protocol::audit_signer::{
    SignerHelperDeregisterVm, SignerHelperRegisterVm, SignerHelperRequest, SignerHelperResponse,
};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::warn;

use crate::audit_signer::helper_client::SignerHelperClient;

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
    /// UDS bound by this daemon's supervised signer helper child.
    pub signer_helper_uds_path: PathBuf,
    /// Tenant signing key path handed to the signer helper child. The
    /// host-agent never reads this key; it only passes the path across the
    /// process moat.
    pub software_chain_key_path: PathBuf,
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
    signer_helper_uds_path: Option<PathBuf>,
    registration_journal: Option<RegistrationJournal>,
    max_frame_bytes: usize,
    vms: HashMap<String, VmHandle>,
    registrations: HashMap<String, RegisterVm>,
}

#[derive(Debug, Clone)]
struct RegistrationJournal {
    path: PathBuf,
}

impl RegistrationJournal {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn load(&self) -> Result<Vec<RegisterVm>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("read registration journal {}", self.path.display()));
            }
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&bytes)
            .with_context(|| format!("decode registration journal {}", self.path.display()))
    }

    fn store<'a>(&self, registrations: impl IntoIterator<Item = &'a RegisterVm>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create registration journal dir {}", parent.display()))?;
        }

        let mut registrations: Vec<RegisterVm> = registrations.into_iter().cloned().collect();
        registrations.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));

        let mut bytes = serde_json::to_vec_pretty(&registrations)
            .context("encode registration journal snapshot")?;
        bytes.push(b'\n');

        let tmp_path = self.tmp_path()?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("write registration journal temp {}", tmp_path.display()))?;
        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e).with_context(|| {
                format!(
                    "replace registration journal {} with {}",
                    self.path.display(),
                    tmp_path.display()
                )
            });
        }
        Ok(())
    }

    fn tmp_path(&self) -> Result<PathBuf> {
        let file_name = self
            .path
            .file_name()
            .context("registration journal path must have a file name")?
            .to_string_lossy();
        let mut tmp_path = self.path.clone();
        tmp_path.set_file_name(format!("{file_name}.{}.tmp", std::process::id()));
        Ok(tmp_path)
    }
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
            signer_helper_uds_path: None,
            registration_journal: None,
            max_frame_bytes,
            vms: HashMap::new(),
            registrations: HashMap::new(),
        }
    }

    /// New daemon wired to a supervised resident signer helper. Registered VMs
    /// route `host.audit.v1` appends through this helper instead of a per-VM
    /// audit-signer process.
    pub fn new_with_signer_helper(
        tenant_id: impl Into<String>,
        verifying_key: VerifyingKey,
        signer_helper_uds_path: impl Into<PathBuf>,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            verifying_key,
            signer_helper_uds_path: Some(signer_helper_uds_path.into()),
            registration_journal: None,
            max_frame_bytes,
            vms: HashMap::new(),
            registrations: HashMap::new(),
        }
    }

    /// Persist the live registration set to `path` after every successful
    /// register/deregister and use it for daemon restart recovery.
    pub fn with_registration_journal(mut self, path: impl Into<PathBuf>) -> Self {
        self.registration_journal = Some(RegistrationJournal::new(path));
        self
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
                self.registrations.remove(&d.vm_id);
                if let Err(e) = self.deregister_helper_vm(&d.vm_id) {
                    warn!(vm_id = %d.vm_id, error = %e, "signer-helper deregister failed");
                }
                self.persist_registrations()?;
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
        self.registrations.remove(&r.vm_id);
        if let Err(e) = self.deregister_helper_vm(&r.vm_id) {
            warn!(vm_id = %r.vm_id, error = %e, "stale signer-helper deregister failed before re-register");
        }

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

        self.register_helper_vm(r)?;

        // Per-VM registry: in daemon mode its `host.audit.v1` handler points
        // at the resident helper with this server-derived `vm_id`; legacy
        // per-VM broker mode still points at a per-VM audit-signer UDS.
        let mut registry = Registry::new();
        if let Some(helper) = &self.signer_helper_uds_path {
            registry.register(Arc::new(HostAuditV1Handler::new(
                AuditClient::new_signer_helper(helper.clone(), r.vm_id.clone()),
            )));
        } else if let Some(signer) = &r.audit_signer_uds_path {
            registry.register(Arc::new(HostAuditV1Handler::new(AuditClient::new(
                signer.clone(),
            ))));
        }
        let registry = Arc::new(registry);

        let tenant = self.tenant_id.clone();
        let workload_id = r.workload_id.clone().unwrap_or_else(|| r.vm_id.clone());
        let mfb = self.max_frame_bytes;
        // `workload_id` is server-derived from registration context; the guest
        // frame carries none, and this socket only ever serves this VM.
        let serve_task = tokio::spawn(async move {
            if let Err(e) = serve_on_listener(listener, registry, workload_id, tenant, mfb).await {
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
        self.registrations.insert(r.vm_id.clone(), r.clone());
        self.persist_registrations()?;
        Ok(())
    }

    /// Replay the persisted live registration set after the daemon itself
    /// restarts. Each replay goes through the normal `register` path, so tenant
    /// checks, vm-id validation, socket bind, and signer-helper rebind all
    /// remain fail-closed.
    pub fn restore_journaled_registrations(&mut self) -> Result<usize> {
        let Some(journal) = &self.registration_journal else {
            return Ok(0);
        };
        let registrations = journal.load()?;
        let mut restored = 0usize;
        for registration in registrations {
            self.register(&registration)
                .with_context(|| format!("restore VM registration {}", registration.vm_id))?;
            restored += 1;
        }
        Ok(restored)
    }

    fn persist_registrations(&self) -> Result<()> {
        if let Some(journal) = &self.registration_journal {
            journal.store(self.registrations.values())?;
        }
        Ok(())
    }

    /// Re-register every live VM with a freshly restarted signer helper.
    ///
    /// The host-agent keeps the live registration set in memory while it owns
    /// the broker sockets. If the key-holding helper restarts under the same
    /// UDS path, replaying these registrations reopens each per-VM chain from
    /// disk and restores helper routing without rebinding guest-facing sockets.
    pub fn rebind_signer_helper_registrations(&self) -> Result<usize> {
        if self.signer_helper_uds_path.is_none() {
            return Ok(0);
        }
        let mut rebound = 0usize;
        for registration in self.registrations.values() {
            self.register_helper_vm(registration)
                .with_context(|| format!("re-register signer-helper VM {}", registration.vm_id))?;
            rebound += 1;
        }
        Ok(rebound)
    }

    fn register_helper_vm(&self, r: &RegisterVm) -> Result<()> {
        let Some(path) = &self.signer_helper_uds_path else {
            return Ok(());
        };
        let req = SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: format!("register-{}", r.vm_id),
            vm_id: r.vm_id.clone(),
            tenant_id: r.tenant_id.clone(),
            workload_id: r.workload_id.clone().unwrap_or_else(|| r.vm_id.clone()),
            workload_chain_path: r.workload_chain_path.clone(),
            chain_head_secondary_path: r
                .workload_chain_head_path
                .clone()
                .unwrap_or_else(|| r.workload_chain_path.with_extension("head")),
        });
        match SignerHelperClient::new(path.clone()).send(&req)? {
            SignerHelperResponse::Registered { .. } => Ok(()),
            SignerHelperResponse::Err { message, .. } => {
                bail!("signer-helper register refused: {message}")
            }
            other => bail!("signer-helper returned unexpected register response: {other:?}"),
        }
    }

    fn deregister_helper_vm(&self, vm_id: &str) -> Result<()> {
        let Some(path) = &self.signer_helper_uds_path else {
            return Ok(());
        };
        let req = SignerHelperRequest::DeregisterVm(SignerHelperDeregisterVm {
            request_id: format!("deregister-{vm_id}"),
            vm_id: vm_id.to_string(),
        });
        match SignerHelperClient::new(path.clone()).send(&req)? {
            SignerHelperResponse::Deregistered { .. } => Ok(()),
            SignerHelperResponse::Err { message, .. } => {
                bail!("signer-helper deregister refused: {message}")
            }
            other => bail!("signer-helper returned unexpected deregister response: {other:?}"),
        }
    }

    /// Bind the per-tenant control UDS (mode 0700, host-only) and process
    /// host-signed Register/Deregister messages until the listener errors.
    pub async fn run(self, control_socket: &Path) -> Result<()> {
        Self::run_shared(Arc::new(Mutex::new(self)), control_socket).await
    }

    /// Shared-state control loop used when another supervisor task needs to
    /// replay helper registrations after a helper restart.
    pub async fn run_shared(daemon: Arc<Mutex<Self>>, control_socket: &Path) -> Result<()> {
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
            let verifying_key = {
                let daemon = daemon.lock().await;
                daemon.verifying_key
            };
            let resp = match read_frame::<SignedControl>(&mut stream, CONTROL_MAX_FRAME_BYTES).await
            {
                Ok(signed) => match signed.verify(&verifying_key) {
                    Ok(req) => {
                        let req = req.clone();
                        let mut daemon = daemon.lock().await;
                        match daemon.apply(&req) {
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
    use crate::audit_signer::helper::{
        SignerHelper, serve_on_listener as serve_helper_on_listener,
    };
    use crate::audit_signer::verify::verify_workload_chain;
    use crate::broker::control::DeregisterVm;
    use ed25519_dalek::SigningKey;
    use mvm_core::protocol::broker::{ServiceCall, ServiceId, ServiceResponse};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    fn daemon(tenant: &str) -> HostAgentDaemon {
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        HostAgentDaemon::new(tenant, vk, 64 * 1024)
    }

    fn register(dir: &Path, vm: &str, tenant: &str, signer: Option<PathBuf>) -> RegisterVm {
        RegisterVm {
            vm_id: vm.into(),
            workload_id: Some(format!("wl-{vm}")),
            tenant_id: tenant.into(),
            broker_listen_socket: dir.join(format!("{vm}.sock")),
            workload_chain_path: dir.join(format!("{tenant}.{vm}.workload.jsonl")),
            workload_chain_head_path: Some(dir.join(format!("{tenant}.{vm}.head"))),
            audit_signer_uds_path: signer,
            services_bindings: vec![],
        }
    }

    async fn start_helper(
        helper_sock: PathBuf,
        tenant_id: &str,
        key_path: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        let helper_listener = UnixListener::bind(&helper_sock).unwrap();
        let helper = Arc::new(Mutex::new(SignerHelper::new(tenant_id, Some(key_path))));
        let task = tokio::spawn({
            let helper = helper.clone();
            async move {
                let _ = serve_helper_on_listener(helper_listener, helper, 65_536).await;
            }
        });
        tokio::task::yield_now().await;
        task
    }

    async fn emit_audit(sock: &Path, vm: &str) -> ServiceResponse {
        let mut client = UnixStream::connect(sock).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({
                "ts": "2026-06-17T00:00:00Z",
                "fields": {"vm": vm}
            }),
        };
        write_frame(&mut client, &call).await.unwrap();
        read_frame(&mut client, 64 * 1024).await.unwrap()
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

    #[test]
    fn registration_journal_stores_sorted_snapshot_and_loads_it() {
        let dir = tempfile::tempdir().unwrap();
        let journal = RegistrationJournal::new(dir.path().join("registrations.json"));
        let reg_b = register(dir.path(), "vm-b", "local", None);
        let reg_a = register(dir.path(), "vm-a", "local", None);

        journal.store([&reg_b, &reg_a]).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("registrations.json")).unwrap();
        assert!(
            raw.find("\"vm-a\"").unwrap() < raw.find("\"vm-b\"").unwrap(),
            "journal snapshot should be stable by vm_id"
        );
        assert_eq!(journal.load().unwrap(), vec![reg_a, reg_b]);
    }

    #[tokio::test]
    async fn deregister_updates_registration_journal_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("registrations.json");
        let mut d = daemon("local").with_registration_journal(&journal_path);

        d.apply(&ControlRequest::Register(register(
            dir.path(),
            "vm-1",
            "local",
            None,
        )))
        .unwrap();
        assert_eq!(
            RegistrationJournal::new(journal_path.clone())
                .load()
                .unwrap()
                .len(),
            1
        );

        d.apply(&ControlRequest::Deregister(DeregisterVm {
            vm_id: "vm-1".into(),
        }))
        .unwrap();
        assert!(
            RegistrationJournal::new(journal_path.clone())
                .load()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn daemon_restart_restores_journaled_registration() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("registrations.json");
        let reg = register(dir.path(), "vm-1", "local", None);
        let sock = reg.broker_listen_socket.clone();

        {
            let mut first = daemon("local").with_registration_journal(&journal_path);
            first.apply(&ControlRequest::Register(reg)).unwrap();
            assert!(first.is_registered("vm-1"));
            assert!(sock.exists(), "first daemon bound broker socket");
        }
        assert!(!sock.exists(), "dropping daemon unbinds broker socket");

        let mut restarted = daemon("local").with_registration_journal(&journal_path);
        assert_eq!(restarted.restore_journaled_registrations().unwrap(), 1);
        assert!(restarted.is_registered("vm-1"));
        assert!(sock.exists(), "restarted daemon rebound broker socket");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_backed_registered_vm_can_only_write_its_own_chain() {
        let dir = tempfile::tempdir().unwrap();
        let helper_sock = dir.path().join("signer-helper.sock");
        let key_path = dir.path().join("tenant-key.ed25519");
        std::fs::write(&key_path, [12u8; 32]).unwrap();
        let helper_task = start_helper(helper_sock.clone(), "local", key_path).await;

        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let mut d = HostAgentDaemon::new_with_signer_helper("local", vk, &helper_sock, 64 * 1024);
        let reg_a = register(dir.path(), "vm-a", "local", None);
        let sock_a = reg_a.broker_listen_socket.clone();
        let chain_a = reg_a.workload_chain_path.clone();
        let reg_b = register(dir.path(), "vm-b", "local", None);
        let chain_b = reg_b.workload_chain_path.clone();

        d.apply(&ControlRequest::Register(reg_a)).unwrap();
        d.apply(&ControlRequest::Register(reg_b)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&sock_a).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.audit.v1").unwrap(),
            verb: "emit".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("guest-picked-id"),
            payload: serde_json::json!({
                "ts": "2026-06-17T00:00:00Z",
                "fields": {"vm": "a"}
            }),
        };
        write_frame(&mut client, &call).await.unwrap();
        let resp: ServiceResponse = read_frame(&mut client, 64 * 1024).await.unwrap();
        assert!(matches!(resp, ServiceResponse::Ok { .. }));

        let a_lines = std::fs::read_to_string(&chain_a).unwrap();
        assert_eq!(a_lines.lines().count(), 1);
        assert!(
            !chain_b.exists() || std::fs::read_to_string(&chain_b).unwrap().is_empty(),
            "vm-a socket must not write vm-b chain"
        );

        helper_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_restart_rebinds_live_registration_and_preserves_chain() {
        let dir = tempfile::tempdir().unwrap();
        let helper_sock = dir.path().join("signer-helper.sock");
        let key_path = dir.path().join("tenant-key.ed25519");
        std::fs::write(&key_path, [12u8; 32]).unwrap();
        let helper_task = start_helper(helper_sock.clone(), "local", key_path.clone()).await;

        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let mut d = HostAgentDaemon::new_with_signer_helper("local", vk, &helper_sock, 64 * 1024);
        let reg = register(dir.path(), "vm-a", "local", None);
        let sock = reg.broker_listen_socket.clone();
        let chain = reg.workload_chain_path.clone();
        d.apply(&ControlRequest::Register(reg)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let before = emit_audit(&sock, "before-restart").await;
        assert!(matches!(before, ServiceResponse::Ok { .. }));

        helper_task.abort();
        let _ = helper_task.await;
        let _ = std::fs::remove_file(&helper_sock);
        let restarted = start_helper(helper_sock.clone(), "local", key_path).await;

        assert_eq!(d.rebind_signer_helper_registrations().unwrap(), 1);
        let after = emit_audit(&sock, "after-restart").await;
        assert!(matches!(after, ServiceResponse::Ok { .. }));

        let verifying_key = SigningKey::from_bytes(&[12u8; 32]).verifying_key();
        let count = verify_workload_chain(&chain, &verifying_key).unwrap();
        assert_eq!(count, 2);
        assert_eq!(std::fs::read_to_string(&chain).unwrap().lines().count(), 2);

        restarted.abort();
    }
}
