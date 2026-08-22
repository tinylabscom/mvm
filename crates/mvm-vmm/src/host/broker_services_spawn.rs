//! Legacy per-VM broker-services subprocess spawn primitives.
//!
//! Backend launch paths now use per-tenant host-agent registration.
//! This module remains as the shared low-level process-spawn scaffold and for
//! tests that exercise the old `mvm-broker` / `mvm-audit-signer` binaries.
//!
//! The helpers mirror [`crate::host::network_endpoint_spawn`]: locate the bin, hand it a
//! JSON config on stdin, detach via `setsid`, wait for readiness, and write a
//! PID file for direct reaping in tests. mvm-backend can't depend on mvm-hostd,
//! so the config is emitted as raw JSON matching the bin's `deny_unknown_fields`
//! `SubprocessConfig` — exactly as `spawn_network_endpoint` does for its
//! `EndpointConfig`.
//!
//! Chain provenance: the audit-signer signs with the **host-signer key**
//! (`~/.mvm/keys/host-signer.ed25519`, the same key that signs the claim-8
//! `plan.admitted`/`plan.launched` entries) and appends to the **per-VM**
//! workload chain `workload_audit_path(tenant, vm)` —
//! `<tenant>.<vm>.workload.jsonl` — kept separate from the per-tenant lifecycle
//! chain because the signer is single-writer (in-memory head, `O_APPEND`, no
//! flock), so two VMs of one tenant must not co-write one file. Both chains
//! verify against the same host pubkey, so `verify_workload_chain` /
//! `mvmctl trust audit verify` checks workload entries alongside the lifecycle
//! chain.
//!
//! Readiness: the audit-signer emits no stdout handshake (unlike the
//! substitution endpoint) — it just binds its UDS — so readiness is detected
//! by polling for the UDS path to appear.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use mvm_contract::builder::BuilderError;

/// Filename of the per-VM audit-signer UDS under the VM state dir (the broker
/// connects here; the supervisor owns it).
pub const AUDIT_SIGNER_SOCK: &str = "audit-signer.sock";

/// PID file for the per-VM audit-signer, under the VM state dir.
pub const AUDIT_SIGNER_PID_FILE: &str = "audit-signer.pid";

/// Secondary chain-head persistence file under the per-VM state dir (per-VM by
/// construction, so two VMs of one tenant never share it).
pub const AUDIT_SIGNER_HEAD_FILE: &str = "audit-signer.head";

/// Host-signer secret-key filename under `mvm_keys_dir()` — the chain key the
/// audit-signer signs with so workload entries chain off the claim-8 log.
pub const HOST_SIGNER_KEY: &str = "host-signer.ed25519";

/// How long the audit-signer gets to bind its UDS before the spawn is declared
/// failed (it then gets SIGKILLed and the caller fails closed).
pub const AUDIT_SIGNER_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Inputs to [`spawn_audit_signer`].
pub struct AuditSignerSpawnParams<'a> {
    /// Admitted workload id, stamped into the subprocess config + every entry.
    pub workload_id: &'a str,
    /// Tenant id; with `vm_name` selects the per-VM workload audit chain.
    pub tenant_id: &'a str,
    /// VM name; the per-VM chain is keyed on it (the signer is single-writer, so
    /// two VMs of one tenant must not co-write one chain file).
    pub vm_name: &'a str,
    /// Per-VM state dir; holds the audit-signer UDS + PID + secondary-head files.
    pub state_dir: &'a Path,
}

impl<'a> AuditSignerSpawnParams<'a> {
    /// Start building a [`AuditSignerSpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> AuditSignerSpawnParamsBuilder<'a> {
        AuditSignerSpawnParamsBuilder::new()
    }
}

/// Builder for [`AuditSignerSpawnParams`]. Required fields are checked by
/// [`AuditSignerSpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct AuditSignerSpawnParamsBuilder<'a> {
    workload_id: Option<&'a str>,
    tenant_id: Option<&'a str>,
    vm_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
}

impl<'a> AuditSignerSpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workload_id: None,
            tenant_id: None,
            vm_name: None,
            state_dir: None,
        }
    }

    /// Set `workload_id`.
    #[must_use]
    pub fn workload_id(mut self, workload_id: &'a str) -> Self {
        self.workload_id = Some(workload_id);
        self
    }

    /// Set `tenant_id`.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: &'a str) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `state_dir`.
    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<AuditSignerSpawnParams<'a>, BuilderError> {
        Ok(AuditSignerSpawnParams {
            workload_id: self.workload_id.ok_or(BuilderError::missing(
                "AuditSignerSpawnParams",
                "workload_id",
            ))?,
            tenant_id: self
                .tenant_id
                .ok_or(BuilderError::missing("AuditSignerSpawnParams", "tenant_id"))?,
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("AuditSignerSpawnParams", "vm_name"))?,
            state_dir: self
                .state_dir
                .ok_or(BuilderError::missing("AuditSignerSpawnParams", "state_dir"))?,
        })
    }
}

impl<'a> Default for AuditSignerSpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a spawned audit-signer: the UDS the broker's `host.audit.v1`
/// handler connects to.
#[derive(Debug)]
pub struct AuditSignerHandle {
    /// The UDS the audit-signer bound and the broker forwards entries to.
    pub uds_path: PathBuf,
}

/// Spawn the per-VM `mvm-audit-signer` moat. Hands it a JSON `SubprocessConfig`
/// on stdin (chain JSONL + host-signer key + the UDS to bind), detaches it via
/// `setsid` so it outlives `mvmctl up`, waits for it to bind the UDS, and
/// writes `AUDIT_SIGNER_PID_FILE` for the stop path to reap.
pub fn spawn_audit_signer(params: AuditSignerSpawnParams<'_>) -> Result<AuditSignerHandle> {
    spawn_audit_signer_with_timeout(params, AUDIT_SIGNER_READY_TIMEOUT)
}

/// [`spawn_audit_signer`] with an explicit readiness timeout — the test seam
/// that exercises the fail-closed no-bind path without a 10-second wait.
fn spawn_audit_signer_with_timeout(
    params: AuditSignerSpawnParams<'_>,
    ready_timeout: Duration,
) -> Result<AuditSignerHandle> {
    let AuditSignerSpawnParams {
        workload_id,
        tenant_id,
        vm_name,
        state_dir,
    } = params;

    let bin = resolve_subprocess_bin("mvm-audit-signer", "MVM_AUDIT_SIGNER_PATH")?;
    let uds_path = state_dir.join(AUDIT_SIGNER_SOCK);
    let audit_dir = mvm_core::config::mvm_audit_dir();
    // The audit-signer opens the JSONL with O_APPEND|create; its parent must
    // exist first. (Dir-immutable hardening is the supervisor's job — deferred.)
    std::fs::create_dir_all(&audit_dir)
        .map_err(|e| anyhow!("create audit dir {}: {e}", audit_dir.display()))?;

    let cfg = serde_json::json!({
        "workload_id": workload_id,
        "tenant_id": tenant_id,
        "uds_path": uds_path,
        // Per-VM workload chain (NOT the per-tenant lifecycle chain): the signer
        // is single-writer, so each VM owns its own `<tenant>.<vm>.workload.jsonl`
        // — the path the `verify_workload_chain` verifier checks. Signed with the
        // host-signer key so it verifies against the same host pubkey as the
        // claim-8 lifecycle entries.
        "audit_jsonl_path": mvm_core::config::workload_audit_path(tenant_id, vm_name),
        "chain_head_secondary_path": state_dir.join(AUDIT_SIGNER_HEAD_FILE),
        "software_chain_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY),
    });

    let child = spawn_detached_with_config(&bin, &cfg, "mvm-audit-signer")?;
    // The audit-signer emits no stdout handshake — it binds its UDS after
    // parsing config. Readiness = the UDS path appears. On timeout, fail closed.
    wait_for_uds("mvm-audit-signer", &uds_path, child.id(), ready_timeout)?;

    let pid_file = state_dir.join(AUDIT_SIGNER_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    // Detach: drop the child handle without killing. The subprocess runs
    // daemonized (setsid) and is reaped by the stop path via the PID file.
    Ok(AuditSignerHandle { uds_path })
}

/// Locate a per-VM subprocess binary `bin`: `<env_var>` override → sibling of
/// the current exe → workspace `target/{release,debug}`. Mirrors
/// `network_endpoint_spawn::resolve_network_endpoint_path`; shared by the
/// audit-signer + broker spawns so the lookup can't drift.
pub(crate) fn resolve_subprocess_bin(bin: &str, env_var: &str) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(env_var).map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!("{env_var} points at {} which is not a file", p.display());
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root.join("target").join(variant).join(bin);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("could not locate the {bin} binary (set {env_var})")
}

/// Poll for the subprocess's UDS to appear within `timeout`. The subprocess
/// binds it shortly after parsing its stdin config; a missing socket past the
/// deadline (or an early exit) means the spawn failed — SIGKILL it and bail so
/// the caller rolls back the VM (fail closed). Adaptive backoff keeps a fast
/// bind cheap while bounding a slow one.
pub(crate) fn wait_for_uds(what: &str, uds_path: &Path, pid: u32, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_millis(5);
    loop {
        if uds_path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!(
                "{what} did not bind {} within {timeout:?}",
                uds_path.display()
            );
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(100));
    }
}

/// Reap the per-VM audit-signer (if this VM spawned one) and drop its PID file.
/// Best-effort + idempotent: a VM with no audit-signer is a no-op. The liveness
/// guard prevents signalling a recycled PID from a stale pidfile.
pub fn reap_audit_signer(state_dir: &Path) {
    let pid_file = state_dir.join(AUDIT_SIGNER_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(&pid_file);
}

// ============================================================================
// mvm-broker spawn
// ============================================================================

/// PID file for the per-VM broker, under the VM state dir.
pub const BROKER_PID_FILE: &str = "broker.pid";

/// Host-signer public-key filename under `mvm_keys_dir()` — the broker reads it
/// to verify secrets-dispatcher response signatures.
pub const HOST_SIGNER_PUB: &str = "host-signer.pub";

/// How long the broker gets to bind its UDS before the spawn is declared failed
/// (it then gets SIGKILLed and the caller fails closed).
pub const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Inputs to [`spawn_broker`].
pub struct BrokerSpawnParams<'a> {
    /// Admitted workload id.
    pub workload_id: &'a str,
    /// Tenant id.
    pub tenant_id: &'a str,
    /// The per-VM `BROKER_PORT` socket the broker binds — the **backend-specific**
    /// path the VMM forwards the guest's `connect_host_vsock(BROKER_PORT)` to:
    /// `vm_vsock_port_socket` on libkrun (the VMM proxies straight to it),
    /// `vm_hvf_vsock_port_socket` on hvf (the supervisor splices to it). Passed in
    /// rather than derived because the two backends use different socket paths.
    pub broker_uds_path: &'a Path,
    /// Per-VM state dir; holds the broker PID file.
    pub state_dir: &'a Path,
    /// The audit-signer UDS from [`spawn_audit_signer`] — the broker's
    /// `host.audit.v1` handler forwards entries here, and only registers that
    /// service when this is set.
    pub audit_signer_uds_path: &'a Path,
    /// Exact host-service bindings from the admitted execution plan.
    pub services: &'a [mvm_core::protocol::broker::ServiceId],
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
}

impl<'a> BrokerSpawnParams<'a> {
    /// Start building a [`BrokerSpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> BrokerSpawnParamsBuilder<'a> {
        BrokerSpawnParamsBuilder::new()
    }
}

/// Builder for [`BrokerSpawnParams`]. Required fields are checked by
/// [`BrokerSpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct BrokerSpawnParamsBuilder<'a> {
    workload_id: Option<&'a str>,
    tenant_id: Option<&'a str>,
    broker_uds_path: Option<&'a Path>,
    state_dir: Option<&'a Path>,
    audit_signer_uds_path: Option<&'a Path>,
    services: Option<&'a [mvm_core::protocol::broker::ServiceId]>,
    capability_bindings: Option<&'a [mvm_contract::protocol::agent_capability::CapabilityBinding]>,
}

impl<'a> BrokerSpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workload_id: None,
            tenant_id: None,
            broker_uds_path: None,
            state_dir: None,
            audit_signer_uds_path: None,
            services: None,
            capability_bindings: None,
        }
    }

    /// Set `workload_id`.
    #[must_use]
    pub fn workload_id(mut self, workload_id: &'a str) -> Self {
        self.workload_id = Some(workload_id);
        self
    }

    /// Set `tenant_id`.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: &'a str) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set `broker_uds_path`.
    #[must_use]
    pub fn broker_uds_path(mut self, broker_uds_path: &'a Path) -> Self {
        self.broker_uds_path = Some(broker_uds_path);
        self
    }

    /// Set `state_dir`.
    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Set `audit_signer_uds_path`.
    #[must_use]
    pub fn audit_signer_uds_path(mut self, audit_signer_uds_path: &'a Path) -> Self {
        self.audit_signer_uds_path = Some(audit_signer_uds_path);
        self
    }

    /// Set `services`.
    #[must_use]
    pub fn services(mut self, services: &'a [mvm_core::protocol::broker::ServiceId]) -> Self {
        self.services = Some(services);
        self
    }

    #[must_use]
    pub fn capability_bindings(
        mut self,
        bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    ) -> Self {
        self.capability_bindings = Some(bindings);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<BrokerSpawnParams<'a>, BuilderError> {
        Ok(BrokerSpawnParams {
            workload_id: self
                .workload_id
                .ok_or(BuilderError::missing("BrokerSpawnParams", "workload_id"))?,
            tenant_id: self
                .tenant_id
                .ok_or(BuilderError::missing("BrokerSpawnParams", "tenant_id"))?,
            broker_uds_path: self.broker_uds_path.ok_or(BuilderError::missing(
                "BrokerSpawnParams",
                "broker_uds_path",
            ))?,
            state_dir: self
                .state_dir
                .ok_or(BuilderError::missing("BrokerSpawnParams", "state_dir"))?,
            audit_signer_uds_path: self.audit_signer_uds_path.ok_or(BuilderError::missing(
                "BrokerSpawnParams",
                "audit_signer_uds_path",
            ))?,
            services: self
                .services
                .ok_or(BuilderError::missing("BrokerSpawnParams", "services"))?,
            capability_bindings: self.capability_bindings.ok_or(BuilderError::missing(
                "BrokerSpawnParams",
                "capability_bindings",
            ))?,
        })
    }
}

impl<'a> Default for BrokerSpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a spawned broker: the per-VM `BROKER_PORT` UDS the VMM proxies the
/// guest's `connect_host_vsock(BROKER_PORT)` to.
#[derive(Debug)]
pub struct BrokerHandle {
    /// The `vm_vsock_port_socket(vm_name, BROKER_PORT)` the broker bound.
    pub uds_path: PathBuf,
}

/// Spawn the per-VM `mvm-broker` moat, binding the `BROKER_PORT` UDS the VMM
/// forwards the guest's dial to. Hands it a JSON `SubprocessConfig` on stdin
/// (the audit-signer UDS to forward `host.audit.v1` to + the host-signer
/// pubkey), `setsid`-detaches, waits for the UDS, and writes
/// `BROKER_PID_FILE` for the stop path to reap.
pub fn spawn_broker(params: BrokerSpawnParams<'_>) -> Result<BrokerHandle> {
    spawn_broker_with_timeout(params, BROKER_READY_TIMEOUT)
}

/// [`spawn_broker`] with an explicit readiness timeout — the test seam.
fn spawn_broker_with_timeout(
    params: BrokerSpawnParams<'_>,
    ready_timeout: Duration,
) -> Result<BrokerHandle> {
    let BrokerSpawnParams {
        workload_id,
        tenant_id,
        broker_uds_path,
        state_dir,
        audit_signer_uds_path,
        services,
        capability_bindings,
    } = params;

    let bin = resolve_subprocess_bin("mvm-broker", "MVM_BROKER_PATH")?;
    // The broker binds the backend-specific per-VM BROKER_PORT socket the VMM
    // forwards the guest's `connect_host_vsock(BROKER_PORT)` dial to (the caller
    // passes the right path — libkrun and hvf differ).
    let uds_path = broker_uds_path;
    if let Some(parent) = uds_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create broker socket dir {}: {e}", parent.display()))?;
    }

    let cfg = serde_json::json!({
        "workload_id": workload_id,
        "tenant_id": tenant_id,
        "uds_path": uds_path,
        "host_signer_public_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUB),
        // host.audit.v1 forwards each accepted entry to the per-VM audit-signer;
        // the broker only registers that service when this is set.
        "audit_signer_uds_path": audit_signer_uds_path,
        "services_bindings": services,
        "capability_bindings": capability_bindings,
    });

    let child = spawn_detached_with_config(&bin, &cfg, "mvm-broker")?;
    // No stdout handshake — the broker just binds. Readiness = the UDS appears.
    wait_for_uds("mvm-broker", uds_path, child.id(), ready_timeout)?;
    let pid_file = state_dir.join(BROKER_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    Ok(BrokerHandle {
        uds_path: uds_path.to_path_buf(),
    })
}

/// Spawn `bin` detached (`setsid`), write `cfg` JSON to its stdin then close it
/// (EOF), and hand back the child. The shared core of the audit-signer + broker
/// spawns so the detach/pipe moat can't drift between them. stdout/stderr are
/// nulled — both subprocesses log structured JSON to the supervisor's capture,
/// and neither emits a stdout handshake (readiness is detected by UDS-poll).
pub(crate) fn spawn_detached_with_config(
    bin: &Path,
    cfg: &serde_json::Value,
    what: &str,
) -> Result<std::process::Child> {
    use std::io::Write;
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
        .map_err(|e| anyhow!("spawn {what} ({}): {e}", bin.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("{what} stdin was not piped"))?
        .write_all(cfg.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe SubprocessConfig to {what}: {e}"))?;
    // (stdin writer dropped here → EOF, so the subprocess stops reading config.)
    Ok(child)
}

/// Reap the per-VM broker (if spawned) and drop its PID file. Best-effort +
/// idempotent + liveness-guarded.
pub fn reap_broker(state_dir: &Path) {
    let pid_file = state_dir.join(BROKER_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(&pid_file);
}

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

pub(crate) fn kill(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(pid, sig);
    }
}

// ============================================================================
// Gated spawn of both subprocesses + RAII reaper (the backend `start()` seam)
// ============================================================================

/// Inputs to [`spawn_broker_services_if_admitted`].
pub struct BrokerServicesSpawnParams<'a> {
    /// Admitted workload id (stamped into both subprocess configs).
    pub workload_id: &'a str,
    /// Tenant id from the admitted plan. `None` ⇒ no admitted plan ⇒ the spawn
    /// is a defused no-op (an unadmitted dev VM has no broker services, so a
    /// stray guest dial to `BROKER_PORT` gets `ECONNREFUSED`).
    pub tenant_id: Option<&'a str>,
    /// VM name; keys the per-VM workload chain (`<tenant>.<vm>.workload.jsonl`).
    pub vm_name: &'a str,
    /// Per-VM state dir.
    pub state_dir: &'a Path,
    /// The `BROKER_PORT` socket the broker binds — backend-specific (the caller
    /// passes `vm_vsock_port_socket` on libkrun, `vm_hvf_vsock_port_socket` on
    /// hvf; the VMM forwards the guest's `connect_host_vsock(BROKER_PORT)` here).
    pub broker_listen_socket: &'a Path,
    /// Exact host-service bindings from the admitted execution plan.
    pub services: &'a [mvm_core::protocol::broker::ServiceId],
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
}

impl<'a> BrokerServicesSpawnParams<'a> {
    /// Start building a [`BrokerServicesSpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> BrokerServicesSpawnParamsBuilder<'a> {
        BrokerServicesSpawnParamsBuilder::new()
    }
}

/// Builder for [`BrokerServicesSpawnParams`]. Required fields are checked by
/// [`BrokerServicesSpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct BrokerServicesSpawnParamsBuilder<'a> {
    workload_id: Option<&'a str>,
    tenant_id: Option<&'a str>,
    vm_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
    broker_listen_socket: Option<&'a Path>,
    services: Option<&'a [mvm_core::protocol::broker::ServiceId]>,
    capability_bindings: Option<&'a [mvm_contract::protocol::agent_capability::CapabilityBinding]>,
}

impl<'a> BrokerServicesSpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workload_id: None,
            tenant_id: None,
            vm_name: None,
            state_dir: None,
            broker_listen_socket: None,
            services: None,
            capability_bindings: None,
        }
    }

    /// Set `workload_id`.
    #[must_use]
    pub fn workload_id(mut self, workload_id: &'a str) -> Self {
        self.workload_id = Some(workload_id);
        self
    }

    /// Set `tenant_id`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: impl Into<Option<&'a str>>) -> Self {
        self.tenant_id = tenant_id.into();
        self
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `state_dir`.
    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Set `broker_listen_socket`.
    #[must_use]
    pub fn broker_listen_socket(mut self, broker_listen_socket: &'a Path) -> Self {
        self.broker_listen_socket = Some(broker_listen_socket);
        self
    }

    /// Set `services`.
    #[must_use]
    pub fn services(mut self, services: &'a [mvm_core::protocol::broker::ServiceId]) -> Self {
        self.services = Some(services);
        self
    }

    #[must_use]
    pub fn capability_bindings(
        mut self,
        bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    ) -> Self {
        self.capability_bindings = Some(bindings);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<BrokerServicesSpawnParams<'a>, BuilderError> {
        Ok(BrokerServicesSpawnParams {
            workload_id: self.workload_id.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "workload_id",
            ))?,
            tenant_id: self.tenant_id,
            vm_name: self.vm_name.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "vm_name",
            ))?,
            state_dir: self.state_dir.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "state_dir",
            ))?,
            broker_listen_socket: self.broker_listen_socket.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "broker_listen_socket",
            ))?,
            services: self.services.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "services",
            ))?,
            capability_bindings: self.capability_bindings.ok_or(BuilderError::missing(
                "BrokerServicesSpawnParams",
                "capability_bindings",
            ))?,
        })
    }
}

impl<'a> Default for BrokerServicesSpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the per-VM broker services (audit-signer **then** broker) when the VM
/// carries an admitted plan, returning an armed [`BrokerServicesGuard`] that
/// reaps both on drop until [`BrokerServicesGuard::defuse`]d.
///
/// Order matters: the audit-signer binds first so its UDS exists before the
/// broker's `host.audit.v1` handler is pointed at it. The guard is armed
/// *before* the broker spawn so a broker-spawn failure still reaps the
/// already-running audit-signer (fail closed). An unadmitted VM yields a
/// defused no-op guard — nothing spawns.
pub fn spawn_broker_services_if_admitted(
    params: BrokerServicesSpawnParams<'_>,
) -> Result<BrokerServicesGuard> {
    let BrokerServicesSpawnParams {
        workload_id,
        tenant_id,
        vm_name,
        state_dir,
        broker_listen_socket,
        services,
        capability_bindings,
    } = params;
    let Some(tenant_id) = tenant_id else {
        return Ok(BrokerServicesGuard::defused());
    };

    // Arm the guard before spawning so any spawn failure below drops it and
    // reaps whatever already started (fail closed).
    let guard = BrokerServicesGuard::armed(state_dir);
    let audit = spawn_audit_signer(AuditSignerSpawnParams {
        workload_id,
        tenant_id,
        vm_name,
        state_dir,
    })?;
    spawn_broker(BrokerSpawnParams {
        workload_id,
        tenant_id,
        broker_uds_path: broker_listen_socket,
        state_dir,
        audit_signer_uds_path: &audit.uds_path,
        services,
        capability_bindings,
    })?;
    Ok(guard)
}

/// Reap both per-VM broker-services subprocesses (broker, then audit-signer) and
/// drop their PID files. Best-effort + idempotent — a VM with none is a no-op.
pub fn reap_broker_services(state_dir: &Path) {
    reap_broker(state_dir);
    reap_audit_signer(state_dir);
}

/// RAII reaper for the per-VM broker services, armed while a backend's `start`
/// wires the VM and dropped on any early-return so a half-spawned pair can't
/// outlive a failed launch. Defused once the VM is fully up (the `stop` path
/// then owns teardown). Mirrors `network_endpoint_spawn::EndpointGuard`.
pub struct BrokerServicesGuard {
    /// `Some(state_dir)` while armed; `None` once defused.
    state_dir: Option<PathBuf>,
}

impl BrokerServicesGuard {
    fn armed(state_dir: &Path) -> Self {
        Self {
            state_dir: Some(state_dir.to_path_buf()),
        }
    }
    /// A guard for a VM that spawned no broker services — Drop is a no-op.
    pub fn defused() -> Self {
        Self { state_dir: None }
    }
    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.state_dir = None;
    }
}

impl Drop for BrokerServicesGuard {
    fn drop(&mut self) {
        if let Some(ref dir) = self.state_dir {
            tracing::warn!(state_dir = %dir.display(), "BrokerServicesGuard: reaping orphaned broker services");
            reap_broker_services(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    /// Serialize tests that mutate process-wide env / home.
    static HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn spawn_audit_signer_writes_chain_config_and_waits_for_uds() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-as-spawn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Route mvm_audit_dir() / mvm_keys_dir() under a disposable MVM_HOME.
        env.set("MVM_HOME", &dir);

        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let uds = state_dir.join(AUDIT_SIGNER_SOCK);
        let captured = dir.join("captured-config.json");

        // Stub audit-signer: dump the stdin config, create the UDS (the
        // readiness signal the real bin produces by binding), then idle so the
        // PID file points at a live process the test reaps.
        let stub = dir.join("stub-audit-signer.sh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\ncat > {cap}\ntouch {uds}\nsleep 5\n",
                cap = captured.display(),
                uds = uds.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.set("MVM_AUDIT_SIGNER_PATH", &stub);

        let res = spawn_audit_signer(AuditSignerSpawnParams {
            workload_id: "wl-001",
            tenant_id: "tenant-x",
            vm_name: "vm-1",
            state_dir: &state_dir,
        });

        let handle = res.expect("spawn with stub audit-signer should succeed");
        assert_eq!(handle.uds_path, uds);

        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&captured).expect("stub wrote config"))
                .expect("config is JSON");
        assert_eq!(cfg["workload_id"], "wl-001");
        assert_eq!(cfg["tenant_id"], "tenant-x");
        assert_eq!(cfg["uds_path"], uds.to_string_lossy().as_ref());
        // Chain wiring: the per-VM workload chain (NOT the per-tenant lifecycle
        // chain) — the exact path the verifier checks — signed with the
        // host-signer key for claim-8 continuity.
        assert_eq!(
            cfg["audit_jsonl_path"].as_str().unwrap(),
            mvm_core::config::workload_audit_path("tenant-x", "vm-1")
                .to_string_lossy()
                .as_ref(),
            "audit_jsonl_path must be the per-VM workload chain"
        );
        assert!(
            cfg["software_chain_key_path"]
                .as_str()
                .unwrap()
                .ends_with("host-signer.ed25519"),
            "chain key must be the host-signer key: {}",
            cfg["software_chain_key_path"]
        );
        assert!(
            state_dir.join(AUDIT_SIGNER_PID_FILE).exists(),
            "pid file must be written after readiness"
        );

        reap_audit_signer(&state_dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_audit_signer_fails_closed_when_uds_never_binds() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-as-nobind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_HOME", &dir);
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        // Stub that drains its config but NEVER binds the UDS (just idles), so
        // the readiness poll must time out and fail closed.
        let stub = dir.join("stub-nobind.sh");
        std::fs::write(&stub, "#!/bin/sh\ncat > /dev/null\nsleep 5\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.set("MVM_AUDIT_SIGNER_PATH", &stub);

        let res = spawn_audit_signer_with_timeout(
            AuditSignerSpawnParams {
                workload_id: "wl",
                tenant_id: "t",
                vm_name: "vm",
                state_dir: &state_dir,
            },
            Duration::from_millis(200),
        );

        let err = res.expect_err("must fail closed when the UDS never binds");
        assert!(err.to_string().contains("did not bind"), "got {err}");
        // No PID file is left behind on a failed spawn.
        assert!(!state_dir.join(AUDIT_SIGNER_PID_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_audit_signer_errors_when_bin_override_missing() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-as-nobin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_AUDIT_SIGNER_PATH", dir.join("nope"));

        let res = spawn_audit_signer(AuditSignerSpawnParams {
            workload_id: "wl",
            tenant_id: "t",
            vm_name: "vm",
            state_dir: &dir,
        });

        let err = res.expect_err("a missing bin override must error");
        assert!(err.to_string().contains("is not a file"), "got {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_broker_binds_broker_port_with_audit_signer_uds() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-broker-spawn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_HOME", &dir);

        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        // The broker binds the per-VM BROKER_PORT socket the VMM forwards to.
        let uds = mvm_core::config::vm_vsock_port_socket("vm-1", mvm_agentd::vsock::BROKER_PORT);
        std::fs::create_dir_all(uds.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&uds);
        let captured = dir.join("captured-broker-config.json");

        let stub = dir.join("stub-broker.sh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\ncat > {cap}\ntouch {uds}\nsleep 5\n",
                cap = captured.display(),
                uds = uds.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        env.set("MVM_BROKER_PATH", &stub);

        let audit_uds = state_dir.join(AUDIT_SIGNER_SOCK);
        let res = spawn_broker(BrokerSpawnParams {
            workload_id: "wl-001",
            tenant_id: "tenant-x",
            broker_uds_path: &uds,
            state_dir: &state_dir,
            audit_signer_uds_path: &audit_uds,
            services: &[],
            capability_bindings: &[],
        });

        let handle = res.expect("spawn with stub broker should succeed");
        assert_eq!(handle.uds_path, uds);

        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&captured).expect("stub wrote config"))
                .expect("config is JSON");
        assert_eq!(cfg["workload_id"], "wl-001");
        assert_eq!(cfg["tenant_id"], "tenant-x");
        // The broker binds the per-VM BROKER_PORT socket so the VMM forwards the
        // guest's connect_host_vsock(BROKER_PORT) dial straight to it.
        assert_eq!(cfg["uds_path"], uds.to_string_lossy().as_ref());
        // host.audit.v1 is only registered when the audit-signer UDS is present.
        assert_eq!(
            cfg["audit_signer_uds_path"],
            audit_uds.to_string_lossy().as_ref()
        );
        assert!(
            cfg["host_signer_public_key_path"]
                .as_str()
                .unwrap()
                .ends_with("host-signer.pub"),
            "broker must point at the host-signer pubkey: {}",
            cfg["host_signer_public_key_path"]
        );
        assert!(state_dir.join(BROKER_PID_FILE).exists());

        reap_broker(&state_dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn broker_services_defused_and_no_spawn_when_not_admitted() {
        let dir = std::env::temp_dir().join(format!("mvm-bs-noadmit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // tenant_id None ⇒ unadmitted ⇒ the gate short-circuits before any spawn
        // (no bin overrides are set, so a spawn attempt would error — proving the
        // gate returns a defused no-op without trying).
        let guard = spawn_broker_services_if_admitted(BrokerServicesSpawnParams {
            workload_id: "wl",
            tenant_id: None,
            vm_name: "vm",
            state_dir: &dir,
            // Unused on the unadmitted path (the gate short-circuits first).
            broker_listen_socket: &dir,
            services: &[],
            capability_bindings: &[],
        })
        .expect("unadmitted VM yields a defused no-op guard");
        drop(guard); // a defused guard's Drop reaps nothing
        assert!(!dir.join(AUDIT_SIGNER_PID_FILE).exists());
        assert!(!dir.join(BROKER_PID_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn broker_services_spawns_both_when_admitted() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-bs-admit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_HOME", &dir);

        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let audit_uds = state_dir.join(AUDIT_SIGNER_SOCK);
        let broker_uds =
            mvm_core::config::vm_vsock_port_socket("vm-1", mvm_agentd::vsock::BROKER_PORT);
        std::fs::create_dir_all(broker_uds.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&broker_uds);

        // Two stubs, each binds (touches) its own UDS so both readiness polls pass.
        let as_stub = dir.join("stub-as.sh");
        std::fs::write(
            &as_stub,
            format!(
                "#!/bin/sh\ncat > /dev/null\ntouch {}\nsleep 5\n",
                audit_uds.display()
            ),
        )
        .unwrap();
        let br_stub = dir.join("stub-br.sh");
        std::fs::write(
            &br_stub,
            format!(
                "#!/bin/sh\ncat > /dev/null\ntouch {}\nsleep 5\n",
                broker_uds.display()
            ),
        )
        .unwrap();
        for s in [&as_stub, &br_stub] {
            std::fs::set_permissions(s, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_AUDIT_SIGNER_PATH", &as_stub);
        env.set("MVM_BROKER_PATH", &br_stub);

        let res = spawn_broker_services_if_admitted(BrokerServicesSpawnParams {
            workload_id: "wl-001",
            tenant_id: Some("tenant-x"),
            vm_name: "vm-1",
            state_dir: &state_dir,
            broker_listen_socket: &broker_uds,
            services: &[],
            capability_bindings: &[],
        });

        let mut guard = res.expect("admitted VM spawns both broker services");
        // Both subprocesses bound their UDS and wrote their PID files.
        assert!(
            state_dir.join(AUDIT_SIGNER_PID_FILE).exists(),
            "audit-signer pid"
        );
        assert!(state_dir.join(BROKER_PID_FILE).exists(), "broker pid");

        guard.defuse();
        reap_broker_services(&state_dir);
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod broker_spawn_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = BrokerSpawnParams::builder().build() else {
            panic!("an empty BrokerSpawnParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("BrokerSpawnParams", "workload_id")
        );
    }
}

#[cfg(test)]
mod broker_services_spawn_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = BrokerServicesSpawnParams::builder().build() else {
            panic!("an empty BrokerServicesSpawnParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("BrokerServicesSpawnParams", "workload_id")
        );
    }
}

#[cfg(test)]
mod audit_signer_spawn_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = AuditSignerSpawnParams::builder().build() else {
            panic!("an empty AuditSignerSpawnParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("AuditSignerSpawnParams", "workload_id")
        );
    }
}
