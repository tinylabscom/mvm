//! Backend seam for the per-tenant host-agent daemon.
//!
//! Replaces the per-VM `mvm-broker` *fork* ([`crate::host::broker_services_spawn`])
//! with registration against one resident `mvm-host-agent` daemon per tenant:
//!
//! - [`ensure_host_agent_daemon`] lazily spawns the tenant's daemon (idempotent
//!   under a `flock`, so concurrent `up`s converge on one) and returns its
//!   control socket.
//! - [`register_vm`] / [`deregister_vm`] sign a control message with the host
//!   key and send it over that socket — the daemon binds/unbinds the VM's
//!   `BROKER_PORT` socket in response.
//!
//! The daemon owns all VM registrations for the tenant. Its supervised signer
//! helper is also per-tenant, so additional VMs add broker sockets and
//! registrations, not host-service processes.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mvm_contract::builder::BuilderError;
use mvm_core::protocol::broker_control::{
    self, ControlRequest, ControlResponse, DeregisterVm, RegisterVm,
};

use crate::host::broker_services_spawn::{
    AUDIT_SIGNER_HEAD_FILE, HOST_SIGNER_KEY, HOST_SIGNER_PUB, pid_alive, read_pid,
    resolve_subprocess_bin, spawn_detached_with_config,
};

/// PID file for the per-tenant host-agent daemon, under `host_agent_dir`.
const DAEMON_PID_FILE: &str = "daemon.pid";
/// Spawn lock so concurrent `up`s converge on one daemon.
const SPAWN_LOCK: &str = "spawn.lock";
/// How long the daemon gets to bind its control socket before the spawn fails.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Control-frame cap (replies are tiny).
const CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Bound a single control exchange so a daemon that dies after accepting a
/// request cannot hold the VM launch path indefinitely.
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Control reconnect attempts when the worker is restarting under the wrapper.
const CONTROL_RETRIES: u32 = 4;
/// Base delay for exponential control reconnect backoff.
const CONTROL_RETRY_BASE_DELAY_MS: u64 = 100;
/// Cap for exponential control reconnect backoff.
const CONTROL_RETRY_CAP_DELAY_MS: u64 = 500;

fn warm_claim_debug(message: &str) {
    let Some(path) = std::env::var_os("MVM_HVF_AGENT_DEBUG") else {
        return;
    };
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(file, "[host-agent-registration] {message}");
}

fn control_retry_delay(attempt: u32) -> Duration {
    let scaled = CONTROL_RETRY_BASE_DELAY_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(scaled.min(CONTROL_RETRY_CAP_DELAY_MS))
}

fn is_transient_control_error(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<std::io::Error>().is_some_and(|io| {
        matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotFound
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::UnexpectedEof
        )
    })
}

/// Whether a failed control attempt is worth another try.
///
/// The retry ladder exists so the register path can wait out a daemon that has
/// bound its socket but is not serving yet. It cannot wait a socket that is
/// not on disk into existence: no daemon is listening there, so nothing is
/// registered for a deregister to change and nothing will answer a register.
/// Without this, tearing down a VM whose daemon never started sleeps through
/// the whole ladder to reach a conclusion it could have drawn immediately.
fn should_retry_control(err: &(dyn std::error::Error + 'static), socket_exists: bool) -> bool {
    socket_exists && is_transient_control_error(err)
}

fn control_socket_is_ready(control_socket: &Path) -> bool {
    UnixStream::connect(control_socket).is_ok()
}

fn wait_for_control_socket(control_socket: &Path, pid: u32, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if control_socket_is_ready(control_socket) {
            return Ok(());
        }
        if !pid_alive(pid as libc::pid_t) {
            bail!(
                "mvm-host-agent exited before binding {}",
                control_socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    bail!(
        "mvm-host-agent did not bind {} within {:?}",
        control_socket.display(),
        timeout
    )
}

/// Load the raw 32-byte host signing key from `mvm_keys_dir()`.
pub fn load_host_signing_key() -> Result<[u8; 32]> {
    let path = mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY);
    let bytes =
        std::fs::read(&path).with_context(|| format!("read host signer key {}", path.display()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("host signer key must be 32 bytes, got {}", bytes.len()))
}

/// Ensure the per-tenant host-agent daemon is running and return its control
/// socket. Idempotent: if the daemon is already up (live pid + bound socket),
/// returns immediately; otherwise spawns it under an exclusive `flock` so two
/// concurrent `up`s can't both spawn one.
pub fn ensure_host_agent_daemon(tenant: &str) -> Result<PathBuf> {
    let dir = mvm_core::config::host_agent_dir(tenant);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create host-agent dir {}", dir.display()))?;
    warm_claim_debug("daemon_dir_ready");
    let control_socket = mvm_core::config::host_agent_control_socket(tenant);

    // Serialise spawn decisions per tenant.
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(SPAWN_LOCK))
        .with_context(|| format!("open host-agent spawn lock in {}", dir.display()))?;
    // SAFETY: flock on an owned fd; released on lock_file drop / process exit.
    let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("flock host-agent spawn lock");
    }
    warm_claim_debug("spawn_lock_acquired");

    // Already up? (live pid + connectable socket).
    let pid_file = dir.join(DAEMON_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        warm_claim_debug("pid_live");
        if control_socket_is_ready(&control_socket) {
            warm_claim_debug("control_ready");
            return Ok(control_socket);
        }
        warm_claim_debug("wait_existing_control");
        wait_for_control_socket(&control_socket, pid as u32, DAEMON_READY_TIMEOUT)?;
        warm_claim_debug("existing_control_ready");
        return Ok(control_socket);
    }

    // Stale socket from a dead daemon would block the rebind.
    let _ = std::fs::remove_file(&control_socket);
    warm_claim_debug("resolve_daemon_binary");
    let bin = resolve_subprocess_bin("mvm-host-agent", "MVM_HOST_AGENT_PATH")?;
    let cfg = serde_json::json!({
        "tenant_id": tenant,
        "control_socket": control_socket,
        "host_signer_public_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUB),
        "signer_helper_uds_path": mvm_core::config::host_agent_signer_helper_socket(tenant),
        "software_chain_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY),
    });
    let child = spawn_detached_with_config(&bin, &cfg, "mvm-host-agent")?;
    warm_claim_debug("daemon_spawned");
    wait_for_control_socket(&control_socket, child.id(), DAEMON_READY_TIMEOUT)?;
    warm_claim_debug("new_control_ready");
    std::fs::write(&pid_file, child.id().to_string())
        .with_context(|| format!("write {}", pid_file.display()))?;
    warm_claim_debug("daemon_pid_written");
    Ok(control_socket)
    // lock_file drops here → flock released.
}

/// Register a VM with the daemon: it binds the VM's `BROKER_PORT` socket and
/// serves host-services on it. Host-signed.
pub fn register_vm(control_socket: &Path, key_bytes: &[u8; 32], reg: RegisterVm) -> Result<()> {
    send_control(
        control_socket,
        key_bytes,
        ControlRequest::Register(Box::new(reg)),
    )
}

/// Deregister a VM at teardown: the daemon unbinds + drops it. Host-signed,
/// idempotent on the daemon side. The daemon itself is left running (warm).
pub fn deregister_vm(control_socket: &Path, key_bytes: &[u8; 32], vm_id: &str) -> Result<()> {
    send_control(
        control_socket,
        key_bytes,
        ControlRequest::Deregister(DeregisterVm {
            vm_id: vm_id.to_string(),
        }),
    )
}

/// Marker file under the VM state dir recording the tenant whose host-agent
/// daemon this VM registered with — so `stop()` can deregister without a flag
/// or a re-derivation of the tenant.
const HOST_AGENT_TENANT_REF: &str = "host-agent.tenant";

/// Inputs to [`register_host_agent_services_if_admitted`] — mirrors the per-VM
/// fork's `BrokerServicesSpawnParams`.
pub struct HostAgentServicesParams<'a> {
    /// Admitted workload id.
    pub workload_id: &'a str,
    /// Tenant id from the admitted plan. `None` ⇒ no admitted plan ⇒ defused
    /// no-op (an unadmitted dev VM registers no host services).
    pub tenant_id: Option<&'a str>,
    /// VM name; the registration's `vm_id` and the per-VM chain key.
    pub vm_name: &'a str,
    /// Per-VM state dir (audit-signer pid/sock + the tenant-ref marker).
    pub state_dir: &'a Path,
    /// The backend-specific `BROKER_PORT` socket the daemon should bind for this
    /// VM (libkrun `vm_vsock_port_socket`, hvf `vm_hvf_vsock_port_socket`).
    pub broker_listen_socket: &'a Path,
    /// Exact host-service bindings from the admitted execution plan.
    pub services: &'a [mvm_core::protocol::broker::ServiceId],
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    /// Host-only controller-backed typed services prepared by admission.
    pub service_proxies: &'a [mvm_contract::protocol::broker_control::ServiceProxyBinding],
}

impl<'a> HostAgentServicesParams<'a> {
    /// Start building a [`HostAgentServicesParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> HostAgentServicesParamsBuilder<'a> {
        HostAgentServicesParamsBuilder::new()
    }
}

/// Builder for [`HostAgentServicesParams`]. Required fields are checked by
/// [`HostAgentServicesParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct HostAgentServicesParamsBuilder<'a> {
    workload_id: Option<&'a str>,
    tenant_id: Option<&'a str>,
    vm_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
    broker_listen_socket: Option<&'a Path>,
    services: Option<&'a [mvm_core::protocol::broker::ServiceId]>,
    capability_bindings: Option<&'a [mvm_contract::protocol::agent_capability::CapabilityBinding]>,
    service_proxies: Option<&'a [mvm_contract::protocol::broker_control::ServiceProxyBinding]>,
}

impl<'a> HostAgentServicesParamsBuilder<'a> {
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
            service_proxies: Some(&[]),
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

    /// Set controller-backed typed service bindings.
    #[must_use]
    pub fn service_proxies(
        mut self,
        bindings: &'a [mvm_contract::protocol::broker_control::ServiceProxyBinding],
    ) -> Self {
        self.service_proxies = Some(bindings);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<HostAgentServicesParams<'a>, BuilderError> {
        Ok(HostAgentServicesParams {
            workload_id: self.workload_id.ok_or(BuilderError::missing(
                "HostAgentServicesParams",
                "workload_id",
            ))?,
            tenant_id: self.tenant_id,
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("HostAgentServicesParams", "vm_name"))?,
            state_dir: self.state_dir.ok_or(BuilderError::missing(
                "HostAgentServicesParams",
                "state_dir",
            ))?,
            broker_listen_socket: self.broker_listen_socket.ok_or(BuilderError::missing(
                "HostAgentServicesParams",
                "broker_listen_socket",
            ))?,
            services: self
                .services
                .ok_or(BuilderError::missing("HostAgentServicesParams", "services"))?,
            capability_bindings: self.capability_bindings.ok_or(BuilderError::missing(
                "HostAgentServicesParams",
                "capability_bindings",
            ))?,
            service_proxies: self.service_proxies.ok_or(BuilderError::missing(
                "HostAgentServicesParams",
                "service_proxies",
            ))?,
        })
    }
}

impl<'a> Default for HostAgentServicesParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon-path equivalent of `spawn_broker_services_if_admitted`: ensure the
/// per-tenant host-agent daemon and register the VM with it. The daemon binds
/// `broker_listen_socket`; its resident signer-helper child owns the per-VM
/// workload chain.
/// Returns a guard that, until [`HostAgentServicesGuard::defuse`]d, deregisters
/// the VM on drop (the daemon stays warm). An unadmitted VM yields a defused
/// no-op.
pub fn register_host_agent_services_if_admitted(
    params: HostAgentServicesParams<'_>,
) -> Result<HostAgentServicesGuard> {
    let HostAgentServicesParams {
        workload_id,
        tenant_id,
        vm_name,
        state_dir,
        broker_listen_socket,
        services,
        capability_bindings,
        service_proxies,
    } = params;
    let Some(tenant) = tenant_id else {
        return Ok(HostAgentServicesGuard::defused());
    };

    // Arm before any spawn so a failure below reaps what already started.
    let guard = HostAgentServicesGuard::armed(state_dir, tenant, vm_name);

    warm_claim_debug("ensure_daemon_begin");
    let control_socket = ensure_host_agent_daemon(tenant)?;
    warm_claim_debug("ensure_daemon_done");
    let key = load_host_signing_key()?;
    warm_claim_debug("load_key_done");
    write_host_agent_owner_ref(state_dir)?;
    warm_claim_debug("owner_ref_done");
    register_vm(
        &control_socket,
        &key,
        RegisterVm {
            vm_id: vm_name.to_string(),
            workload_id: Some(workload_id.to_string()),
            tenant_id: tenant.to_string(),
            broker_listen_socket: broker_listen_socket.to_string_lossy().into_owned(),
            workload_chain_path: mvm_core::config::workload_audit_path(tenant, vm_name)
                .to_string_lossy()
                .into_owned(),
            workload_chain_head_path: Some(
                state_dir
                    .join(AUDIT_SIGNER_HEAD_FILE)
                    .to_string_lossy()
                    .into_owned(),
            ),
            audit_signer_uds_path: None,
            services_bindings: services.to_vec(),
            capability_bindings: capability_bindings.to_vec(),
            service_proxies: service_proxies.to_vec(),
            assurance: None,
        },
    )?;
    warm_claim_debug("register_vm_done");
    // Record the tenant so the stop path can deregister without a flag.
    std::fs::write(state_dir.join(HOST_AGENT_TENANT_REF), tenant)
        .with_context(|| format!("write host-agent tenant ref in {}", state_dir.display()))?;
    warm_claim_debug("tenant_ref_done");
    Ok(guard)
}

/// Teardown for a VM that registered with a host-agent daemon: deregister it
/// (best-effort — the daemon stays warm). Also reaps the legacy per-VM
/// audit-signer if an older daemon-path launch left one behind. Idempotent.
pub fn reap_host_agent_services(state_dir: &Path, tenant: &str, vm_name: &str) {
    if let Ok(key) = load_host_signing_key() {
        let control_socket = mvm_core::config::host_agent_control_socket(tenant);
        // Best-effort: a missing daemon (already gone) is fine.
        let _ = deregister_vm(&control_socket, &key, vm_name);
    }
    crate::host::broker_services_spawn::reap_audit_signer(state_dir);
    let _ = std::fs::remove_file(state_dir.join(HOST_AGENT_TENANT_REF));
    let _ = std::fs::remove_file(state_dir.join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE));
}

fn write_host_agent_owner_ref(state_dir: &Path) -> Result<()> {
    let reference = state_dir.join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE);
    let Some(owner_pid_path) = crate::host::process_liveness::live_process_pid_file(state_dir)
    else {
        let _ = std::fs::remove_file(reference);
        return Ok(());
    };
    let bytes = serde_json::to_vec(&owner_pid_path).context("encode host-agent owner PID path")?;
    std::fs::write(&reference, bytes)
        .with_context(|| format!("write host-agent owner ref {}", reference.display()))
}

/// The `stop()`-side reap: if this VM registered with a daemon (the tenant-ref
/// marker is present), deregister + reap; otherwise a no-op. So `stop()` need
/// not know which path `start()` took — and it composes with the fork path's
/// `reap_broker_services` (each is a no-op for the other path).
pub fn reap_host_agent_services_from_state(state_dir: &Path, vm_name: &str) {
    let ref_path = state_dir.join(HOST_AGENT_TENANT_REF);
    if let Ok(tenant) = std::fs::read_to_string(&ref_path) {
        let tenant = tenant.trim();
        if !tenant.is_empty() {
            reap_host_agent_services(state_dir, tenant, vm_name);
        }
    }
}

/// RAII guard mirroring `BrokerServicesGuard` for the daemon path: while armed,
/// Drop deregisters the VM + reaps its audit-signer; `defuse` once the VM is up
/// and the `stop` path owns teardown.
pub struct HostAgentServicesGuard {
    /// `Some((state_dir, tenant, vm))` while armed; `None` once defused.
    armed: Option<(PathBuf, String, String)>,
}

impl HostAgentServicesGuard {
    fn armed(state_dir: &Path, tenant: &str, vm_name: &str) -> Self {
        Self {
            armed: Some((
                state_dir.to_path_buf(),
                tenant.to_string(),
                vm_name.to_string(),
            )),
        }
    }
    /// A guard for a VM that registered nothing — Drop is a no-op.
    pub fn defused() -> Self {
        Self { armed: None }
    }
    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.armed = None;
    }
}

impl Drop for HostAgentServicesGuard {
    fn drop(&mut self) {
        if let Some((state_dir, tenant, vm)) = self.armed.take() {
            reap_host_agent_services(&state_dir, &tenant, &vm);
        }
    }
}

/// Whether the host-agent daemon path is selected. **Default: enabled** — the
/// per-tenant daemon is the default for an admitted libkrun/hvf workload, so
/// `host.audit.v1` is available on a plain `up` (no `MVM_GATEWAY_BRIDGE`).
/// `MVM_HOST_AGENT_DAEMON=0` is the opt-out escape hatch back to the per-VM
/// broker fork during the transition; the fork is removed once the daemon path
/// has soaked. Any value other than `0` leaves the daemon on.
pub fn host_agent_daemon_enabled() -> bool {
    daemon_enabled_from(std::env::var("MVM_HOST_AGENT_DAEMON").ok().as_deref())
}

/// Pure decision for [`host_agent_daemon_enabled`] — unset ⇒ on; explicit `0`
/// ⇒ off (fork); anything else ⇒ on.
fn daemon_enabled_from(env: Option<&str>) -> bool {
    env != Some("0")
}

/// Unifies the two start-path service guards (fork vs daemon) so a backend's
/// `start()` holds one value and `defuse`s it once the VM is up.
pub enum ServicesGuard {
    /// The per-VM broker fork path.
    Fork(crate::host::broker_services_spawn::BrokerServicesGuard),
    /// The per-tenant host-agent daemon path.
    Agent(HostAgentServicesGuard),
    /// Nothing armed (unadmitted, or a spawn failure that was logged).
    None,
}

impl ServicesGuard {
    /// Whether host services are actually registered for this VM.
    ///
    /// Registration is best-effort: a failure is logged and the workload still
    /// runs, which means a launch can succeed with `host.audit.v1` unavailable.
    /// Something has to be able to see that, or a degraded launch is
    /// indistinguishable from a healthy one.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        !matches!(self, Self::None)
    }
}

impl ServicesGuard {
    /// Disarm whichever path armed; the `stop` path owns teardown after this.
    pub fn defuse(&mut self) {
        match self {
            ServicesGuard::Fork(g) => g.defuse(),
            ServicesGuard::Agent(g) => g.defuse(),
            ServicesGuard::None => {}
        }
    }
}

/// Sign `request` with the host key, send it framed over `control_socket`, and
/// map the daemon's `ControlResponse` onto a `Result`.
fn send_control(
    control_socket: &Path,
    key_bytes: &[u8; 32],
    request: ControlRequest,
) -> Result<()> {
    let signed = broker_control::sign_with_key_bytes(request, key_bytes)
        .context("sign host-agent control request")?;
    let mut last_err = None;
    for attempt in 0..CONTROL_RETRIES {
        let result = (|| -> Result<()> {
            let mut stream = UnixStream::connect(control_socket).with_context(|| {
                format!(
                    "connect host-agent control socket {}",
                    control_socket.display()
                )
            })?;
            stream
                .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
                .context("set host-agent control read timeout")?;
            stream
                .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
                .context("set host-agent control write timeout")?;
            write_framed(&mut stream, &signed)?;
            match read_framed::<ControlResponse>(&mut stream)? {
                ControlResponse::Ok => Ok(()),
                ControlResponse::Err { message } => {
                    bail!("host-agent refused control request: {message}")
                }
            }
        })();

        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !should_retry_control(e.root_cause(), control_socket.exists()) {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt + 1 < CONTROL_RETRIES {
                    std::thread::sleep(control_retry_delay(attempt));
                }
            }
        }
    }
    Err(last_err.expect("control retry loop must record the final error"))
}

/// 4-byte big-endian length prefix + JSON body — the same wire the daemon's
/// async `read_frame`/`write_frame` use, in a sync form for the spawn path.
fn write_framed<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("encode control frame")?;
    let len = u32::try_from(body.len()).context("control frame too large for u32 prefix")?;
    stream
        .write_all(&len.to_be_bytes())
        .context("write control frame len")?;
    stream
        .write_all(&body)
        .context("write control frame body")?;
    stream.flush().context("flush control frame")?;
    Ok(())
}

fn read_framed<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("read control reply len")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > CONTROL_MAX_FRAME_BYTES {
        bail!("control reply {len} bytes exceeds cap {CONTROL_MAX_FRAME_BYTES}");
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .context("read control reply body")?;
    serde_json::from_slice(&body).context("decode control reply")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bind_unix_listener, error_chain_has_permission_denied};
    use mvm_core::protocol::broker_control::SignedControl;

    fn key() -> [u8; 32] {
        [11u8; 32]
    }

    #[test]
    fn control_retry_delay_grows_then_caps() {
        assert_eq!(control_retry_delay(0), Duration::from_millis(100));
        assert_eq!(control_retry_delay(1), Duration::from_millis(200));
        assert_eq!(control_retry_delay(2), Duration::from_millis(400));
        assert_eq!(control_retry_delay(3), Duration::from_millis(500));
        assert_eq!(control_retry_delay(32), Duration::from_millis(500));
    }

    #[test]
    fn transient_control_errors_cover_restart_races() {
        assert!(is_transient_control_error(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "socket missing during restart"
        )));
        assert!(is_transient_control_error(&std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "worker restarting"
        )));
        assert!(is_transient_control_error(&std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "worker died mid-reply"
        )));
        assert!(!is_transient_control_error(&std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "caller bug"
        )));
    }

    /// A stub control endpoint: bind `socket`, accept one connection, read the
    /// framed `SignedControl`, and reply with `response`. Returns the captured
    /// request for assertions.
    fn stub_endpoint(
        socket: PathBuf,
        response: ControlResponse,
    ) -> std::thread::JoinHandle<Option<SignedControl>> {
        std::thread::spawn(move || {
            let listener = bind_unix_listener(&socket)?;
            let (mut s, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).unwrap();
            let signed: SignedControl = serde_json::from_slice(&buf).unwrap();
            let body = serde_json::to_vec(&response).unwrap();
            s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            s.write_all(&body).unwrap();
            s.flush().unwrap();
            Some(signed)
        })
    }

    fn sample_register(dir: &Path) -> RegisterVm {
        RegisterVm {
            vm_id: "vm-1".into(),
            workload_id: Some("wl-1".into()),
            tenant_id: "local".into(),
            broker_listen_socket: dir.join("vsock-5300.sock").to_string_lossy().into_owned(),
            workload_chain_path: dir
                .join("local.vm-1.workload.jsonl")
                .to_string_lossy()
                .into_owned(),
            workload_chain_head_path: Some(
                dir.join("local.vm-1.head").to_string_lossy().into_owned(),
            ),
            audit_signer_uds_path: Some(
                dir.join("audit-signer.sock").to_string_lossy().into_owned(),
            ),
            services_bindings: vec![],
            capability_bindings: vec![],
            assurance: None,
            service_proxies: vec![],
        }
    }

    #[test]
    fn register_vm_signs_and_sends_and_accepts_ok() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let handle = stub_endpoint(socket.clone(), ControlResponse::Ok);
        // Give the stub a beat to bind.
        std::thread::sleep(Duration::from_millis(50));

        if let Err(err) = register_vm(&socket, &key(), sample_register(dir.path())) {
            let captured = handle.join().unwrap();
            if captured.is_none() {
                return;
            }
            if error_chain_has_permission_denied(err.as_ref()) {
                eprintln!("skipping test: sandbox denied control socket usage: {err}");
                return;
            }
            panic!("register ok: {err}");
        }

        // The endpoint received a signed Register carrying the right vm_id. (The
        // signature's validity under the host key is covered by mvm-core's
        // SignedControl tests; here we assert the seam encoded + sent it.)
        let signed = handle.join().unwrap().expect("captured");
        assert!(!signed.sig.is_empty(), "request was signed");
        match &signed.request {
            ControlRequest::Register(r) => assert_eq!(r.vm_id, "vm-1"),
            other => panic!("expected Register, got {other:?}"),
        }
    }

    #[test]
    fn control_err_response_is_surfaced() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let handle = stub_endpoint(
            socket.clone(),
            ControlResponse::Err {
                message: "unsafe vm_id".into(),
            },
        );
        std::thread::sleep(Duration::from_millis(50));

        let err = match deregister_vm(&socket, &key(), "vm-1") {
            Ok(()) => panic!("Err surfaces"),
            Err(err) => err,
        };
        let captured = handle.join().unwrap();
        if captured.is_none() {
            return;
        }
        if error_chain_has_permission_denied(err.as_ref()) {
            eprintln!("skipping test: sandbox denied control socket usage: {err}");
            return;
        }
        assert!(err.to_string().contains("unsafe vm_id"));
    }

    #[test]
    fn register_vm_retries_across_control_socket_restart() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn({
            let socket = socket.clone();
            let dir = dir.path().to_path_buf();
            move || -> bool {
                let Some(listener) = bind_unix_listener(&socket) else {
                    let _ = ready_tx.send(false);
                    return false;
                };
                if ready_tx.send(true).is_err() {
                    return false;
                }
                let Some((mut stream, _)) = accept_with_timeout(&listener) else {
                    return false;
                };
                let signed = read_framed::<SignedControl>(&mut stream).unwrap();
                match &signed.request {
                    ControlRequest::Register(r) => assert_eq!(r.vm_id, "vm-1"),
                    other => panic!("expected Register, got {other:?}"),
                }
                drop(stream);
                drop(listener);

                std::fs::remove_file(&socket).unwrap();

                let Some(listener) = bind_unix_listener(&socket) else {
                    return false;
                };
                let Some((mut stream, _)) = accept_with_timeout(&listener) else {
                    return false;
                };
                let signed = read_framed::<SignedControl>(&mut stream).unwrap();
                match &signed.request {
                    ControlRequest::Register(r) => {
                        assert_eq!(r.vm_id, "vm-1");
                        assert_eq!(
                            r.broker_listen_socket,
                            dir.join("vsock-5300.sock").to_string_lossy()
                        );
                    }
                    other => panic!("expected Register, got {other:?}"),
                }
                write_framed(&mut stream, &ControlResponse::Ok).unwrap();
                true
            }
        });

        match ready_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                assert!(!worker.join().unwrap(), "the control endpoint must bind");
                return;
            }
        }

        if let Err(err) = register_vm(&socket, &key(), sample_register(dir.path())) {
            let helper_ready = worker.join().unwrap();
            if !helper_ready {
                return;
            }
            if error_chain_has_permission_denied(err.as_ref()) {
                eprintln!("skipping test: sandbox denied control socket usage: {err}");
                return;
            }
            panic!("register retries across daemon restart: {err}");
        }
        assert!(worker.join().unwrap());
    }

    fn accept_with_timeout(
        listener: &std::os::unix::net::UnixListener,
    ) -> Option<(UnixStream, std::os::unix::net::SocketAddr)> {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok(connection) => return Some(connection),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn unadmitted_register_is_a_defused_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let guard = register_host_agent_services_if_admitted(HostAgentServicesParams {
            workload_id: "wl",
            tenant_id: None,
            vm_name: "vm",
            state_dir: dir.path(),
            broker_listen_socket: &dir.path().join("vsock-5300.sock"),
            services: &[],
            capability_bindings: &[],
            service_proxies: &[],
        })
        .expect("unadmitted VM registers nothing");
        drop(guard); // defused Drop reaps nothing
        // No tenant-ref written, no audit-signer pid.
        assert!(!dir.path().join(HOST_AGENT_TENANT_REF).exists());
    }

    #[test]
    fn owner_ref_records_the_live_supervisor_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("hvf.pid");
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();

        write_host_agent_owner_ref(dir.path()).unwrap();

        let bytes = std::fs::read(
            dir.path()
                .join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE),
        )
        .unwrap();
        assert_eq!(serde_json::from_slice::<PathBuf>(&bytes).unwrap(), pid_path);
    }

    #[test]
    fn owner_ref_removes_stale_marker_without_a_live_supervisor() {
        let dir = tempfile::tempdir().unwrap();
        let reference = dir
            .path()
            .join(mvm_core::config::HOST_AGENT_OWNER_PID_REF_FILE);
        std::fs::write(&reference, b"stale").unwrap();

        write_host_agent_owner_ref(dir.path()).unwrap();

        assert!(!reference.exists());
    }

    #[test]
    fn reap_from_state_is_a_no_op_without_a_tenant_ref() {
        let dir = tempfile::tempdir().unwrap();
        // No host-agent.tenant marker ⇒ fork path ⇒ this must do nothing and
        // must not panic (so it's safe to call unconditionally in stop()).
        reap_host_agent_services_from_state(dir.path(), "vm-1");
    }

    #[test]
    fn daemon_is_the_default_with_a_zero_opt_out() {
        // Default (unset) is on; only an explicit "0" opts back to the fork.
        assert!(daemon_enabled_from(None), "default is the daemon");
        assert!(!daemon_enabled_from(Some("0")), "0 opts out to the fork");
        assert!(daemon_enabled_from(Some("1")));
        assert!(daemon_enabled_from(Some("")), "non-0 stays on the daemon");
    }

    #[test]
    fn defused_guard_drop_does_not_reap() {
        // A defused guard's Drop must be inert (no key load, no deregister).
        let mut g = HostAgentServicesGuard::defused();
        g.defuse();
        drop(g);
    }
}

#[cfg(test)]
mod retry_policy_tests {
    use super::*;

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "synthetic")
    }

    #[test]
    fn a_transient_error_retries_only_while_the_socket_exists() {
        let err = io(std::io::ErrorKind::ConnectionRefused);
        assert!(
            should_retry_control(&err, true),
            "a refused connect to a live socket is worth retrying"
        );
        assert!(
            !should_retry_control(&err, false),
            "no socket on disk means no daemon to wait for"
        );
    }

    #[test]
    fn a_missing_socket_is_not_waited_out() {
        // The exact shape that cost 700ms: connecting to an absent socket
        // yields NotFound, which is transient in general but not when the
        // socket itself is what is absent.
        let err = io(std::io::ErrorKind::NotFound);
        assert!(is_transient_control_error(&err));
        assert!(!should_retry_control(&err, false));
        assert!(should_retry_control(&err, true));
    }

    #[test]
    fn a_permanent_error_never_retries() {
        let err = io(std::io::ErrorKind::PermissionDenied);
        assert!(!should_retry_control(&err, true));
        assert!(!should_retry_control(&err, false));
    }

    #[test]
    fn an_unregistered_guard_reports_itself_as_degraded() {
        assert!(!ServicesGuard::None.is_registered());
    }
}

#[cfg(test)]
mod host_agent_services_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = HostAgentServicesParams::builder().build() else {
            panic!("an empty HostAgentServicesParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("HostAgentServicesParams", "workload_id")
        );
    }
}
