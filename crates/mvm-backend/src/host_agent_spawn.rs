//! Backend seam for the per-tenant host-agent daemon.
//!
//! Replaces the per-VM `mvm-broker` *fork* ([`crate::broker_services_spawn`])
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
use mvm_core::protocol::broker_control::{
    ControlRequest, ControlResponse, DeregisterVm, RegisterVm, SignedControl,
};

use crate::broker_services_spawn::{
    AUDIT_SIGNER_HEAD_FILE, HOST_SIGNER_KEY, HOST_SIGNER_PUB, pid_alive, read_pid,
    resolve_subprocess_bin, spawn_detached_with_config, wait_for_uds,
};

/// PID file for the per-tenant host-agent daemon, under `host_agent_dir`.
const DAEMON_PID_FILE: &str = "daemon.pid";
/// Spawn lock so concurrent `up`s converge on one daemon.
const SPAWN_LOCK: &str = "spawn.lock";
/// How long the daemon gets to bind its control socket before the spawn fails.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Control-frame cap (replies are tiny).
const CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;

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

    // Already up? (live pid + bound socket).
    let pid_file = dir.join(DAEMON_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
        && control_socket.exists()
    {
        return Ok(control_socket);
    }

    // Stale socket from a dead daemon would block the rebind.
    let _ = std::fs::remove_file(&control_socket);
    let bin = resolve_subprocess_bin("mvm-host-agent", "MVM_HOST_AGENT_PATH")?;
    let cfg = serde_json::json!({
        "tenant_id": tenant,
        "control_socket": control_socket,
        "host_signer_public_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUB),
        "signer_helper_uds_path": mvm_core::config::host_agent_signer_helper_socket(tenant),
        "software_chain_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY),
    });
    let child = spawn_detached_with_config(&bin, &cfg, "mvm-host-agent")?;
    wait_for_uds(
        "mvm-host-agent",
        &control_socket,
        child.id(),
        DAEMON_READY_TIMEOUT,
    )?;
    std::fs::write(&pid_file, child.id().to_string())
        .with_context(|| format!("write {}", pid_file.display()))?;
    Ok(control_socket)
    // lock_file drops here → flock released.
}

/// Register a VM with the daemon: it binds the VM's `BROKER_PORT` socket and
/// serves host-services on it. Host-signed.
pub fn register_vm(control_socket: &Path, key_bytes: &[u8; 32], reg: RegisterVm) -> Result<()> {
    send_control(control_socket, key_bytes, ControlRequest::Register(reg))
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
    /// VM (libkrun `vm_vsock_port_socket`, vz `vm_vz_vsock_port_socket`).
    pub broker_listen_socket: &'a Path,
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
    } = params;
    let Some(tenant) = tenant_id else {
        return Ok(HostAgentServicesGuard::defused());
    };

    // Arm before any spawn so a failure below reaps what already started.
    let guard = HostAgentServicesGuard::armed(state_dir, tenant, vm_name);

    let control_socket = ensure_host_agent_daemon(tenant)?;
    let key = load_host_signing_key()?;
    register_vm(
        &control_socket,
        &key,
        RegisterVm {
            vm_id: vm_name.to_string(),
            workload_id: Some(workload_id.to_string()),
            tenant_id: tenant.to_string(),
            broker_listen_socket: broker_listen_socket.to_path_buf(),
            workload_chain_path: mvm_core::config::workload_audit_path(tenant, vm_name),
            workload_chain_head_path: Some(state_dir.join(AUDIT_SIGNER_HEAD_FILE)),
            audit_signer_uds_path: None,
            services_bindings: vec![],
        },
    )?;
    // Record the tenant so the stop path can deregister without a flag.
    std::fs::write(state_dir.join(HOST_AGENT_TENANT_REF), tenant)
        .with_context(|| format!("write host-agent tenant ref in {}", state_dir.display()))?;
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
    crate::broker_services_spawn::reap_audit_signer(state_dir);
    let _ = std::fs::remove_file(state_dir.join(HOST_AGENT_TENANT_REF));
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
/// per-tenant daemon is the default for an admitted libkrun/vz workload, so
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
    Fork(crate::broker_services_spawn::BrokerServicesGuard),
    /// The per-tenant host-agent daemon path.
    Agent(HostAgentServicesGuard),
    /// Nothing armed (unadmitted, or a spawn failure that was logged).
    None,
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
    let signed = SignedControl::sign_with_key_bytes(request, key_bytes)
        .context("sign host-agent control request")?;
    let mut stream = UnixStream::connect(control_socket).with_context(|| {
        format!(
            "connect host-agent control socket {}",
            control_socket.display()
        )
    })?;
    write_framed(&mut stream, &signed)?;
    match read_framed::<ControlResponse>(&mut stream)? {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Err { message } => bail!("host-agent refused control request: {message}"),
    }
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
    use std::os::unix::net::UnixListener;

    fn key() -> [u8; 32] {
        [11u8; 32]
    }

    /// A stub control endpoint: bind `socket`, accept one connection, read the
    /// framed `SignedControl`, and reply with `response`. Returns the captured
    /// request for assertions.
    fn stub_endpoint(
        socket: PathBuf,
        response: ControlResponse,
    ) -> std::thread::JoinHandle<Option<SignedControl>> {
        std::thread::spawn(move || {
            let listener = UnixListener::bind(&socket).unwrap();
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
            broker_listen_socket: dir.join("vsock-5300.sock"),
            workload_chain_path: dir.join("local.vm-1.workload.jsonl"),
            workload_chain_head_path: Some(dir.join("local.vm-1.head")),
            audit_signer_uds_path: Some(dir.join("audit-signer.sock")),
            services_bindings: vec![],
        }
    }

    #[test]
    fn register_vm_signs_and_sends_and_accepts_ok() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let handle = stub_endpoint(socket.clone(), ControlResponse::Ok);
        // Give the stub a beat to bind.
        std::thread::sleep(Duration::from_millis(50));

        register_vm(&socket, &key(), sample_register(dir.path())).expect("register ok");

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

        let err = deregister_vm(&socket, &key(), "vm-1").expect_err("Err surfaces");
        assert!(err.to_string().contains("unsafe vm_id"));
        handle.join().unwrap();
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
        })
        .expect("unadmitted VM registers nothing");
        drop(guard); // defused Drop reaps nothing
        // No tenant-ref written, no audit-signer pid.
        assert!(!dir.path().join(HOST_AGENT_TENANT_REF).exists());
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
