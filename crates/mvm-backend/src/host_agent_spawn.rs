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
//! The audit-signer stays per-VM (forked by `broker_services_spawn`); the
//! daemon's `host.audit.v1` handler forwards to it. This slice is the seam
//! only — it is not yet wired into `start()`/`stop()` (that lands behind a flag
//! next), so it changes no behavior on its own.

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
    HOST_SIGNER_KEY, HOST_SIGNER_PUB, pid_alive, read_pid, resolve_subprocess_bin,
    spawn_detached_with_config, wait_for_uds,
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
            tenant_id: "local".into(),
            broker_listen_socket: dir.join("vsock-5300.sock"),
            workload_chain_path: dir.join("local.vm-1.workload.jsonl"),
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
}
