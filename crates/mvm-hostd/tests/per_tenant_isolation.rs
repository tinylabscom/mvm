use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mvm_core::config;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::protocol::broker_control::RegisterVm;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::host_keypair;
use mvm_hostd::audit_signer::verify::verify_workload_chain;
use mvm_runtime::{deregister_vm, ensure_host_agent_daemon, load_host_signing_key, register_vm};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const HOST_AGENT_BIN: &str = env!("CARGO_BIN_EXE_mvm-host-agent");
const SIGNER_HELPER_BIN: &str = env!("CARGO_BIN_EXE_mvm-signer-helper");

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn kill_process_group(pid: libc::pid_t) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

fn kill_pid(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

async fn write_frame(stream: &mut UnixStream, value: &impl serde::Serialize) -> Result<()> {
    let body = serde_json::to_vec(value).context("encode frame")?;
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .context("write frame len")?;
    stream.write_all(&body).await.context("write frame body")?;
    stream.flush().await.context("flush frame")?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .await
        .context("read frame len")?;
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .await
        .context("read frame body")?;
    serde_json::from_slice(&body).context("decode frame")
}

async fn emit_audit(sock: &Path, event: &str) -> Result<ServiceResponse> {
    let mut conn = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect broker socket {}", sock.display()))?;
    let call = ServiceCall {
        service: ServiceId::parse("host.audit.v1").expect("service id"),
        verb: "emit".into(),
        correlation_id: CorrelationId::new("guest-supplied-ignored"),
        payload: serde_json::json!({
            "ts": "2026-06-19T00:00:00Z",
            "fields": {"event": event},
        }),
        capability: None,
    };
    write_frame(&mut conn, &call).await?;
    read_frame(&mut conn).await
}

/// Hang guard — deliberately **not** a budget.
///
/// This waits on a real spawned broker becoming ready. That it becomes ready
/// is the assertion; how fast is a property of the host scheduler. A deadline
/// sized to "ready is quick, 10s is plenty" is a guess about machine load, and
/// under full workspace parallelism the guess loses. Chosen to be unreachable
/// by a merely-slow machine, and never to be tuned toward "fast enough".
const HANG_GUARD: Duration = Duration::from_secs(120);

async fn wait_for_emit(sock: &Path, event: &str) -> ServiceResponse {
    let started = Instant::now();
    let deadline = started + HANG_GUARD;
    let mut last_error = None;
    let mut attempts = 0usize;
    while Instant::now() < deadline {
        match emit_audit(sock, event).await {
            Ok(resp) => return resp,
            Err(e) => last_error = Some(e),
        }
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "broker at {} did not become ready after {attempts} attempt(s) in {:.1}s \
         (hang guard, not a budget): {:#}",
        sock.display(),
        started.elapsed().as_secs_f64(),
        last_error.expect("at least one attempt")
    );
}

struct TenantHandle {
    vm: String,
    control_socket: PathBuf,
    broker_socket: PathBuf,
    chain: PathBuf,
    worker_pid_path: PathBuf,
    daemon_pid_path: PathBuf,
    key_bytes: [u8; 32],
}

impl Drop for TenantHandle {
    fn drop(&mut self) {
        if let Some(pid) = read_pid(&self.worker_pid_path) {
            kill_process_group(pid);
        }
        if let Some(pid) = read_pid(&self.daemon_pid_path) {
            kill_pid(pid);
        }
    }
}

/// Owns the shared environment and temp dir so they outlive both tenants' Drop.
struct Harness {
    _env: TestEnv,
    _data_dir: TempDir,
    a: TenantHandle,
    b: TenantHandle,
}

/// Start a host-agent daemon for one tenant and register one VM.
///
/// The env vars (MVM_HOME etc.) must already be set by the caller before
/// this runs.
async fn start_tenant(id: &str) -> TenantHandle {
    let keys_dir = config::mvm_keys_dir();
    host_keypair::load_or_init_at(&keys_dir).expect("host signer");
    let key_bytes = load_host_signing_key().expect("host signing key bytes");
    let vm = format!("{id}-vm-1");
    let control_socket = ensure_host_agent_daemon(id).expect("start host-agent");
    let broker_socket = config::host_agent_dir(id).join("broker.sock");
    let chain = config::workload_audit_path(id, &vm);
    let worker_pid_path = config::host_agent_worker_pid(id);
    let daemon_pid_path = config::host_agent_dir(id).join("daemon.pid");

    let reg = RegisterVm {
        vm_id: vm.clone(),
        workload_id: Some(format!("wl-{vm}")),
        tenant_id: id.to_string(),
        broker_listen_socket: broker_socket.to_string_lossy().into_owned(),
        workload_chain_path: chain.to_string_lossy().into_owned(),
        workload_chain_head_path: Some(
            config::host_agent_dir(id)
                .join("signer.head")
                .to_string_lossy()
                .into_owned(),
        ),
        audit_signer_uds_path: None,
        services_bindings: vec![ServiceId::parse("host.audit.v1").expect("service id")],
        capability_bindings: vec![],
        assurance: None,
        service_proxies: vec![],
    };
    register_vm(&control_socket, &key_bytes, reg).expect("register vm");

    TenantHandle {
        vm,
        control_socket,
        broker_socket,
        chain,
        worker_pid_path,
        daemon_pid_path,
        key_bytes,
    }
}

async fn build_harness() -> Harness {
    let mut env = TestEnv::new();
    let data_dir = tempfile::tempdir().expect("data dir");
    env.set("MVM_HOME", data_dir.path());
    env.set("MVM_HOST_AGENT_PATH", HOST_AGENT_BIN);
    env.set("MVM_SIGNER_HELPER_PATH", SIGNER_HELPER_BIN);

    let a = start_tenant("tenant-a").await;
    let b = start_tenant("tenant-b").await;

    Harness {
        _env: env,
        _data_dir: data_dir,
        a,
        b,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_tenant_daemon_paths_are_isolated() {
    let harness = build_harness().await;
    let a = &harness.a;
    let b = &harness.b;

    // Each tenant has its own control socket, worker pid file, broker socket,
    // and workload chain.
    assert_ne!(
        a.control_socket, b.control_socket,
        "control sockets must differ"
    );
    assert_ne!(
        a.broker_socket, b.broker_socket,
        "broker sockets must differ"
    );
    assert_ne!(a.chain, b.chain, "workload chains must differ");
    assert_ne!(
        a.worker_pid_path, b.worker_pid_path,
        "worker pid files must differ"
    );

    // Both workers are live and have distinct PIDs.
    let pid_a = read_pid(&a.worker_pid_path);
    let pid_b = read_pid(&b.worker_pid_path);
    assert!(pid_a.is_some(), "tenant-a worker must be running");
    assert!(pid_b.is_some(), "tenant-b worker must be running");
    assert_ne!(pid_a, pid_b, "worker PIDs must differ");

    // An emit to A's broker lands in A's chain; B's chain must not be created.
    let resp = wait_for_emit(&a.broker_socket, "a-only").await;
    assert!(
        matches!(resp, ServiceResponse::Ok { .. }),
        "A broker emit must succeed"
    );

    let verifying_key = host_keypair::load_or_init_at(&config::mvm_keys_dir())
        .expect("host signer")
        .verifying;

    let a_entries = verify_workload_chain(&a.chain, &verifying_key).expect("A chain verifies");
    assert_eq!(a_entries, 1, "A chain must have exactly one entry");

    // B's chain is opened at registration time, not at emit time.  The
    // isolation guarantee is that A's emit writes zero entries to B's chain.
    let b_entries = verify_workload_chain(&b.chain, &verifying_key).expect("B chain verifies");
    assert_eq!(b_entries, 0, "B chain must not receive A's emit");

    deregister_vm(&a.control_socket, &a.key_bytes, &a.vm).expect("deregister tenant-a vm");
    deregister_vm(&b.control_socket, &b.key_bytes, &b.vm).expect("deregister tenant-b vm");
}
