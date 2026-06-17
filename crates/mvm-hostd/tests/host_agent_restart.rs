use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_backend::{deregister_vm, ensure_host_agent_daemon, load_host_signing_key, register_vm};
use mvm_core::config;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::protocol::broker_control::RegisterVm;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::host_keypair;
use mvm_hostd::audit_signer::verify::verify_workload_chain;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const HOST_AGENT_BIN: &str = env!("CARGO_BIN_EXE_mvm-host-agent");
const SIGNER_HELPER_BIN: &str = env!("CARGO_BIN_EXE_mvm-signer-helper");

struct HostAgentFixture {
    _env: TestEnv,
    _data_dir: TempDir,
    tenant_id: String,
    vm_name: String,
    control_socket: PathBuf,
    broker_socket: PathBuf,
    workload_chain: PathBuf,
    verifying_key: VerifyingKey,
    daemon_pid_path: PathBuf,
    worker_pid_path: PathBuf,
    key_bytes: [u8; 32],
}

impl HostAgentFixture {
    async fn start() -> Self {
        let mut env = TestEnv::new();
        let data_dir = tempfile::tempdir().expect("temp data dir");
        env.set("MVM_DATA_DIR", data_dir.path());
        env.set("MVM_HOST_AGENT_PATH", HOST_AGENT_BIN);
        env.set("MVM_SIGNER_HELPER_PATH", SIGNER_HELPER_BIN);

        let keys_dir = config::mvm_keys_dir();
        let signer = host_keypair::load_or_init_at(&keys_dir).expect("host signer");
        let key_bytes = load_host_signing_key().expect("host signer key bytes");
        let tenant_id = "local".to_string();
        let vm_name = "vm-1".to_string();
        let control_socket = ensure_host_agent_daemon(&tenant_id).expect("start host-agent");
        let broker_socket = data_dir.path().join("broker.sock");
        let workload_chain = config::workload_audit_path(&tenant_id, &vm_name);
        let daemon_pid_path = config::host_agent_dir(&tenant_id).join("daemon.pid");
        let worker_pid_path = config::host_agent_worker_pid(&tenant_id);

        let reg = RegisterVm {
            vm_id: vm_name.clone(),
            workload_id: Some("wl-vm-1".to_string()),
            tenant_id: tenant_id.clone(),
            broker_listen_socket: broker_socket.clone(),
            workload_chain_path: workload_chain.clone(),
            workload_chain_head_path: Some(data_dir.path().join("audit-signer.head")),
            audit_signer_uds_path: None,
            services_bindings: vec![],
        };
        register_vm(&control_socket, &key_bytes, reg).expect("register vm");

        Self {
            _env: env,
            _data_dir: data_dir,
            tenant_id,
            vm_name,
            control_socket,
            broker_socket,
            workload_chain,
            verifying_key: signer.verifying,
            daemon_pid_path,
            worker_pid_path,
            key_bytes,
        }
    }

    fn daemon_pid(&self) -> Option<libc::pid_t> {
        read_pid(&self.daemon_pid_path)
    }

    fn worker_pid(&self) -> Option<libc::pid_t> {
        read_pid(&self.worker_pid_path)
    }

    async fn try_emit(&self, event: &str) -> Result<ServiceResponse> {
        emit_audit(&self.broker_socket, event).await
    }

    async fn emit(&self, event: &str) -> ServiceResponse {
        self.try_emit(event).await.expect("emit audit")
    }

    async fn wait_for_emit(&self, event: &str) -> ServiceResponse {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last_error = None;
        while Instant::now() < deadline {
            match self.try_emit(event).await {
                Ok(resp) => return resp,
                Err(e) => last_error = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "host-agent broker did not recover before timeout: {:#}",
            last_error.expect("at least one recovery attempt")
        );
    }

    fn chain_entries(&self) -> usize {
        verify_workload_chain(&self.workload_chain, &self.verifying_key).expect("chain verifies")
    }
}

impl Drop for HostAgentFixture {
    fn drop(&mut self) {
        if let Some(pid) = read_pid(&self.worker_pid_path) {
            kill_process_group(pid);
        }
        if let Some(pid) = read_pid(&self.daemon_pid_path) {
            kill_pid(pid);
        }
    }
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn kill_pid(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

fn kill_process_group(pid: libc::pid_t) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
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
            "ts": "2026-06-17T00:00:00Z",
            "fields": {"event": event},
        }),
    };
    write_frame(&mut conn, &call).await?;
    read_frame(&mut conn).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_restart_restores_journaled_registration_and_chain() {
    let fixture = HostAgentFixture::start().await;
    let resp = fixture.emit("initial").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));
    assert_eq!(fixture.chain_entries(), 1);

    let worker_pid = fixture.worker_pid().expect("worker pid");
    kill_process_group(worker_pid);

    let resp = fixture.wait_for_emit("after-worker-restart").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));
    assert_eq!(fixture.chain_entries(), 2);

    deregister_vm(
        &fixture.control_socket,
        &fixture.key_bytes,
        &fixture.vm_name,
    )
    .expect("deregister vm");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrapper_restart_restores_journaled_registration_and_chain() {
    let fixture = HostAgentFixture::start().await;
    let resp = fixture.emit("initial").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));
    assert_eq!(fixture.chain_entries(), 1);

    let daemon_pid = fixture.daemon_pid().expect("daemon pid");
    kill_pid(daemon_pid);

    let control_socket = ensure_host_agent_daemon(&fixture.tenant_id).expect("restart host-agent");
    assert_eq!(control_socket, fixture.control_socket);

    let resp = fixture.emit("after-restart").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));
    assert_eq!(fixture.chain_entries(), 2);

    deregister_vm(
        &fixture.control_socket,
        &fixture.key_bytes,
        &fixture.vm_name,
    )
    .expect("deregister vm");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_crash_mid_flight_loses_at_most_one_call_and_preserves_chain() {
    let fixture = HostAgentFixture::start().await;
    let resp = fixture.emit("initial").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));
    assert_eq!(fixture.chain_entries(), 1);

    let mut conn = UnixStream::connect(&fixture.broker_socket)
        .await
        .expect("connect broker socket");
    let call = ServiceCall {
        service: ServiceId::parse("host.audit.v1").expect("service id"),
        verb: "emit".into(),
        correlation_id: CorrelationId::new("guest-supplied-ignored"),
        payload: serde_json::json!({
            "ts": "2026-06-17T00:00:01Z",
            "fields": {"event": "in-flight"},
        }),
    };
    write_frame(&mut conn, &call)
        .await
        .expect("write in-flight frame");

    let worker_pid = fixture.worker_pid().expect("worker pid");
    kill_process_group(worker_pid);
    drop(conn);

    let resp = fixture.wait_for_emit("after-crash").await;
    assert!(matches!(resp, ServiceResponse::Ok { .. }));

    let entries = fixture.chain_entries();
    assert!(
        entries == 2 || entries == 3,
        "restart should preserve a clean chain; got {entries} entries"
    );

    deregister_vm(
        &fixture.control_socket,
        &fixture.key_bytes,
        &fixture.vm_name,
    )
    .expect("deregister vm");
}
