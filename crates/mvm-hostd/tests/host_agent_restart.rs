use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
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
const BROKER_RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);

/// Hang guard — deliberately **not** a budget.
///
/// These tests spawn real processes and wait for them to reach a state. What
/// they assert is that the state is reached at all; how fast is a property of
/// the host scheduler, not of the code under test. A deadline picked from
/// "this should take ~1.5s, so 6s is ample headroom" encodes a 4x guess about
/// machine load, and at full workspace parallelism that guess is wrong — the
/// test goes red while the same code passes in about a second alone.
///
/// So this value is chosen to be unreachable by a merely-slow machine, and it
/// must never be tuned toward "what seems fast enough". If a wait reaches it,
/// something is stuck, and the panic says what was observed rather than only
/// that a clock ran out.
const HANG_GUARD: Duration = Duration::from_secs(120);

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
        Self::start_inner(None).await
    }

    async fn start_with_idle_timeout(secs: u64) -> Self {
        Self::start_inner(Some(secs)).await
    }

    async fn start_inner(idle_timeout_secs: Option<u64>) -> Self {
        let mut env = TestEnv::new();
        let data_dir = tempfile::tempdir().expect("temp data dir");
        env.set("MVM_HOME", data_dir.path());
        env.set("MVM_HOST_AGENT_PATH", HOST_AGENT_BIN);
        env.set("MVM_SIGNER_HELPER_PATH", SIGNER_HELPER_BIN);
        if let Some(secs) = idle_timeout_secs {
            env.set("MVM_HOST_AGENT_IDLE_TIMEOUT", secs.to_string());
        }

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
            broker_listen_socket: broker_socket.to_string_lossy().into_owned(),
            workload_chain_path: workload_chain.to_string_lossy().into_owned(),
            workload_chain_head_path: Some(
                data_dir
                    .path()
                    .join("audit-signer.head")
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
        let deadline = Instant::now() + BROKER_RECOVERY_TIMEOUT;
        self.wait_for_emit_until(event, deadline).await
    }

    async fn wait_for_emit_until(&self, event: &str, deadline: Instant) -> ServiceResponse {
        let started = Instant::now();
        let mut last_error = None;
        let mut attempts = 0usize;
        while Instant::now() < deadline {
            match self.try_emit(event).await {
                Ok(resp) => return resp,
                Err(e) => last_error = Some(e),
            }
            attempts += 1;
            // A dead daemon will never bring the broker back, so waiting out
            // the guard would only turn a decidable failure into a slow one.
            // Fail on the state change instead of on elapsed time.
            if let Some(pid) = self.daemon_pid()
                && !pid_alive(pid)
            {
                panic!(
                    "host-agent daemon (pid {pid}) exited after {attempts} recovery \
                     attempt(s) in {:.1}s; the broker cannot recover. Last error: {:#}",
                    started.elapsed().as_secs_f64(),
                    last_error.expect("at least one recovery attempt")
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "host-agent broker did not recover after {attempts} attempt(s) in {:.1}s \
             (hang guard, not a budget). Last error: {:#}",
            started.elapsed().as_secs_f64(),
            last_error.expect("at least one recovery attempt")
        );
    }

    async fn wait_for_worker_replacement(&self, previous_pid: libc::pid_t, deadline: Instant) {
        let started = Instant::now();
        while Instant::now() < deadline {
            if let Some(pid) = self.worker_pid()
                && pid != previous_pid
                && pid_alive(pid)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "host-agent worker did not restart in {:.1}s (hang guard, not a budget); \
             previous pid was {previous_pid}, current pid file reads {:?}",
            started.elapsed().as_secs_f64(),
            self.worker_pid()
        );
    }

    fn chain_entries(&self) -> usize {
        verify_workload_chain(&self.workload_chain, &self.verifying_key).expect("chain verifies")
    }

    fn deregister(&self) {
        deregister_vm(&self.control_socket, &self.key_bytes, &self.vm_name).expect("deregister vm");
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

fn pid_alive(pid: libc::pid_t) -> bool {
    // Reap zombie children before probing: if the process is a zombie, waitpid
    // removes it from the table so a subsequent kill(pid, 0) returns ESRCH.
    // SAFETY: WNOHANG never blocks; we discard the status.
    unsafe {
        libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
    }
    // SAFETY: kill(pid, 0) probes process existence without delivering a signal.
    // Returns 0 if alive (including zombies not yet reaped), -1/ESRCH if gone.
    unsafe { libc::kill(pid, 0) == 0 }
}

async fn wait_until_pid_dead(pid: libc::pid_t, deadline: Instant) {
    let started = Instant::now();
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Say what was observed, not just that a clock ran out: a bare "still
    // alive at deadline" cannot distinguish a stuck process from a loaded one,
    // which is what made this family unactionable when it went red in CI.
    panic!(
        "pid {pid} was still alive after {:.1}s (hang guard, not a budget) — \
         the process never exited",
        started.elapsed().as_secs_f64()
    );
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
        capability: None,
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

    // A successful kill(2) does not mean the old process has stopped
    // accepting work yet. Under workspace load, connecting immediately can
    // reach that dying worker after its signer helper has exited and observe
    // a transient broker error. Wait for the supervisor's replacement
    // identity before asserting restored registration and chain state.
    let worker_deadline = Instant::now() + BROKER_RECOVERY_TIMEOUT;
    fixture
        .wait_for_worker_replacement(worker_pid, worker_deadline)
        .await;

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
        capability: None,
    };
    write_frame(&mut conn, &call)
        .await
        .expect("write in-flight frame");

    let worker_pid = fixture.worker_pid().expect("worker pid");
    kill_process_group(worker_pid);
    drop(conn);

    let worker_deadline = Instant::now() + BROKER_RECOVERY_TIMEOUT;
    fixture
        .wait_for_worker_replacement(worker_pid, worker_deadline)
        .await;
    let emit_deadline = Instant::now() + BROKER_RECOVERY_TIMEOUT;
    let resp = fixture
        .wait_for_emit_until("after-crash", emit_deadline)
        .await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_daemon_self_terminates_when_last_vm_deregisters() {
    // 1s idle timeout — the daemon should exit well within our 6s deadline.
    let fixture = HostAgentFixture::start_with_idle_timeout(1).await;

    // Sanity check: the tree is alive before we pull the registration.
    let daemon_pid = fixture.daemon_pid().expect("daemon pid");
    let worker_pid = fixture.worker_pid().expect("worker pid");
    assert!(
        pid_alive(daemon_pid),
        "daemon must be alive before deregister"
    );
    assert!(
        pid_alive(worker_pid),
        "worker must be alive before deregister"
    );

    // Deregister the only VM → registration count drops to 0.
    fixture.deregister();

    // Poll until both the worker and the wrapper (daemon) are gone. The idle
    // watcher polls every 500ms against a 1s timeout, so an unloaded machine
    // sees the worker exit in ~1.5s and the wrapper follow it. The assertion
    // is that they exit — not that they exit quickly — so the wait is bounded
    // by the hang guard rather than by a multiple of the expected duration.
    let deadline = Instant::now() + HANG_GUARD;
    wait_until_pid_dead(worker_pid, deadline).await;
    wait_until_pid_dead(daemon_pid, deadline).await;
}
