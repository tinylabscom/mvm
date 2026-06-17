//! `mvm-host-agent` — the resident per-tenant host-services daemon.
//!
//! One process per tenant (not per VM). It binds a host-only control UDS,
//! accepts host-signed `RegisterVm`/`DeregisterVm` messages, and for each
//! registered VM binds that VM's `BROKER_PORT` socket and serves
//! `host.audit.v1` (and future host services) on it. A tenant's microVMs are
//! *registrations*, not processes.
//!
//! Spawn contract:
//!
//! 1. The supervisor cosign-verifies this binary at spawn (supervisor side).
//! 2. It spawns this process under the tenant's cgroup + namespaces + seccomp
//!    + setpriv (supervisor side).
//! 3. It writes a JSON [`HostAgentConfig`] to stdin, then closes stdin.
//! 4. This process binds the control UDS (mode 0700) and serves until killed.
//!
//! It holds **no signing key** — it verifies control messages against the host
//! signer *public* key and forwards audit entries to the per-VM audit-signer
//! that holds the private key. The moat (keyless parser / key-holding signer)
//! is preserved; this is the keyless half.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};

use mvm_hostd::audit_signer::config::SignerHelperConfig;
use mvm_hostd::broker::daemon::{HostAgentConfig, HostAgentDaemon};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const HOST_AGENT_WORKER_ENV: &str = "MVM_HOST_AGENT_WORKER";
const SIGNER_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_RESTART_BACKOFF: Duration = Duration::from_millis(250);
const REGISTRATION_JOURNAL_FILE: &str = "registrations.json";

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-agent stdin read failed")?;
    Ok(buf)
}

fn is_worker_mode() -> bool {
    std::env::var(HOST_AGENT_WORKER_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn worker_pid_path(cfg: &HostAgentConfig) -> Result<PathBuf> {
    Ok(mvm_core::config::host_agent_worker_pid(&cfg.tenant_id))
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn kill_process_group(pgid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(-pgid, sig);
    }
}

fn reap_stale_worker_group(pid_path: &Path) {
    if let Some(pid) = read_pid(pid_path)
        && pid_alive(pid)
    {
        kill_process_group(pid, libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(50));
        kill_process_group(pid, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(pid_path);
}

async fn wait_for_worker_ready(
    child: &mut Child,
    control_socket: &Path,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::UnixStream::connect(control_socket)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .context("poll mvm-host-agent worker status")?
        {
            anyhow::bail!("mvm-host-agent worker exited before readiness: {status}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    anyhow::bail!(
        "mvm-host-agent worker did not bind {} within {:?}",
        control_socket.display(),
        timeout
    )
}

async fn spawn_worker(raw_cfg: &[u8]) -> Result<Child> {
    let bin = std::env::current_exe().context("resolve mvm-host-agent current_exe")?;
    let mut command = Command::new(&bin);
    command
        .env(HOST_AGENT_WORKER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    unsafe {
        command.as_std_mut().pre_exec(|| {
            let rc = libc::setsid();
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn mvm-host-agent worker {}", bin.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .context("mvm-host-agent worker stdin was not piped")?;
    stdin
        .write_all(raw_cfg)
        .await
        .context("pipe HostAgentConfig to mvm-host-agent worker")?;
    drop(stdin);
    Ok(child)
}

async fn spawn_signer_helper(cfg: &HostAgentConfig) -> Result<Child> {
    let bin = signer_helper_bin_path()?;
    let helper_cfg = SignerHelperConfig {
        tenant_id: cfg.tenant_id.clone(),
        uds_path: cfg.signer_helper_uds_path.clone(),
        software_chain_key_path: Some(cfg.software_chain_key_path.clone()),
        max_frame_bytes: cfg.max_frame_bytes,
    };
    let _ = std::fs::remove_file(&cfg.signer_helper_uds_path);
    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn mvm-signer-helper {}", bin.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .context("mvm-signer-helper stdin was not piped")?;
    stdin
        .write_all(&serde_json::to_vec(&helper_cfg)?)
        .await
        .context("pipe SignerHelperConfig to mvm-signer-helper")?;
    drop(stdin);
    wait_for_helper_uds(&mut child, &cfg.signer_helper_uds_path).await?;
    Ok(child)
}

fn signer_helper_bin_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("MVM_SIGNER_HELPER_PATH")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_exe().context("resolve mvm-host-agent current_exe")?;
    Ok(current.with_file_name("mvm-signer-helper"))
}

async fn wait_for_helper_uds(child: &mut Child, uds_path: &Path) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < SIGNER_HELPER_READY_TIMEOUT {
        if let Some(status) = child.try_wait().context("poll mvm-signer-helper status")? {
            anyhow::bail!("mvm-signer-helper exited before readiness: {status}");
        }
        if uds_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = child.start_kill();
    anyhow::bail!(
        "mvm-signer-helper did not bind {} within {:?}",
        uds_path.display(),
        SIGNER_HELPER_READY_TIMEOUT
    )
}

async fn supervise_signer_helper(
    cfg: HostAgentConfig,
    daemon: Arc<Mutex<HostAgentDaemon>>,
    first_ready: oneshot::Sender<Result<()>>,
) {
    let mut first_ready = Some(first_ready);
    loop {
        match spawn_signer_helper(&cfg).await {
            Ok(mut child) => {
                let rebound = {
                    let daemon = daemon.lock().await;
                    daemon.rebind_signer_helper_registrations()
                };
                match rebound {
                    Ok(count) => {
                        tracing::info!(
                            tenant_id = %cfg.tenant_id,
                            registrations = count,
                            "mvm-signer-helper ready"
                        );
                        if let Some(tx) = first_ready.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %cfg.tenant_id,
                            error = %e,
                            "mvm-signer-helper registration replay failed"
                        );
                        if let Some(tx) = first_ready.take() {
                            let _ = tx.send(Err(e));
                            return;
                        }
                    }
                }

                match child.wait().await {
                    Ok(status) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        status = %status,
                        "mvm-signer-helper exited; restarting"
                    ),
                    Err(e) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        error = %e,
                        "mvm-signer-helper wait failed; restarting"
                    ),
                }
            }
            Err(e) => {
                if let Some(tx) = first_ready.take() {
                    let _ = tx.send(Err(e));
                    return;
                }
                tracing::warn!(
                    tenant_id = %cfg.tenant_id,
                    error = %e,
                    "mvm-signer-helper spawn failed; retrying"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn run_worker_once(cfg: HostAgentConfig) -> Result<()> {
    let verifying_key = cfg.load_verifying_key()?;
    tracing::info!(
        tenant_id = %cfg.tenant_id,
        control_socket = %cfg.control_socket.display(),
        signer_helper_uds_path = %cfg.signer_helper_uds_path.display(),
        "mvm-host-agent worker starting"
    );

    let registration_journal = registration_journal_path(&cfg)?;
    let daemon = Arc::new(Mutex::new(
        HostAgentDaemon::new_with_signer_helper(
            cfg.tenant_id.clone(),
            verifying_key,
            cfg.signer_helper_uds_path.clone(),
            cfg.max_frame_bytes,
        )
        .with_registration_journal(registration_journal),
    ));
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(supervise_signer_helper(
        cfg.clone(),
        daemon.clone(),
        ready_tx,
    ));
    ready_rx
        .await
        .context("mvm-signer-helper supervisor stopped before readiness")??;
    let restored = {
        let mut daemon = daemon.lock().await;
        daemon.restore_journaled_registrations()
    }?;
    tracing::info!(
        tenant_id = %cfg.tenant_id,
        registrations = restored,
        "mvm-host-agent registration journal restored"
    );
    HostAgentDaemon::run_shared(daemon, &cfg.control_socket).await?;

    Ok(())
}

async fn supervise_worker(cfg: HostAgentConfig, raw_cfg: Vec<u8>) -> Result<()> {
    let worker_pid_path = worker_pid_path(&cfg)?;
    reap_stale_worker_group(&worker_pid_path);
    let mut startup_failures = 0u32;

    loop {
        let mut worker = spawn_worker(&raw_cfg).await?;
        let worker_pid = worker
            .id()
            .context("mvm-host-agent worker pid missing after spawn")?
            as libc::pid_t;
        if let Some(parent) = worker_pid_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create worker pid dir {}", parent.display()))?;
        }
        std::fs::write(&worker_pid_path, worker_pid.to_string())
            .with_context(|| format!("write {}", worker_pid_path.display()))?;

        match wait_for_worker_ready(&mut worker, &cfg.control_socket, WORKER_READY_TIMEOUT).await {
            Ok(()) => {
                startup_failures = 0;
                match worker.wait().await {
                    Ok(status) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        status = %status,
                        "mvm-host-agent worker exited; restarting"
                    ),
                    Err(e) => tracing::warn!(
                        tenant_id = %cfg.tenant_id,
                        error = %e,
                        "mvm-host-agent worker wait failed; restarting"
                    ),
                }
            }
            Err(e) => {
                startup_failures += 1;
                tracing::warn!(
                    tenant_id = %cfg.tenant_id,
                    error = %e,
                    failures = startup_failures,
                    "mvm-host-agent worker failed before readiness; restarting"
                );
                if startup_failures >= 3 {
                    reap_stale_worker_group(&worker_pid_path);
                    let _ = worker.wait().await;
                    let _ = std::fs::remove_file(&worker_pid_path);
                    return Err(e);
                }
            }
        }

        reap_stale_worker_group(&worker_pid_path);
        let _ = worker.wait().await;
        tokio::time::sleep(WORKER_RESTART_BACKOFF).await;
    }
}

fn registration_journal_path(cfg: &HostAgentConfig) -> Result<PathBuf> {
    let dir = cfg
        .control_socket
        .parent()
        .context("host-agent control socket path must have a parent directory")?;
    Ok(dir.join(REGISTRATION_JOURNAL_FILE))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg: HostAgentConfig =
        serde_json::from_slice(&raw).context("mvm-host-agent config parse failed")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-host-agent")
        .build()
        .context("mvm-host-agent supervisor tokio runtime build failed")?;
    if is_worker_mode() {
        runtime.block_on(run_worker_once(cfg))?;
    } else {
        runtime.block_on(supervise_worker(cfg, raw))?;
    }
    Ok(())
}
