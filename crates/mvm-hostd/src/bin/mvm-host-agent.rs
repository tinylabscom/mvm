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

const SIGNER_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTRATION_JOURNAL_FILE: &str = "registrations.json";

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-agent stdin read failed")?;
    Ok(buf)
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
    let verifying_key = cfg.load_verifying_key()?;
    tracing::info!(
        tenant_id = %cfg.tenant_id,
        control_socket = %cfg.control_socket.display(),
        signer_helper_uds_path = %cfg.signer_helper_uds_path.display(),
        "mvm-host-agent starting"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-host-agent")
        .build()
        .context("mvm-host-agent tokio runtime build failed")?;

    runtime.block_on(async move {
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
        HostAgentDaemon::run_shared(daemon, &cfg.control_socket).await
    })?;

    Ok(())
}
