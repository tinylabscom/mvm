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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use mvm_hostd::audit_signer::config::SignerHelperConfig;
use mvm_hostd::broker::daemon::{HostAgentConfig, HostAgentDaemon};

const SIGNER_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(10);

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-agent stdin read failed")?;
    Ok(buf)
}

struct SignerHelperChild {
    child: Child,
}

impl Drop for SignerHelperChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn spawn_signer_helper(cfg: &HostAgentConfig) -> Result<SignerHelperChild> {
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
        .spawn()
        .with_context(|| format!("spawn mvm-signer-helper {}", bin.display()))?;
    child
        .stdin
        .take()
        .context("mvm-signer-helper stdin was not piped")?
        .write_all(serde_json::to_string(&helper_cfg)?.as_bytes())
        .context("pipe SignerHelperConfig to mvm-signer-helper")?;
    wait_for_helper_uds(&mut child, &cfg.signer_helper_uds_path)?;
    Ok(SignerHelperChild { child })
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

fn wait_for_helper_uds(child: &mut Child, uds_path: &Path) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < SIGNER_HELPER_READY_TIMEOUT {
        if let Some(status) = child.try_wait().context("poll mvm-signer-helper status")? {
            anyhow::bail!("mvm-signer-helper exited before readiness: {status}");
        }
        if uds_path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    anyhow::bail!(
        "mvm-signer-helper did not bind {} within {:?}",
        uds_path.display(),
        SIGNER_HELPER_READY_TIMEOUT
    )
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
    let _signer_helper = spawn_signer_helper(&cfg)?;
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
        let daemon = HostAgentDaemon::new_with_signer_helper(
            cfg.tenant_id,
            verifying_key,
            cfg.signer_helper_uds_path.clone(),
            cfg.max_frame_bytes,
        );
        daemon.run(&cfg.control_socket).await
    })?;

    Ok(())
}
