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

use anyhow::{Context, Result};

use mvm_hostd::broker::daemon::{HostAgentConfig, HostAgentDaemon};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-agent stdin read failed")?;
    Ok(buf)
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
        "mvm-host-agent starting"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-host-agent")
        .build()
        .context("mvm-host-agent tokio runtime build failed")?;

    runtime.block_on(async move {
        let daemon = HostAgentDaemon::new(cfg.tenant_id, verifying_key, cfg.max_frame_bytes);
        daemon.run(&cfg.control_socket).await
    })?;

    Ok(())
}
