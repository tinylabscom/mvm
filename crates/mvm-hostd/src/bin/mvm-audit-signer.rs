//! `mvm-audit-signer` binary — the audit chain-signer subprocess entry
//! point.
//!
//! Spawn contract (some steps still deferred, noted inline):
//!
//! 1. Supervisor cosign-verifies this binary at spawn (deferred).
//! 2. Supervisor spawns under workload-specific cgroup + PID/mount
//!    namespace + seccomp + setpriv (deferred).
//! 3. Supervisor writes a JSON `SubprocessConfig` to stdin, then closes
//!    stdin. Parsed unsigned today; a signed envelope wraps it later.
//! 4. Process loads or generates the chain-signing key (software path),
//!    opens the JSONL with `O_APPEND` only, and recovers the chain head
//!    from the JSONL tail.
//! 5. Process binds a UDS at `cfg.uds_path` and enters the dispatch
//!    loop.
//! 6. Process exits when the supervisor dies (parent-death signal —
//!    deferred).

use std::io::Read;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info};

use mvm_hostd::audit_signer::chain::Chain;
use mvm_hostd::audit_signer::config::{SubprocessConfig, parse as parse_config};
use mvm_hostd::audit_signer::server::{default_max_frame_bytes, serve_on_listener};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-audit-signer stdin read failed")?;
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
    let cfg: SubprocessConfig =
        parse_config(&raw).context("mvm-audit-signer config parse failed")?;
    info!(
        workload_id = %cfg.workload_id,
        tenant_id = %cfg.tenant_id,
        uds_path = %cfg.uds_path.display(),
        audit_jsonl_path = %cfg.audit_jsonl_path.display(),
        chain_head_secondary_path = %cfg.chain_head_secondary_path.display(),
        software_chain_key_path = ?cfg.software_chain_key_path,
        "mvm-audit-signer config loaded"
    );

    let chain = Chain::open(
        &cfg.audit_jsonl_path,
        &cfg.chain_head_secondary_path,
        cfg.software_chain_key_path.as_deref(),
    )?;
    let chain = Arc::new(Mutex::new(chain));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-audit-signer")
        .build()
        .context("mvm-audit-signer tokio runtime build failed")?;

    runtime.block_on(async move {
        let listener = UnixListener::bind(&cfg.uds_path).with_context(|| {
            format!(
                "mvm-audit-signer UDS bind failed on {}",
                cfg.uds_path.display()
            )
        })?;
        info!(
            uds_path = %cfg.uds_path.display(),
            "mvm-audit-signer listening (W1b.1 software-fallback chain key path; W8 replaces with HW enclave + at-rest AEAD)"
        );
        if let Err(e) = serve_on_listener(
            listener,
            chain,
            cfg.workload_id,
            default_max_frame_bytes(),
        )
        .await
        {
            error!(error = %e, "mvm-audit-signer serve loop exited with error");
            return Err::<(), _>(e);
        }
        Ok(())
    })?;

    Ok(())
}
