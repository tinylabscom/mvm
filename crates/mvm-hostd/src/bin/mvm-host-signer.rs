//! `mvm-host-signer` binary — the host-signer subprocess entry point.
//!
//! Spawn contract (some steps still deferred, noted inline):
//!
//! 1. Supervisor cosign-verifies this binary at spawn (deferred).
//! 2. Supervisor spawns under workload-specific cgroup + PID/mount
//!    namespace + seccomp + setpriv (deferred).
//! 3. Supervisor writes a JSON `SubprocessConfig` to stdin, then
//!    closes stdin. Parsed unsigned today; a signed envelope wraps it
//!    later.
//! 4. This process loads or generates a software in-memory key; a
//!    hardware enclave keygen / handle replaces it later.
//! 5. Process binds a UDS at `cfg.uds_path` and enters the sign loop.
//! 6. Process exits when the supervisor dies (parent-death signal —
//!    deferred).

use std::io::Read;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tracing::{error, info};

use mvm_hostd::host_signer::config::{SubprocessConfig, parse as parse_config};
use mvm_hostd::host_signer::keystore::Keystore;
use mvm_hostd::host_signer::server::{default_max_frame_bytes, serve_on_listener};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-host-signer stdin read failed")?;
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
        parse_config(&raw).context("mvm-host-signer config parse failed")?;
    info!(
        workload_id = %cfg.workload_id,
        tenant_id = %cfg.tenant_id,
        uds_path = %cfg.uds_path.display(),
        software_key_path = ?cfg.software_key_path,
        "mvm-host-signer config loaded"
    );

    let keystore = match &cfg.software_key_path {
        Some(path) => Keystore::load_from_file(path)?,
        None => Keystore::generate(),
    };
    let keystore = Arc::new(keystore);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-host-signer")
        .build()
        .context("mvm-host-signer tokio runtime build failed")?;

    runtime.block_on(async move {
        let listener = UnixListener::bind(&cfg.uds_path).with_context(|| {
            format!(
                "mvm-host-signer UDS bind failed on {}",
                cfg.uds_path.display()
            )
        })?;
        info!(
            uds_path = %cfg.uds_path.display(),
            "mvm-host-signer listening (W1b.1 software-fallback key path; W8 replaces with HW enclave)"
        );
        if let Err(e) = serve_on_listener(
            listener,
            keystore,
            cfg.workload_id,
            default_max_frame_bytes(),
        )
        .await
        {
            error!(error = %e, "mvm-host-signer serve loop exited with error");
            return Err::<(), _>(e);
        }
        Ok(())
    })?;

    Ok(())
}
