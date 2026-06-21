//! `mvm-signer-helper` — resident per-tenant key-holding signer helper.
//!
//! The host-agent daemon supervises this child. The helper holds the tenant's
//! signing key material, opens per-VM workload chains on `RegisterVm`, routes
//! appends by server-derived `vm_id`, and closes chains on `DeregisterVm`.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info};

use mvm_hostd::audit_signer::config::{SignerHelperConfig, parse_signer_helper as parse_config};
use mvm_hostd::audit_signer::helper::{SignerHelper, serve_on_listener};

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-signer-helper stdin read failed")?;
    Ok(buf)
}

fn main() -> Result<()> {
    // A signer-helper whose host-agent parent is gone holds key material no one
    // can reach — exit rather than leak as an orphan.
    mvm_hostd::parent_death::exit_when_orphaned();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg: SignerHelperConfig =
        parse_config(&raw).context("mvm-signer-helper config parse failed")?;
    info!(
        tenant_id = %cfg.tenant_id,
        uds_path = %cfg.uds_path.display(),
        software_chain_key_path = ?cfg.software_chain_key_path,
        max_frame_bytes = cfg.max_frame_bytes,
        "mvm-signer-helper config loaded"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-signer-helper")
        .build()
        .context("mvm-signer-helper tokio runtime build failed")?;

    runtime.block_on(async move {
        if let Some(parent) = cfg.uds_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create signer-helper dir {}", parent.display()))?;
        }
        let _ = std::fs::remove_file(&cfg.uds_path);
        let listener = UnixListener::bind(&cfg.uds_path).with_context(|| {
            format!(
                "mvm-signer-helper UDS bind failed on {}",
                cfg.uds_path.display()
            )
        })?;
        std::fs::set_permissions(&cfg.uds_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", cfg.uds_path.display()))?;
        let helper = Arc::new(Mutex::new(SignerHelper::new(
            cfg.tenant_id,
            cfg.software_chain_key_path,
        )));
        if let Err(e) = serve_on_listener(listener, helper, cfg.max_frame_bytes).await {
            error!(error = %e, "mvm-signer-helper serve loop exited with error");
            return Err::<(), _>(e);
        }
        Ok(())
    })?;

    Ok(())
}
