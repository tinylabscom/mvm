//! `mvm-broker` binary — the general-broker subprocess entry point.
//!
//! Spawn contract:
//!
//! 1. The supervisor cosign-verifies this binary at spawn
//!    (supervisor side).
//! 2. The supervisor spawns this process under a workload-specific
//!    cgroup + PID/mount namespace + seccomp + setpriv
//!    (supervisor side).
//! 3. The supervisor writes a JSON [`SubprocessConfig`] to this
//!    process's stdin, then closes stdin. Today the config is parsed
//!    unsigned; a signed envelope will be required.
//! 4. This process binds a UDS at `cfg.uds_path` (mode 0600 set by the
//!    supervisor on the parent dir) and enters the dispatch loop.
//! 5. It exits when the supervisor dies (parent-death signal — Linux
//!    `PR_SET_PDEATHSIG`, macOS kqueue parent-pid watcher — wired by
//!    the supervisor side; defensive double-attach in this
//!    binary lands at the same time).
//!
//! Handlers registered at startup:
//!
//! - `host.audit.v1` — workload-emitted audit emission. Only
//!   registered when admitted and `cfg.audit_signer_uds_path` is set, since the
//!   handler needs a UDS path to forward to. If the supervisor spawns
//!   without an audit-signer (test fixtures, doctor probes), the
//!   binary logs a warn and `host.audit.v1` calls return `NotBound`.
//! - `host.time.v1` — registered only when named by the exact admitted
//!   service bindings; returns the host-authoritative wall clock.
//!
//! `host.cost.v1` and `broker.v1` remain unregistered.

use std::io::Read;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use mvm_hostd::broker::audit_client::AuditClient;
use mvm_hostd::broker::config::{SubprocessConfig, parse as parse_config};
use mvm_hostd::broker::handlers::host_audit_v1::HostAuditV1Handler;
use mvm_hostd::broker::handlers::register_bound_handlers;
use mvm_hostd::broker::registry::Registry;
use mvm_hostd::broker::server::serve_on_listener;

fn read_stdin_blocking() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .context("mvm-broker stdin read failed")?;
    Ok(buf)
}

fn main() -> Result<()> {
    // First statement in the process: a panic before this line would
    // print its payload unredacted.
    mvm_hostd::panic_hook::install("broker");
    // Spawn-contract step 5: exit when the supervisor dies. This is the
    // "defensive double-attach in this binary" the contract above promises —
    // the child-side half that also covers macOS and abnormal parent death.
    mvm_hostd::parent_death::exit_when_orphaned();

    // The supervisor spawns with stdout/stderr captured for the audit
    // log; structured logging is the only useful trace.
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let raw = read_stdin_blocking()?;
    let cfg: SubprocessConfig = parse_config(&raw).context("mvm-broker config parse failed")?;
    info!(
        workload_id = %cfg.workload_id,
        tenant_id = %cfg.tenant_id,
        uds_path = %cfg.uds_path.display(),
        max_frame_bytes = cfg.max_frame_bytes,
        "mvm-broker config loaded"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-broker")
        .build()
        .context("mvm-broker tokio runtime build failed")?;

    runtime.block_on(async move {
        let listener = UnixListener::bind(&cfg.uds_path)
            .with_context(|| format!("mvm-broker UDS bind failed on {}", cfg.uds_path.display()))?;
        let mut registry = Registry::new();
        registry
            .admit_capabilities(cfg.capability_bindings.clone())
            .context("load admitted extension capability bindings")?;
        register_handlers(&mut registry, &cfg);
        let registry = Arc::new(registry);
        info!(
            uds_path = %cfg.uds_path.display(),
            handlers_registered = !registry.is_empty(),
            "mvm-broker listening"
        );
        if let Err(e) = serve_on_listener(
            listener,
            registry,
            cfg.workload_id,
            cfg.tenant_id,
            cfg.max_frame_bytes,
        )
        .await
        {
            error!(error = %e, "mvm-broker serve loop exited with error");
            return Err::<(), _>(e);
        }
        Ok(())
    })?;

    Ok(())
}

/// Register every handler that has a runtime dependency satisfied by
/// the inbound `SubprocessConfig`. Anything missing logs a warn and
/// leaves the registry without that handler; callers get
/// `Err(NotBound)` for the missing service.
fn register_handlers(registry: &mut Registry, cfg: &SubprocessConfig) {
    let _bound = register_bound_handlers(registry, &cfg.services_bindings);
    let host_audit = mvm_core::protocol::broker::ServiceId::parse("host.audit.v1")
        .expect("host.audit.v1 is a valid ServiceId");
    if !cfg.services_bindings.contains(&host_audit) {
        return;
    }
    match &cfg.audit_signer_uds_path {
        Some(path) => {
            let client = AuditClient::new(path.clone());
            let handler = Arc::new(HostAuditV1Handler::new(client));
            registry.register(handler.clone());
            for descriptor in HostAuditV1Handler::capability_descriptors() {
                registry
                    .register_capability(handler.clone(), descriptor)
                    .expect("host.audit capability descriptors are unique and valid");
            }
            info!(
                audit_signer_uds_path = %path.display(),
                "host.audit.v1 handler registered"
            );
        }
        None => {
            warn!(
                "host.audit.v1 NOT registered: SubprocessConfig.audit_signer_uds_path missing; \
                 calls will return NotBound"
            );
        }
    }
}
