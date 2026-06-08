//! Internal `mvmctl __qemu-vsock-bridge` subcommand (Plan 166 Phase 2).
//!
//! Hidden helper spawned (detached) by the QEMU workload backend
//! (`mvm_backend::qemu`). QEMU's virtio-vsock speaks real AF_VSOCK, but
//! the shared agent client connects to the per-port UNIX socket that
//! libkrun/Firecracker expose. This process bridges the two: it listens
//! on the UNIX socket and splices each connection to the guest's
//! `AF_VSOCK(cid, port)`, exiting when the watched qemu process dies.
//!
//! The AF_VSOCK + splice logic lives in `mvm_backend::qemu` (beside the
//! backend that needs it); this is just the argument surface + forward.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// UNIX socket to listen on (the agent client connects here).
    #[arg(long)]
    uds: PathBuf,
    /// Guest CID to dial over AF_VSOCK.
    #[arg(long)]
    cid: u32,
    /// Guest vsock port to dial.
    #[arg(long)]
    port: u32,
    /// VM name — used to locate the stashed admitted plan and write the
    /// per-VM substitution handoff sidecar (Plan 129).
    #[arg(long)]
    name: String,
    /// Exit when this PID file's process is no longer alive (the VM is gone).
    #[arg(long)]
    watch_pid_file: PathBuf,
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    // Plan 129 #1b: if this VM's admitted plan binds secrets, serve the egress
    // substitution endpoint over AF_VSOCK alongside the agent bridge. The guest
    // reaches it via `connect_host_vsock(SUBSTITUTION_PORT)` -> host CID 2.
    // Best-effort + self-gating (no plan / no secrets -> no-op); the agent
    // bridge below is the blocking call that owns process lifetime.
    #[cfg(target_os = "linux")]
    serve_substitution(&args.name);
    mvm_backend::qemu::run_vsock_bridge(&args.uds, args.cid, args.port, &args.watch_pid_file)
}

/// Spawn the egress-substitution `serve_vsock` for `name` on a background
/// thread if its admitted plan (stashed at `<vm_state_dir>/plan.json` by
/// `stash_plan_for_bridge`) binds secrets. Process exit reaps the thread.
#[cfg(target_os = "linux")]
fn serve_substitution(name: &str) {
    use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
    use mvm_hostd::supervisor::substitution_proxy::prepare_substitution;

    /// Real-TLS forward timeout for the host substitution leg.
    const FORWARD_TIMEOUT_SECS: u64 = 30;

    let plan_path = mvm_core::config::vm_state_dir(name).join("plan.json");
    let body = match std::fs::read(&plan_path) {
        Ok(b) => b,
        // No admission (legacy / dev-test boot) -> nothing to substitute.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(error = %e, vm = %name, "read stashed plan for substitution");
            return;
        }
    };
    // The stash is host-written 0600; decode without re-verify, mirroring the
    // libkrun supervisor (defense-in-depth `verify_plan` is the same follow-up
    // flagged there — the host is in the TCB per ADR-002).
    let plan: ExecutionPlan = match serde_json::from_slice::<SignedExecutionPlan>(&body)
        .and_then(|signed| serde_json::from_slice::<ExecutionPlan>(&signed.0.payload))
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, vm = %name, "decode stashed plan for substitution");
            return;
        }
    };
    if plan.secrets.is_empty() {
        return;
    }

    let tenant = plan.tenant.0.clone();
    let proxy_url = mvm_guest::forward_proxy::proxy_env_url();
    let prepared = match prepare_substitution(
        &plan.secrets,
        &tenant,
        name,
        &proxy_url,
        FORWARD_TIMEOUT_SECS,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, vm = %name, "prepare substitution");
            return;
        }
    };

    let name_owned = name.to_string();
    let spawned = std::thread::Builder::new()
        .name("mvm-subst-serve".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "build substitution serve runtime");
                    return;
                }
            };
            if let Err(e) = rt.block_on(
                prepared
                    .service
                    .serve_vsock_port(mvm_guest::vsock::SUBSTITUTION_PORT),
            ) {
                tracing::error!(error = %e, vm = %name_owned, "bind/serve substitution vsock");
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, vm = %name, "spawn substitution serve thread");
    }
}
