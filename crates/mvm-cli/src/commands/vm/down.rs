//! `mvmctl down` — stop one or more running VMs.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_client::{LocalBackend, MachineFilter, MachineId, MachineStatus, MvmClient};
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::readiness::record_vm_readiness;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// VM name to stop (or all VMs if omitted)
    pub name: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // The facade owns the lifecycle op: it resolves the VMM that started each
    // VM (so a QEMU/libkrun VM is stopped by its own hypervisor, not the
    // platform default) and deregisters the machine from the name registry on
    // success. The CLI keeps the cross-cutting observability around that call —
    // the `Stopping` readiness milestone before it and the `VmStop` audit entry
    // after.
    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for stopping machines")?;
    match args.name.as_deref() {
        Some(n) => stop_one(&client, &runtime, n),
        None => stop_all(&client, &runtime),
    }
}

/// Stop a single named VM: record the `Stopping` milestone, hand the stop to
/// the facade, then emit the `VmStop` audit entry with the ok/fail outcome.
fn stop_one(client: &LocalBackend, runtime: &tokio::runtime::Runtime, name: &str) -> Result<()> {
    // Persist the `Stopping` readiness milestone BEFORE the stop so a concurrent
    // `mvmctl ls --json` running during the stop window sees the in-flight
    // state. On success the facade deregisters the entry and the milestone goes
    // away with it; if the stop fails the milestone stays at `Stopping`, which
    // is the right signal for "stop attempted, did not complete — retry or
    // investigate".
    record_vm_readiness(name, InstanceReadiness::Stopping);
    let result = runtime.block_on(client.stop_machine(&MachineId(name.to_string())));
    // A state-changing CLI verb emits an audit entry regardless of outcome; the
    // matching `VmStart` lives in `vm/up.rs`.
    let outcome = if result.is_ok() { "ok" } else { "stop_failed" };
    mvm_core::audit_emit!(VmStop, vm: name, "{outcome}");
    result.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Stop every running VM. Fleet/multi-VM is mvmd's job; this is the local
/// "stop them all" convenience. Each VM is stopped by its owning VMM (resolved
/// inside the facade), so QEMU/libkrun VMs are stopped too — not just whichever
/// backend the CLI defaulted to.
fn stop_all(client: &LocalBackend, runtime: &tokio::runtime::Runtime) -> Result<()> {
    let machines = runtime
        .block_on(client.list_machines(MachineFilter::all()))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing machines to stop")?;
    let mut last_err = None;
    for m in machines {
        // The host-wide listing folds in registered-but-stopped machines; only
        // the actually-running ones are stop targets (mirroring the old
        // live-VM-only scan), so a stopped registry row is left alone.
        if m.status == MachineStatus::Stopped {
            continue;
        }
        record_vm_readiness(&m.name, InstanceReadiness::Stopping);
        if let Err(e) = runtime.block_on(client.stop_machine(&m.id)) {
            last_err = Some(e);
        }
    }
    let outcome = if last_err.is_none() {
        "stop_all_ok"
    } else {
        "stop_all_failed"
    };
    mvm_core::audit_emit!(VmStop, "{outcome}");
    last_err.map_or(Ok(()), |e| Err(anyhow::anyhow!("{e}")))
}
