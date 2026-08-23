//! `mvmctl vm <sub>` — operations on an existing/running microVM.
//!
//! The single-VM operational verbs collapse under one `vm` namespace
//! (everything that acts on a VM that's already been launched). The leaf
//! modules are unchanged — this is purely the grouped surface and its
//! dispatch. The everyday flow (`up`/`run`/`exec`/`invoke`/`ls`/`console`/
//! `down`/`logs`) stays top-level.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{
    checkpoint, cp, diff, forward, fs, pause, proc, rekernel, sandbox, session, set_ttl, snapshot,
    volume, wait,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: VmCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum VmCmd {
    /// Pause and seal a running VM
    #[command(hide = true)]
    Pause(pause::PauseArgs),
    /// Verify and resume a sealed snapshot
    #[command(hide = true)]
    Resume(pause::ResumeArgs),
    /// Manage sealed instance snapshots (`ls`, `rm`)
    #[command(hide = true)]
    Snapshot(snapshot::SnapshotArgs),
    /// Save a running VM's memory + disk state (requires a backend with
    /// memory-snapshot support)
    #[command(hide = true)]
    Save(checkpoint::SaveArgs),
    /// Capture, list, remove, or fork rootfs checkpoints
    #[command(hide = true)]
    Checkpoint(checkpoint::CheckpointArgs),
    /// Copy one file between the host and a running VM
    #[command(hide = true)]
    Cp(cp::Args),
    /// Run filesystem RPC against a VM
    #[command(hide = true)]
    Fs(fs::Args),
    /// Run process-control RPC against a VM
    #[command(hide = true)]
    Proc(proc::Args),
    /// Show filesystem changes in a running VM
    #[command(hide = true)]
    Diff(diff::Args),
    /// Wait for guest readiness
    #[command(hide = true)]
    Wait(wait::WaitArgs),
    /// Print guest readiness and boot timings
    #[command(name = "boot-report", hide = true)]
    BootReport(wait::BootReportArgs),
    /// Set or clear a sandbox TTL
    #[command(name = "set-ttl", hide = true)]
    SetTtl(set_ttl::Args),
    /// Explain how to migrate dynamic forwarding to declared ingress
    #[command(hide = true)]
    Forward(forward::Args),
    /// Inspect and clean sandbox lifecycle state
    #[command(hide = true)]
    Sandbox(sandbox::Args),
    /// Manage long-running VM sessions
    #[command(hide = true)]
    Session(session::Args),
    /// Manage virtio-fs volume mounts
    #[command(hide = true)]
    Volume(volume::Args),
    /// Relaunch a VM on a chosen/updated workload kernel
    Rekernel(rekernel::Args),
}

impl VmCmd {
    /// Whether this grouped VM op emits structured output on stdout.
    pub(in crate::commands) fn emits_machine_readable_stdout(&self) -> bool {
        match self {
            VmCmd::Snapshot(a) => match &a.command {
                snapshot::SnapshotCmd::Ls { json } | snapshot::SnapshotCmd::Rm { json, .. } => {
                    *json
                }
            },
            VmCmd::Save(a) => a.json,
            _ => false,
        }
    }

    /// Whether this VM op warrants the reconcile-on-entry convergence pass.
    /// Only the running-VM lifecycle ops converge stale dead records first;
    /// registry-record and guest-RPC ops (set-ttl, cp, fs, wait, forward, …)
    /// must not, or convergence would sweep a registered VM whose process
    /// isn't live before the op reads its record.
    pub(in crate::commands) fn touches_vm_state(&self) -> bool {
        matches!(
            self,
            VmCmd::Pause(_) | VmCmd::Resume(_) | VmCmd::Snapshot(_) | VmCmd::Save(_)
        )
    }

    /// The `<verb>` slot in `cmd.<verb>.*` audit events for this op. Keeps the
    /// per-op audit taxonomy (`cmd.pause.*`, `cmd.set-ttl.*`, …) stable now
    /// that these ops are reached through `machine` instead of `vm`. Values
    /// MUST match the clap subcommand names.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            VmCmd::Pause(_) => "pause",
            VmCmd::Resume(_) => "resume",
            VmCmd::Snapshot(_) => "snapshot",
            VmCmd::Save(_) => "save",
            VmCmd::Checkpoint(_) => "checkpoint",
            VmCmd::Cp(_) => "cp",
            VmCmd::Fs(_) => "fs",
            VmCmd::Proc(_) => "proc",
            VmCmd::Diff(_) => "diff",
            VmCmd::Wait(_) => "wait",
            VmCmd::BootReport(_) => "boot-report",
            VmCmd::SetTtl(_) => "set-ttl",
            VmCmd::Forward(_) => "forward",
            VmCmd::Sandbox(_) => "sandbox",
            VmCmd::Session(_) => "session",
            VmCmd::Volume(_) => "volume",
            VmCmd::Rekernel(_) => "rekernel",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        VmCmd::Pause(a) => pause::run_pause(cli, a, cfg),
        VmCmd::Resume(a) => pause::run_resume(cli, a, cfg),
        VmCmd::Snapshot(a) => snapshot::run_snapshot(cli, a, cfg),
        VmCmd::Save(a) => checkpoint::run_save(cli, a),
        VmCmd::Checkpoint(a) => checkpoint::run_checkpoint(cli, a),
        VmCmd::Cp(a) => cp::run(cli, a, cfg),
        VmCmd::Fs(a) => fs::run(cli, a, cfg),
        VmCmd::Proc(a) => proc::run(cli, a, cfg),
        VmCmd::Diff(a) => diff::run(cli, a, cfg),
        VmCmd::Wait(a) => wait::run_wait(cli, a, cfg),
        VmCmd::BootReport(a) => wait::run_boot_report(cli, a, cfg),
        VmCmd::SetTtl(a) => set_ttl::run(cli, a, cfg),
        VmCmd::Forward(a) => forward::run(cli, a, cfg),
        VmCmd::Sandbox(a) => sandbox::run(cli, a, cfg),
        VmCmd::Session(a) => session::run(cli, a, cfg),
        VmCmd::Volume(a) => volume::run(cli, a, cfg),
        VmCmd::Rekernel(a) => rekernel::run(cli, a, cfg),
    }
}
