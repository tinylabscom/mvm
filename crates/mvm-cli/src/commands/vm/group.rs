//! `mvmctl vm <sub>` — operations on an existing/running microVM.
//!
//! Plan 178 / ADR-077: the single-VM operational verbs collapse under one
//! `vm` namespace (everything that acts on a VM that's already been launched).
//! The leaf modules are unchanged — this is purely the grouped surface and
//! its dispatch. The everyday flow (`up`/`run`/`exec`/`invoke`/`ls`/`console`/
//! `down`/`logs`) stays top-level.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{cp, diff, forward, fs, pause, proc, sandbox, session, set_ttl, volume, wait};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: VmCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum VmCmd {
    /// Pause and seal a running VM
    Pause(pause::PauseArgs),
    /// Verify and resume a sealed snapshot
    Resume(pause::ResumeArgs),
    /// Manage sealed instance snapshots (`ls`, `rm`)
    Snapshot(pause::SnapshotArgs),
    /// Copy one file between the host and a running VM
    Cp(cp::Args),
    /// Run filesystem RPC against a VM
    Fs(fs::Args),
    /// Run process-control RPC against a VM
    Proc(proc::Args),
    /// Show filesystem changes in a running VM
    Diff(diff::Args),
    /// Wait for guest readiness
    Wait(wait::WaitArgs),
    /// Print guest readiness and boot timings
    #[command(name = "boot-report")]
    BootReport(wait::BootReportArgs),
    /// Set or clear a sandbox TTL
    #[command(name = "set-ttl")]
    SetTtl(set_ttl::Args),
    /// Forward a port from a running microVM to localhost
    Forward(forward::Args),
    /// Inspect and clean sandbox lifecycle state
    Sandbox(sandbox::Args),
    /// Manage long-running VM sessions
    Session(session::Args),
    /// Manage virtio-fs volume mounts
    Volume(volume::Args),
}

impl VmCmd {
    /// Audit verb name for this VM op. Preserves the per-op audit taxonomy
    /// (`cmd.pause.*`, `cmd.cp.*`, …) unchanged across the `vm` grouping —
    /// the CLI path moved to `vm <sub>` but the audit verbs did not, so
    /// claims 8/12/13 event names are stable.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            VmCmd::Pause(_) => "pause",
            VmCmd::Resume(_) => "resume",
            VmCmd::Snapshot(_) => "snapshot",
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
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        VmCmd::Pause(a) => pause::run_pause(cli, a, cfg),
        VmCmd::Resume(a) => pause::run_resume(cli, a, cfg),
        VmCmd::Snapshot(a) => pause::run_snapshot(cli, a, cfg),
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
    }
}
