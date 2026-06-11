//! `mvmctl reconcile` — explicit registry/runtime convergence pass.
//!
//! The same cheap convergence the CLI entry path runs for state-touching
//! commands, surfaced as an observable verb (sibling to `cache prune`).
//! `--dry-run` reports drift without healing it; `--json` emits the
//! `ConvergeReport` for scripting.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm::vm::reconcile::{self, ConvergeOpts};
use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Report drift without tearing down state, reaping orphans, or
    /// deregistering records. The registry on disk is left untouched.
    #[arg(long)]
    pub dry_run: bool,
    /// Emit the convergence report as JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let report = reconcile::converge(&ConvergeOpts {
        dry_run: args.dry_run,
    });

    if args.json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }

    if report.is_clean() {
        ui::info("Registry is consistent with runtime state. Nothing to reconcile.");
        return Ok(());
    }

    let prefix = if args.dry_run { "(dry-run) Would " } else { "" };
    if !report.dead_process_reaped.is_empty() {
        ui::info(&format!(
            "{prefix}tear down {} dead-process record(s): {}",
            report.dead_process_reaped.len(),
            report.dead_process_reaped.join(", "),
        ));
    }
    if !report.stale_record_dropped.is_empty() {
        ui::info(&format!(
            "{prefix}drop {} stale record(s) (state vanished): {}",
            report.stale_record_dropped.len(),
            report.stale_record_dropped.join(", "),
        ));
    }
    if !report.orphan_state_reaped.is_empty() {
        ui::info(&format!(
            "{prefix}reap {} orphan state dir(s) (no record): {}",
            report.orphan_state_reaped.len(),
            report.orphan_state_reaped.join(", "),
        ));
    }
    for err in &report.errors {
        ui::warn(&format!("reconcile: {err}"));
    }

    if args.dry_run {
        ui::info(&format!(
            "{} record(s) would be reconciled. Re-run without --dry-run to apply.",
            report.reconciled_count()
        ));
    } else {
        ui::success(&format!(
            "Reconciled {} drift item(s).",
            report.reconciled_count()
        ));
    }
    Ok(())
}
