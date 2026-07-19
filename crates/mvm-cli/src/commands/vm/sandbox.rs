//! `mvmctl sandbox` — inspect and clean sandbox lifecycle state.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use std::collections::BTreeSet;

use mvm_client::MvmClient;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: SandboxAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum SandboxAction {
    /// Remove stale sandbox registry entries. Dry-run by default.
    Gc(GcArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct GcArgs {
    /// Report candidates without mutating registry state. This is the default.
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,
    /// Actually remove stale registry entries.
    #[arg(long)]
    pub apply: bool,
    /// Print a machine-readable GC summary as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GcCandidate {
    name: String,
    reason: GcReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum GcReason {
    ExpiredStopped,
    Stopped,
}

impl GcReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExpiredStopped => "expired-stopped",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct GcSummary {
    schema_version: u32,
    dry_run: bool,
    applied: bool,
    candidate_count: usize,
    removed_count: usize,
    candidates: Vec<GcCandidate>,
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        SandboxAction::Gc(a) => run_gc(cli, a, cfg),
    }
}

fn run_gc(_cli: &Cli, args: GcArgs, _cfg: &MvmConfig) -> Result<()> {
    let running_names = collect_live_vm_names();
    let now = chrono::Utc::now().to_rfc3339();
    let stale = mvm_client::gc_stale_registrations(&running_names, &now, args.apply)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("garbage-collecting the VM name registry")?;
    let candidates: Vec<GcCandidate> = stale
        .into_iter()
        .map(|s| GcCandidate {
            name: s.name,
            reason: if s.expired {
                GcReason::ExpiredStopped
            } else {
                GcReason::Stopped
            },
        })
        .collect();
    let dry_run = !args.apply;
    let removed_count = if dry_run { 0 } else { candidates.len() };
    let summary = GcSummary::new(dry_run, removed_count, candidates);
    emit_gc_summary(&summary, args.json)?;

    if !dry_run {
        let names: Vec<&str> = summary.candidates.iter().map(|c| c.name.as_str()).collect();
        let detail = if names.len() <= 8 {
            format!("removed={},names=[{}]", names.len(), names.join(","))
        } else {
            format!("removed={}", names.len())
        };
        mvm_core::audit_emit!(SandboxGc, "{detail}");
    }
    Ok(())
}

impl GcSummary {
    fn new(dry_run: bool, removed_count: usize, candidates: Vec<GcCandidate>) -> Self {
        let candidate_count = candidates.len();
        Self {
            schema_version: 1,
            dry_run,
            applied: !dry_run,
            candidate_count,
            removed_count,
            candidates,
        }
    }
}

fn emit_gc_summary(summary: &GcSummary, json: bool) -> Result<()> {
    if json {
        crate::json_out::emit_json(summary)?;
        return Ok(());
    }

    if summary.dry_run {
        if summary.candidates.is_empty() {
            println!("sandbox gc: no stale sandbox registry entries (dry-run)");
            return Ok(());
        }
        println!(
            "sandbox gc: would remove {} stale registry entr{} (dry-run):",
            summary.candidates.len(),
            if summary.candidates.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
        for candidate in &summary.candidates {
            println!("  {} ({})", candidate.name, candidate.reason.as_str());
        }
        println!("re-run with --apply to actually remove registry entries");
        return Ok(());
    }

    println!(
        "sandbox gc: removed {} stale registry entr{}",
        summary.removed_count,
        if summary.removed_count == 1 {
            "y"
        } else {
            "ies"
        }
    );
    for candidate in &summary.candidates {
        println!("  {} ({})", candidate.name, candidate.reason.as_str());
    }
    Ok(())
}

fn collect_live_vm_names() -> BTreeSet<String> {
    let client = mvm_client::LocalBackend::new();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return BTreeSet::new();
    };
    let machines = runtime
        .block_on(client.list_machines(mvm_client::MachineFilter::all()))
        .unwrap_or_default();
    machines
        .into_iter()
        .filter(|m| {
            matches!(
                m.status,
                mvm_client::MachineStatus::Starting
                    | mvm_client::MachineStatus::Running
                    | mvm_client::MachineStatus::Paused
            )
        })
        .map(|m| m.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_summary_serializes_candidates_and_counts() {
        let summary = GcSummary::new(
            true,
            0,
            vec![GcCandidate {
                name: "stopped".to_string(),
                reason: GcReason::Stopped,
            }],
        );
        let json = serde_json::to_string(&summary).expect("json");

        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"candidate_count\":1"));
        assert!(json.contains("\"removed_count\":0"));
        assert!(json.contains("\"name\":\"stopped\""));
        assert!(json.contains("\"reason\":\"stopped\""));
    }
}
