//! `mvmctl sandbox` — inspect and clean sandbox lifecycle state.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use std::collections::BTreeSet;

use mvm_backend::backend::AnyBackend;
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::VmStatus;

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
    let registry_path = mvm::vm::name_registry::registry_path();
    let mut registry =
        mvm::vm::name_registry::VmNameRegistry::load(&registry_path).with_context(|| {
            format!(
                "Failed to load VM name registry at {}",
                registry_path.display()
            )
        })?;
    let running_names = collect_live_vm_names();
    let now = chrono::Utc::now();
    let candidates = gc_candidates(&registry, &running_names, now);
    let dry_run = !args.apply;

    if dry_run {
        let summary = GcSummary::new(true, 0, candidates);
        emit_gc_summary(&summary, args.json)?;
        return Ok(());
    }

    for candidate in &candidates {
        registry.deregister(&candidate.name);
    }
    registry.save(&registry_path).with_context(|| {
        format!(
            "Failed to save VM name registry at {}",
            registry_path.display()
        )
    })?;

    let removed_count = candidates.len();
    let summary = GcSummary::new(false, removed_count, candidates);
    emit_gc_summary(&summary, args.json)?;

    let names: Vec<&str> = summary.candidates.iter().map(|c| c.name.as_str()).collect();
    let detail = if names.len() <= 8 {
        format!("removed={},names=[{}]", names.len(), names.join(","))
    } else {
        format!("removed={}", names.len())
    };
    mvm_core::audit_emit!(SandboxGc, "{detail}");
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
    let mut names = BTreeSet::new();
    for hypervisor in ["apple-container", "docker", "firecracker"] {
        let backend = AnyBackend::from_hypervisor(hypervisor);
        let Ok(vms) = backend.list() else { continue };
        for vm in vms {
            if matches!(
                vm.status,
                VmStatus::Starting | VmStatus::Running | VmStatus::Paused
            ) {
                names.insert(vm.name);
            }
        }
    }
    names
}

fn gc_candidates(
    registry: &mvm::vm::name_registry::VmNameRegistry,
    live_names: &BTreeSet<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<GcCandidate> {
    let mut candidates: Vec<GcCandidate> = registry
        .vms
        .iter()
        .filter_map(|(name, reg)| {
            if live_names.contains(name) {
                return None;
            }
            let expired = reg
                .expires_at
                .as_deref()
                .and_then(mvm_core::util::time::parse_iso8601)
                .map(|expires_at| expires_at < now)
                .unwrap_or(false);
            let reason = if expired {
                GcReason::ExpiredStopped
            } else {
                GcReason::Stopped
            };
            Some(GcCandidate {
                name: name.clone(),
                reason,
            })
        })
        .collect();
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm::vm::name_registry::{RegisterParams, VmNameRegistry};

    fn registry_with(name: &str, expires_at: Option<&str>) -> VmNameRegistry {
        let mut registry = VmNameRegistry::default();
        let mut params = RegisterParams::minimal(name, "/tmp/mvm-test-vm", "default");
        params.expires_at = expires_at.map(str::to_string);
        registry
            .register_with_metadata(params)
            .expect("register vm");
        registry
    }

    #[test]
    fn gc_candidates_skip_live_vms() {
        let registry = registry_with("live", None);
        let live_names = BTreeSet::from(["live".to_string()]);
        let candidates = gc_candidates(&registry, &live_names, chrono::Utc::now());
        assert!(candidates.is_empty());
    }

    #[test]
    fn gc_candidates_include_stopped_registry_entries() {
        let registry = registry_with("stopped", None);
        let candidates = gc_candidates(&registry, &BTreeSet::new(), chrono::Utc::now());
        assert_eq!(
            candidates,
            vec![GcCandidate {
                name: "stopped".to_string(),
                reason: GcReason::Stopped,
            }]
        );
    }

    #[test]
    fn gc_candidates_mark_expired_stopped_entries() {
        let registry = registry_with("expired", Some("2000-01-01T00:00:00Z"));
        let candidates = gc_candidates(&registry, &BTreeSet::new(), chrono::Utc::now());
        assert_eq!(
            candidates,
            vec![GcCandidate {
                name: "expired".to_string(),
                reason: GcReason::ExpiredStopped,
            }]
        );
    }

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
