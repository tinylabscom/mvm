//! `mvmctl cleanup` — remove old build artifacts and run nix garbage collection.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::shell;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Number of newest build revisions to keep
    #[arg(long)]
    pub keep: Option<usize>,
    /// Remove all cached build revisions
    #[arg(long)]
    pub all: bool,
    /// Print each cached build path that gets removed
    #[arg(long)]
    pub verbose: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let keep_count = if args.all { 0 } else { args.keep.unwrap_or(5) };

    if !args.all && keep_count == 0 {
        anyhow::bail!("--keep must be greater than 0 (or use --all)");
    }

    // Show disk usage before cleanup.
    let disk_before = vm_disk_usage_pct();
    if let Some(pct) = disk_before {
        ui::info(&format!("Lima VM disk usage: {}%", pct));
    }

    // Step 1: Clear temp files first — when the disk is 100% full the nix
    // daemon cannot start, so we need to free a little space before GC.
    ui::info("Clearing temporary files...");
    let _ = shell::run_in_vm("sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null");

    // Step 2: Remove old dev-build symlinks and artifacts.
    let env = mvm_runtime::build_env::RuntimeBuildEnv;
    let report = mvm_build::dev_build::cleanup_old_dev_builds(&env, keep_count)?;

    if args.verbose {
        if report.removed_paths.is_empty() {
            ui::info("No cached build paths removed.");
        } else {
            ui::info("Removed cached build paths:");
            for path in &report.removed_paths {
                println!("  {}", path);
            }
        }
    }

    if args.all {
        ui::success(&format!(
            "Removed {} cached build(s).",
            report.removed_count
        ));
    } else {
        ui::success(&format!(
            "Removed {} cached build(s), kept newest {}.",
            report.removed_count, keep_count
        ));
    }

    // Step 3: Garbage-collect unreferenced Nix store paths inside the Lima VM.
    ui::info("Running nix-collect-garbage...");
    match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
        Ok(output) => {
            let trimmed = output.trim();
            if !trimmed.is_empty() {
                println!("{trimmed}");
            }
        }
        Err(e) => {
            // If GC fails (disk too full for daemon), try clearing the Nix
            // user profile links and retrying once.
            ui::warn(&format!("nix-collect-garbage failed: {e}"));
            ui::info("Retrying after clearing Nix profile generations...");
            let _ = shell::run_in_vm("rm -rf ~/.local/state/nix/profiles/* 2>/dev/null");
            match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
                Ok(output) => {
                    let trimmed = output.trim();
                    if !trimmed.is_empty() {
                        println!("{trimmed}");
                    }
                }
                Err(e2) => ui::warn(&format!("nix-collect-garbage retry failed: {e2}")),
            }
        }
    }

    // Show disk usage after cleanup.
    let disk_after = vm_disk_usage_pct();
    if let Some(pct) = disk_after {
        let freed_msg = match disk_before {
            Some(before) if before > pct => format!(" (freed {}%)", before - pct),
            _ => String::new(),
        };
        ui::success(&format!("Lima VM disk usage: {}%{}", pct, freed_msg));
    }

    Ok(())
}

/// Read the Lima VM root filesystem usage percentage.
fn vm_disk_usage_pct() -> Option<u8> {
    let output = shell::run_in_vm_stdout("df --output=pcent / 2>/dev/null | tail -1").ok()?;
    output.trim().trim_end_matches('%').trim().parse().ok()
}
