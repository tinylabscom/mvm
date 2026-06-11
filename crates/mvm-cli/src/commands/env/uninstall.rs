//! `mvmctl uninstall` — remove state directories and the mvmctl binary.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

use crate::ui;

use mvm_backend::microvm;
use mvm_core::user_config::MvmConfig;

use super::Cli;

/// Optionally rewrite an absolute system path under a sandbox prefix.
/// When `MVM_UNINSTALL_PATH_PREFIX` is set, the verb's
/// `/var/lib/mvm` and `/usr/local/bin/mvmctl` targets relocate under
/// the prefix and the sudo invocation is skipped (plain
/// `std::fs::remove_*`) because the rewritten paths live in
/// test-owned territory. Logs a `ui::warn` on bypass so the
/// override is visible.
///
/// Returns `(rewritten_path, use_sudo)`. `use_sudo == false` means
/// the caller should bypass `sudo` because either (a) the override
/// is set, or (b) future caller logic may want to drop sudo for
/// some other reason — currently only (a) is wired.
fn sandbox_path(p: &str) -> (PathBuf, bool) {
    match std::env::var("MVM_UNINSTALL_PATH_PREFIX") {
        Ok(prefix) if !prefix.trim().is_empty() => {
            let stripped = p.strip_prefix('/').unwrap_or(p);
            (PathBuf::from(prefix.trim()).join(stripped), false)
        }
        _ => (PathBuf::from(p), true),
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
    /// Also remove ~/.mvm/ and the mvmctl binary
    #[arg(long)]
    pub all: bool,
    /// Print actions without performing them
    #[arg(long)]
    pub dry_run: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Build the action plan. Dry-run avoids any external process calls so
    // it stays fast.
    let mut actions: Vec<String> = vec![
        "Stop running microVMs (best-effort)".to_string(),
        "Remove /var/lib/mvm/ (VM state, volumes, run-info)".to_string(),
    ];
    if args.all {
        actions.push("Remove ~/.mvm/ (config, signing keys)".to_string());
        actions.push("Remove /usr/local/bin/mvmctl (binary)".to_string());
    }

    if args.dry_run {
        ui::info("Dry run — the following would be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        return Ok(());
    }

    // Confirmation prompt — also avoids any external calls.
    if !args.yes {
        ui::info("The following will be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        if !ui::confirm("Proceed with uninstall?") {
            ui::info("Cancelled.");
            return Ok(());
        }
    }

    // When MVM_UNINSTALL_PATH_PREFIX is set the system paths below get
    // rewritten under that prefix and sudo is skipped. Surface the bypass
    // loudly so a misconfigured production caller can't miss it.
    let prefix_set = std::env::var("MVM_UNINSTALL_PATH_PREFIX")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if prefix_set {
        ui::warn(
            "MVM_UNINSTALL_PATH_PREFIX set; rewriting system paths under \
             the prefix and skipping sudo (test path).",
        );
    }

    // Stop running microVMs first (best-effort). Lima was dropped; there
    // is no Lima VM to destroy.
    if let Err(e) = microvm::stop() {
        tracing::warn!("failed to stop microVMs before uninstall: {e}");
    }

    // Remove /var/lib/mvm/.
    let (state_dir, use_sudo) = sandbox_path("/var/lib/mvm");
    if state_dir.exists() {
        ui::info(&format!("Removing {}...", state_dir.display()));
        if use_sudo {
            let status = std::process::Command::new("sudo")
                .args(["rm", "-rf"])
                .arg(&state_dir)
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("sudo rm {} exited with status {s}", state_dir.display()),
                Err(e) => tracing::warn!("failed to remove {}: {e}", state_dir.display()),
            }
        } else if let Err(e) = std::fs::remove_dir_all(&state_dir) {
            tracing::warn!("failed to remove {}: {e}", state_dir.display());
        }
    }

    if args.all {
        // Remove the mvm data dir (~/.mvm or MVM_DATA_DIR). Skip if it
        // can't be resolved (no HOME + no override) rather than guessing.
        if let Ok(config_dir) = mvm_core::config::mvm_data_dir_strict()
            && config_dir.exists()
        {
            ui::info("Removing ~/.mvm/...");
            if let Err(e) = std::fs::remove_dir_all(&config_dir) {
                tracing::warn!("failed to remove ~/.mvm/: {e}");
            }
        }

        // Remove /usr/local/bin/mvmctl.
        let (bin, use_sudo) = sandbox_path("/usr/local/bin/mvmctl");
        if bin.exists() {
            ui::info(&format!("Removing {}...", bin.display()));
            if use_sudo {
                let status = std::process::Command::new("sudo")
                    .args(["rm", "-f"])
                    .arg(&bin)
                    .status();
                match status {
                    Ok(s) if s.success() => {}
                    Ok(s) => tracing::warn!("sudo rm {} exited with status {s}", bin.display()),
                    Err(e) => tracing::warn!("failed to remove {}: {e}", bin.display()),
                }
            } else if let Err(e) = std::fs::remove_file(&bin) {
                tracing::warn!("failed to remove {}: {e}", bin.display());
            }
        }
    }

    mvm_core::audit_emit!(Uninstall);
    ui::success("Uninstall complete.");
    Ok(())
}
