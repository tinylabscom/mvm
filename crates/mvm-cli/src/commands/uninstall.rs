//! `mvmctl uninstall` — remove the Lima VM, state directories, and binary.

use anyhow::Result;

use crate::ui;

use mvm_runtime::vm::{lima, microvm};

pub(super) fn cmd_uninstall(yes: bool, all: bool, dry_run: bool) -> Result<()> {
    // Build the action plan. Dry-run avoids any external process calls so it
    // stays fast even when Lima/limactl is unresponsive.
    let mut actions: Vec<String> = vec![
        "Destroy Lima VM 'mvm' (if present)".to_string(),
        "Remove /var/lib/mvm/ (VM state, volumes, run-info)".to_string(),
    ];
    if all {
        actions.push("Remove ~/.mvm/ (config, signing keys)".to_string());
        actions.push("Remove /usr/local/bin/mvmctl (binary)".to_string());
    }

    if dry_run {
        ui::info("Dry run — the following would be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        return Ok(());
    }

    // Confirmation prompt — also avoids any external calls.
    if !yes {
        ui::info("The following will be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        if !ui::confirm("Proceed with uninstall?") {
            ui::info("Cancelled.");
            return Ok(());
        }
    }

    // Now query Lima — only when actually performing the uninstall.
    let lima_status = lima::get_status().unwrap_or(lima::LimaStatus::NotFound);

    // Stop running microVMs first (best-effort).
    if matches!(lima_status, lima::LimaStatus::Running)
        && let Err(e) = microvm::stop()
    {
        tracing::warn!("failed to stop microVMs before uninstall: {e}");
    }

    // Destroy Lima VM.
    if !matches!(lima_status, lima::LimaStatus::NotFound) {
        ui::info("Destroying Lima VM...");
        if let Err(e) = lima::destroy() {
            tracing::warn!("failed to destroy Lima VM: {e}");
        }
    }

    // Remove /var/lib/mvm/.
    let state_dir = std::path::Path::new("/var/lib/mvm");
    if state_dir.exists() {
        ui::info("Removing /var/lib/mvm/...");
        let status = std::process::Command::new("sudo")
            .args(["rm", "-rf", "/var/lib/mvm"])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::warn!("sudo rm /var/lib/mvm exited with status {s}"),
            Err(e) => tracing::warn!("failed to remove /var/lib/mvm: {e}"),
        }
    }

    if all {
        // Remove ~/.mvm/.
        if let Ok(home) = std::env::var("HOME") {
            let config_dir = std::path::PathBuf::from(home).join(".mvm");
            if config_dir.exists() {
                ui::info("Removing ~/.mvm/...");
                if let Err(e) = std::fs::remove_dir_all(&config_dir) {
                    tracing::warn!("failed to remove ~/.mvm/: {e}");
                }
            }
        }

        // Remove /usr/local/bin/mvmctl.
        let bin = std::path::Path::new("/usr/local/bin/mvmctl");
        if bin.exists() {
            ui::info("Removing /usr/local/bin/mvmctl...");
            let status = std::process::Command::new("sudo")
                .args(["rm", "-f", "/usr/local/bin/mvmctl"])
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("sudo rm mvmctl exited with status {s}"),
                Err(e) => tracing::warn!("failed to remove /usr/local/bin/mvmctl: {e}"),
            }
        }
    }

    mvm_core::audit::emit(mvm_core::audit::LocalAuditKind::Uninstall, None, None);
    ui::success("Uninstall complete.");
    Ok(())
}
