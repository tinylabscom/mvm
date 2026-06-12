//! `mvmctl sign` — re-sign mvmctl + supervisor binaries with the
//! VZ/Hypervisor entitlements (user-facing repair of the auto-sign
//! path). macOS-only; a no-op on other platforms.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if !cfg!(target_os = "macos") {
        if args.json {
            crate::json_out::emit_json(&Vec::<mvm_backend::codesign::SignReport>::new())?;
        } else {
            ui::info("mvmctl sign is macOS-only (codesign entitlements); nothing to do here.");
        }
        return Ok(());
    }

    let targets = mvm_backend::codesign::collect_sign_targets();
    let reports = mvm_backend::codesign::sign_binaries(&targets);

    if args.json {
        crate::json_out::emit_json(&reports)?;
        return Ok(());
    }

    for r in &reports {
        let verb = if r.applied {
            "signed"
        } else {
            "already signed"
        };
        let mark = if r.entitlements_present { "✓" } else { "✗" };
        ui::status_line(&format!("  {} {}:", mark, r.path.display()), verb);
    }
    if reports.iter().all(|r| r.entitlements_present) {
        ui::success("All binaries carry the VZ + Hypervisor entitlements.");
        Ok(())
    } else {
        anyhow::bail!("one or more binaries failed to acquire both entitlements");
    }
}
