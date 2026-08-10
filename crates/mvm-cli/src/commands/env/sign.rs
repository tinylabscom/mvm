//! `mvmctl env sign` — repair the macOS entitlements on mvmctl's VM launch
//! targets. Normal installs and updates do this automatically; this remains
//! useful for source builds and older installations.

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
            crate::json_out::emit_json(&Vec::<mvm_runtime::codesign::SignReport>::new())?;
        } else {
            ui::info("mvmctl env sign is macOS-only (codesign entitlements); nothing to do here.");
        }
        return Ok(());
    }

    let targets = mvm_runtime::codesign::collect_sign_targets();
    let reports = mvm_runtime::codesign::sign_targets(&targets);

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
        ui::success("All VM launch targets carry their required macOS entitlements.");
        Ok(())
    } else {
        anyhow::bail!(
            "one or more VM launch targets failed to acquire their required entitlements"
        );
    }
}
