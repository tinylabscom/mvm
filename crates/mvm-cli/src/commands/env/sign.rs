//! `mvmctl env sign` — repair the macOS entitlements on mvmctl's VM launch
//! targets. Normal installs and updates do this automatically; this remains
//! useful for source builds and older installations.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::maintenance::sign::{SignReport, SignRequest, SignTargetReport, sign};

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
    let report = sign(&sign_request(&args))?;
    if !report.supported {
        if args.json {
            crate::json_out::emit_json(&report.targets)?;
        } else {
            ui::info("mvmctl env sign is macOS-only (codesign entitlements); nothing to do here.");
        }
        return Ok(());
    }

    let reports = &report.targets;

    if args.json {
        crate::json_out::emit_json(&reports)?;
    } else {
        for r in reports {
            let (mark, verb) = signing_status(r);
            ui::status_line(&format!("  {} {}:", mark, r.path.display()), verb);
            if let Some(error) = &r.error {
                ui::warn(error);
            }
        }
    }
    ensure_signing_complete(&report)?;
    if !args.json {
        ui::success("All VM launch targets carry their required macOS entitlements.");
    }
    Ok(())
}

fn signing_status(report: &SignTargetReport) -> (&'static str, &'static str) {
    if report.error.is_some() || !report.entitlements_present {
        ("✗", "signing failed")
    } else if report.applied {
        ("✓", "signed")
    } else {
        ("✓", "already signed")
    }
}

fn ensure_signing_complete(report: &SignReport) -> Result<()> {
    if report.is_complete() {
        Ok(())
    } else {
        anyhow::bail!(
            "one or more VM launch targets failed to acquire their required entitlements"
        );
    }
}

fn sign_request(_args: &Args) -> SignRequest {
    SignRequest { apply: true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_selects_rendering_not_preview() {
        assert!(sign_request(&Args { json: false }).apply);
        assert!(sign_request(&Args { json: true }).apply);
        assert!(!SignRequest::default().apply);
    }

    #[test]
    fn failed_apply_is_not_rendered_as_already_signed_or_a_successful_command() {
        let mut row = SignTargetReport {
            path: "/fixture".into(),
            applied: false,
            entitlements_present: false,
            error: Some("signature rejected".into()),
        };
        assert_eq!(signing_status(&row), ("✗", "signing failed"));
        let report = SignReport {
            supported: true,
            targets: vec![row.clone()],
        };
        assert!(ensure_signing_complete(&report).is_err());
        row.entitlements_present = true;
        assert_eq!(signing_status(&row), ("✗", "signing failed"));
        row.error = None;
        assert_eq!(signing_status(&row), ("✓", "already signed"));
        row.applied = true;
        assert_eq!(signing_status(&row), ("✓", "signed"));
    }
}
