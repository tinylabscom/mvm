//! `mvmctl validate` — render the shared builder's flake-check verdict.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::builder::{FlakeValidationReport, FlakeValidationRequest, validate_flake};
use mvm_core::user_config::MvmConfig;

use crate::ui;

use super::Cli;
use super::shared::resolve_flake_ref;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Flake path or reference (default: current directory)
    #[arg(long, default_value = ".")]
    pub flake: String,
    /// Output structured JSON instead of human-readable output
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let report = validate_flake(&FlakeValidationRequest {
        flake_ref: resolve_flake_ref(&args.flake)?,
        visible: !args.json,
    })?;
    if args.json {
        println!("{}", render_json(&report)?);
        if !report.valid {
            mvm_observability::exit(1);
        }
    } else if report.valid {
        ui::success("Flake is valid.");
    } else {
        anyhow::bail!(
            "{}",
            report.error.as_deref().unwrap_or("Flake check failed")
        );
    }
    Ok(())
}

fn render_json(report: &FlakeValidationReport) -> Result<String> {
    Ok(serde_json::to_string(report)?)
}

#[cfg(test)]
mod tests {
    use clap::{Command, FromArgMatches};

    use super::*;

    #[test]
    fn default_is_current_directory_and_human_output() {
        let matches = Args::augment_args(Command::new("validate"))
            .try_get_matches_from(["validate"])
            .unwrap();
        let args = Args::from_arg_matches(&matches).unwrap();
        assert_eq!(args.flake, ".");
        assert!(!args.json);
    }

    #[test]
    fn reports_are_json_even_with_quotes_and_newlines() {
        let report = FlakeValidationReport {
            valid: false,
            error: Some("quoted \"message\"\nnext line".to_string()),
        };
        let json = render_json(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<FlakeValidationReport>(&json).unwrap(),
            report
        );
        assert_eq!(
            render_json(&FlakeValidationReport {
                valid: true,
                error: None
            })
            .unwrap(),
            r#"{"valid":true}"#
        );
    }
}
