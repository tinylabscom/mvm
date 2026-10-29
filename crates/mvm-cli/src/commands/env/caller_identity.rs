//! Argument parsing and output for explicit caller identity enrollment.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use mvm_client::caller_identity;
use mvm_core::config;

pub(crate) use mvm_client::caller_identity::load_enrolled_identity;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Action {
    /// Explicitly enroll a new dedicated native caller identity (macOS only)
    Enroll,
    /// Read public enrollment metadata without accessing native custody
    #[command(alias = "status")]
    Show,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let home = config::mvm_home_strict()?;
    match args.action {
        Action::Enroll => {
            let identity = caller_identity::enroll_at(&home)?;
            println!("{}", serde_json::to_string_pretty(&identity)?);
        }
        Action::Show => {
            let record = caller_identity::show_at(&home)?;
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
    }
    Ok(())
}
