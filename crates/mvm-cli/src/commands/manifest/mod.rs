//! `mvmctl manifest` — registry / inspection / object-storage operations
//! on built manifest slots (plan 38 §4).
//!
//! Top-level user-facing verbs (`init`, `build`, `up`, `run`, `exec`)
//! handle the everyday flow. This module hosts the less-common ops:
//! listing built slots, showing a slot's metadata, removing a slot,
//! pushing/pulling artifacts via the registry, and pruning orphans.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod info;
mod ls;
mod rm;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ManifestAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ManifestAction {
    /// List built manifest slots (manifest path, optional name, last build)
    #[command(alias = "list")]
    Ls(ls::Args),
    /// Print details for one slot (manifest, current revision, snapshot, provenance)
    #[command(alias = "show")]
    Info(info::Args),
    /// Remove a slot's artifacts from the local registry
    #[command(alias = "delete")]
    Rm(rm::Args),
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        ManifestAction::Ls(a) => ls::run(cli, a, cfg),
        ManifestAction::Info(a) => info::run(cli, a, cfg),
        ManifestAction::Rm(a) => rm::run(cli, a, cfg),
    }
}
