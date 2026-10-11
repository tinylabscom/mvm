//! `mvmctl pack registry` — manage installed signed registry packs: list,
//! remove, and update. Distinct from the attested runtime-pack cache this
//! verb's other subcommands manage: registry packs are content-addressed
//! under a locked signed-manifest digest.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

mod ls;
mod revocations;
mod rm;
mod update;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: RegistryAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum RegistryAction {
    /// List pinned registry packs and whether each is installed
    Ls(LsArgs),
    /// Remove a registry pack's cache entry and lock pin
    Rm(RmArgs),
    /// Re-pull a pack, adopting a newer published version when there is one
    Update(UpdateArgs),
    /// Verify and update the locally cached signed revocation feed
    Revocations(revocations::Args),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct LsArgs {
    /// Emit machine-readable JSON to stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RmArgs {
    /// The pack to remove; a version must match the lock pin
    #[arg(value_name = "ns/name[@version]")]
    pub reference: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct UpdateArgs {
    /// The pack to update: `namespace/name`, optionally `@version`
    #[arg(value_name = "ns/name[@version]")]
    pub reference: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        RegistryAction::Ls(action) => ls::run(action),
        RegistryAction::Rm(action) => rm::run(action),
        RegistryAction::Update(action) => update::run(action),
        RegistryAction::Revocations(action) => revocations::run(action),
    }
}
