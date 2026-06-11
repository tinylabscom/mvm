//! `mvmctl manifest` — registry / inspection / object-storage operations
//! on built manifest slots.
//!
//! Top-level user-facing verbs (`init`, `build`, `up`, `run`, `exec`)
//! handle the everyday flow. This module hosts the less-common ops:
//! listing built slots, showing a slot's metadata, removing a slot,
//! pushing/pulling artifacts via the registry, and pruning orphans.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod alias;
mod export_oci;
mod info;
mod ls;
mod prune;
mod rm;
mod tag;
mod verify;

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
    /// Cleanup orphaned slots (slots whose source manifest file is gone)
    Prune(prune::Args),
    /// Verify a slot's artifacts against its checksums (and cosign
    /// signatures)
    Verify(verify::Args),
    /// Manage free-form tags on a template (`add`, `rm`, `ls`).
    /// Tags filter `mvmctl manifest ls` and surface in catalogs.
    Tag(tag::Args),
    /// Manage movable `alias → revision_hash` pointers (`set`, `rm`, `ls`).
    /// `mvmctl up --manifest <template>@<alias>` resolves through here.
    Alias(alias::Args),
    /// Export a slot's OCI tarball (`image.tar.gz`) so a non-KVM
    /// host can `docker load` the workload. Requires the flake's
    /// `mkGuest` to opt into `dockerTools.streamLayeredImage`.
    #[command(name = "export-oci")]
    ExportOci(export_oci::Args),
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        ManifestAction::Ls(a) => ls::run(cli, a, cfg),
        ManifestAction::Info(a) => info::run(cli, a, cfg),
        ManifestAction::Rm(a) => rm::run(cli, a, cfg),
        ManifestAction::Prune(a) => prune::run(cli, a, cfg),
        ManifestAction::Verify(a) => verify::run(cli, a, cfg),
        ManifestAction::Tag(a) => tag::run(cli, a, cfg),
        ManifestAction::Alias(a) => alias::run(cli, a, cfg),
        ManifestAction::ExportOci(a) => export_oci::run(cli, a, cfg),
    }
}
