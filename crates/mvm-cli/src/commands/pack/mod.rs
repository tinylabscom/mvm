//! `mvmctl pack` - list, roll back, prune, and (for the builder pack)
//! download/update the versioned attested-pack cache.
//!
//! Mirrors `commands/image/`: a thin `Args`/`Subcommand` shell dispatching to
//! one submodule per verb, each of which is a thin wrapper over the
//! `mvm_core::pack_cache` lifecycle facade.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_core::packs::PackKind;
use mvm_core::user_config::MvmConfig;

use super::Cli;

mod download;
mod list;
mod prune;
mod rollback;
mod update;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PackAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PackAction {
    /// List every recorded pack version, marking each key's active one
    List {
        /// Only list versions of this pack class
        #[arg(long)]
        kind: Option<PackKindArg>,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Point a pack class's active version at an already-cached one
    Rollback {
        /// Which pack class to roll back
        kind: PackKindArg,
        /// A release version (e.g. "v0.17.0") or a pack-hash prefix to
        /// activate. Omit to roll back to the second-newest version.
        #[arg(long)]
        to: Option<String>,
    },
    /// Reclaim non-active pack versions beyond the newest N per key
    Prune {
        /// How many of the newest versions per key to keep (beyond the active one)
        #[arg(long, default_value_t = 2)]
        keep_recent: usize,
        /// Print what would be removed without removing anything
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Fetch a pack version into the cache without changing the active one
    Download {
        /// Which pack class to fetch
        kind: PackKindArg,
        /// Release version to fetch. Omit to fetch the latest.
        #[arg(long)]
        version: Option<String>,
    },
    /// Fetch the latest pack version and activate it
    Update {
        /// Which pack class to update
        kind: PackKindArg,
    },
}

/// `mvmctl pack <kind>` CLI selector, mapping onto [`PackKind`]. `dev-image`
/// is the user-facing name for [`PackKind::ImageProject`].
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum PackKindArg {
    Builder,
    Runtime,
    #[value(name = "dev-image")]
    DevImage,
    Extension,
}

impl PackKindArg {
    pub(in crate::commands) fn to_pack_kind(self) -> PackKind {
        match self {
            PackKindArg::Builder => PackKind::Builder,
            PackKindArg::Runtime => PackKind::Runtime,
            PackKindArg::DevImage => PackKind::ImageProject,
            PackKindArg::Extension => PackKind::Extension,
        }
    }

    /// User-facing label for error/status messages — matches the clap value name.
    pub(in crate::commands) fn label(self) -> &'static str {
        match self {
            PackKindArg::Builder => "builder",
            PackKindArg::Runtime => "runtime",
            PackKindArg::DevImage => "dev-image",
            PackKindArg::Extension => "extension",
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        PackAction::List { kind, json } => list::run(kind, json),
        PackAction::Rollback { kind, to } => rollback::run(kind, to),
        PackAction::Prune {
            keep_recent,
            dry_run,
            json,
        } => prune::run(keep_recent, dry_run, json),
        PackAction::Download { kind, version } => download::run(kind, version),
        PackAction::Update { kind } => update::run(kind),
    }
}
