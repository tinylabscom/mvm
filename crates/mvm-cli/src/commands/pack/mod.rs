//! `mvmctl pack` - manage signed workload packs and the system pack cache.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_core::packs::PackKind;
use mvm_core::registry_pack::PackReference;
use mvm_core::user_config::MvmConfig;

use super::{Cli, pull, search};

mod author;
pub(in crate::commands) mod build;
pub(crate) mod inspect;
mod list;
pub(in crate::commands) mod new;
mod prune;
mod registry;
mod rollback;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PackAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PackAction {
    /// List installed workload packs
    Ls(registry::LsArgs),
    /// Draft an unpublished application pack (binary embedded in a .mvmpkg) for registry review
    New(new::Args),
    /// Remove an installed workload pack and its lock pin
    Rm {
        /// The pack to remove; a version must match the lock pin
        #[arg(value_name = "ns/name[@version]")]
        reference: PackReference,
    },
    /// Manage the builder, runtime, and image-project pack cache
    System(SystemArgs),
    /// Update an installed workload pack by reference
    Update {
        #[arg(value_name = "ns/name[@version]")]
        reference: PackReference,
    },
    /// Show the signed manifest and policy of an installed workload pack
    Info {
        /// Installed pack selected by its lock pin
        #[arg(value_name = "ns/name[@version]")]
        reference: String,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Verify an installed workload pack's signature and every payload file
    Verify {
        /// Installed pack selected by its lock pin
        #[arg(value_name = "ns/name[@version]")]
        reference: String,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Resolve an authored pack spec against its source into a frozen lock
    Lock(author::LockArgs),
    /// Compile a pack spec into a flake artifact, refusing a missing or stale lock
    Compile(author::CompileArgs),
    /// Search available workload packs
    Search(search::Args),
    /// Fetch, verify, install, and pin a workload pack
    Pull(pull::Args),
    /// Compatibility commands for signed workload packs
    Registry(registry::Args),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SystemArgs {
    #[command(subcommand)]
    action: SystemAction,
}

#[derive(Subcommand, Debug, Clone)]
enum SystemAction {
    /// List every recorded version, marking each key's active one
    List {
        /// Only list versions of this pack class
        #[arg(long)]
        kind: Option<PackKindArg>,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Activate an already-cached version of a pack class
    Rollback {
        /// Which pack class to roll back
        kind: PackKindArg,
        /// Version or pack-hash prefix; defaults to the second-newest version
        #[arg(long)]
        to: Option<String>,
    },
    /// Reclaim non-active versions beyond the newest N per key
    Prune {
        /// How many newest versions per key to keep beyond the active one
        #[arg(long, default_value_t = 2)]
        keep_recent: usize,
        /// Print what would be removed without removing anything
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
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

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        PackAction::Ls(args) => registry::run(
            cli,
            registry::Args {
                action: registry::RegistryAction::Ls(args),
            },
            cfg,
        ),
        PackAction::Rm { reference } => registry::run(
            cli,
            registry::Args {
                action: registry::RegistryAction::Rm(registry::RmArgs {
                    reference: reference.to_string(),
                }),
            },
            cfg,
        ),
        PackAction::System(args) => match args.action {
            SystemAction::List { kind, json } => list::run(kind, json),
            SystemAction::Rollback { kind, to } => rollback::run(kind, to),
            SystemAction::Prune {
                keep_recent,
                dry_run,
                json,
            } => prune::run(keep_recent, dry_run, json),
        },
        PackAction::Update { reference } => registry::run(
            cli,
            registry::Args {
                action: registry::RegistryAction::Update(registry::UpdateArgs {
                    reference: reference.to_string(),
                }),
            },
            cfg,
        ),
        PackAction::New(args) => new::run(args),
        PackAction::Info { reference, json } => inspect::run(&reference, json, false),
        PackAction::Verify { reference, json } => inspect::run(&reference, json, true),
        PackAction::Lock(args) => author::run_lock(args),
        PackAction::Compile(args) => author::run_compile(args),
        PackAction::Search(args) => search::run(cli, args, cfg),
        PackAction::Pull(args) => pull::run(cli, args, cfg),
        PackAction::Registry(action) => registry::run(cli, action, cfg),
    }
}
