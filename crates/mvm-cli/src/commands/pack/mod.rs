//! `mvmctl pack` - manage signed workload packs and the system pack cache.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_core::packs::PackKind;
use mvm_core::registry_pack::PackReference;
use mvm_core::user_config::MvmConfig;

use super::{Cli, pull, search};

mod download;
mod inspect;
mod list;
mod prune;
mod registry;
mod rollback;
mod update;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PackAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PackAction {
    /// List installed workload packs
    Ls(registry::LsArgs),
    /// Remove an installed workload pack and its lock pin
    Rm {
        /// The pack to remove; a version must match the lock pin
        #[arg(value_name = "ns/name[@version]")]
        reference: PackReference,
    },
    /// Manage the builder, runtime, and image-project pack cache
    System(SystemArgs),
    /// List every recorded system pack version (compatibility syntax)
    List {
        /// Only list versions of this pack class
        #[arg(long)]
        kind: Option<PackKindArg>,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Roll back a system pack class (compatibility syntax)
    Rollback {
        /// Which pack class to roll back
        kind: PackKindArg,
        /// A release version (e.g. "v0.17.0") or a pack-hash prefix to
        /// activate. Omit to roll back to the second-newest version.
        #[arg(long)]
        to: Option<String>,
    },
    /// Prune the system pack cache (compatibility syntax)
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
    /// Download a system pack class (compatibility syntax)
    Download {
        /// Which pack class to fetch
        kind: PackKindArg,
    },
    /// Update a workload pack by reference or a system pack by class
    Update {
        /// Workload reference (`ns/name[@version]`) or system class
        #[arg(value_name = "ns/name[@version]|SYSTEM_KIND")]
        target: UpdateTarget,
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
    /// Fetch a version into the cache without activating it
    Download {
        /// Which pack class to fetch
        kind: PackKindArg,
    },
    /// Fetch the latest version of a pack class and activate it
    Update {
        /// Which pack class to update
        kind: PackKindArg,
    },
}

#[derive(Debug, Clone)]
pub(in crate::commands) enum UpdateTarget {
    System(PackKindArg),
    Workload(PackReference),
}

impl std::str::FromStr for UpdateTarget {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "builder" => Ok(Self::System(PackKindArg::Builder)),
            "runtime" => Ok(Self::System(PackKindArg::Runtime)),
            "dev-image" => Ok(Self::System(PackKindArg::DevImage)),
            "extension" => Ok(Self::System(PackKindArg::Extension)),
            _ => value
                .parse::<PackReference>()
                .map(Self::Workload)
                .map_err(|error| {
                    format!("expected a workload reference or system pack class: {error}")
                }),
        }
    }
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
            SystemAction::Download { kind } => download::run(kind),
            SystemAction::Update { kind } => update::run(kind),
        },
        PackAction::List { kind, json } => list::run(kind, json),
        PackAction::Rollback { kind, to } => rollback::run(kind, to),
        PackAction::Prune {
            keep_recent,
            dry_run,
            json,
        } => prune::run(keep_recent, dry_run, json),
        PackAction::Download { kind } => download::run(kind),
        PackAction::Update { target } => match target {
            UpdateTarget::System(kind) => update::run(kind),
            UpdateTarget::Workload(reference) => registry::run(
                cli,
                registry::Args {
                    action: registry::RegistryAction::Update(registry::UpdateArgs {
                        reference: reference.to_string(),
                    }),
                },
                cfg,
            ),
        },
        PackAction::Info { reference, json } => inspect::run(&reference, json, false),
        PackAction::Verify { reference, json } => inspect::run(&reference, json, true),
        PackAction::Search(args) => search::run(cli, args, cfg),
        PackAction::Pull(args) => pull::run(cli, args, cfg),
        PackAction::Registry(action) => registry::run(cli, action, cfg),
    }
}
