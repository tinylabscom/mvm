//! `mvmctl env <sub>` — mvm environment / install lifecycle.
//!
//! Plan 178 / ADR-077 (D5): `bootstrap`, `cleanup`, `uninstall`, `update`,
//! `sign` collapse under one `env` namespace (set up / maintain / tear down
//! the mvm install + dev environment). The daily/entry commands `dev`,
//! `doctor`, `init` stay top-level. Leaf modules are unchanged.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{bootstrap, cleanup, sign, uninstall, update};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: EnvCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum EnvCmd {
    /// Full environment setup from scratch
    Bootstrap(bootstrap::Args),
    /// Remove old dev-build artifacts and run Nix garbage collection
    Cleanup(cleanup::Args),
    /// Remove local mvm state
    Uninstall(uninstall::Args),
    /// Check for and install the latest version of mvmctl
    Update(update::Args),
    /// Re-sign mvmctl + supervisors with VZ entitlements (macOS)
    Sign(sign::Args),
}

impl EnvCmd {
    /// Audit verb name (matches the clap subcommand name).
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            EnvCmd::Bootstrap(_) => "bootstrap",
            EnvCmd::Cleanup(_) => "cleanup",
            EnvCmd::Uninstall(_) => "uninstall",
            EnvCmd::Update(_) => "update",
            EnvCmd::Sign(_) => "sign",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        EnvCmd::Bootstrap(a) => bootstrap::run(cli, a, cfg),
        EnvCmd::Cleanup(a) => cleanup::run(cli, a, cfg),
        EnvCmd::Uninstall(a) => uninstall::run(cli, a, cfg),
        EnvCmd::Update(a) => update::run(cli, a, cfg),
        EnvCmd::Sign(a) => sign::run(cli, a, cfg),
    }
}
