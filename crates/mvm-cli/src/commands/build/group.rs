//! `mvmctl build <sub>` — build-time commands.
//!
//! `compile`/`validate`/`kernel` are the remaining build-time verbs.
//! Image builds moved to `machine build`. Leaf modules are unchanged.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{compile, kernel, validate};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: BuildCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BuildCmd {
    /// Compile Workload IR into build artifacts
    Compile(compile::Args),
    /// Validate a Nix flake before building (runs `nix flake check`)
    Validate(validate::Args),
    /// Build the custom microVM kernels (builder / workload)
    Kernel(kernel::Args),
}

impl BuildCmd {
    /// Audit verb name (matches the clap subcommand name).
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            BuildCmd::Compile(_) => "compile",
            BuildCmd::Validate(_) => "validate",
            BuildCmd::Kernel(_) => "kernel",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BuildCmd::Compile(a) => compile::run(cli, a, cfg),
        BuildCmd::Validate(a) => validate::run(cli, a, cfg),
        BuildCmd::Kernel(a) => kernel::run(cli, a, cfg),
    }
}
