//! `mvmctl build <sub>` — build-time commands.
//!
//! Plan 178 / ADR-077 (D1): the image build plus `compile`/`validate`/
//! `kernel` collapse under one `build` namespace. `build image` is the
//! former top-level `build`. Leaf modules are unchanged.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{build, compile, kernel, validate};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: BuildCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BuildCmd {
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Image(build::Args),
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
            BuildCmd::Image(_) => "image",
            BuildCmd::Compile(_) => "compile",
            BuildCmd::Validate(_) => "validate",
            BuildCmd::Kernel(_) => "kernel",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BuildCmd::Image(a) => build::run(cli, a, cfg),
        BuildCmd::Compile(a) => compile::run(cli, a, cfg),
        BuildCmd::Validate(a) => validate::run(cli, a, cfg),
        BuildCmd::Kernel(a) => kernel::run(cli, a, cfg),
    }
}
