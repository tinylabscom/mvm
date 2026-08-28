//! `mvmctl build <sub>` — build-time commands.
//!
//! `address`/`compile`/`validate`/`kernel`/`runtime-overlay`/`sdk-sidecar` are the
//! build-time verbs. Image builds moved to `machine build`.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{address, compile, kernel, runtime_overlay, sdk_sidecar, validate};

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
    /// Prebuild or refresh the read-only runtime overlay cache
    #[command(name = "runtime-overlay")]
    RuntimeOverlay(runtime_overlay::Args),
    /// Build the source checkout's SDK host-services sidecar via Stage 0
    #[command(name = "sdk-sidecar")]
    SdkSidecar(sdk_sidecar::Args),
    /// Print a Workload IR's workload address and ir-hash
    Address(address::Args),
}

impl BuildCmd {
    /// Audit verb name (matches the clap subcommand name).
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            BuildCmd::Compile(_) => "compile",
            BuildCmd::Validate(_) => "validate",
            BuildCmd::Kernel(_) => "kernel",
            BuildCmd::RuntimeOverlay(_) => "runtime-overlay",
            BuildCmd::SdkSidecar(_) => "sdk-sidecar",
            BuildCmd::Address(_) => "address",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BuildCmd::Compile(a) => compile::run(cli, a, cfg),
        BuildCmd::Validate(a) => validate::run(cli, a, cfg),
        BuildCmd::Kernel(a) => kernel::run(cli, a, cfg),
        BuildCmd::RuntimeOverlay(a) => runtime_overlay::run(cli, a, cfg),
        BuildCmd::SdkSidecar(a) => sdk_sidecar::run(cli, a, cfg),
        BuildCmd::Address(a) => address::run(cli, a, cfg),
    }
}
