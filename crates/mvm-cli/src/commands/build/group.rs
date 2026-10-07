//! `mvmctl build <sub>` — build-time commands.
//!
//! `address`/`compile`/`validate`/`kernel`/`runtime-overlay`/`sdk-sidecar`/`image-set`/`guest-bins` are the
//! build-time verbs. Image builds moved to `machine build`.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::{
    address, compile, guest_bins, image_set, kernel, runtime_overlay, sdk_sidecar, validate,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Allow building the builder VM image from a local `mvm-images` checkout for this invocation.
    /// This sets MVM_ALLOW_LOCAL_BUILDER_BUILD=1 for the process, enabling contributor-only local builder image builds.
    #[arg(long)]
    pub allow_local_builder_build: bool,

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
    /// Build one role of the MVM_IMAGES_DIR checkout into the local image cache
    #[command(name = "image-set")]
    ImageSet(image_set::Args),
    /// Assemble mvmctl's guest-runtime archive (mvm-guest-bins) from this checkout
    ///
    /// Every guest artifact mvm owns, for each guest architecture.
    ///
    /// Its consumer is mvmctl; mvm-images does not consume it.
    ///
    /// Needs the pinned cross toolchain: `just payload::toolchain`.
    #[command(name = "guest-bins")]
    GuestBins(guest_bins::Args),
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
            BuildCmd::ImageSet(_) => "image-set",
            BuildCmd::GuestBins(_) => "guest-bins",
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
        BuildCmd::ImageSet(a) => image_set::run(cli, a, cfg),
        BuildCmd::GuestBins(a) => guest_bins::run(cli, a, cfg),
    }
}
