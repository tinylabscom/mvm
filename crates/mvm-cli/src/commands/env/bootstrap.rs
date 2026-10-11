//! CLI arguments and presentation for explicit environment preparation.
use super::{Cli, setup::run_setup_steps};
use crate::{bootstrap, ui};
use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt).
    #[arg(long)]
    pub production: bool,
    /// Permit building the builder image from the selected local checkout.
    #[arg(long)]
    pub allow_local_builder_build: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    let phase = ui::activity::start("Preparing builder and workload artifacts".to_owned());
    let kernel = mvm_client::builder_images::environment::prepare_environment()?;
    phase.finish();
    ui::success(&format!(
        "\nBootstrap complete. Builder VM, host helpers, workload kernel, runtime overlay, initramfs, and OCI guest shims are ready.\nSDK sidecars for glibc and musl are ready. Future machine runs will reuse prepared artifacts.\nWorkload kernel: {kernel}"
    ));
    Ok(())
}

pub(super) fn run_steps(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");
    if !production {
        bootstrap::check_package_manager()?;
    }
    bootstrap::hint_libkrun_if_useful();
    run_setup_steps(false, 8, 16)?;
    Ok(())
}
