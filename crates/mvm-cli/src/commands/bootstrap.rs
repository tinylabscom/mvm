//! `mvmctl bootstrap` — prepare the local environment from scratch.
//!
//! Runs the host-tooling setup and **pre-acquires the builder VM image and
//! workload kernel** so the first machine run is ready: expensive first-run
//! downloads (release install) or local builds (source checkout) are paid here,
//! ahead of time, not on the launch path. Idempotent — a fast verification when
//! the environment and both artifacts are already cached.
//!
//! `install.sh` runs this automatically after installing the binary unless
//! `MVM_SKIP_BOOTSTRAP=1`, and users can run it explicitly any time.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt).
    #[arg(long)]
    pub production: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    super::env::bootstrap::bootstrap_environment(args.production)
}

#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct BuilderVmBootstrapArgs {}

pub(in crate::commands) fn run_builder_vm_bootstrap(
    _cli: &Cli,
    _args: BuilderVmBootstrapArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    super::env::builder_vm::bootstrap_builder_vm_image()
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct BuilderEgressSupervisorArgs {
    /// Endpoint executable to keep alive for the persistent builder VM.
    #[arg(long)]
    pub endpoint: PathBuf,
}

pub(in crate::commands) fn run_builder_egress_supervisor(
    _cli: &Cli,
    args: BuilderEgressSupervisorArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    mvm_client::builder::supervise_egress_endpoint(&args.endpoint)?;
    Ok(())
}
