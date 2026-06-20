//! `mvmctl bootstrap` — prepare the local environment from scratch.
//!
//! Runs the host-tooling setup and **pre-acquires the builder VM image** so
//! the first `mvmctl dev up` is fast: the expensive first-run image
//! download (release install) or local build (source checkout) is paid here,
//! ahead of time, not on the hot path. Idempotent — a fast no-op when the
//! environment is already set up and the image is cached.
//!
//! `install.sh` runs this automatically after installing the binary (unless
//! `MVM_SKIP_BUILDER_PREFETCH=1`), and users can run it explicitly any time.

use anyhow::Result;
use clap::Args as ClapArgs;

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
