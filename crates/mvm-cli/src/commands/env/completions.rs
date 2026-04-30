//! `mvmctl completions` — generate shell completion scripts.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Shell to generate completions for
    pub shell: clap_complete::Shell,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let mut cmd = super::super::cli_command();
    clap_complete::generate(args.shell, &mut cmd, "mvmctl", &mut std::io::stdout());
    Ok(())
}
