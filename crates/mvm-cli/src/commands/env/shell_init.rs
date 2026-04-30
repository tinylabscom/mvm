//! `mvmctl shell-init` — print the shell init block (completions + dev aliases) to stdout.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {}

pub(in crate::commands) fn run(_cli: &Cli, _args: Args, _cfg: &MvmConfig) -> Result<()> {
    crate::shell_init::print_shell_init()
}
