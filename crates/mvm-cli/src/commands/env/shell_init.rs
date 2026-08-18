//! `mvmctl shell-init` — print the shell init block (completions + dev aliases) to stdout.
//!
//! The per-shell completion script it evals comes from `mvmctl completions`,
//! the public verb. This used to carry a hidden `--emit-completions` flag for
//! that, which the published reference then documented as the way to get
//! completions — documented and unfindable at once.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {}

pub(in crate::commands) fn run(_cli: &Cli, _args: Args, _cfg: &MvmConfig) -> Result<()> {
    crate::shell_init::print_shell_init()
}
