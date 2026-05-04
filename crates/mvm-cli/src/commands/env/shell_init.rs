//! `mvmctl shell-init` — print the shell init block (completions + dev aliases) to stdout.
//!
//! Plan 40 folded the standalone `mvmctl completions <shell>` verb into
//! a hidden `--emit-completions <shell>` flag here, so the eval'd init
//! block is self-contained.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Emit the shell-completion script for the given shell and exit
    /// (replaces the old `mvmctl completions <shell>` verb). Hidden
    /// because it's an implementation detail of the `eval` block.
    #[arg(long, value_name = "SHELL", hide = true)]
    pub emit_completions: Option<clap_complete::Shell>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if let Some(shell) = args.emit_completions {
        let mut cmd = super::super::cli_command();
        clap_complete::generate(shell, &mut cmd, "mvmctl", &mut std::io::stdout());
        return Ok(());
    }
    crate::shell_init::print_shell_init()
}
