//! `mvmctl completions` — generate shell completion scripts.

use anyhow::Result;

pub(super) fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = super::cli_command();
    clap_complete::generate(shell, &mut cmd, "mvmctl", &mut std::io::stdout());
    Ok(())
}
