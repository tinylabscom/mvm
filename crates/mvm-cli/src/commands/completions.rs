//! `mvmctl completions <shell>` — print a completion script.
//!
//! The renderer has been here all along; what it lacked was a name a user
//! could type. It was reachable only through `shell-init --emit-completions`,
//! a flag deliberately hidden as "an implementation detail of the eval block"
//! — while the published CLI reference documented that same hidden flag as the
//! way to get completions. Documented and unfindable is the pattern this
//! surface has been shedding.
//!
//! So the flag becomes a verb, and the eval block calls the verb. One name for
//! one thing, and the name is the discoverable one.

use anyhow::Result;
use clap::Args as ClapArgs;

use super::env::shell_completion::{Shell, render};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Which shell to emit for.
    #[arg(value_enum)]
    pub shell: Shell,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    print!("{}", render(super::cli_command(), args.shell));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(shell: &str) -> Result<Args> {
        let cli = crate::commands::Cli::try_parse_from(["mvmctl", "completions", shell])?;
        match cli.command {
            crate::commands::Commands::Completions(a) => Ok(a),
            _ => panic!("expected Commands::Completions"),
        }
    }

    #[test]
    fn every_supported_shell_is_selectable() {
        for (flag, expected) in [("bash", Shell::Bash), ("zsh", Shell::Zsh)] {
            let args = parse(flag).unwrap_or_else(|e| panic!("`{flag}` must parse: {e}"));
            assert_eq!(args.shell, expected);
        }
    }

    /// The renderer supports bash and zsh. Accepting `fish` and emitting a
    /// bash script would be worse than refusing: the user would source it and
    /// get errors that look like a bug in their shell.
    #[test]
    fn an_unsupported_shell_is_refused_rather_than_approximated() {
        let err = parse("fish").expect_err("fish is not supported");
        let msg = err.to_string();
        assert!(
            msg.contains("bash") && msg.contains("zsh"),
            "the refusal must list what is supported: {msg}"
        );
    }

    #[test]
    fn the_rendered_script_names_the_binary_and_real_verbs() {
        let script = render(crate::commands::cli_command(), Shell::Bash);
        assert!(script.contains("mvmctl"), "must complete for `mvmctl`");
        for verb in ["machine", "run", "doctor"] {
            assert!(
                script.contains(verb),
                "a completion script that omits `{verb}` completes nothing useful"
            );
        }
    }
}
