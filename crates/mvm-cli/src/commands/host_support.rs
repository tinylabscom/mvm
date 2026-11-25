//! The supported-host gate every command passes before it does anything.

use anyhow::{Result, bail};

use super::{Commands, env};

/// Refuse `command` with `refusal` when the host is unsupported. Uninstall
/// stays available so an install made before the host lost support can still
/// be removed.
pub(super) fn refuse_unsupported_host(command: &Commands, refusal: Option<&str>) -> Result<()> {
    let uninstall = matches!(
        command,
        Commands::Env(env::group::Args {
            action: env::group::EnvCmd::Uninstall(_),
        })
    );
    match refusal {
        Some(message) if !uninstall => bail!("{message}"),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::commands::Cli;
    use mvm_core::platform::UNSUPPORTED_HOST_MESSAGE;

    fn command(args: &[&str]) -> Commands {
        Cli::try_parse_from(args)
            .expect("a valid command line")
            .command
    }

    #[test]
    fn a_macos_25_host_is_refused_with_the_supported_hosts() {
        for args in [
            &["mvmctl", "doctor"][..],
            &["mvmctl", "backend", "detect", "--plain"],
            &["mvmctl", "backend", "list"],
        ] {
            let error = refuse_unsupported_host(&command(args), Some(UNSUPPORTED_HOST_MESSAGE))
                .expect_err("an unsupported host runs no command");
            assert_eq!(
                error.to_string(),
                "this host is not supported: mvm runs on Apple Silicon macOS 26 or later and \
                 on Linux with KVM. See https://runmvm.com/reference/platform-support/"
            );
        }
    }

    #[test]
    fn an_unsupported_host_can_still_uninstall() {
        let uninstall = command(&["mvmctl", "env", "uninstall"]);
        assert!(refuse_unsupported_host(&uninstall, Some(UNSUPPORTED_HOST_MESSAGE)).is_ok());
    }

    #[test]
    fn a_supported_host_is_never_refused() {
        assert!(refuse_unsupported_host(&command(&["mvmctl", "doctor"]), None).is_ok());
    }
}
