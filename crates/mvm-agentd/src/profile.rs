//! The agent profile a guest boots under.
//!
//! The profile decides which verb classes the dispatcher will consider at all;
//! the signed verb grant then narrows what remains. Two host-controlled sources
//! can name it: the `mvm.profile=` token on the kernel command line, and the
//! `security-policy.json` policy file on the config drive or a sealed rootfs.
//! The universal initramfs has no config drive, so for that boot the command
//! line is the only source that exists.

use mvm_core::security::AgentProfile;

/// The kernel cmdline key the host names the profile under. Matches
/// `mvm_vmm::host::egress_bridge::PROFILE_CMDLINE_KEY`, which the agent cannot
/// depend on.
pub const CMDLINE_KEY: &str = "mvm.profile";

/// The profile `cmdline` names, `None` when it names none.
///
/// # Errors
///
/// A value that is not a profile, or the key given twice. Either means the
/// host and guest disagree about the boot contract.
pub fn profile_from_cmdline(cmdline: &str) -> Result<Option<AgentProfile>, String> {
    let prefix = format!("{CMDLINE_KEY}=");
    let mut values = cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(prefix.as_str()));
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("{CMDLINE_KEY} is named more than once"));
    }
    value
        .parse::<AgentProfile>()
        .map(Some)
        .map_err(|error| format!("{CMDLINE_KEY}: {error}"))
}

/// The profile the agent runs under, given what each source said.
///
/// The more restrictive source wins: `sealed-prod` from either one is
/// `sealed-prod`, so a command line can never widen a sealed rootfs's own
/// policy. A source that is present but unreadable or malformed also yields
/// `sealed-prod`, because guessing a more permissive profile for a file the
/// host meant to constrain would fail open. With neither source the image is
/// unprovisioned and runs `dev`, as it always has.
#[must_use]
pub fn resolve<E1, E2>(
    from_cmdline: Result<Option<AgentProfile>, E1>,
    from_policy_file: Result<Option<AgentProfile>, E2>,
) -> AgentProfile {
    let (Ok(from_cmdline), Ok(from_policy_file)) = (from_cmdline, from_policy_file) else {
        return AgentProfile::SealedProd;
    };
    if from_cmdline == Some(AgentProfile::SealedProd)
        || from_policy_file == Some(AgentProfile::SealedProd)
    {
        return AgentProfile::SealedProd;
    }
    from_cmdline
        .or(from_policy_file)
        .unwrap_or(AgentProfile::Dev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use AgentProfile::{Builder, Dev, SealedProd};

    type Source = Result<Option<AgentProfile>, ()>;

    #[test]
    fn the_cmdline_names_a_profile_or_none() {
        assert_eq!(profile_from_cmdline("console=ttyS0"), Ok(None));
        assert_eq!(
            profile_from_cmdline("a mvm.profile=sealed-prod b"),
            Ok(Some(SealedProd))
        );
        assert_eq!(profile_from_cmdline("mvm.profile=dev"), Ok(Some(Dev)));
        assert_eq!(profile_from_cmdline("mvm.profile_x=dev"), Ok(None));
    }

    #[test]
    fn a_bad_or_repeated_profile_token_is_an_error_not_a_guess() {
        assert!(profile_from_cmdline("mvm.profile=prod").is_err());
        assert!(profile_from_cmdline("mvm.profile=").is_err());
        assert!(profile_from_cmdline("mvm.profile=dev mvm.profile=sealed-prod").is_err());
    }

    #[test]
    fn with_neither_source_an_unprovisioned_image_runs_dev() {
        assert_eq!(resolve::<(), ()>(Ok(None), Ok(None)), Dev);
    }

    #[test]
    fn the_command_line_alone_names_the_profile_of_a_universal_boot() {
        assert_eq!(
            resolve::<(), ()>(Ok(Some(SealedProd)), Ok(None)),
            SealedProd
        );
        assert_eq!(resolve::<(), ()>(Ok(Some(Dev)), Ok(None)), Dev);
        assert_eq!(resolve::<(), ()>(Ok(Some(Builder)), Ok(None)), Builder);
    }

    #[test]
    fn the_policy_file_alone_still_names_the_profile() {
        assert_eq!(
            resolve::<(), ()>(Ok(None), Ok(Some(SealedProd))),
            SealedProd
        );
        assert_eq!(resolve::<(), ()>(Ok(None), Ok(Some(Dev))), Dev);
    }

    #[test]
    fn sealed_from_either_source_is_sealed_whatever_the_other_says() {
        for (cmdline, file) in [
            (Some(Dev), Some(SealedProd)),
            (Some(SealedProd), Some(Dev)),
            (Some(Builder), Some(SealedProd)),
            (Some(SealedProd), None),
        ] {
            assert_eq!(
                resolve::<(), ()>(Ok(cmdline), Ok(file)),
                SealedProd,
                "{cmdline:?} {file:?}"
            );
        }
    }

    #[test]
    fn an_unreadable_source_fails_closed() {
        let bad: Source = Err(());
        assert_eq!(resolve(bad, Ok::<_, ()>(Some(Dev))), SealedProd);
        assert_eq!(resolve(Ok::<_, ()>(Some(Dev)), bad), SealedProd);
        assert_eq!(resolve(bad, bad), SealedProd);
    }
}
