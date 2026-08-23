//! How the default boot image is acquired: built locally, or fetched prebuilt.
//!
//! A source checkout builds its own images unconditionally, so a contributor
//! editing an image flake sees that edit on the next boot with no release
//! round-trip. That is the right default and it stays the default. But it is
//! also unconditional, which makes it expensive when the image is not what is
//! being worked on — a one-line change elsewhere still pays for an image build.
//!
//! `MVM_BOOT_IMAGE` is the opt-out:
//!
//! | value   | behaviour                                    |
//! |---------|----------------------------------------------|
//! | unset   | auto-detect — today's behaviour, unchanged   |
//! | `build` | force a local build even when installed      |
//! | `fetch` | fetch a prebuilt even in a source checkout   |
//!
//! Priority is the same shape the builder backend already uses: explicit flag,
//! then env var (case-insensitive, trimmed, unrecognised warns and falls
//! through), then auto-detect.
//!
//! `fetch` inside a source checkout is the one case that weakens "a source
//! checkout never depends on a published artifact". It does so only on explicit
//! opt-in, and the resulting image records that it was fetched, so a stale
//! prebuilt cannot later be mistaken for a build of the working tree.
//!
//! [`resolve`] takes the source-checkout answer as an argument rather than
//! probing for it. The oracle lives above this crate, and a pure function is
//! exhaustively testable without a filesystem.

/// Env var the acquisition arm consults. A constant so `mvmctl doctor` can name
/// it without re-deriving the string.
pub const MVM_BOOT_IMAGE_ENV: &str = "MVM_BOOT_IMAGE";

/// Which arm produces the boot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootImageAcquisition {
    /// Build the image locally from the in-repo flake.
    Build,
    /// Fetch a published prebuilt.
    Fetch,
}

impl BootImageAcquisition {
    /// Stable lowercase name — the same token the env var accepts, so the
    /// readout and the input cannot drift apart.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Fetch => "fetch",
        }
    }
}

/// Why the arm was chosen. Carried rather than re-derived, so `doctor` reports
/// the actual decision instead of guessing at it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootImageSource {
    /// An explicit CLI flag.
    Flag,
    /// [`MVM_BOOT_IMAGE_ENV`].
    Env,
    /// Neither override present.
    AutoDetect,
}

impl BootImageSource {
    /// Operator-facing phrase for the `doctor` line.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Flag => "override via --boot-image".to_string(),
            Self::Env => format!("override via ${MVM_BOOT_IMAGE_ENV}"),
            Self::AutoDetect => "auto-detected".to_string(),
        }
    }
}

/// The arm and the reason for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedBootImage {
    /// The arm that will run.
    pub choice: BootImageAcquisition,
    /// Where that answer came from.
    pub source: BootImageSource,
}

/// Parse the env var alone. `None` means "no override present", which a caller
/// must be able to tell apart from "the user asked for build".
///
/// An unrecognised value warns and returns `None` so the caller falls through
/// to auto-detect — the same fail-without-aborting policy the builder backend
/// selection uses. A typo must not silently change which arm runs, and must not
/// abort a build either.
#[must_use]
pub fn resolve_env_override() -> Option<BootImageAcquisition> {
    let raw = std::env::var_os(MVM_BOOT_IMAGE_ENV)?;
    parse(&raw.to_string_lossy())
}

/// Parse one env value. Split out so the table test does not have to mutate
/// process environment to cover the grammar.
#[must_use]
pub fn parse(value: &str) -> Option<BootImageAcquisition> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "build" => Some(BootImageAcquisition::Build),
        "fetch" => Some(BootImageAcquisition::Fetch),
        other => {
            tracing::warn!(
                value = %other,
                "{MVM_BOOT_IMAGE_ENV} value not recognised; falling through to auto-detect"
            );
            None
        }
    }
}

/// Apply the priority: flag, then env, then auto-detect.
///
/// `is_source_checkout` is the auto-detect input: a checkout builds, an
/// installed binary fetches. Passed in because the oracle for it lives above
/// this crate.
#[must_use]
pub fn resolve(flag: Option<BootImageAcquisition>, is_source_checkout: bool) -> ResolvedBootImage {
    if let Some(choice) = flag {
        return ResolvedBootImage {
            choice,
            source: BootImageSource::Flag,
        };
    }
    if let Some(choice) = resolve_env_override() {
        return ResolvedBootImage {
            choice,
            source: BootImageSource::Env,
        };
    }
    ResolvedBootImage {
        choice: auto_detect(
            crate::artifact_acquisition::compiled_channel(),
            is_source_checkout,
        ),
        source: BootImageSource::AutoDetect,
    }
}

fn auto_detect(
    channel: crate::artifact_acquisition::DistributionChannel,
    is_source_checkout: bool,
) -> BootImageAcquisition {
    match crate::artifact_acquisition::default_acquisition(channel, is_source_checkout) {
        crate::artifact_acquisition::DefaultAcquisition::Build => BootImageAcquisition::Build,
        crate::artifact_acquisition::DefaultAcquisition::Download => BootImageAcquisition::Fetch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn the_grammar_accepts_both_arms_case_insensitively_and_trimmed() {
        for (input, want) in [
            ("build", Some(BootImageAcquisition::Build)),
            ("fetch", Some(BootImageAcquisition::Fetch)),
            ("  BUILD  ", Some(BootImageAcquisition::Build)),
            ("Fetch", Some(BootImageAcquisition::Fetch)),
        ] {
            assert_eq!(parse(input), want, "input {input:?}");
        }
    }

    /// Empty and unrecognised both mean "no override" rather than an error.
    /// A typo must not abort a build, and must not silently pick an arm.
    #[test]
    fn an_empty_or_unrecognised_value_is_not_an_override() {
        for input in ["", "   ", "download", "prebuilt", "true", "1"] {
            assert_eq!(parse(input), None, "input {input:?}");
        }
    }

    /// The whole table for contributor builds: every knob state against both
    /// source-availability states.
    #[cfg(not(feature = "release-channel"))]
    #[test]
    fn each_knob_value_resolves_to_the_intended_arm() {
        use BootImageAcquisition::{Build, Fetch};
        use BootImageSource::{AutoDetect, Env};

        let cases = [
            // (env, is_source_checkout, choice, source)
            (None, true, Build, AutoDetect),
            (None, false, Fetch, AutoDetect),
            (Some("build"), true, Build, Env),
            (Some("build"), false, Build, Env),
            (Some("fetch"), true, Fetch, Env),
            (Some("fetch"), false, Fetch, Env),
            // Unrecognised falls through to auto-detect rather than erroring.
            (Some("nonsense"), true, Build, AutoDetect),
            (Some("nonsense"), false, Fetch, AutoDetect),
        ];

        for (env, checkout, want_choice, want_source) in cases {
            let mut test_env = TestEnv::new();
            match env {
                Some(v) => test_env.set(MVM_BOOT_IMAGE_ENV, v),
                None => test_env.remove(MVM_BOOT_IMAGE_ENV),
            }
            let got = resolve(None, checkout);
            assert_eq!(
                got,
                ResolvedBootImage {
                    choice: want_choice,
                    source: want_source
                },
                "env={env:?} source_checkout={checkout}"
            );
        }
    }

    /// An explicit flag outranks the env var, which outranks auto-detect.
    #[test]
    fn an_explicit_flag_outranks_the_env_var() {
        let mut test_env = TestEnv::new();
        test_env.set(MVM_BOOT_IMAGE_ENV, "fetch");
        let got = resolve(Some(BootImageAcquisition::Build), false);
        assert_eq!(got.choice, BootImageAcquisition::Build);
        assert_eq!(got.source, BootImageSource::Flag);
    }

    /// Contributor builds continue to compile artifacts available in the checkout.
    #[test]
    fn an_unset_knob_leaves_a_source_checkout_building() {
        assert_eq!(
            auto_detect(
                crate::artifact_acquisition::DistributionChannel::Source,
                true,
            ),
            BootImageAcquisition::Build
        );
    }

    #[test]
    fn release_channel_auto_detect_never_builds_inside_a_checkout() {
        assert_eq!(
            auto_detect(
                crate::artifact_acquisition::DistributionChannel::Release,
                true,
            ),
            BootImageAcquisition::Fetch
        );
    }
}
