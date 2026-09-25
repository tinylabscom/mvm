//! Small, I/O-free helpers shared by `mvm-cli`'s build script, kept out of it
//! so they can be unit-tested without running a real build.

use std::path::{Path, PathBuf};

/// Return a nested Cargo target shared by every feature fingerprint of the
/// same outer profile. Cargo gives each build-script fingerprint a different
/// `OUT_DIR`; placing nested builds directly below it makes identical embedded
/// binaries rebuild for clippy, feature tests, and examples. Their common
/// `build/` parent is still isolated from the outer Cargo lock while allowing
/// the nested Cargo invocation to reuse its own fingerprints.
pub(crate) fn shared_nested_target_dir(out_dir: &Path) -> PathBuf {
    let build_dir = out_dir
        .parent()
        .and_then(Path::parent)
        .expect("Cargo OUT_DIR must end in build/<package-fingerprint>/out");
    build_dir.join("mvm-cli-nested-target")
}

/// Why a build embeds the Linux host payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbedRequest {
    /// `embed-host-bins` is on. Asked for by name, so a host that cannot
    /// cross-compile fails the build.
    Feature,
    /// A release-profile build. Embedded by default so the binary a
    /// contributor builds is the one they can run, but never at the cost of a
    /// build that would otherwise have succeeded.
    ReleaseProfile,
    /// Neither. The build compiles nothing and ships only what the content
    /// store can prove belongs to this tree.
    NotRequested,
}

/// Whether `MVM_EMBED` opts a release build out of embedding.
fn opts_out(mvm_embed: Option<&str>) -> bool {
    mvm_embed.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
}

/// Decide whether this build embeds, from the `embed-host-bins` feature, cargo's
/// `PROFILE` and `MVM_EMBED`.
///
/// Cargo reports `release` for every profile that inherits from `release`, so a
/// custom release-derived profile embeds too. The feature outranks the opt-out:
/// the release workflow names it, and an `MVM_EMBED=0` left in a shell must not
/// be able to ship a release binary without its payload.
pub(crate) fn embed_request(feature: bool, profile: &str, mvm_embed: Option<&str>) -> EmbedRequest {
    if feature {
        EmbedRequest::Feature
    } else if profile == "release" && !opts_out(mvm_embed) {
        EmbedRequest::ReleaseProfile
    } else {
        EmbedRequest::NotRequested
    }
}

/// What the build script does about the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmbedDecision {
    /// Cross-compile whatever the content store does not already hold.
    Compile,
    /// Restore from the content store and compile nothing. `warning` is set
    /// when the build wanted to embed and could not, and is shown only if the
    /// restore also comes up empty.
    RestoreOnly { warning: Option<String> },
}

/// Settle a request against the cross-compile toolchain's readiness.
///
/// Only a profile-implied request consults `toolchain`: an explicit feature
/// keeps failing inside the compile with the toolchain's own message, and a
/// build that did not ask never needs one.
pub(crate) fn embed_decision(
    request: EmbedRequest,
    toolchain: Result<(), String>,
) -> EmbedDecision {
    match (request, toolchain) {
        (EmbedRequest::Feature, _) | (EmbedRequest::ReleaseProfile, Ok(())) => {
            EmbedDecision::Compile
        }
        (EmbedRequest::ReleaseProfile, Err(reason)) => EmbedDecision::RestoreOnly {
            warning: Some(unembedded_release_warning(&reason)),
        },
        (EmbedRequest::NotRequested, _) => EmbedDecision::RestoreOnly { warning: None },
    }
}

/// The `cargo:warning=` a release build prints when it could not embed.
fn unembedded_release_warning(reason: &str) -> String {
    format!(
        "this release mvmctl does not embed its Linux host binaries, because the pinned \
         cross-compile toolchain is unavailable: {reason} It will try to build them the \
         first time it needs a builder VM, which needs the same toolchain. Install it with \
         `just toolchain-embed`, or set MVM_EMBED=0 to build without them on purpose."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_feature_embeds_in_every_profile() {
        for profile in ["debug", "release"] {
            assert_eq!(
                embed_request(true, profile, None),
                EmbedRequest::Feature,
                "{profile}"
            );
        }
    }

    #[test]
    fn a_release_build_embeds_without_the_feature() {
        assert_eq!(
            embed_request(false, "release", None),
            EmbedRequest::ReleaseProfile
        );
        assert_eq!(
            embed_request(false, "release", Some("1")),
            EmbedRequest::ReleaseProfile
        );
    }

    /// Debug is where `cargo check`, clippy and nextest run. None of them may
    /// start a multi-minute cross-compile.
    #[test]
    fn a_debug_build_never_embeds_by_default() {
        assert_eq!(
            embed_request(false, "debug", None),
            EmbedRequest::NotRequested
        );
    }

    #[test]
    fn mvm_embed_0_opts_a_release_build_out() {
        for value in ["0", "false", "NO", " off "] {
            assert_eq!(
                embed_request(false, "release", Some(value)),
                EmbedRequest::NotRequested,
                "{value:?}"
            );
        }
    }

    /// The release workflow names the feature. A stray opt-out in the
    /// environment must not ship a release without its payload.
    #[test]
    fn the_feature_outranks_the_opt_out() {
        assert_eq!(
            embed_request(true, "release", Some("0")),
            EmbedRequest::Feature
        );
    }

    #[test]
    fn a_ready_toolchain_compiles_a_release_build() {
        assert_eq!(
            embed_decision(EmbedRequest::ReleaseProfile, Ok(())),
            EmbedDecision::Compile
        );
    }

    /// A release build that cannot embed still succeeds, and says why.
    #[test]
    fn a_missing_toolchain_downgrades_a_release_build_to_a_warning() {
        let decision = embed_decision(
            EmbedRequest::ReleaseProfile,
            Err("zig 0.13.0 was not found.".to_string()),
        );
        let EmbedDecision::RestoreOnly {
            warning: Some(warning),
        } = decision
        else {
            panic!("expected a warning, got {decision:?}");
        };
        assert!(warning.contains("zig 0.13.0 was not found."), "{warning}");
        assert!(warning.contains("just toolchain-embed"), "{warning}");
        assert!(warning.contains("MVM_EMBED=0"), "{warning}");
    }

    /// Asked for by name, the compile runs and fails with the toolchain's own
    /// message rather than being quietly skipped.
    #[test]
    fn a_missing_toolchain_still_compiles_an_explicit_feature_build() {
        assert_eq!(
            embed_decision(EmbedRequest::Feature, Err("no zig".to_string())),
            EmbedDecision::Compile
        );
    }

    #[test]
    fn an_unrequested_build_restores_quietly() {
        assert_eq!(
            embed_decision(EmbedRequest::NotRequested, Err("no zig".to_string())),
            EmbedDecision::RestoreOnly { warning: None }
        );
    }

    #[test]
    fn nested_target_is_shared_across_package_fingerprints() {
        let first = Path::new("/target/debug/build/mvm-cli-first/out");
        let second = Path::new("/target/debug/build/mvm-cli-second/out");
        assert_eq!(
            shared_nested_target_dir(first),
            shared_nested_target_dir(second)
        );
    }
}
