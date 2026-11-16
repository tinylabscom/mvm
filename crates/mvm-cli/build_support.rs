//! Small, I/O-free helpers shared by `mvm-cli`'s build script, kept out of it
//! so they can be unit-tested without running a real build.

use std::path::{Path, PathBuf};

/// Workspace inputs used both for the source dirty flag and Cargo invalidation.
pub(crate) const SOURCE_IDENTITY_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "crates",
    "src",
];

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

/// What the build script does about the Linux host payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmbedDecision {
    /// Cross-compile whatever the content store does not already hold.
    Compile,
    /// Restore from the content store and compile nothing.
    RestoreOnly,
}

/// Whether this build embeds: only when the `embed-host-bins` feature is on.
///
/// The profile, the environment and the toolchain on the host do not enter into
/// it. The same command line therefore produces the same kind of binary on every
/// machine, and a host that cannot cross-compile fails the build when it asked
/// for the feature instead of quietly shipping something else.
pub(crate) fn embed_decision(feature: bool) -> EmbedDecision {
    if feature {
        EmbedDecision::Compile
    } else {
        EmbedDecision::RestoreOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_feature_compiles_the_payload() {
        assert_eq!(embed_decision(true), EmbedDecision::Compile);
    }

    /// Release, debug and every custom profile alike: without the feature a
    /// build compiles nothing. `cargo check`, clippy and nextest are debug builds
    /// that must never start a multi-minute cross-compile, and a plain
    /// `cargo build --release` is the fast build.
    #[test]
    fn without_the_feature_nothing_is_compiled() {
        assert_eq!(embed_decision(false), EmbedDecision::RestoreOnly);
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
