//! The positional `SOURCE` of `run` and `machine run`: an OCI image reference
//! or a signed `.mvmpkg` artifact, named before the `--` that starts the
//! guest command.
//!
//! What a value means is decided by its shape alone, the way `RootfsSource`
//! decides it, never by what happens to exist in the working directory. A
//! path-shaped `.mvmpkg` is an artifact and anything else is an image
//! reference. A path that is not an artifact, and a `flake:` source, each have
//! a flag of their own, and saying so beats guessing which one was meant.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use mvm_core::rootfs_source::RootfsSource;

use super::RunArgs;

const ARTIFACT_EXTENSION: &str = "mvmpkg";

/// What the positional names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PositionalSource {
    /// A signed bundle on disk.
    Artifact(PathBuf),
    /// An OCI image reference, as `--image` takes it.
    Image(String),
}

/// Turn the positional, if any, into the source flag it stands for.
///
/// An image reference becomes `--image`. An artifact becomes
/// `--manifest <path>`, which verifies the archive against the trust store,
/// installs it on first use, and boots it by its bundle SHA-256, exactly as
/// writing `--manifest ./app.mvmpkg` does.
pub(in crate::commands) fn apply_positional_source(args: &mut RunArgs) -> Result<()> {
    let Some(raw) = args.source.take() else {
        return Ok(());
    };
    match classify(&raw)? {
        PositionalSource::Image(image) => args.image = Some(image),
        PositionalSource::Artifact(path) => args.manifest = Some(path.display().to_string()),
    }
    Ok(())
}

/// Whether `raw` names something a run can boot — an image reference or an
/// artifact — rather than, say, a script path.
pub(in crate::commands) fn names_a_boot_source(raw: &str) -> bool {
    classify(raw).is_ok()
}

fn classify(raw: &str) -> Result<PositionalSource> {
    match raw.parse::<RootfsSource>()? {
        RootfsSource::LocalPath(path) if is_artifact(&path) => Ok(PositionalSource::Artifact(path)),
        RootfsSource::LocalPath(path) => bail!(
            "`{}` is a path, and a path before `--` must be a signed `.{ARTIFACT_EXTENSION}` \
             artifact. Use `--manifest {0}` for an mvm.toml or a built slot, or \
             `--deployment {0}` for a deployment directory.",
            path.display()
        ),
        RootfsSource::Flake { flake_ref, attr } => bail!(
            "`{raw}` is a flake; build and boot it with `--flake {flake_ref}` \
             (`--flake-profile` selects a variant other than `{attr}`)"
        ),
        RootfsSource::Oci { image_ref } if is_artifact(Path::new(&image_ref)) => bail!(
            "`{image_ref}` reads as an image reference, not a file. Write \
             `./{image_ref}` to boot the artifact in the working directory."
        ),
        RootfsSource::Oci { image_ref } => Ok(PositionalSource::Image(image_ref)),
    }
}

fn is_artifact(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension == ARTIFACT_EXTENSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(source: &str) -> RunArgs {
        RunArgs {
            source: Some(source.to_string()),
            ..RunArgs::default()
        }
    }

    #[test]
    fn an_image_reference_becomes_the_image_flag() {
        for reference in ["alpine", "alpine:3.20", "ghcr.io/team/app@sha256:abc"] {
            let mut args = args_with(reference);
            apply_positional_source(&mut args).expect("an image");
            assert_eq!(args.image.as_deref(), Some(reference));
            assert!(args.source.is_none() && args.manifest.is_none());
        }
    }

    #[test]
    fn an_artifact_becomes_the_manifest_flag() {
        let mut args = args_with("./dist/app.mvmpkg");
        apply_positional_source(&mut args).expect("an artifact");
        assert_eq!(args.manifest.as_deref(), Some("./dist/app.mvmpkg"));
        assert!(args.image.is_none() && args.source.is_none());
    }

    #[test]
    fn absolute_relative_and_explicit_path_artifacts_are_artifacts() {
        for path in ["/tmp/app.mvmpkg", "../app.mvmpkg", "path:app.mvmpkg"] {
            assert!(
                matches!(classify(path).unwrap(), PositionalSource::Artifact(_)),
                "{path}"
            );
        }
    }

    #[test]
    fn a_bare_artifact_name_is_refused_rather_than_pulled() {
        let err = classify("app.mvmpkg").unwrap_err().to_string();
        assert!(err.contains("./app.mvmpkg"), "{err}");
    }

    #[test]
    fn a_path_that_is_not_an_artifact_names_the_flags_that_take_it() {
        let err = classify("./project").unwrap_err().to_string();
        assert!(err.contains("--manifest ./project"), "{err}");
        assert!(err.contains("--deployment ./project"), "{err}");
    }

    #[test]
    fn a_flake_names_the_flake_flag() {
        let err = classify("flake:./app#default").unwrap_err().to_string();
        assert!(err.contains("--flake ./app"), "{err}");
    }

    #[test]
    fn images_and_artifacts_name_a_boot_source_and_scripts_do_not() {
        assert!(names_a_boot_source("alpine@sha256:abc"));
        assert!(names_a_boot_source("./app.mvmpkg"));
        assert!(!names_a_boot_source("./script.py"));
        assert!(!names_a_boot_source("app.mvmpkg"));
    }

    #[test]
    fn no_positional_changes_nothing() {
        let mut args = RunArgs::default();
        apply_positional_source(&mut args).expect("nothing to do");
        assert!(args.image.is_none() && args.manifest.is_none());
    }
}
