//! `mvmctl env verify-release` — check a downloaded release archive against
//! its Sigstore bundle, offline.
//!
//! This is the verifier `mvmctl env update` runs, exposed so a shell installer
//! can use an `mvmctl` already on the host instead of depending on `cosign`.
//! Both files are read from disk; nothing is fetched. The emergency skip
//! variable that `env update` honours is deliberately not read here: a command
//! whose only job is to verify has nothing to skip to.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The downloaded release archive, e.g. `mvmctl-aarch64-apple-darwin.tar.gz`
    pub archive: PathBuf,
    /// Its Sigstore bundle. Defaults to `<archive>.bundle` beside it
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Release tag the archive claims to come from, e.g. `v0.18.0`. Only that
    /// release's workflow identity is accepted
    #[arg(long)]
    pub tag: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let bundle = bundle_path(&args);
    verify_release_files(&args.archive, &bundle, &args.tag)?;
    ui::success(&format!(
        "{} is signed by the {} release workflow.",
        args.archive.display(),
        args.tag
    ));
    Ok(())
}

/// The bundle to check: the one named, else the release's own name for it.
fn bundle_path(args: &Args) -> PathBuf {
    args.bundle.clone().unwrap_or_else(|| {
        let mut name = args.archive.clone().into_os_string();
        name.push(".bundle");
        PathBuf::from(name)
    })
}

/// Verify `archive` against `bundle` under the CLI release workflow at `tag`.
pub(crate) fn verify_release_files(archive: &Path, bundle: &Path, tag: &str) -> Result<()> {
    let asset = archive
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} does not name a file", archive.display()))?;
    let archive_bytes =
        std::fs::read(archive).with_context(|| format!("reading {}", archive.display()))?;
    let bundle_bytes = std::fs::read(bundle).with_context(|| {
        format!(
            "reading the signature bundle {} — an unsigned archive is not installable",
            bundle.display()
        )
    })?;
    let version = tag.strip_prefix('v').unwrap_or(tag);
    mvm_build::release_signature::verify_release_archive_bytes(
        &archive_bytes,
        &bundle_bytes,
        asset,
        &mvm_core::release_trust::accepted_release_identities(version),
        mvm_core::release_trust::RELEASE_OIDC_ISSUER,
    )
    .with_context(|| format!("{asset} is not signed by the {tag} release workflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: &str = "mvmctl-aarch64-apple-darwin.tar.gz";

    fn stage(bundle: Option<&[u8]>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(ARCHIVE);
        std::fs::write(&archive, b"archive").unwrap();
        if let Some(bundle) = bundle {
            std::fs::write(dir.path().join(format!("{ARCHIVE}.bundle")), bundle).unwrap();
        }
        (dir, archive)
    }

    #[test]
    fn the_bundle_defaults_to_the_published_name_beside_the_archive() {
        let args = Args {
            archive: PathBuf::from("/tmp/x/mvmctl-t.tar.gz"),
            bundle: None,
            tag: "v1.0.0".into(),
        };
        assert_eq!(
            bundle_path(&args),
            PathBuf::from("/tmp/x/mvmctl-t.tar.gz.bundle")
        );
    }

    #[test]
    fn a_missing_bundle_is_refused() {
        let (dir, archive) = stage(None);
        let bundle = dir.path().join(format!("{ARCHIVE}.bundle"));

        let err = verify_release_files(&archive, &bundle, "v9.9.9")
            .expect_err("an archive with no bundle must not verify");
        assert!(format!("{err:#}").contains("signature bundle"));
    }

    #[test]
    fn a_garbage_bundle_is_refused_and_names_the_asset() {
        let (dir, archive) = stage(Some(b"not a sigstore bundle"));
        let bundle = dir.path().join(format!("{ARCHIVE}.bundle"));

        let err = verify_release_files(&archive, &bundle, "v9.9.9")
            .expect_err("a bundle that does not parse must not verify");
        let msg = format!("{err:#}");
        assert!(msg.contains(ARCHIVE), "names the asset: {msg}");
        assert!(msg.contains("v9.9.9"), "names the release: {msg}");
    }

    /// Ignores `MVM_SKIP_COSIGN_VERIFY`, which `env update` honours: this
    /// command has no other job to fall back to.
    #[test]
    fn the_update_skip_variable_does_not_skip_verification() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let (dir, archive) = stage(Some(b"not a sigstore bundle"));
        let bundle = dir.path().join(format!("{ARCHIVE}.bundle"));

        verify_release_files(&archive, &bundle, "v9.9.9")
            .expect_err("the skip variable must not admit an unverified archive");
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn a_real_release_bundle_verifies_only_under_its_own_tag() {
        let asset = "builder-vm-aarch64-checksums-sha256.txt";
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");
        let archive = dir.join(asset);
        let bundle = dir.join(format!("{asset}.bundle"));

        verify_release_files(&archive, &bundle, "v0.18.0-rc.1")
            .expect("the release workflow's own signature must verify");
        verify_release_files(&archive, &bundle, "v0.18.0")
            .expect_err("another release's workflow must not be accepted");
    }
}
