//! `xtask image-source-ref [--manifest <image-set.json>]`
//!
//! Print the `mvm-images` commit that produced the image set
//! `crates/mvm-core/images.lock` pins.
//!
//! Some CI lanes build from an `mvm-images` checkout rather than fetching the
//! published images: the documented-surface lanes build the source-matched SDK
//! sidecar through its recipe, and the merge queue's guest-image witness builds
//! the default tenant and runtime overlay with the `mvm` input overridden to the
//! tree under test. Those checkouts used to track `mvm-images` `main`, so a
//! change landing in the other repository could fail this one's release after
//! it was tagged. The ref has to be the one this tree is known to work with,
//! and the lock is the only place that knowledge lives.
//!
//! The lock pins a release tag and the root manifest's digest. The commit comes
//! from that manifest's `producer.source_commit`, read only after the bytes
//! hash to the pinned digest and `check_against_lock` accepts them, so it is a
//! derivation of the pin rather than a second copy of it — and, unlike the tag,
//! it cannot be moved after the fact.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use mvm_core::image_set::{GitCommit, ImageSetManifest, ImageTrainLock, check_against_lock};
use mvm_core::packs::Sha256Hex;

const LOCK_FILE: &str = "crates/mvm-core/images.lock";
const USAGE: &str = "usage: image-source-ref [--manifest <image-set.json>]";

pub(crate) fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let lock_path = workspace.join(LOCK_FILE);
    let lock_text = fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock = parse_lock(&lock_text)?;
    let manifest = match args {
        [] => download_manifest(&lock)?,
        [flag, path] if flag == "--manifest" => {
            fs::read(path).with_context(|| format!("reading {path}"))?
        }
        _ => bail!(USAGE),
    };
    println!("{}", source_commit(&lock, &manifest)?);
    Ok(())
}

fn parse_lock(text: &str) -> Result<ImageTrainLock> {
    ImageTrainLock::parse(text).with_context(|| format!("parsing {LOCK_FILE}"))
}

/// The commit that produced the root `manifest`, accepted only when those
/// bytes are the root `lock` pins.
pub(crate) fn source_commit(lock: &ImageTrainLock, manifest: &[u8]) -> Result<GitCommit> {
    let pinned = &lock.image_set;
    let digest = Sha256Hex::from_bytes(manifest);
    // Checked before parsing, so a manifest this tree was never pinned to is
    // refused for what it is rather than for whichever field it grew.
    if digest != pinned.manifest_sha256 {
        bail!(
            "{} hashes to {}, but {LOCK_FILE} pins {}; refusing to name a source commit \
             for an image set this tree does not pin",
            pinned.manifest_asset,
            digest.as_str(),
            pinned.manifest_sha256.as_str()
        );
    }
    let root: ImageSetManifest = serde_json::from_slice(manifest)
        .with_context(|| format!("{} is not an image-set manifest", pinned.manifest_asset))?;
    check_against_lock(&root, &digest, pinned)
        .with_context(|| format!("{} does not match {LOCK_FILE}", pinned.manifest_asset))?;
    let Some(release) = root.producer.release() else {
        bail!("the pinned root was not produced by a release, so it names no source commit");
    };
    Ok(release.source_commit.clone())
}

/// The pinned root, from the release the lock names.
fn download_manifest(lock: &ImageTrainLock) -> Result<Vec<u8>> {
    let url = lock.manifest_url();
    let output = Command::new("curl")
        .args(["-fsSL", "--retry", "3", &url])
        .output()
        .context("running curl")?;
    if !output.status.success() {
        bail!(
            "downloading {url} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repin_image_lock::fixtures::{SOURCE_COMMIT, checked_in_lock, next_root};
    use crate::repin_image_lock::repin;

    /// The checked-in lock, advanced to pin the fixture root.
    fn lock_pinning_next_root() -> ImageTrainLock {
        let text = repin(&checked_in_lock(), &next_root()).expect("the fixture root repins");
        parse_lock(&text).expect("the repinned lock parses")
    }

    fn refusal(lock: &ImageTrainLock, manifest: &[u8]) -> String {
        format!(
            "{:#}",
            source_commit(lock, manifest).expect_err("must refuse")
        )
    }

    #[test]
    fn the_pinned_root_yields_its_producer_commit() {
        let commit = source_commit(&lock_pinning_next_root(), &next_root()).expect("resolves");

        assert_eq!(commit.as_str(), SOURCE_COMMIT);
    }

    #[test]
    fn a_root_the_lock_does_not_pin_is_refused_by_digest() {
        let lock = lock_pinning_next_root();
        let mut other: serde_json::Value = serde_json::from_slice(&next_root()).unwrap();
        other["producer"]["source_commit"] = "f".repeat(40).into();
        let other = serde_json::to_vec(&other).unwrap();

        let error = refusal(&lock, &other);

        assert!(error.contains("does not pin"), "{error}");
    }

    /// A lock whose digest matches but whose own fields disagree with the bytes
    /// it pins names a release the commit did not produce.
    #[test]
    fn a_lock_naming_another_release_than_its_root_is_refused() {
        let text = repin(&checked_in_lock(), &next_root())
            .unwrap()
            .replace("image-set/v0.2.0", "image-set/v0.3.0");
        let lock = parse_lock(&text).expect("still a well-formed lock");

        let error = refusal(&lock, &next_root());

        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn a_malformed_lock_is_refused() {
        for text in [
            "not = [toml".to_string(),
            checked_in_lock().replace("[image_set]", "[image_set_renamed]"),
        ] {
            let error = format!("{:#}", parse_lock(&text).expect_err("must refuse"));
            assert!(error.contains(LOCK_FILE), "{error}");
        }
    }

    #[test]
    fn bytes_that_hash_right_but_are_not_a_manifest_are_refused() {
        let text = checked_in_lock().replace(
            checked_in_lock_digest().as_str(),
            Sha256Hex::from_bytes(b"{}").as_str(),
        );
        let lock = parse_lock(&text).unwrap();

        let error = refusal(&lock, b"{}");

        assert!(error.contains("is not an image-set manifest"), "{error}");
    }

    #[test]
    fn unknown_arguments_are_refused_with_the_usage() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let error =
            run(&workspace, &["--role".into(), "boot_image".into()]).expect_err("must refuse");

        assert!(format!("{error:#}").contains(USAGE));
    }

    fn checked_in_lock_digest() -> Sha256Hex {
        parse_lock(&checked_in_lock())
            .unwrap()
            .image_set
            .manifest_sha256
    }
}
