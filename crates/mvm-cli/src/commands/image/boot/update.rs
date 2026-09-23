//! `mvmctl image boot update` — fetch, verify, then swap the cache entry.
//!
//! The ordering is the point. Every byte lands in a staging directory and is
//! held to the release's own signed checksum manifest there; the live entry is
//! not touched until the staged one has passed. A half-written boot image is
//! worse than no update path at all, because it fails at boot on a host that
//! was working a moment earlier.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::image_set::ImageTrainLock;

use super::cache::{self, AcquiredProvenance};
use crate::commands::env::builder_vm::default_microvm::DefaultMicrovmVariant;
use crate::ui;

/// Which image to install, and whether the source-checkout refusal applies.
pub(super) struct UpdateRequest {
    /// Pinned tag, or `None` to take the latest published.
    pub(super) tag: Option<String>,
    /// An explicitly selected older lock for a bounded rollback.
    pub(super) lock: Option<PathBuf>,
    /// Waive the source-checkout refusal.
    pub(super) force: bool,
}

/// Only the prod variant is published. The dev variant is built locally by
/// design — it carries an interactive shell no release should ship — so there
/// is nothing to fetch for it, and claiming otherwise would 404 at the first
/// asset.
const PUBLISHED_VARIANT: DefaultMicrovmVariant = DefaultMicrovmVariant::Prod;

pub(super) fn run(request: &UpdateRequest) -> Result<()> {
    refuse_in_source_checkout(request.force)?;
    let train = select_train(request.lock.as_deref())?;
    let tag = resolve_tag(request.tag.as_deref(), &train)?;
    let target = cache::variant_dir(PUBLISHED_VARIANT);

    ui::info(&format!("Updating boot image to {tag}..."));
    let staging = StagingDir::beside(&target)?;
    fetch_into(staging.path(), &tag, &train)?;
    cache::stamp_provenance(staging.path(), &AcquiredProvenance::fetched(&tag))?;
    staging.publish_over(&target)?;

    // Emitted only after the swap: the audit stream records what the host now
    // boots, not what it attempted. A refused update leaves no entry because
    // nothing changed.
    mvm_core::audit_emit!(
        ImageFetch,
        "source=image_boot_update tag={} variant={} dir={}",
        tag,
        PUBLISHED_VARIANT.cache_subdir(),
        target.display()
    );
    ui::success(&format!("Boot image updated to {tag}."));
    crate::commands::env::builder_vm::report_recorded_boot_tier("Boot image", &target);
    Ok(())
}

/// Where images are built from source, the working tree is authoritative:
/// replacing the locally built image with a prebuilt would make the tree a
/// lie about what the next boot runs.
fn refuse_in_source_checkout(force: bool) -> Result<()> {
    if force || !crate::commands::env::builder_vm::images_built_from_source() {
        return Ok(());
    }
    bail!(
        "refusing to replace the boot image from a source checkout: the local build is \
         authoritative here, and a prebuilt would silently disagree with the working tree. \
         Pass --force if that is what you want."
    )
}

fn resolve_tag(pinned: Option<&str>, train: &ImageTrainLock) -> Result<String> {
    let locked = train.image_set.release_tag.as_str();
    if let Some(tag) = pinned
        && tag != locked
    {
        bail!(
            "requested image set {tag} is not the build's locked image set {locked}; update images.lock through the pin-update workflow first"
        );
    }
    Ok(locked.to_string())
}

/// Download the curated workload from the signed root pinned by this build.
fn fetch_into(dir: &Path, tag: &str, train: &ImageTrainLock) -> Result<()> {
    let locked = train.image_set.release_tag.as_str();
    if tag != locked {
        bail!("refusing unlocked image set {tag}; this build pins {locked}");
    }
    let arch = mvm_core::arch::GuestArch::host();
    crate::commands::env::published_image_set::PublishedImageSet::acquire_with_train(train)?
        .fetch_default_workload(arch, dir)
}

/// Select the compiled lock, or validate an explicit older lock against the
/// same canonical producer trust root. The lock carries an exact signed-root
/// digest, so rollback never means accepting a mutable tag or rebuilding the
/// binary.
fn select_train(path: Option<&Path>) -> Result<ImageTrainLock> {
    let current = mvm_core::image_set::image_train_lock();
    let Some(path) = path else {
        return Ok(current.clone());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read rollback image lock {}", path.display()))?;
    let candidate = ImageTrainLock::parse(&text)
        .with_context(|| format!("parse rollback image lock {}", path.display()))?;
    validate_rollback_lock(current, &candidate)?;
    Ok(candidate)
}

fn validate_rollback_lock(current: &ImageTrainLock, candidate: &ImageTrainLock) -> Result<()> {
    if candidate.repository != current.repository
        || candidate.image_set.signing_identity.workflow
            != current.image_set.signing_identity.workflow
    {
        bail!(
            "rollback lock changes the canonical image producer or workflow; only an older signed set from {} {} is accepted",
            current.repository,
            current.image_set.signing_identity.workflow
        );
    }
    let current_namespace = current
        .image_set
        .release_tag
        .as_str()
        .strip_suffix(current.image_set.release_tag.version().as_str())
        .expect("a validated release tag ends with its parsed version");
    let candidate_namespace = candidate
        .image_set
        .release_tag
        .as_str()
        .strip_suffix(candidate.image_set.release_tag.version().as_str())
        .expect("a validated release tag ends with its parsed version");
    if candidate_namespace != current_namespace {
        bail!(
            "rollback lock changes the image release namespace from {current_namespace} to {candidate_namespace}"
        );
    }
    match candidate
        .image_set
        .release_tag
        .version()
        .cmp_precedence(current.image_set.release_tag.version())
    {
        std::cmp::Ordering::Less => Ok(()),
        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => bail!(
            "rollback lock selects {}, which is not older than this build's {}",
            candidate.image_set.release_tag,
            current.image_set.release_tag
        ),
    }
}

/// A scratch directory beside the live entry, removed on drop unless it was
/// published.
///
/// Beside rather than in `/tmp` so the final move is a rename within one
/// filesystem: a cross-device copy would reintroduce exactly the partial-write
/// window the staging directory exists to close.
struct StagingDir {
    path: PathBuf,
    published: bool,
}

impl StagingDir {
    fn beside(target: &Path) -> Result<Self> {
        let parent = target
            .parent()
            .with_context(|| format!("{} has no parent directory", target.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create the cache root {}", parent.display()))?;
        let path = parent.join(format!(
            ".{}.staging.{}",
            target
                .file_name()
                .map_or_else(|| "boot-image".into(), |n| n.to_string_lossy()),
            std::process::id()
        ));
        // A staging dir left by a killed run must not contribute bytes to this
        // one; the hash gate would catch a corrupt file but not a stale extra.
        remove_dir_if_present(&path)?;
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create the staging directory {}", path.display()))?;
        Ok(Self {
            path,
            published: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Swap the staged entry in, keeping the previous one until the swap has
    /// completed. If the second rename fails the previous entry is put back,
    /// so the failure mode is "no update" rather than "no image".
    fn publish_over(mut self, target: &Path) -> Result<()> {
        let previous = target.with_extension(format!("previous.{}", std::process::id()));
        remove_dir_if_present(&previous)?;
        let had_previous = target.exists();
        if had_previous {
            std::fs::rename(target, &previous).with_context(|| {
                format!("move the existing boot image {} aside", target.display())
            })?;
        }
        match std::fs::rename(&self.path, target) {
            Ok(()) => {
                self.published = true;
                remove_dir_if_present(&previous)?;
                Ok(())
            }
            Err(error) => {
                if had_previous {
                    std::fs::rename(&previous, target).with_context(|| {
                        format!(
                            "restore the previous boot image to {} after a failed swap",
                            target.display()
                        )
                    })?;
                }
                Err(error).with_context(|| {
                    format!("install the staged boot image at {}", target.display())
                })
            }
        }
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn remove_dir_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove the directory {}", path.display()))
        }
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;
    use mvm_core::image_set::{ReleaseTag, RepositorySlug, TagRef};

    fn older_lock_file() -> tempfile::NamedTempFile {
        let mut candidate = mvm_core::image_set::image_train_lock().clone();
        let tag = ReleaseTag::new("image-set/v0.0.9").expect("valid older tag");
        candidate.image_set.release_tag = tag.clone();
        candidate.boot_image.release_tag = tag.clone();
        candidate.stage0_kernel.release_tag = tag;
        candidate.image_set.signing_identity.tag_ref =
            TagRef::new("refs/tags/image-set/v0.0.9").expect("valid older ref");
        let file = tempfile::NamedTempFile::new().expect("create rollback lock");
        std::fs::write(
            file.path(),
            toml::to_string(&candidate).expect("serialize rollback lock"),
        )
        .expect("write rollback lock");
        file
    }

    #[test]
    fn an_older_lock_from_the_same_canonical_producer_is_accepted() {
        let file = older_lock_file();
        let selected = select_train(Some(file.path())).expect("select older signed pin");
        assert_eq!(selected.image_set.release_tag.as_str(), "image-set/v0.0.9");
    }

    #[test]
    fn rollback_cannot_replace_the_canonical_trust_root() {
        let file = older_lock_file();
        let text = std::fs::read_to_string(file.path()).expect("read rollback lock");
        let mut candidate = ImageTrainLock::parse(&text).expect("parse rollback lock");
        candidate.repository = RepositorySlug::new("attacker/images").expect("valid slug");
        candidate.image_set.repository = candidate.repository.clone();
        std::fs::write(
            file.path(),
            toml::to_string(&candidate).expect("serialize changed lock"),
        )
        .expect("write changed lock");

        let error = select_train(Some(file.path())).expect_err("trust-root drift must fail");
        assert!(
            error.to_string().contains("canonical image producer"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn rollback_requires_a_strictly_older_version() {
        let current = mvm_core::image_set::image_train_lock();
        let error = validate_rollback_lock(current, current).expect_err("same pin is not rollback");
        assert!(
            error.to_string().contains("not older"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn rollback_cannot_switch_to_another_tag_namespace() {
        let current = mvm_core::image_set::image_train_lock();
        let mut candidate = current.clone();
        let tag = ReleaseTag::new("other-train/v0.0.9").expect("valid other tag");
        candidate.image_set.release_tag = tag.clone();
        candidate.boot_image.release_tag = tag.clone();
        candidate.stage0_kernel.release_tag = tag;
        candidate.image_set.signing_identity.tag_ref =
            TagRef::new("refs/tags/other-train/v0.0.9").expect("valid other ref");
        let error = validate_rollback_lock(current, &candidate)
            .expect_err("another signed namespace is not this train");
        assert!(
            error.to_string().contains("release namespace"),
            "unexpected error: {error:#}"
        );
    }
}
