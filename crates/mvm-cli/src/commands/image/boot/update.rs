//! `mvmctl image boot update` — fetch, verify, then swap the cache entry.
//!
//! The ordering is the point. Every byte lands in a staging directory and is
//! held to the release's own signed checksum manifest there; the live entry is
//! not touched until the staged one has passed. A half-written boot image is
//! worse than no update path at all, because it fails at boot on a host that
//! was working a moment earlier.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::cache::{self, AcquiredProvenance};
use crate::commands::env::builder_vm::default_microvm::DefaultMicrovmVariant;
use crate::ui;

/// Which image to install, and whether the source-checkout refusal applies.
pub(super) struct UpdateRequest {
    /// Pinned tag, or `None` to take the latest published.
    pub(super) tag: Option<String>,
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
    let tag = resolve_tag(request.tag.as_deref())?;
    let target = cache::variant_dir(PUBLISHED_VARIANT);

    ui::info(&format!("Updating boot image to {tag}..."));
    let staging = StagingDir::beside(&target)?;
    fetch_into(staging.path(), &tag)?;
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

fn resolve_tag(pinned: Option<&str>) -> Result<String> {
    let locked = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str();
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
fn fetch_into(dir: &Path, tag: &str) -> Result<()> {
    let locked = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str();
    if tag != locked {
        bail!("refusing unlocked image set {tag}; this build pins {locked}");
    }
    let arch = mvm_core::arch::GuestArch::host();
    crate::commands::env::published_image_set::PublishedImageSet::acquire()?
        .fetch_default_workload(arch, dir)
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
