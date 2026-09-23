//! Staging helpers for consuming a pair-built image-set entry.
//!
//! Pair cache entries name their files the way the image repository's
//! manifest emitter names them (`<role>-<arch>-<contract-name>`), while the
//! installers below them read a fixed layout. Staging hardlinks the contract
//! files under their canonical names so both sides stay decoupled: the
//! producer owns its naming, the installers keep their layout.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_build::image_source::CachedImageSet;

/// A staging directory holding `entry`'s contract files under their
/// canonical names, for installers that read a fixed layout (the SDK sidecar
/// installer). Removed on drop; hardlinks, not copies.
pub fn staged_contract_files(
    entry: &CachedImageSet,
    files: &[(&str, &str)],
) -> Result<tempfile::TempDir> {
    let parent = Path::new(&mvm_core::config::mvm_cache_dir()).join("local-image-builds");
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix("contract-")
        .tempdir_in(&parent)
        .with_context(|| format!("creating a staging directory in {}", parent.display()))?;
    mvm_build::image_source::stage_contract_files(entry, files, tmp.path())?;
    Ok(tmp)
}

/// The overlay artifact from a pair entry: contract files staged under
/// their canonical names in a temp directory that lives as long as the
/// returned value, read through the fixed-layout reader.
pub fn staged_overlay_artifact(
    entry: &CachedImageSet,
    arch: mvm_core::arch::GuestArch,
) -> Result<(tempfile::TempDir, mvm_fs::overlay::RuntimeOverlayArtifact)> {
    let parent = Path::new(&mvm_core::config::mvm_cache_dir()).join("local-image-builds");
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix("overlay-")
        .tempdir_in(&parent)
        .with_context(|| format!("creating a staging directory in {}", parent.display()))?;
    mvm_build::image_source::stage_overlay_contract_files(entry, tmp.path())?;
    let artifact = mvm_fs::overlay::read_overlay_artifact_from_dir(tmp.path(), &arch.to_string())?;
    Ok((tmp, artifact))
}
