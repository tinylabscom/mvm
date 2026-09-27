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

/// Install one libc variant of the SDK sidecar from a pair entry into the
/// version-matched cache under `cache_root`, stamped with `fingerprint` (the
/// pair identity) so launches under this pair trust it.
///
/// The entry's files carry the producer's manifest names; the installer reads
/// the canonical `sdk.ext4` / `VERSION` / `checksums-sha256.txt` layout, so the
/// contract files are staged under those names first. Both the launch path and
/// `mvmctl build sdk-sidecar build` install through here.
pub fn install_pair_sidecar(
    entry: &CachedImageSet,
    fingerprint: &str,
    cache_root: &Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Result<mvm_fs::sdk_sidecar::SdkSidecarArtifact> {
    let role = mvm_core::image_set::ImageSetRole::SdkSidecar(libc).to_string();
    let staged = staged_contract_files(
        entry,
        &[
            (role.as_str(), mvm_fs::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE),
            (role.as_str(), mvm_fs::sdk_sidecar::SDK_SIDECAR_VERSION_FILE),
            (role.as_str(), mvm_fs::overlay::CHECKSUM_MANIFEST_FILE),
        ],
    )
    .with_context(|| {
        format!(
            "staging the {libc} SDK sidecar from the pair entry at {}",
            entry.dir.display()
        )
    })?;
    mvm_build::sdk_sidecar::install_source_built_sidecar(
        staged.path(),
        cache_root,
        version,
        arch,
        libc,
        fingerprint,
    )
    .with_context(|| {
        format!(
            "installing the {libc} SDK sidecar staged from {} into {}",
            entry.dir.display(),
            cache_root.display()
        )
    })
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
