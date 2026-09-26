//! Fork- and restore-time content helpers for vm_full checkpoints: the memory
//! digest a load-verifying backend needs, the fresh identity a fork mints, and
//! the dm-verity binding a clone must keep. Split out of the checkpoint module
//! root to keep that file under the file-size gate; the checkpoint module root
//! is their only caller.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointMeta, ContentBlob, DeviceAnchors};

use super::{chunks, sha256_file_hex};

/// Replace a forked child's cloned FlowMux identity drive with a freshly minted
/// one so the child never boots on the parent's signing key.
///
/// `materialize_checkpoint_blobs` clones every captured blob into the child's
/// state dir, including the identity drive when the checkpoint carried one. That
/// copy holds the *parent's* per-boot signing key; a fork is a new VM identity,
/// so it mints its own key pinned to the same host signer and writes it over the
/// clone. Checkpoints captured before the identity drive was content — and every
/// backend that attaches none — leave nothing to replace, and this is a no-op.
pub(super) fn reseed_forked_identity_drive(child_vm_name: &str, child_dir: &Path) -> Result<()> {
    let drive = child_dir.join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE);
    if !drive.is_file() {
        return Ok(());
    }
    mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial::mint_from_host_signer(child_vm_name)
        .context("minting a fresh FlowMux identity for the fork")?
        .write_drive(&drive)
        .with_context(|| {
            format!(
                "writing the fork's fresh identity drive to {}",
                drive.display()
            )
        })
}

/// Hand a load-verifying backend the whole-file digest of the memory blob.
///
/// A chunked blob's [`ContentBlob::sha256`] is its chunk-index content-address,
/// not the digest of the reassembled bytes. A backend that verifies the saved
/// RAM on load hashes the materialized file, so comparing that against the
/// index address always mismatches. The materialization already verified those
/// bytes against the chain-bound index, so substitute the whole-file digest of
/// the verified material for the memory blob; every other entry is untouched.
/// A whole (unchunked) memory blob already records its own digest and is left
/// alone.
pub(super) fn content_with_load_memory_digest(
    content: &[ContentBlob],
    content_dir: &Path,
    materialized_memory: &Path,
) -> Result<Vec<ContentBlob>> {
    content
        .iter()
        .map(|blob| {
            if blob.name == mvm_core::checkpoint::MEMORY_BLOB
                && chunks::is_chunked_blob(content_dir, blob)
            {
                Ok(ContentBlob {
                    name: blob.name.clone(),
                    sha256: sha256_file_hex(materialized_memory)?,
                })
            } else {
                Ok(blob.clone())
            }
        })
        .collect()
}

/// Ensure a cloned checkpoint keeps the complete dm-verity binding and the
/// device-path metadata needed to remap snapshot references to child files.
pub(super) fn validate_fork_verity_binding(
    parent: &CheckpointMeta,
    child_dir: &Path,
) -> Result<()> {
    let has_verity = parent
        .content
        .iter()
        .any(|blob| blob.name == "rootfs.verity");
    let has_roothash = parent
        .content
        .iter()
        .any(|blob| blob.name == "rootfs.roothash");
    anyhow::ensure!(
        has_verity == has_roothash,
        "checkpoint '{}' has an incomplete dm-verity sidecar set",
        parent.id
    );

    let anchors_path = child_dir.join("device-anchors.json");
    anyhow::ensure!(
        anchors_path.is_file(),
        "checkpoint '{}' is missing device-anchors.json",
        parent.id
    );
    let anchors: DeviceAnchors = serde_json::from_slice(
        &std::fs::read(&anchors_path)
            .with_context(|| format!("reading {}", anchors_path.display()))?,
    )
    .with_context(|| format!("parsing {}", anchors_path.display()))?;

    if has_verity {
        anyhow::ensure!(
            anchors.rootfs_verity.is_some()
                && child_dir.join("rootfs.verity").is_file()
                && child_dir.join("rootfs.roothash").is_file(),
            "checkpoint '{}' would drop its dm-verity binding during fork",
            parent.id
        );
    } else {
        anyhow::ensure!(
            anchors.rootfs_verity.is_none(),
            "checkpoint '{}' has a verity device anchor without sidecars",
            parent.id
        );
    }
    Ok(())
}
