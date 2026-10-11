//! What a capture is admitted to write, decided before it starts.
//!
//! A store that carries key custody seals every capture: the domain's keys
//! and the private staging area are admitted here, before a VM is paused or a
//! byte is cloned, so a missing or unreadable key refuses the capture instead
//! of leaving machine state on disk in the clear. A store opened without
//! custody writes the legacy unprotected layout, and says so in the record.
//!
//! The restore side lives here too: opening a protected checkpoint's blobs
//! into a destination its caller owns, and restoring from private staging.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::checkpoint::{
    CheckpointKeyDomain, CheckpointMeta, CheckpointProtection, ContentBlob,
};
use mvm_core::crypto::checkpoint_object::DomainKeys;

use super::{
    CheckpointStore, SUPERVISOR_CONFIG_FILE_NAME, VmFullRestore, chunks,
    materialize_checkpoint_manifest, sealed, staging,
};

/// The admitted protection for one capture.
pub(super) enum CaptureProtection {
    /// The legacy plaintext layout, for a store opened without custody.
    Unprotected,
    /// Seal everything under these keys.
    Sealed(DomainKeys),
}

impl CaptureProtection {
    /// Admit keys and staging for a capture into `domain`. Runs before the
    /// capture touches the VM or stages anything.
    pub(super) fn admit(store: &CheckpointStore, domain: &CheckpointKeyDomain) -> Result<Self> {
        let protection = match store.custody() {
            None => Self::Unprotected,
            Some(custody) => Self::Sealed(
                custody
                    .domain_keys(domain)
                    .context("admitting the checkpoint key before capture")?,
            ),
        };
        staging::admit_private_staging(store)?;
        Ok(protection)
    }

    /// The protection the record states.
    pub(super) fn kind(&self) -> CheckpointProtection {
        match self {
            Self::Unprotected => CheckpointProtection::Unprotected,
            Self::Sealed(_) => CheckpointProtection::SealedV1,
        }
    }

    /// Store a large blob in chunks. Unprotected, the source stays for the
    /// caller to remove once it has served any mirror; sealed, it is removed
    /// as soon as its chunks and index are durable.
    pub(super) fn store_chunked(
        &self,
        store: &CheckpointStore,
        domain: &CheckpointKeyDomain,
        content_dir: &Path,
        name: &str,
        source: &Path,
        retain_digest: bool,
    ) -> Result<ContentBlob> {
        match self {
            Self::Unprotected => {
                let pool = chunks::ObjectPool::new(store.root(), domain)?;
                chunks::chunk_blob(&pool, content_dir, name, source, retain_digest)
            }
            Self::Sealed(keys) => sealed::Sealer::new(store.root(), keys)?.seal_file(
                content_dir,
                name,
                source,
                retain_digest,
            ),
        }
    }

    /// Bring every blob the capture recorded to its at-rest form. Unprotected
    /// content is already there. Sealed, each blob still held as a plaintext
    /// file is checked against the digest the capture recorded for it, sealed,
    /// and removed; then the content dir must hold nothing else.
    pub(super) fn finish(
        &self,
        store: &CheckpointStore,
        content_dir: &Path,
        content: Vec<ContentBlob>,
    ) -> Result<Vec<ContentBlob>> {
        let Self::Sealed(keys) = self else {
            return Ok(content);
        };
        let sealer = sealed::Sealer::new(store.root(), keys)?;
        let content = content
            .into_iter()
            .map(|blob| seal_whole_blob(&sealer, content_dir, blob))
            .collect::<Result<Vec<_>>>()?;
        sealed::ensure_only_sealed(content_dir, &content)?;
        Ok(content)
    }
}

fn seal_whole_blob(
    sealer: &sealed::Sealer<'_>,
    content_dir: &Path,
    blob: ContentBlob,
) -> Result<ContentBlob> {
    if sealed::index_path(content_dir, &blob.name).is_file() {
        return Ok(blob);
    }
    chunks::validate_blob_name(&blob.name)?;
    let path = content_dir.join(&blob.name);
    let actual = super::sha256_file_hex(&path)?;
    anyhow::ensure!(
        actual == blob.sha256,
        "checkpoint blob {:?} changed between capture and sealing: recorded {}, found {actual}",
        blob.name,
        blob.sha256
    );
    sealer.seal_file(content_dir, &blob.name, &path, true)
}

/// Remove a capture's plaintext source if sealing has not already done so.
pub(super) fn remove_source(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("removing chunked source {}", path.display()))
        }
    }
}

/// Open every blob of a protected checkpoint into `destination_dir`, which
/// the caller owns, replacing anything already there under a blob's name.
pub(super) fn open_all_blobs(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    keys: &DomainKeys,
    destination_dir: &Path,
) -> Result<Vec<ContentBlob>> {
    let content_dir = store.content_dir(&meta.id);
    mvm_core::config::create_private_dir(destination_dir).with_context(|| {
        format!(
            "creating checkpoint materialization directory {}",
            destination_dir.display()
        )
    })?;
    meta.content
        .iter()
        .map(|blob| {
            let destination = destination_dir.join(&blob.name);
            remove_source(&destination)?;
            let sha256 = sealed::materialize_blob(keys, &content_dir, blob, &destination)
                .with_context(|| {
                    format!(
                        "opening protected checkpoint '{}' blob {:?}",
                        meta.id, blob.name
                    )
                })?;
            Ok(ContentBlob {
                name: blob.name.clone(),
                sha256,
            })
        })
        .collect()
}

/// Drop the sealed indexes and object links a snapshot mirror copied beside
/// the plaintext it now holds; they are opaque, and no longer needed there.
pub(super) fn remove_mirrored_sealed_content(
    meta: &CheckpointMeta,
    destination_dir: &Path,
) -> Result<()> {
    for blob in &meta.content {
        remove_source(&sealed::index_path(destination_dir, &blob.name))?;
    }
    let membership = destination_dir.join(chunks::MEMBERSHIP_DIR);
    match std::fs::remove_dir_all(&membership) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", membership.display())),
    }
}

/// Restore a protected checkpoint from plaintext opened into `scratch`, a
/// private directory the restore owns and removes when it returns.
pub(super) fn restore_protected(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    target_vm: &str,
    restore: &dyn VmFullRestore,
    scratch: &Path,
) -> Result<()> {
    let content = materialize_checkpoint_manifest(store, meta, scratch)?;
    let stored_config = scratch.join(SUPERVISOR_CONFIG_FILE_NAME);
    let config_src = stored_config.is_file().then_some(stored_config.as_path());
    restore.restore(
        target_vm,
        &scratch.join(mvm_core::checkpoint::ROOTFS_BLOB),
        &scratch.join(mvm_core::checkpoint::MEMORY_BLOB),
        &scratch.join("machine-id"),
        config_src,
        &content,
    )
}
