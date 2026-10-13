//! Materialization of authenticated checkpoint blobs into caller-owned files.

use super::{CheckpointMeta, CheckpointStore, ContentBlob, chunks, sealed};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) fn clone_or_materialize_blob(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    blob: &ContentBlob,
    destination: &Path,
) -> Result<()> {
    let content_dir = store.content_dir(&meta.id);
    chunks::validate_blob_name(&blob.name)?;
    if chunks::is_chunked_blob(&content_dir, blob) {
        chunks::materialize_blob_cached(
            store.root(),
            &meta.key_domain,
            &content_dir,
            blob,
            destination,
        )
        .map(|_| ())
        .with_context(|| format!("materializing checkpoint blob {}", blob.name))
    } else {
        crate::base::cow::clone_rootfs_for_instance(&content_dir.join(&blob.name), destination)
            .map(|_| ())
            .with_context(|| format!("cloning checkpoint blob {}", blob.name))
    }
}

/// Rebuild a chunked blob as one contiguous file in caller-owned scratch.
pub fn materialized_source(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    name: &str,
    scratch: &Path,
) -> Result<PathBuf> {
    let content_dir = store.content_dir(&meta.id);
    let blob = meta
        .content
        .iter()
        .find(|blob| blob.name == name)
        .with_context(|| format!("checkpoint '{}' has no {name} blob", meta.id))?;
    let destination = scratch.join(name);
    if let Some(keys) = store.keys_for(meta)? {
        sealed::materialize_blob(&keys, &content_dir, blob, &destination)
            .with_context(|| format!("opening protected checkpoint blob {name}"))?;
        return Ok(destination);
    }
    chunks::ensure_chunked_layout(&content_dir, meta)?;
    chunks::materialize_blob_cached(
        store.root(),
        &meta.key_domain,
        &content_dir,
        blob,
        &destination,
    )
    .map(|_| ())
    .with_context(|| format!("materializing checkpoint blob {name}"))?;
    Ok(destination)
}
