//! Atomic sidecar publication for audit-derived state.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};

use super::atomic_sync::{AtomicSyncState, atomic_sync_is_batched, defer_atomic_sync, sync_path};

/// Atomically replace `path` without waiting for stable storage.
///
/// The rename still guarantees that readers observe either the complete old
/// file or the complete new file. Use this only for state reconstructible from
/// data that is already durable.
pub(crate) fn write_atomic_unsynced(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_inner(path, bytes, false, None)
}

/// Atomically replace `path` and make the new file data durable before return.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_inner(path, bytes, true, None)
}

/// Atomically replace `path`, joining its stable-storage wait to `state` when
/// the caller has an active durability batch.
pub(crate) fn write_atomic_batched(
    path: &Path,
    bytes: &[u8],
    state: &AtomicSyncState,
) -> Result<()> {
    write_atomic_inner(path, bytes, true, Some(state))
}

fn write_atomic_inner(
    path: &Path,
    bytes: &[u8],
    sync: bool,
    state: Option<&AtomicSyncState>,
) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path {} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("path {} has no file name", path.display()))?;
    let temporary = dir.join(format!(".{file_name}.tmp.{}", std::process::id()));

    // Best-effort: if any step before the rename fails, do not leave the
    // partial temporary file behind.
    let batched_sync = sync && state.is_some_and(atomic_sync_is_batched);
    let write = (|| -> Result<()> {
        let mut file = std::fs::File::create(&temporary)
            .with_context(|| format!("creating temp file {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("writing temp file {}", temporary.display()))?;
        if sync && !batched_sync {
            // The subsequent rename publishes the directory entry; syncing
            // file data here preserves the bytes and size needed to read it.
            file.sync_data()
                .with_context(|| format!("fdatasync temp file {}", temporary.display()))?;
        }
        Ok(())
    })();
    if let Err(error) = write {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow::Error::from(error))
            .with_context(|| format!("renaming {} to {}", temporary.display(), path.display()));
    }
    if batched_sync && !state.is_some_and(|state| defer_atomic_sync(state, path)) {
        sync_path(path).with_context(|| format!("fdatasync file {}", path.display()))?;
    }
    Ok(())
}
