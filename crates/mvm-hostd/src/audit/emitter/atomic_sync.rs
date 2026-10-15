use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;

/// Atomic publications made inside one admission durability boundary.
#[derive(Debug, Default)]
pub(crate) struct AtomicSyncState {
    paths: Mutex<Option<HashSet<PathBuf>>>,
}

pub(super) struct AtomicSyncBatch {
    state: Arc<AtomicSyncState>,
    finished: bool,
}

impl AtomicSyncBatch {
    pub(super) fn begin(state: Arc<AtomicSyncState>) -> Result<Self> {
        let mut paths = state.paths.lock().expect("atomic sync state poisoned");
        if paths.is_some() {
            anyhow::bail!("nested atomic durability batches are not supported");
        }
        *paths = Some(HashSet::new());
        drop(paths);
        Ok(Self {
            state,
            finished: false,
        })
    }

    /// Close the batch and hand back every path it owes a sync, including the
    /// atomic publications it deferred. The caller owns the sync from here.
    pub(super) fn close(mut self, mut paths: Vec<PathBuf>) -> PendingSync {
        paths.extend(take_atomic_sync_batch(&self.state));
        self.finished = true;
        PendingSync {
            paths,
            synced: false,
        }
    }
}

impl Drop for AtomicSyncBatch {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        PendingSync {
            paths: take_atomic_sync_batch(&self.state),
            synced: false,
        }
        .sync_best_effort();
    }
}

/// Files a closed batch has written to and not yet synced.
///
/// Dropping one without [`sync`](Self::sync) or [`detach`](Self::detach)
/// still syncs it, best-effort: the records were written and something may
/// already have been told they exist.
pub(crate) struct PendingSync {
    paths: Vec<PathBuf>,
    synced: bool,
}

impl PendingSync {
    /// Sync every file now, concurrently, and report the first failure.
    pub(crate) fn sync(mut self) -> Result<()> {
        self.synced = true;
        sync_paths_concurrently(std::mem::take(&mut self.paths))
    }

    /// Start the sync on its own thread and return the handle that waits for
    /// it. If the thread cannot be spawned the sync runs inline, so the handle
    /// is never one whose sync silently did not happen.
    pub(crate) fn detach(mut self) -> mvm_core::admission_durability::AdmissionDurability {
        use mvm_core::admission_durability::AdmissionDurability;
        self.synced = true;
        let paths = std::mem::take(&mut self.paths);
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(paths)));
        let for_worker = std::sync::Arc::clone(&shared);
        let take = |slot: &std::sync::Mutex<Option<Vec<PathBuf>>>| {
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_default()
        };
        match AdmissionDurability::spawn(move || sync_paths_concurrently(take(&for_worker))) {
            Ok(durability) => durability,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "could not start the audit sync thread; syncing inline"
                );
                AdmissionDurability::settled(sync_paths_concurrently(take(&shared)))
            }
        }
    }

    fn sync_best_effort(&mut self) {
        self.synced = true;
        for path in std::mem::take(&mut self.paths) {
            if let Err(error) = sync_path(&path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "flushing an interrupted atomic durability batch failed"
                );
            }
        }
    }
}

impl Drop for PendingSync {
    fn drop(&mut self) {
        if !self.synced {
            self.sync_best_effort();
        }
    }
}

fn take_atomic_sync_batch(state: &AtomicSyncState) -> Vec<PathBuf> {
    state
        .paths
        .lock()
        .expect("atomic sync state poisoned")
        .take()
        .unwrap_or_default()
        .into_iter()
        .collect()
}

pub(super) fn atomic_sync_is_batched(state: &AtomicSyncState) -> bool {
    state
        .paths
        .lock()
        .expect("atomic sync state poisoned")
        .is_some()
}

pub(super) fn defer_atomic_sync(state: &AtomicSyncState, path: &Path) -> bool {
    let mut batch = state.paths.lock().expect("atomic sync state poisoned");
    let Some(paths) = batch.as_mut() else {
        return false;
    };
    paths.insert(path.to_path_buf());
    true
}

#[cfg(test)]
pub(super) fn deferred_path_count(state: &AtomicSyncState) -> usize {
    state
        .paths
        .lock()
        .expect("atomic sync state poisoned")
        .as_ref()
        .map_or(0, HashSet::len)
}

pub(super) fn sync_path(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)?
        .sync_data()
}

fn sync_paths_concurrently(paths: Vec<PathBuf>) -> Result<()> {
    let paths: HashSet<PathBuf> = paths.into_iter().collect();
    let results = std::thread::scope(|scope| {
        paths
            .into_iter()
            .map(|path| scope.spawn(move || sync_path(&path).map_err(|error| (path, error))))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("durability worker panicked"))?
                    .map_err(|(path, error)| {
                        anyhow::anyhow!("fdatasync {}: {error}", path.display())
                    })
            })
            .collect::<Result<Vec<_>>>()
    });
    results.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(paths: Vec<PathBuf>) -> PendingSync {
        PendingSync {
            paths,
            synced: false,
        }
    }

    #[test]
    fn a_detached_sync_reports_success_through_its_handle() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("chain.jsonl");
        std::fs::write(&file, b"entry\n").unwrap();
        pending(vec![file]).detach().wait().expect("synced");
    }

    #[test]
    fn a_detached_sync_that_fails_is_reported_to_the_waiter() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone.jsonl");
        let error = pending(vec![missing.clone()])
            .detach()
            .wait()
            .expect_err("a file that cannot be synced is not durable");
        assert!(
            format!("{error:#}").contains(&missing.display().to_string()),
            "the failure names the file: {error:#}"
        );
    }
}
