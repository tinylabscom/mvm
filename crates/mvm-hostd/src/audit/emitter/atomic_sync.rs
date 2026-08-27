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
    fallback_paths: Vec<PathBuf>,
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
            fallback_paths: Vec::new(),
        })
    }

    pub(super) fn finish(mut self, mut paths: Vec<PathBuf>) -> Result<()> {
        paths.extend(take_atomic_sync_batch(&self.state));
        self.fallback_paths = paths.clone();
        sync_paths_concurrently(paths)?;
        self.fallback_paths.clear();
        self.finished = true;
        Ok(())
    }
}

impl Drop for AtomicSyncBatch {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.fallback_paths
            .extend(take_atomic_sync_batch(&self.state));
        for path in &self.fallback_paths {
            if let Err(error) = sync_path(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "flushing an interrupted atomic durability batch failed"
                );
            }
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
