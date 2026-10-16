use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use mvm_core::atomic_io::{self, FileLock};

use super::Record;
use super::environment::{Snapshot, private_file};

/// Held from before record read/claim until every cleanup action finishes.
/// The stable adjacent inode is never unlinked; process death releases flock.
pub(super) struct RecordLock {
    _lock: FileLock,
}

impl RecordLock {
    pub(super) fn acquire(snapshot: &Snapshot) -> Result<Self> {
        snapshot.revalidate()?;
        let lock_path = snapshot.record().with_extension("lock");
        atomic_io::write_private_new(&lock_path, b"")?;
        private_file(&lock_path)?;
        let lock = FileLock::try_acquire(snapshot.record())?
            .context("fixture record is exclusively owned")?;
        Ok(Self { _lock: lock })
    }

    pub(super) fn read(&self, path: &Path) -> Result<Record> {
        private_file(path)?;
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut bytes = Vec::new();
        File::from(descriptor)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 64 * 1024, "fixture record exceeds its bound");
        serde_json::from_slice(&bytes).context("decode locked fixture record")
    }
}
