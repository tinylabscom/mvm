//! Atomic file I/O and file-based locking utilities.
//!
//! Prevents partial writes (crash-safe) and concurrent mutation of state files.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use fs2::FileExt;

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, flush + sync, then rename into place.
///
/// On crash or power loss, the file either has the old content or the new
/// content — never a partial write.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create parent dir: {}", parent.display()))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file in {}", parent.display()))?;

    tmp.write_all(data)
        .with_context(|| format!("failed to write temp file for {}", path.display()))?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;

    tmp.persist(path)
        .with_context(|| format!("failed to persist temp file to {}", path.display()))?;

    Ok(())
}

/// Write a string to `path` atomically.
pub fn atomic_write_str(path: &Path, content: &str) -> Result<()> {
    atomic_write(path, content.as_bytes())
}

/// RAII file lock using `flock(2)`.
///
/// Acquires an exclusive lock on a `.lock` file adjacent to the target path.
/// The lock is released when the guard is dropped.
pub struct FileLock {
    _file: fs::File,
}

impl FileLock {
    /// Acquire an exclusive lock for operations on `path`.
    ///
    /// Creates `<path>.lock` if it doesn't exist, then acquires an exclusive
    /// flock. Blocks until the lock is available.
    pub fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file: {}", lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("failed to acquire lock: {}", lock_path.display()))?;
        Ok(Self { _file: file })
    }

    /// Try to acquire the lock without blocking.
    ///
    /// Returns `None` if another process holds the lock.
    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file: {}", lock_path.display()))?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("failed to try lock: {}", lock_path.display()))
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // flock is released when the file descriptor is closed (automatic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        atomic_write(&path, b"hello world").expect("write");
        let content = fs::read_to_string(&path).expect("read");
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(&path, b"old content").expect("seed");
        atomic_write(&path, b"new content").expect("write");
        let content = fs::read_to_string(&path).expect("read");
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_atomic_write_creates_parent_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a/b/c/state.json");
        atomic_write(&path, b"nested").expect("write");
        let content = fs::read_to_string(&path).expect("read");
        assert_eq!(content, "nested");
    }

    #[test]
    fn test_atomic_write_str() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.txt");
        atomic_write_str(&path, "hello").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "hello");
    }

    #[test]
    fn test_file_lock_acquire_and_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(&path, b"data").expect("seed");

        {
            let _lock = FileLock::acquire(&path).expect("lock");
            // Lock file should exist
            assert!(dir.path().join("state.lock").exists());
        }
        // Lock released on drop — should be acquirable again
        let _lock2 = FileLock::acquire(&path).expect("lock again");
    }

    #[test]
    fn test_file_lock_try_acquire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");

        let lock1 = FileLock::try_acquire(&path)
            .expect("try_acquire")
            .expect("got lock");
        // Second try should return None (lock is held)
        let lock2 = FileLock::try_acquire(&path).expect("try_acquire");
        assert!(lock2.is_none(), "should not get lock while held");

        drop(lock1);
        // Now should succeed
        let lock3 = FileLock::try_acquire(&path)
            .expect("try_acquire")
            .expect("got lock after drop");
        drop(lock3);
    }

    #[test]
    fn test_file_lock_nonexistent_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path: PathBuf = dir.path().join("sub/dir/state.json");
        let _lock = FileLock::acquire(&path).expect("lock with nested path");
    }
}
