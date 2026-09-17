//! Atomic file I/O and file-based locking utilities.
//!
//! Prevents partial writes (crash-safe) and concurrent mutation of state files.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, flush + sync, then rename into place.
///
/// On crash or power loss, the file either has the old content or the new
/// content — never a partial write.
///
/// The sync is `sync_data` (`fdatasync`), not `sync_all`. `fdatasync` still
/// flushes the metadata a later read needs to retrieve the data — the file's
/// size above all, which is the part that matters for a temp file this call
/// just created — and skips the rest. On rotational storage that is the
/// difference between one seek and two, and this is the shared write path
/// behind the audit chain, the receipt store, and every other record mvm
/// persists, so it is paid on the launch critical path.
///
/// The metadata `sync_all` additionally flushed was not buying a stronger
/// guarantee here in any case: this function never fsyncs the *parent
/// directory* after the rename, so the rename's own durability across a crash
/// is unguaranteed either way. Making that stronger means adding a directory
/// fsync, not keeping a more expensive file sync.
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
    tmp.as_file().sync_data()?;

    tmp.persist(path)
        .with_context(|| format!("failed to persist temp file to {}", path.display()))?;

    Ok(())
}

/// Write a string to `path` atomically.
pub fn atomic_write_str(path: &Path, content: &str) -> Result<()> {
    atomic_write(path, content.as_bytes())
}

/// Write `data` to `path`, but only if `path` does not already exist.
///
/// Same crash-safety as [`atomic_write`] — write to a temp file in the same
/// directory, flush, `fdatasync`, then move into place — except the final
/// step is a no-clobber move (`renameat2(..., RENAME_NOREPLACE)` on Linux,
/// its macOS equivalent, or a `link` + `unlink` fallback where neither is
/// available) instead of an unconditional rename.
///
/// Two writers racing to create the same path can no longer both "win": the
/// filesystem admits exactly one no-clobber move, and the loser gets back an
/// error whose chain carries a [`std::io::Error`] of kind
/// [`std::io::ErrorKind::AlreadyExists`] (test with [`is_already_exists`]).
/// The loser's own temp file is removed automatically — it was never linked
/// into the target directory under its final name.
pub fn atomic_write_new(path: &Path, data: &[u8]) -> Result<()> {
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
    tmp.as_file().sync_data()?;

    match tmp.persist_noclobber(path) {
        // The dropped `PersistError::file` here is the losing temp file;
        // `NamedTempFile`'s `Drop` deletes it, so a lost race leaves nothing
        // behind under the target directory.
        Ok(_) => Ok(()),
        Err(err) => {
            let kind = err.error.kind();
            Err(std::io::Error::new(
                kind,
                format!(
                    "failed to persist temp file to {}: {}",
                    path.display(),
                    err.error
                ),
            )
            .into())
        }
    }
}

/// Whether `err`'s cause chain carries an `AlreadyExists` I/O error — the
/// signal [`atomic_write_new`] raises when a concurrent writer already
/// claimed the path. `anyhow::Error::downcast_ref` walks the whole
/// `.context()` chain, not just the outermost frame, so this sees through
/// any context a caller layered on top.
pub fn is_already_exists(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::AlreadyExists)
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
        file.lock()
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
        // std distinguishes contention from a real error in the type, so
        // "another process holds it" no longer rides on an errno comparison.
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => {
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
    fn atomic_write_new_creates_an_absent_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        atomic_write_new(&path, b"first").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "first");
    }

    #[test]
    fn atomic_write_new_refuses_an_existing_file_and_leaves_it_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        atomic_write_new(&path, b"original").expect("first write");

        let err = atomic_write_new(&path, b"second writer loses").expect_err("refused");
        assert!(is_already_exists(&err), "expected AlreadyExists: {err:#}");

        // The loser must not have clobbered the winner's content.
        assert_eq!(fs::read_to_string(&path).expect("read"), "original");
    }

    #[test]
    fn atomic_write_new_leaves_no_temp_file_behind_on_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        atomic_write_new(&path, b"original").expect("first write");

        atomic_write_new(&path, b"loses").expect_err("refused");

        // Only the target file remains in the directory — the losing
        // writer's temp file was cleaned up when its `NamedTempFile` guard
        // dropped rather than left orphaned under a `.tmp*` name.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("state.json")]);
    }

    #[test]
    fn is_already_exists_is_false_for_unrelated_errors() {
        let err = anyhow::anyhow!("some other failure");
        assert!(!is_already_exists(&err));

        let other_io =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(!is_already_exists(&other_io));
    }

    #[test]
    fn is_already_exists_sees_through_added_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        atomic_write_new(&path, b"original").expect("first write");

        let err = atomic_write_new(&path, b"loses")
            .context("wrapped by a caller")
            .expect_err("refused");
        assert!(is_already_exists(&err), "expected AlreadyExists: {err:#}");
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
