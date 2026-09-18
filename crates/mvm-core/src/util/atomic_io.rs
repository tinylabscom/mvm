//! Atomic file I/O and file-based locking utilities.
//!
//! Prevents partial writes (crash-safe) and concurrent mutation of state files.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Create a temp file in `path`'s parent directory, write `data`, flush, and
/// `fdatasync` it. Shared by [`atomic_write`] and [`atomic_write_new`], which
/// differ only in how they move the finished temp file into place.
///
/// The sync is `sync_data` (`fdatasync`), not `sync_all`. `fdatasync` still
/// flushes the metadata a later read needs to retrieve the data — the file's
/// size above all, which is the part that matters for a temp file this call
/// just created — and skips the rest. On rotational storage that is the
/// difference between one seek and two, and this is the shared write path
/// behind the audit chain, the receipt store, and every other record mvm
/// persists, so it is paid on the launch critical path.
fn synced_temp_in(path: &Path, data: &[u8]) -> Result<tempfile::NamedTempFile> {
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
    Ok(tmp)
}

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, flush + sync, then rename into place.
///
/// On crash or power loss, the file either has the old content or the new
/// content — never a partial write.
///
/// The extra metadata `sync_all` would flush is not buying a stronger
/// guarantee here in any case: this function never fsyncs the *parent
/// directory* after the rename, so the rename's own durability across a crash
/// is unguaranteed either way. Making that stronger means adding a directory
/// fsync, not keeping a more expensive file sync.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = synced_temp_in(path, data)?;
    tmp.persist(path)
        .with_context(|| format!("failed to persist temp file to {}", path.display()))?;
    Ok(())
}

/// Write a string to `path` atomically.
pub fn atomic_write_str(path: &Path, content: &str) -> Result<()> {
    atomic_write(path, content.as_bytes())
}

/// The one failure [`atomic_write_new`] means a caller to read as "another
/// writer already claimed this exact path" — the no-clobber persist step
/// itself lost the race. Nothing else `atomic_write_new` does, including the
/// parent-directory creation ahead of it, raises this marker, so an
/// unrelated `AlreadyExists` I/O error — `create_dir_all` finding a stray
/// non-directory file where a parent directory belongs raises exactly that
/// error kind too — can never be mistaken for a lost race by
/// [`is_already_exists`]. Carries the original I/O error (unmodified, so its
/// `raw_os_error` survives) as the cause.
#[derive(Debug)]
struct LostCreateRace(std::io::Error);

impl std::fmt::Display for LostCreateRace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "path already exists: {}", self.0)
    }
}

impl std::error::Error for LostCreateRace {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Whether `err` means the OS-level no-clobber rename primitive could not
/// even be attempted on this filesystem — as opposed to telling us the
/// target exists. Seen in practice as `EOPNOTSUPP`/`ENOTSUP` (identical on
/// Darwin), which std maps to [`std::io::ErrorKind::Unsupported`]:
/// `renameatx_np(RENAME_EXCL)` refuses this way on a non-APFS macOS volume,
/// and `renameat2(RENAME_NOREPLACE)` on some FUSE filesystems. `ENOSYS` and
/// `EINVAL` never reach here — `tempfile`'s own fallback inside
/// `persist_noclobber` already retries those with a plain `link` + `unlink`
/// before returning to us at all.
fn is_rename_flag_unsupported(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Unsupported
}

/// Write `data` to `path`, but only if `path` does not already exist.
///
/// Same crash-safety as [`atomic_write`] — write to a temp file in the same
/// directory, flush, `fdatasync`, then move into place — except the final
/// step is a no-clobber move: `renameat2(..., RENAME_NOREPLACE)` on Linux,
/// its macOS equivalent, or a `link` + `unlink` fallback when the kernel
/// supports neither (`tempfile` picks between these on its own). If even the
/// no-clobber *flag* is unsupported on this filesystem — the primitive
/// couldn't tell us anything, not even "no conflict" — this falls back to a
/// bare `link` itself: POSIX defines `link(2)` as exclusive outright, with
/// no flag to be unsupported, so it is a safe last resort rather than a
/// second guess at the same rename.
///
/// Two writers racing to create the same path can no longer both "win": at
/// most one of these primitives succeeds, and the loser gets back an error
/// [`is_already_exists`] recognizes. The loser's own temp file is removed
/// automatically — it was never linked into the target directory under its
/// final name.
pub fn atomic_write_new(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = synced_temp_in(path, data)?;
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(LostCreateRace(err.error).into())
        }
        Err(err) if is_rename_flag_unsupported(&err.error) => {
            // `err.file` is the same temp file, handed back unpersisted.
            // It drops (and is removed) at the end of this arm either way —
            // unlike a rename, a successful `hard_link` never consumes the
            // source name.
            let tmp = err.file;
            match std::fs::hard_link(tmp.path(), path) {
                Ok(()) => Ok(()),
                Err(link_err) if link_err.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(LostCreateRace(link_err).into())
                }
                Err(link_err) => Err(link_err)
                    .with_context(|| format!("failed to link temp file to {}", path.display())),
            }
        }
        Err(err) => Err(err.error)
            .with_context(|| format!("failed to persist temp file to {}", path.display())),
    }
}

/// Whether `err` is the signal [`atomic_write_new`] raises when a concurrent
/// writer already claimed the path — false for any other error, including
/// an unrelated `AlreadyExists` I/O error from some other step, since only
/// the private marker type `atomic_write_new` itself constructs matches.
/// `anyhow::Error::downcast_ref` walks the whole `.context()` chain, not
/// just the outermost frame, so this sees through any context a caller
/// layered on top.
pub fn is_already_exists(err: &anyhow::Error) -> bool {
    err.downcast_ref::<LostCreateRace>().is_some()
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
    fn is_already_exists_is_false_for_an_unrelated_already_exists_error() {
        // A plain `AlreadyExists` I/O error from some other step — e.g.
        // `create_dir_all` finding a stray non-directory file where a parent
        // directory belongs — carries the same `ErrorKind` a lost create
        // race does. Only `atomic_write_new`'s own marker means the latter;
        // a bare `io::Error` of that kind must not be classified as one.
        let err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
        assert!(!is_already_exists(&err));
    }

    #[test]
    fn is_rename_flag_unsupported_recognizes_enotsup() {
        // `EOPNOTSUPP`/`ENOTSUP` (identical on Darwin) is what a filesystem
        // that can't even attempt the no-clobber rename flag returns, and
        // std's unix `decode_error_kind` maps it to `Unsupported` — verified
        // against the pinned toolchain's own
        // `library/std/src/sys/io/error/unix.rs`, which is why this test
        // constructs the error from the portable `ErrorKind` rather than a
        // raw errno (no `libc` dependency needed to assert the mapping this
        // classifier relies on).
        let err = std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(is_rename_flag_unsupported(&err));
    }

    #[test]
    fn is_rename_flag_unsupported_is_false_for_other_errors() {
        assert!(!is_rename_flag_unsupported(&std::io::Error::from(
            std::io::ErrorKind::AlreadyExists
        )));
        assert!(!is_rename_flag_unsupported(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
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
