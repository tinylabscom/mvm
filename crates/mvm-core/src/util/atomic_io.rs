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

/// Flush an existing file's data and metadata to stable storage.
///
/// For a file written by some other party — a hypervisor saving guest memory,
/// a copy-on-write clone — whose bytes must be durable before a record naming
/// them is published. On macOS this is `F_FULLFSYNC`, a full device flush.
pub fn sync_file(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("opening {} to sync it", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

/// Flush a directory's entries to stable storage, so a file created in it or
/// renamed into or out of it survives a crash.
///
/// Syncing a file makes its bytes durable but not its name; only syncing the
/// directory that holds the name does that.
pub fn sync_dir(path: &Path) -> Result<()> {
    let dir =
        fs::File::open(path).with_context(|| format!("opening directory {}", path.display()))?;
    anyhow::ensure!(
        dir.metadata()
            .with_context(|| format!("reading {}", path.display()))?
            .is_dir(),
        "{} is not a directory",
        path.display()
    );
    dir.sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

/// [`atomic_write`], then sync the parent directory so the rename itself
/// survives a crash — the step [`atomic_write`] deliberately leaves out.
pub fn atomic_write_durable(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data)?;
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    sync_dir(parent)
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
    match persist_noclobber(tmp, path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(LostCreateRace(err).into())
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to persist temp file to {}", path.display()))
        }
    }
}

/// Move a finished temp file to `path` only if `path` does not exist.
///
/// An `AlreadyExists` error means another writer already holds `path`, and
/// nothing else this does raises that kind. The temp file is removed on every
/// outcome: a rename consumes it, and on a refusal or a link it drops here.
fn persist_noclobber(tmp: tempfile::NamedTempFile, path: &Path) -> std::io::Result<()> {
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(()),
        // `err.file` is the same temp file, handed back unpersisted. Unlike a
        // rename, a successful `hard_link` never consumes the source name, so
        // it is removed when `err.file` drops at the end of this arm.
        Err(err) if is_rename_flag_unsupported(&err.error) => {
            std::fs::hard_link(err.file.path(), path)
        }
        Err(err) => Err(err.error),
    }
}

/// Mode of every file the private writers below leave behind: owner
/// read/write, nothing for anyone else.
const PRIVATE_FILE_MODE: u32 = 0o600;

/// What [`write_new_with_mode`] found at its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFile {
    /// The path was absent and now holds the bytes this call wrote.
    Created,
    /// Another writer's file was already there. This call's bytes were
    /// discarded and the existing file was not touched.
    AlreadyPresent,
}

/// The directory `path` lives in, with a bare file name resolving to the
/// current directory rather than to an empty path.
fn parent_dir(path: &Path) -> std::io::Result<&Path> {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(parent) => Ok(parent),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no parent directory: {}", path.display()),
        )),
    }
}

/// Flush the directory holding `path`, so a name just linked or renamed into
/// it survives a crash.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    fs::File::open(parent_dir(path)?)?.sync_all()
}

/// Write `data` to a new temporary beside `path`, at exactly `mode`, and
/// sync it.
///
/// The temporary is opened `O_EXCL` under a random name, so it cannot be a
/// file another writer is also using, nor a symlink planted ahead of it. Its
/// name is `.<file name>.<random>.tmp`, so a directory listing that already
/// skips `*.tmp` leftovers skips it too. The parent directory must exist:
/// directories holding key material are created by their owners at mode 0700
/// (`config::create_private_dir`), never implicitly at the umask here.
fn synced_temp_with_mode(
    path: &Path,
    data: &[u8],
    mode: u32,
) -> std::io::Result<tempfile::NamedTempFile> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(path.file_name().unwrap_or_default());
    prefix.push(".");
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .permissions(fs::Permissions::from_mode(mode))
        .tempfile_in(parent_dir(path)?)?;
    // The mode given at open is filtered through the process umask. Setting it
    // on the inode pins it to exactly `mode` before the first byte lands.
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

/// Replace `path` with `data` at mode 0600, so that every reader sees either
/// the whole old file or the whole new one.
///
/// For files carrying key material or secrets that a later write legitimately
/// supersedes. Each call writes its own temporary, so two concurrent writers
/// cannot interleave into one file the way two writers sharing a fixed
/// `<name>.tmp` can; the last rename wins with a complete file. The rename
/// replaces a symlink at `path` rather than following it, and the parent
/// directory is synced so the new name survives a crash.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = synced_temp_with_mode(path, data, PRIVATE_FILE_MODE)?;
    tmp.persist(path).map_err(|err| err.error)?;
    sync_parent_dir(path)
}

/// Create `path` holding `data` at exactly `mode`, unless it already exists.
///
/// The bytes are written and synced under a temporary name, then linked into
/// place with a no-clobber rename, so `path` never names a partly written
/// file. Of any number of concurrent callers exactly one gets
/// [`NewFile::Created`]; every other gets [`NewFile::AlreadyPresent`] and must
/// use what is on disk, since its own bytes were thrown away. The parent
/// directory is synced after a successful create.
pub fn write_new_with_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<NewFile> {
    let tmp = synced_temp_with_mode(path, data, mode)?;
    match persist_noclobber(tmp, path) {
        Ok(()) => {
            sync_parent_dir(path)?;
            Ok(NewFile::Created)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(NewFile::AlreadyPresent),
        Err(err) => Err(err),
    }
}

/// [`write_new_with_mode`] at mode 0600, for key material and secrets.
pub fn write_private_new(path: &Path, data: &[u8]) -> std::io::Result<NewFile> {
    write_new_with_mode(path, data, PRIVATE_FILE_MODE)
}

/// Load the private file at `path`, minting it first if it does not exist.
///
/// This is the load-or-init shape every host key uses, made safe against a
/// second process doing the same thing at the same moment. The file on disk
/// is the only source of truth: a caller that mints a key and loses the race
/// to publish it discards its own key and loads the winner's, so no process
/// ever holds a key that does not match the file. `mint` runs only when the
/// file is absent, and `load` always reads what is on disk, including right
/// after this call created it.
///
/// The parent directory must already exist; create it with
/// `config::create_private_dir` so it is 0700.
pub fn load_or_create_private<T, E: From<std::io::Error>>(
    path: &Path,
    mint: impl FnOnce() -> zeroize::Zeroizing<Vec<u8>>,
    load: impl FnOnce(&Path) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // `Created` and `AlreadyPresent` end the same way: the file now holds
            // the one key every caller will load.
            write_private_new(path, &mint()).map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!("creating private file {}: {err}", path.display()),
                )
            })?;
        }
        Err(err) => return Err(err.into()),
    }
    load(path)
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

/// Copy `src` to `dst` and leave `dst` owner-writable, replacing whatever
/// `dst` already was. Returns the number of bytes copied.
///
/// `std::fs::copy` gives the destination the source's permission bits, so a
/// copy out of a read-only source — a Nix store output, a sealed cache entry —
/// lands read-only. A later `std::fs::copy` onto that same destination then
/// fails with `EACCES`, because it has to open the existing file for writing.
/// Any cache that is ever reinstalled from such a source breaks on its second
/// install.
///
/// This copies into a temporary sibling of `dst`, adds the owner-write bit
/// there, and renames the sibling over `dst`. A rename needs write access to
/// the directory, not to the file it replaces, so an existing read-only
/// destination is replaced rather than refused. It also means a reader of
/// `dst` sees either the old file or the new one and never a partial copy,
/// and that a process still holding the old file open keeps reading the old
/// bytes instead of a file truncated under it.
///
/// The bytes are the source's, unchanged. Only the owner-write bit is added;
/// every other mode bit (the execute bits in particular) is kept. A failed
/// copy removes its temporary sibling and leaves `dst` as it was.
pub fn copy_writable(src: &Path, dst: &Path) -> Result<u64> {
    let context = || format!("copying {} to {}", src.display(), dst.display());
    let parent = match dst.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(dst.file_name().unwrap_or_default());
    prefix.push(".");
    // The temporary path does not exist when `fs::copy` runs, so the copy
    // keeps its fast path (a copy-on-write clone where the filesystem has
    // one) instead of rewriting an existing file.
    let tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".partial")
        .make_in(parent, |path| {
            fs::copy(src, path).inspect_err(|_| {
                let _ = fs::remove_file(path);
            })
        })
        .with_context(context)?;
    add_owner_write(tmp.path()).with_context(|| format!("making {} writable", dst.display()))?;
    tmp.persist(dst)
        .map_err(|err| err.error)
        .with_context(context)
}

#[cfg(unix)]
fn add_owner_write(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o200);
    fs::set_permissions(path, perms)
}

/// Unix is the only host this workspace runs on; elsewhere the copy keeps the
/// source's attributes.
#[cfg(not(unix))]
fn add_owner_write(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
    fn atomic_write_durable_replaces_content_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("meta.json");
        fs::write(&path, b"old").expect("seed");
        atomic_write_durable(&path, b"new").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "new");
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("meta.json")]);
    }

    #[test]
    fn sync_file_and_sync_dir_accept_what_exists_and_refuse_what_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("blob");
        fs::write(&file, b"bytes").expect("seed");
        sync_file(&file).expect("sync file");
        sync_dir(dir.path()).expect("sync dir");

        assert!(sync_file(&dir.path().join("absent")).is_err());
        assert!(sync_dir(&dir.path().join("absent")).is_err());
        // A file is not a directory: syncing it as one would silently skip
        // the directory entry the caller meant to make durable.
        assert!(sync_dir(&file).is_err());
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

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn read_only_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes).expect("write source");
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).expect("chmod 0444");
    }

    /// A copy out of a read-only source must not inherit its read-only mode:
    /// the destination is a cache entry the next install writes again.
    #[cfg(unix)]
    #[test]
    fn copy_writable_leaves_a_fresh_destination_owner_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("mvm-meta.json");
        read_only_file(&src, b"{\"v\":1}");
        let dst = dir.path().join("out").join("mvm-meta.json");
        fs::create_dir_all(dst.parent().expect("parent")).expect("mkdir");

        let copied = copy_writable(&src, &dst).expect("copy");

        assert_eq!(copied, 7);
        assert_eq!(fs::read(&dst).expect("read"), b"{\"v\":1}");
        assert_eq!(mode_of(&dst), 0o644, "0444 plus the owner-write bit");
        assert_eq!(mode_of(&src), 0o444, "the source is never touched");
    }

    /// The exact failure a revision reinstall hit: the destination already
    /// exists at 0444 from an earlier copy, and a plain `fs::copy` onto it is
    /// refused with `EACCES` (for any user but root, which bypasses the mode
    /// check — so this does not assert the plain copy's failure itself).
    #[cfg(unix)]
    #[test]
    fn copy_writable_replaces_an_existing_read_only_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        read_only_file(&src, b"new bytes");
        let dst = dir.path().join("dst");
        read_only_file(&dst, b"old");

        copy_writable(&src, &dst).expect("copy over a read-only destination");

        assert_eq!(fs::read(&dst).expect("read"), b"new bytes");
        assert_eq!(mode_of(&dst), 0o644);
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("readdir")
            .map(|entry| entry.expect("entry").file_name())
            .filter(|name| name != "src" && name != "dst")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temporary sibling left: {leftovers:?}"
        );
    }

    /// Only the owner-write bit is added; an executable stays executable.
    #[cfg(unix)]
    #[test]
    fn copy_writable_keeps_the_other_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("microvm-run");
        fs::write(&src, b"#!/bin/sh\n").expect("write");
        fs::set_permissions(&src, fs::Permissions::from_mode(0o555)).expect("chmod");
        let dst = dir.path().join("copy");

        copy_writable(&src, &dst).expect("copy");

        assert_eq!(mode_of(&dst), 0o755);
    }

    /// A copy that fails leaves the existing destination untouched and no
    /// temporary sibling behind.
    #[test]
    fn copy_writable_failure_leaves_the_destination_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dst = dir.path().join("dst");
        fs::write(&dst, b"keep").expect("write");

        let err = copy_writable(&dir.path().join("missing"), &dst)
            .expect_err("a missing source must fail");

        assert!(
            format!("{err:#}").contains("missing"),
            "names the source: {err:#}"
        );
        assert_eq!(fs::read(&dst).expect("read"), b"keep");
        assert_eq!(fs::read_dir(dir.path()).expect("readdir").count(), 1);
    }

    #[test]
    fn test_file_lock_nonexistent_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path: PathBuf = dir.path().join("sub/dir/state.json");
        let _lock = FileLock::acquire(&path).expect("lock with nested path");
    }

    fn dir_entries(dir: &Path) -> Vec<std::ffi::OsString> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn write_private_new_creates_an_owner_only_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.key");
        let outcome = write_private_new(&path, b"key bytes").expect("create");
        assert_eq!(outcome, NewFile::Created);
        assert_eq!(fs::read(&path).expect("read"), b"key bytes");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(dir_entries(dir.path()), vec!["host.key"]);
    }

    #[test]
    fn write_private_new_leaves_an_existing_file_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.key");
        write_private_new(&path, b"winner").expect("first create");

        let outcome = write_private_new(&path, b"loser").expect("second create");

        assert_eq!(outcome, NewFile::AlreadyPresent);
        assert_eq!(fs::read(&path).expect("read"), b"winner");
        assert_eq!(
            dir_entries(dir.path()),
            vec!["host.key"],
            "the loser's temporary must not be left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_new_with_mode_applies_the_requested_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.pub");
        write_new_with_mode(&path, b"public", 0o644).expect("create");
        assert_eq!(mode_of(&path), 0o644);
    }

    /// `OpenOptions::mode` only applies at creation, so rewriting a 0644 file
    /// in place keeps it 0644. A replacement is a new inode at 0600.
    #[cfg(unix)]
    #[test]
    fn write_private_replaces_a_loose_file_with_an_owner_only_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        fs::write(&path, b"old").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        write_private(&path, b"new").expect("write");

        assert_eq!(fs::read(&path).expect("read"), b"new");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(dir_entries(dir.path()), vec!["secret"]);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_replaces_a_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, b"untouched").expect("seed");
        let path = dir.path().join("secret");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

        write_private(&path, b"new").expect("write");

        assert_eq!(fs::read(&elsewhere).expect("read"), b"untouched");
        assert!(!fs::symlink_metadata(&path).expect("stat").is_symlink());
        assert_eq!(fs::read(&path).expect("read"), b"new");
    }

    #[test]
    fn load_or_create_private_loads_an_existing_file_without_minting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.key");
        fs::write(&path, b"existing").expect("seed");

        let loaded: Vec<u8> = load_or_create_private(
            &path,
            || panic!("an existing file must not be re-minted"),
            |p: &Path| fs::read(p),
        )
        .expect("load");

        assert_eq!(loaded, b"existing");
    }

    /// The bug this guards against: two first uses each minted a key, the
    /// second write replaced the first, and the first caller went on using a
    /// key the file no longer held. Every caller must return the file's bytes.
    #[test]
    fn concurrent_load_or_create_callers_all_return_the_key_on_disk() {
        use std::sync::{Arc, Barrier};
        const THREADS: usize = 16;
        for _ in 0..16 {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("host.key");
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|i| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        load_or_create_private(
                            &path,
                            || zeroize::Zeroizing::new(vec![i as u8; 32]),
                            |p: &Path| fs::read(p),
                        )
                    })
                })
                .collect();
            let keys: Vec<Vec<u8>> = handles
                .into_iter()
                .map(|h| h.join().expect("thread").expect("load or create"))
                .collect();
            let on_disk = fs::read(&path).expect("read");
            assert_eq!(on_disk.len(), 32);
            assert!(
                keys.iter().all(|key| *key == on_disk),
                "every caller must hold the published key"
            );
            assert_eq!(dir_entries(dir.path()), vec!["host.key"]);
        }
    }

    /// A reader polling while writers create and then replace the file must
    /// only ever see nothing at all or one writer's complete bytes.
    #[test]
    fn a_concurrent_reader_never_sees_a_partial_file() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        const LEN: usize = 256 * 1024;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.key");
        let done = Arc::new(AtomicBool::new(false));

        let reader = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                let mut observed = 0usize;
                // Keep going past `done` until one read has landed, so the
                // test cannot pass without having looked at the file.
                while !done.load(Ordering::Acquire) || observed == 0 {
                    match fs::read(&path) {
                        Ok(bytes) => {
                            assert_eq!(bytes.len(), LEN, "short read of a published file");
                            assert!(
                                bytes.iter().all(|b| *b == bytes[0]),
                                "bytes from two writers interleaved"
                            );
                            observed += 1;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => panic!("read failed: {err}"),
                    }
                }
                observed
            })
        };

        let writers: Vec<_> = (1..=4u8)
            .map(|fill| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let bytes = vec![fill; LEN];
                    write_private_new(&path, &bytes).expect("create");
                    for _ in 0..25 {
                        write_private(&path, &bytes).expect("replace");
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("writer");
        }
        done.store(true, Ordering::Release);
        reader.join().expect("reader");
    }
}
