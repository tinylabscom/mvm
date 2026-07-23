//! Content-addressed snapshot store.
//!
//! A snapshot is an immutable, content-addressed on-disk artifact that
//! can be cheaply materialized elsewhere via reflink CoW clones. The
//! store is intentionally simple — a directory on a reflink-capable
//! filesystem where each snapshot lives under its opaque id.
//!
//! Two layouts are supported:
//!
//! * **Directory snapshot** — the source path was a directory; the store
//!   keeps it as `<root>/<id>/...` and materializes it with a recursive
//!   directory clone.
//! * **File snapshot** — the source path was a regular file; the store
//!   keeps it as `<root>/<id>/data` with a `.mvm-snapshot-is-file`
//!   marker, and materializes it as a single file.
//!
//! This is the persistence layer behind the warm-parent pool: a paused
//! microVM's rootfs (and, later, memory snapshot) is stored once and then
//! reflink-cloned into each child's per-instance path.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::clone::{CloneStrategy, reflink_or_copy, reflink_or_copy_dir};

const FILE_MARKER: &str = ".mvm-snapshot-is-file";
const META_FILE: &str = ".mvm-snapshot-meta";

/// Opaque identifier for a snapshot stored in a [`SnapshotStore`].
///
/// The `id` is the filesystem directory name under the store root. An
/// optional `digest` can carry a content hash (e.g., SHA-256 of the
/// serialized snapshot) used by callers for attestation or cache keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotId {
    id: String,
    digest: Option<String>,
}

impl SnapshotId {
    /// Create a snapshot id with no digest.
    ///
    /// The id must not contain path separators.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            digest: None,
        }
    }

    /// Create a snapshot id with an associated content digest.
    pub fn with_digest(id: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            digest: Some(digest.into()),
        }
    }

    /// The opaque store id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The optional content digest supplied at creation time.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl From<String> for SnapshotId {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl From<&str> for SnapshotId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

/// A content-addressed store of immutable snapshots.
///
/// Implementations must be thread-safe; callers will use the store from
/// async worker threads.
pub trait SnapshotStore {
    /// Persist `source` as snapshot `id`.
    ///
    /// `source` may be a regular file or a directory. The implementation
    /// must preserve the distinction so that [`SnapshotStore::materialize`]
    /// materializes the same shape.
    ///
    /// Returns `AlreadyExists` if a snapshot with this id already exists.
    fn create(&self, id: &SnapshotId, source: &Path) -> io::Result<()>;

    /// Materialize snapshot `id` at `dst` using reflink CoW when possible,
    /// falling back to byte copies otherwise.
    ///
    /// `dst` must not already exist. Its parent is created if necessary.
    fn materialize(&self, id: &SnapshotId, dst: &Path) -> io::Result<CloneStrategy>;

    /// Remove snapshot `id` and reclaim its storage.
    ///
    /// Returns `NotFound` if the snapshot does not exist.
    fn remove(&self, id: &SnapshotId) -> io::Result<()>;

    /// List the ids of all snapshots currently in the store.
    fn list(&self) -> io::Result<Vec<SnapshotId>>;
}

/// Filesystem-backed [`SnapshotStore`] rooted at a directory.
///
/// The store creates the root directory lazily on first access. It is
/// safe to share the same root between processes as long as the
/// filesystem provides atomic create-unlink semantics for the id
/// directories.
#[derive(Debug, Clone)]
pub struct FsSnapshotStore {
    root: PathBuf,
}

impl FsSnapshotStore {
    /// Open or create a snapshot store at `root`.
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The store root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn snapshot_dir(&self, id: &SnapshotId) -> PathBuf {
        self.root.join(&id.id)
    }

    fn ensure_id_is_safe(id: &str) -> io::Result<()> {
        if id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot id must not be empty",
            ));
        }
        if id.contains('/') || id.contains('\\') || id.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("snapshot id contains path separator: {id}"),
            ));
        }
        Ok(())
    }

    fn write_meta(&self, dir: &Path, id: &SnapshotId) -> io::Result<()> {
        if let Some(digest) = &id.digest {
            let meta = format!("digest={digest}\n");
            fs::write(dir.join(META_FILE), meta)?;
        }
        Ok(())
    }

    fn read_meta(&self, dir: &Path, id: &str) -> SnapshotId {
        let meta_path = dir.join(META_FILE);
        let digest = fs::read_to_string(&meta_path)
            .ok()
            .and_then(|contents| {
                contents
                    .lines()
                    .find(|line| line.starts_with("digest="))
                    .map(|line| line.strip_prefix("digest=").unwrap_or("").to_string())
            })
            .filter(|d| !d.is_empty());
        if let Some(digest) = digest {
            SnapshotId::with_digest(id, digest)
        } else {
            SnapshotId::new(id)
        }
    }
}

impl SnapshotStore for FsSnapshotStore {
    fn create(&self, id: &SnapshotId, source: &Path) -> io::Result<()> {
        Self::ensure_id_is_safe(&id.id)?;
        let dir = self.snapshot_dir(id);
        if dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("snapshot {} already exists", id.id),
            ));
        }

        fs::create_dir_all(&dir)?;

        let meta = fs::symlink_metadata(source)?;
        if meta.is_dir() {
            // Directory snapshot: store contents directly under dir/.
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                let src = entry.path();
                let dst = dir.join(entry.file_name());
                if entry.file_type()?.is_dir() {
                    reflink_or_copy_dir(&src, &dst)?;
                } else if entry.file_type()?.is_file() {
                    reflink_or_copy(&src, &dst)?;
                } else if entry.file_type()?.is_symlink() {
                    let target = fs::read_link(&src)?;
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&target, &dst)?;
                    #[cfg(not(unix))]
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "symlink snapshot is only supported on unix",
                    ));
                }
            }
        } else if meta.is_file() {
            // File snapshot: store under dir/data with a marker.
            let data_path = dir.join("data");
            reflink_or_copy(source, &data_path)?;
            fs::write(dir.join(FILE_MARKER), b"")?;
        } else {
            let _ = fs::remove_dir_all(&dir);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "snapshot source must be a regular file or directory: {}",
                    source.display()
                ),
            ));
        }

        self.write_meta(&dir, id)?;
        Ok(())
    }

    fn materialize(&self, id: &SnapshotId, dst: &Path) -> io::Result<CloneStrategy> {
        Self::ensure_id_is_safe(&id.id)?;
        let dir = self.snapshot_dir(id);
        if !dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {} not found", id.id),
            ));
        }

        if dir.join(FILE_MARKER).exists() {
            let data_path = dir.join("data");
            reflink_or_copy(&data_path, dst)
        } else {
            reflink_or_copy_dir(&dir, dst)
        }
    }

    fn remove(&self, id: &SnapshotId) -> io::Result<()> {
        Self::ensure_id_is_safe(&id.id)?;
        let dir = self.snapshot_dir(id);
        if !dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {} not found", id.id),
            ));
        }
        fs::remove_dir_all(&dir)
    }

    fn list(&self) -> io::Result<Vec<SnapshotId>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                if id.starts_with('.') {
                    continue;
                }
                ids.push(self.read_meta(&entry.path(), &id));
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_snapshot_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("golden.ext4");
        fs::write(&source, b"golden rootfs").unwrap();

        let id = SnapshotId::with_digest("snap-1", "sha256:abc123");
        store.create(&id, &source).expect("create");

        let dst = tmp.path().join("instance.ext4");
        let strategy = store.materialize(&id, &dst).expect("materialize");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        assert_eq!(fs::read(&dst).unwrap(), b"golden rootfs");

        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), "snap-1");
        assert_eq!(listed[0].digest(), Some("sha256:abc123"));
    }

    #[test]
    fn directory_snapshot_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("rootfs-dir");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("vmlinuz"), b"kernel").unwrap();

        let id = SnapshotId::new("dir-snap");
        store.create(&id, &source).expect("create");

        let dst = tmp.path().join("instance-dir");
        let strategy = store.materialize(&id, &dst).expect("materialize");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        assert_eq!(fs::read(dst.join("vmlinuz")).unwrap(), b"kernel");
    }

    #[test]
    fn create_is_idempotent_only_on_distinct_ids() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("file.bin");
        fs::write(&source, b"v1").unwrap();

        let id = SnapshotId::new("same");
        store.create(&id, &source).expect("first create");
        let result = store.create(&id, &source);
        assert!(result.is_err());
    }

    #[test]
    fn remove_deletes_snapshot_and_fails_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("file.bin");
        fs::write(&source, b"data").unwrap();

        let id = SnapshotId::new("gone");
        store.create(&id, &source).expect("create");
        assert!(store.snapshot_dir(&id).exists());

        store.remove(&id).expect("remove");
        assert!(!store.snapshot_dir(&id).exists());

        assert!(store.remove(&id).is_err());
    }

    #[test]
    fn materialize_missing_snapshot_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let id = SnapshotId::new("missing");
        let dst = tmp.path().join("dst");
        assert!(store.materialize(&id, &dst).is_err());
    }

    #[test]
    fn list_is_empty_for_fresh_store() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        assert!(store.list().expect("list").is_empty());
    }

    #[test]
    fn file_snapshot_independence() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("file.bin");
        fs::write(&source, b"original").unwrap();

        let id = SnapshotId::new("isolated");
        store.create(&id, &source).expect("create");

        let dst = tmp.path().join("instance.bin");
        store.materialize(&id, &dst).expect("materialize");

        fs::write(&dst, b"mutated").unwrap();
        store
            .materialize(&id, &tmp.path().join("instance2.bin"))
            .expect("materialize again");
        let data = fs::read(store.snapshot_dir(&id).join("data")).unwrap();
        assert_eq!(data, b"original");
    }

    #[test]
    fn rejects_path_separator_in_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("file.bin");
        fs::write(&source, b"x").unwrap();

        let id = SnapshotId::new("../../etc/passwd");
        assert!(store.create(&id, &source).is_err());
        assert!(store.materialize(&id, &tmp.path().join("dst")).is_err());
        assert!(store.remove(&id).is_err());
    }
}
