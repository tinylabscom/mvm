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
//! microVM's rootfs (and its memory snapshot) is stored once and then
//! reflink-cloned into each child's per-instance path.
//!
//! A memory snapshot — a large, often-sparse `mem.bin` file, or a
//! `{vmstate.bin, mem.bin}` pair stored as a directory — is a first-class
//! content-addressed artifact here: it is stored via
//! [`FsSnapshotStore::create_content_addressed`] like any other snapshot
//! and materialized through the same sparse-aware reflink/copy path, with
//! no separate mechanism. The Firecracker pause/seal lifecycle that
//! produces those bytes stays in mvm-runtime; this store only owns the
//! artifact once it exists on disk.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::clone::{CloneStrategy, reflink_or_copy, reflink_or_copy_dir};
use crate::hash;

const FILE_MARKER: &str = ".mvm-snapshot-is-file";
const META_FILE: &str = ".mvm-snapshot-meta";
const REFCOUNT_FILE: &str = ".mvm-snapshot-refcount";

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
    /// This is a force-remove: it deletes storage unconditionally,
    /// bypassing the reference count that `FsSnapshotStore::retain`/
    /// `release` track for content-addressed snapshots. It's the right
    /// tool for the plain, unshared [`SnapshotStore::create`] path (which
    /// has no refcount) or an explicit force-delete; a content-addressed
    /// snapshot that may be shared should be freed via `release` instead.
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

    fn read_refcount(dir: &Path) -> io::Result<Option<u32>> {
        match fs::read_to_string(dir.join(REFCOUNT_FILE)) {
            Ok(s) => s.trim().parse::<u32>().map(Some).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("corrupt snapshot refcount: {s:?}"),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_refcount(dir: &Path, n: u32) -> io::Result<()> {
        fs::write(dir.join(REFCOUNT_FILE), n.to_string())
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

/// Content-addressed create + reference counting, layered on the plain
/// [`SnapshotStore`] primitives above. Kept as inherent methods rather than
/// trait methods: they're specific to content-addressed dedup, not a
/// capability every `SnapshotStore` implementation is required to offer.
impl FsSnapshotStore {
    /// Persist `source` (file or directory) under an id derived from its
    /// SHA-256 content hash, deduplicating identical content.
    ///
    /// Unlike [`SnapshotStore::create`], which errors when the id already
    /// exists, this is idempotent by construction: since the id *is* the
    /// content hash, a second call with identical bytes is a share, not a
    /// conflict — it increments the refcount and returns the existing id
    /// instead of erroring.
    pub fn create_content_addressed(&self, source: &Path) -> io::Result<SnapshotId> {
        let h = hash::hash_source(source)?;
        let id = SnapshotId::with_digest(h.clone(), format!("sha256:{h}"));
        let dir = self.snapshot_dir(&id);

        if dir.exists() {
            self.retain(&id)?;
            return Ok(id);
        }

        self.create(&id, source)?;
        Self::write_refcount(&dir, 1)?;
        Ok(id)
    }

    /// Increment `id`'s reference count and return the new value.
    ///
    /// Snapshots created via the plain [`SnapshotStore::create`] have no
    /// refcount file; a missing file reads as count 1 before incrementing,
    /// so both creation paths compose under `retain`/`release`.
    ///
    /// Concurrency: this is a plain read-modify-write on one file. Two
    /// processes racing on the same id can lose an update; that's out of
    /// scope for this phase because the warm-pool caller serializes store
    /// mutations.
    pub fn retain(&self, id: &SnapshotId) -> io::Result<u32> {
        let dir = self.existing_snapshot_dir(id)?;
        let next = Self::read_refcount(&dir)?.unwrap_or(1) + 1;
        Self::write_refcount(&dir, next)?;
        Ok(next)
    }

    /// Decrement `id`'s reference count; at 0, delete the snapshot's
    /// storage and return 0.
    ///
    /// Returns `NotFound` if the snapshot does not exist.
    pub fn release(&self, id: &SnapshotId) -> io::Result<u32> {
        let dir = self.existing_snapshot_dir(id)?;
        let current = Self::read_refcount(&dir)?.unwrap_or(1);
        if current <= 1 {
            fs::remove_dir_all(&dir)?;
            Ok(0)
        } else {
            let next = current - 1;
            Self::write_refcount(&dir, next)?;
            Ok(next)
        }
    }

    /// Read `id`'s current reference count without mutating it. A missing
    /// refcount file (a plain-`create`d snapshot) reads as 1.
    ///
    /// Returns `NotFound` if the snapshot does not exist.
    pub fn refcount(&self, id: &SnapshotId) -> io::Result<u32> {
        let dir = self.existing_snapshot_dir(id)?;
        Ok(Self::read_refcount(&dir)?.unwrap_or(1))
    }

    /// Validate `id` and resolve its directory, failing `NotFound` if the
    /// snapshot isn't present. Shared precondition for `retain`/`release`/
    /// `refcount`.
    fn existing_snapshot_dir(&self, id: &SnapshotId) -> io::Result<PathBuf> {
        Self::ensure_id_is_safe(&id.id)?;
        let dir = self.snapshot_dir(id);
        if !dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {} not found", id.id),
            ));
        }
        Ok(dir)
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

    // -- content-addressed create + dedup (work item 2) --

    #[test]
    fn create_content_addressed_dedups_identical_content() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("payload.bin");
        fs::write(&source, b"dedup me").unwrap();

        let id1 = store
            .create_content_addressed(&source)
            .expect("first store");
        let id2 = store
            .create_content_addressed(&source)
            .expect("second store (dedup)");
        assert_eq!(id1.id(), id2.id());
        assert_eq!(
            id1.digest(),
            Some(format!("sha256:{}", id1.id())).as_deref()
        );

        let entries: Vec<_> = fs::read_dir(store.root()).unwrap().collect();
        assert_eq!(entries.len(), 1, "identical content stored exactly once");
        assert_eq!(store.refcount(&id1).expect("refcount"), 2);
    }

    #[test]
    fn create_content_addressed_distinct_content_gets_distinct_ids() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let a = tmp.path().join("a.bin");
        fs::write(&a, b"content a").unwrap();
        let b = tmp.path().join("b.bin");
        fs::write(&b, b"content b").unwrap();

        let id_a = store.create_content_addressed(&a).expect("store a");
        let id_b = store.create_content_addressed(&b).expect("store b");
        assert_ne!(id_a.id(), id_b.id());
    }

    // -- reference counting (work item 3) --

    #[test]
    fn retain_and_release_transition_refcount() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("x.bin");
        fs::write(&source, b"x").unwrap();
        let id = store.create_content_addressed(&source).expect("store");

        assert_eq!(store.refcount(&id).unwrap(), 1);
        assert_eq!(store.retain(&id).unwrap(), 2);
        assert_eq!(store.retain(&id).unwrap(), 3);
        assert_eq!(store.release(&id).unwrap(), 2);
        assert_eq!(store.release(&id).unwrap(), 1);
        assert_eq!(store.release(&id).unwrap(), 0);
        assert!(
            !store.snapshot_dir(&id).exists(),
            "storage reclaimed at refcount 0"
        );
    }

    #[test]
    fn double_create_content_addressed_then_two_releases_deletes_exactly_once() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("shared.bin");
        fs::write(&source, b"shared content").unwrap();

        let id1 = store.create_content_addressed(&source).expect("first");
        let id2 = store
            .create_content_addressed(&source)
            .expect("second (dedup)");
        assert_eq!(id1.id(), id2.id());
        assert_eq!(store.refcount(&id1).unwrap(), 2);

        assert_eq!(store.release(&id1).unwrap(), 1);
        assert!(
            store.snapshot_dir(&id1).exists(),
            "still referenced once, storage intact"
        );
        assert_eq!(store.release(&id1).unwrap(), 0);
        assert!(
            !store.snapshot_dir(&id1).exists(),
            "deleted exactly once, at the second release"
        );

        // A third release must fail closed, not double-delete.
        assert!(store.release(&id1).is_err());
    }

    #[test]
    fn refcount_on_plain_create_snapshot_reads_one() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");
        let source = tmp.path().join("plain.bin");
        fs::write(&source, b"plain").unwrap();

        let id = SnapshotId::new("plain-snap");
        store.create(&id, &source).expect("plain create");

        assert_eq!(store.refcount(&id).expect("refcount"), 1);
        assert_eq!(store.release(&id).expect("release"), 0);
        assert!(!store.snapshot_dir(&id).exists());
    }

    // -- content-addressed memory-snapshot storage (work item 4) --

    #[test]
    fn content_addressed_memory_snapshot_roundtrips_and_is_independent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");

        // Synthetic mem.bin: nonzero header, a large zero run (guest-free
        // RAM), nonzero tail — representative of a real memory snapshot's
        // sparseness, exercising the sparse-copy fallback path.
        let mut mem = vec![0xEE_u8; 8192];
        mem.extend(std::iter::repeat_n(0u8, 131072));
        mem.extend(vec![0x11_u8; 4096]);
        let source = tmp.path().join("mem.bin");
        fs::write(&source, &mem).unwrap();

        let id = store
            .create_content_addressed(&source)
            .expect("store mem snapshot");

        let instance = tmp.path().join("instance-mem.bin");
        store.materialize(&id, &instance).expect("materialize");
        assert_eq!(fs::read(&instance).unwrap(), mem);

        fs::write(&instance, b"mutated instance").unwrap();
        let restored = tmp.path().join("instance-mem-2.bin");
        store
            .materialize(&id, &restored)
            .expect("materialize again");
        assert_eq!(
            fs::read(&restored).unwrap(),
            mem,
            "stored snapshot must be unaffected by instance mutation"
        );
    }

    // -- snapshot-graph-integrity (work item 5) --

    #[test]
    fn deleting_one_snapshot_does_not_affect_sibling_or_materialized_child() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FsSnapshotStore::new(tmp.path().join("store")).expect("store");

        let source_a = tmp.path().join("a.bin");
        fs::write(&source_a, b"snapshot A content").unwrap();
        let source_b = tmp.path().join("b.bin");
        fs::write(&source_b, b"snapshot B content, distinct").unwrap();

        let id_a = store.create_content_addressed(&source_a).expect("store a");
        let id_b = store.create_content_addressed(&source_b).expect("store b");
        assert_ne!(id_a.id(), id_b.id());

        // Materialize a "child" instance off snapshot A.
        let child = tmp.path().join("child-instance.bin");
        store.materialize(&id_a, &child).expect("materialize child");

        // The child is just a materialized copy, not tracked by the store;
        // deleting it and releasing snapshot A entirely must not touch B.
        fs::remove_file(&child).unwrap();
        let remaining = store.release(&id_a).expect("release a");
        assert_eq!(remaining, 0);
        assert!(!store.snapshot_dir(&id_a).exists());

        assert_eq!(store.refcount(&id_b).expect("refcount b"), 1);
        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), id_b.id());

        let materialize_b = tmp.path().join("materialize-b.bin");
        store
            .materialize(&id_b, &materialize_b)
            .expect("sibling still materializes");
        assert_eq!(
            fs::read(&materialize_b).unwrap(),
            b"snapshot B content, distinct"
        );
    }
}
