//! Reclaiming checkpoint storage that nothing refers to any more.
//!
//! Removing a checkpoint is `remove_dir_all` of its directory, which drops its
//! hard links into the object pool but leaves the pool's own link behind. An
//! object whose only remaining link is the pool's (`st_nlink == 1`) is garbage:
//! every checkpoint that used it held a link of its own, staging included. The
//! rule needs no record of who uses what, so it cannot disagree with the
//! filesystem after a crash.
//!
//! A sweep can race a capture. If the capture links an object after the sweep
//! read its link count, the unlink removes only the pool's name and the bytes
//! stay alive under the capture's link; a later capture writes the pool entry
//! again. If the sweep unlinks first, the capture's link fails and it writes
//! the object again (see `ObjectPool::store_and_link`).
//!
//! Restore keeps one verified materialization per index digest. Those are a
//! cache, so an entry whose index no stored checkpoint names any more is
//! removed too, under the same per-blob lock restore takes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use super::CheckpointStore;
use super::chunks::{
    self, ChunkDigest, MATERIALIZATION_TEMP_PREFIX, MATERIALIZATIONS_DIR, OBJECT_TEMP_PREFIX,
    OBJECTS_DIR,
};
use super::staging::{self, STAGING_DIR};

/// An object still being written is linked under its digest within one chunk
/// write and sync. One older than this belongs to a capture that died.
const STALE_OBJECT_TEMP_AGE: Duration = Duration::from_secs(60 * 60);

/// What [`prune_unreferenced_content`] removed, or would remove on a dry run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentPruneReport {
    /// Staging directories left by captures whose process is gone.
    pub abandoned_staging: usize,
    /// Pool objects no checkpoint links, plus objects a dead capture never
    /// finished writing.
    pub objects: usize,
    pub object_bytes: u64,
    /// Cached restore materializations whose index no checkpoint names.
    pub materializations: usize,
    pub materialization_bytes: u64,
}

impl ContentPruneReport {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Entries removed, counted the way `mvmctl cache prune` totals them.
    pub fn entries(&self) -> u64 {
        [self.abandoned_staging, self.objects, self.materializations]
            .into_iter()
            .map(|count| count as u64)
            .sum()
    }

    pub fn bytes(&self) -> u64 {
        self.object_bytes.saturating_add(self.materialization_bytes)
    }
}

/// Remove abandoned staging, then every pool object nothing links, then every
/// cached materialization no stored checkpoint names. The order matters:
/// staging holds links, so objects only it used are reclaimed in the same run.
///
/// Fails before removing anything when the store cannot be listed, because a
/// materialization is judged unreferenced against that listing.
pub fn prune_unreferenced_content(
    store: &CheckpointStore,
    dry_run: bool,
) -> Result<ContentPruneReport> {
    let referenced = referenced_materializations(store)?;
    let staging_root = store.root().join(STAGING_DIR);
    let abandoned_staging = if dry_run {
        staging::abandoned_entries(&staging_root).len()
    } else {
        staging::sweep_abandoned(&staging_root)
    };
    let objects = sweep_pool(store.root(), dry_run, SystemTime::now())?;
    let materializations = sweep_materializations(store.root(), &referenced, dry_run)?;
    Ok(ContentPruneReport {
        abandoned_staging,
        objects: objects.count,
        object_bytes: objects.bytes,
        materializations: materializations.count,
        materialization_bytes: materializations.bytes,
    })
}

#[derive(Debug, Default, Clone, Copy)]
struct Reclaimed {
    count: usize,
    bytes: u64,
}

impl Reclaimed {
    fn add(&mut self, bytes: u64) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// Cache entry paths for every chunked blob of every stored checkpoint.
fn referenced_materializations(store: &CheckpointStore) -> Result<BTreeSet<PathBuf>> {
    let mut referenced = BTreeSet::new();
    for meta in store
        .list()
        .context("listing checkpoints to find referenced chunk content")?
    {
        let content_dir = store.content_dir(&meta.id);
        for blob in &meta.content {
            if chunks::validate_blob_name(&blob.name).is_err()
                || !chunks::is_chunked_blob(&content_dir, blob)
            {
                continue;
            }
            referenced.insert(
                chunks::materialization_blob_cache_root(store.root(), &meta.key_domain, &blob.name)
                    .join(&blob.sha256),
            );
        }
    }
    Ok(referenced)
}

/// `<root>/.objects/<domain>/<shard>/<digest>`: remove what only the pool
/// links, and temporaries a dead capture left.
fn sweep_pool(store_root: &Path, dry_run: bool, now: SystemTime) -> Result<Reclaimed> {
    let mut reclaimed = Reclaimed::default();
    for domain in subdirectories(&store_root.join(OBJECTS_DIR))? {
        for shard in subdirectories(&domain)? {
            let shard_name = file_name(&shard);
            for entry in read_dir(&shard)? {
                let path = entry.path();
                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(error).with_context(|| format!("reading {}", path.display()));
                    }
                };
                if !metadata.file_type().is_file() {
                    continue;
                }
                let name = file_name(&path);
                let garbage = if is_object_name(&name, &shard_name) {
                    link_count(&metadata) == Some(1)
                } else if name.starts_with(OBJECT_TEMP_PREFIX) {
                    metadata
                        .modified()
                        .ok()
                        .and_then(|modified| now.duration_since(modified).ok())
                        .is_some_and(|age| age >= STALE_OBJECT_TEMP_AGE)
                } else {
                    false
                };
                if garbage && remove(&path, dry_run, Removal::File)? {
                    reclaimed.add(metadata.len());
                }
            }
        }
    }
    Ok(reclaimed)
}

/// `<root>/.materialized/<domain>/<blob>/<index digest>/`: remove entries no
/// stored checkpoint names, and staging a dead restore left. Each blob's cache
/// is swept under its lock; one a restore holds now is left for the next prune.
fn sweep_materializations(
    store_root: &Path,
    referenced: &BTreeSet<PathBuf>,
    dry_run: bool,
) -> Result<Reclaimed> {
    let mut reclaimed = Reclaimed::default();
    for domain in subdirectories(&store_root.join(MATERIALIZATIONS_DIR))? {
        for blob_cache in subdirectories(&domain)? {
            let Some(_lock) = mvm_core::atomic_io::FileLock::try_acquire(&blob_cache)? else {
                continue;
            };
            for entry in subdirectories(&blob_cache)? {
                let name = file_name(&entry);
                // Publishing happens under this lock, so a staging directory
                // seen while holding it was left by a restore that died.
                let garbage = name.starts_with(MATERIALIZATION_TEMP_PREFIX)
                    || (ChunkDigest::try_from(name).is_ok() && !referenced.contains(&entry));
                if !garbage {
                    continue;
                }
                let bytes = files_bytes(&entry)?;
                if remove(&entry, dry_run, Removal::Tree)? {
                    reclaimed.add(bytes);
                }
            }
        }
    }
    Ok(reclaimed)
}

/// A pool object's name is its digest, filed under the digest's first byte.
fn is_object_name(name: &str, shard: &str) -> bool {
    name.starts_with(shard) && shard.len() == 2 && ChunkDigest::try_from(name.to_string()).is_ok()
}

#[cfg(unix)]
fn link_count(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Some(metadata.nlink())
}

/// Without a link count there is no way to tell a shared object from garbage,
/// so nothing is reclaimed.
#[cfg(not(unix))]
fn link_count(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

#[derive(Debug, Clone, Copy)]
enum Removal {
    File,
    Tree,
}

/// Remove `path` unless this is a dry run. `false` when something else removed
/// it first, so it is not counted twice.
fn remove(path: &Path, dry_run: bool, removal: Removal) -> Result<bool> {
    if dry_run {
        return Ok(true);
    }
    let removed = match removal {
        Removal::File => std::fs::remove_file(path),
        Removal::Tree => std::fs::remove_dir_all(path),
    };
    match removed {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn read_dir(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("reading {}", dir.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("reading {}", dir.display())),
    }
}

fn subdirectories(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for entry in read_dir(dir)? {
        if entry
            .file_type()
            .with_context(|| format!("reading {}", entry.path().display()))?
            .is_dir()
        {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Bytes of the regular files directly in `dir`: a materialization holds its
/// blob and its index, nothing nested.
fn files_bytes(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in read_dir(dir)? {
        let metadata = entry
            .metadata()
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

    use super::*;
    use crate::checkpoint::chunks::{CHUNK_SIZE, regular_files_recursive, stored_chunk_paths};
    use crate::checkpoint::{CaptureFsQuickParams, capture_fs_quick, verify_content};

    /// A pid far above any `pid_max`, so no live process can hold it.
    const DEAD_PID: u32 = 999_999_999;

    fn chunk(byte: u8) -> Vec<u8> {
        vec![byte; CHUNK_SIZE]
    }

    /// Capture an fs_quick checkpoint whose rootfs is `chunks`, concatenated.
    fn capture(
        store: &CheckpointStore,
        dir: &Path,
        id: &str,
        chunks: &[Vec<u8>],
    ) -> CheckpointMeta {
        let source = dir.join(id);
        std::fs::create_dir_all(&source).unwrap();
        let rootfs = source.join("rootfs.ext4");
        let mut file = std::fs::File::create(&rootfs).unwrap();
        for bytes in chunks {
            file.write_all(bytes).unwrap();
        }
        let params = CaptureFsQuickParams::builder()
            .id(CheckpointId::new(id))
            .vm_name(format!("{id}-vm"))
            .rootfs(rootfs)
            .supervisor_config_digest("d".into())
            .created_unix(1)
            .quiesced(true)
            .build()
            .unwrap();
        capture_fs_quick(store, params).unwrap()
    }

    fn pool_objects(store: &CheckpointStore) -> Vec<PathBuf> {
        regular_files_recursive(&store.root().join(OBJECTS_DIR)).unwrap()
    }

    fn object_names(paths: &[PathBuf]) -> BTreeSet<String> {
        paths.iter().map(|path| file_name(path)).collect()
    }

    fn rootfs_chunk_names(store: &CheckpointStore, meta: &CheckpointMeta) -> BTreeSet<String> {
        let blob = meta
            .content
            .iter()
            .find(|blob| blob.name == "rootfs.ext4")
            .unwrap();
        object_names(&stored_chunk_paths(&store.content_dir(&meta.id), blob).unwrap())
    }

    #[test]
    fn removing_one_of_two_sharing_checkpoints_reclaims_only_what_it_alone_used() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let first = capture(&store, tmp.path(), "first", &[chunk(1), chunk(2), chunk(3)]);
        let second = capture(
            &store,
            tmp.path(),
            "second",
            &[chunk(1), chunk(2), chunk(4)],
        );

        let untouched = prune_unreferenced_content(&store, false).unwrap();
        assert_eq!(untouched.objects, 0, "every object is still linked");
        assert_eq!(pool_objects(&store).len(), 4);

        store.remove(&first.id).unwrap();
        let report = prune_unreferenced_content(&store, false).unwrap();

        let only_first: BTreeSet<_> = rootfs_chunk_names(&store, &second)
            .symmetric_difference(&object_names(&pool_objects(&store)))
            .cloned()
            .collect();
        assert!(
            only_first.is_empty(),
            "pool must hold exactly second's chunks"
        );
        assert_eq!(report.objects, 1);
        assert_eq!(report.object_bytes, CHUNK_SIZE as u64);
        verify_content(&store, &second).unwrap();
    }

    #[test]
    fn a_referenced_object_is_never_reclaimed_even_when_its_checkpoint_is_the_last() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let only = capture(&store, tmp.path(), "only", &[chunk(7), chunk(8)]);

        let report = prune_unreferenced_content(&store, false).unwrap();

        assert!(report.is_empty(), "{report:?}");
        for object in pool_objects(&store) {
            assert_eq!(std::fs::metadata(object).unwrap().nlink(), 2);
        }
        verify_content(&store, &only).unwrap();
    }

    #[test]
    fn a_dry_run_reports_what_a_prune_removes_and_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let gone = capture(&store, tmp.path(), "gone", &[chunk(5), chunk(6)]);
        store.remove(&gone.id).unwrap();

        let dry = prune_unreferenced_content(&store, true).unwrap();
        assert_eq!(pool_objects(&store).len(), 2);
        let real = prune_unreferenced_content(&store, false).unwrap();

        assert_eq!(dry, real);
        assert_eq!(real.objects, 2);
        assert!(pool_objects(&store).is_empty());
    }

    #[test]
    fn abandoned_staging_and_the_objects_only_it_linked_go_in_one_run() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let kept = capture(&store, tmp.path(), "kept", &[chunk(1)]);
        // A capture that died after linking its chunks: its staging holds the
        // only link besides the pool's.
        let staged_content = store
            .root()
            .join(STAGING_DIR)
            .join(format!("{DEAD_PID}-1-0-crashed"))
            .join("content");
        std::fs::create_dir_all(&staged_content).unwrap();
        let pool = chunks::ObjectPool::new(store.root(), &Default::default()).unwrap();
        pool.store_and_link(&staged_content, &chunk(9)).unwrap();
        pool.store_and_link(&staged_content, &chunk(1)).unwrap();

        let report = prune_unreferenced_content(&store, false).unwrap();

        assert_eq!(report.abandoned_staging, 1);
        assert_eq!(report.objects, 1, "chunk 1 is still kept's");
        assert!(!staged_content.exists());
        verify_content(&store, &kept).unwrap();
    }

    #[test]
    fn only_a_stale_unfinished_object_write_is_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        capture(&store, tmp.path(), "c", &[chunk(1)]);
        let shard = pool_objects(&store)[0].parent().unwrap().to_path_buf();
        let stale = shard.join(format!("{OBJECT_TEMP_PREFIX}stale"));
        let fresh = shard.join(format!("{OBJECT_TEMP_PREFIX}fresh"));
        let stranger = shard.join("not-an-object");
        for path in [&stale, &fresh, &stranger] {
            std::fs::write(path, b"partial").unwrap();
        }
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(SystemTime::now() - STALE_OBJECT_TEMP_AGE - Duration::from_secs(1))
            .unwrap();

        let reclaimed = sweep_pool(store.root(), false, SystemTime::now()).unwrap();

        assert_eq!(reclaimed.count, 1);
        assert!(!stale.exists());
        assert!(fresh.exists());
        assert!(stranger.exists());
    }

    #[test]
    fn a_cached_materialization_goes_with_the_last_checkpoint_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let kept = capture(&store, tmp.path(), "kept", &[chunk(1), chunk(2)]);
        let gone = capture(&store, tmp.path(), "gone", &[chunk(3), chunk(4)]);
        for meta in [&kept, &gone] {
            let scratch = tempfile::tempdir().unwrap();
            crate::checkpoint::materialized_source(&store, meta, "rootfs.ext4", scratch.path())
                .unwrap();
        }
        let cached_digest = |meta: &CheckpointMeta| {
            let blob = &meta.content[0];
            chunks::materialization_blob_cache_root(store.root(), &meta.key_domain, &blob.name)
                .join(&blob.sha256)
        };
        assert!(cached_digest(&kept).is_dir());
        assert!(cached_digest(&gone).is_dir());

        store.remove(&gone.id).unwrap();
        let report = prune_unreferenced_content(&store, false).unwrap();

        assert_eq!(report.materializations, 1);
        assert!(report.materialization_bytes >= 2 * CHUNK_SIZE as u64);
        assert!(cached_digest(&kept).is_dir());
        assert!(!cached_digest(&gone).exists());
    }

    #[test]
    fn a_blob_cache_a_restore_holds_is_left_for_the_next_prune() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let gone = capture(&store, tmp.path(), "gone", &[chunk(3)]);
        let scratch = tempfile::tempdir().unwrap();
        crate::checkpoint::materialized_source(&store, &gone, "rootfs.ext4", scratch.path())
            .unwrap();
        let blob = &gone.content[0];
        let cache_root =
            chunks::materialization_blob_cache_root(store.root(), &gone.key_domain, &blob.name);
        store.remove(&gone.id).unwrap();

        let held = mvm_core::atomic_io::FileLock::acquire(&cache_root).unwrap();
        let skipped = prune_unreferenced_content(&store, false).unwrap();
        assert_eq!(skipped.materializations, 0);
        assert!(cache_root.join(&blob.sha256).is_dir());
        drop(held);
        let swept = prune_unreferenced_content(&store, false).unwrap();

        assert_eq!(swept.materializations, 1);
        assert!(!cache_root.join(&blob.sha256).exists());
    }

    /// Stops the sweeper when the capturing side finishes or panics, so a
    /// failed assertion fails the test instead of hanging it.
    struct StopOnDrop<'a>(&'a AtomicBool);

    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn captures_racing_a_prune_always_link_a_verified_object() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let pool = chunks::ObjectPool::new(store.root(), &Default::default()).unwrap();
        let stop = AtomicBool::new(false);

        let swept = std::thread::scope(|scope| {
            let sweeper = scope.spawn(|| {
                let mut swept = 0;
                while !stop.load(Ordering::Relaxed) {
                    swept += sweep_pool(store.root(), false, SystemTime::now())
                        .unwrap()
                        .count;
                }
                swept
            });
            let stop_guard = StopOnDrop(&stop);
            for round in 0..200 {
                let content = tmp.path().join(format!("capture-{round}"));
                let entry = pool.store_and_link(&content, &chunk(0x42)).unwrap();
                let chunks::ChunkEntry::Object(digest) = entry else {
                    panic!("non-zero bytes must be stored");
                };
                let linked = std::fs::read(chunks::membership_path(&content, &digest)).unwrap();
                assert_eq!(ChunkDigest::from_bytes(&linked), digest);
                // Dropping the only checkpoint link turns the object back into
                // garbage, so the next round links it while a sweep may take it.
                std::fs::remove_dir_all(&content).unwrap();
            }
            drop(stop_guard);
            sweeper.join().unwrap()
        });
        assert!(
            swept > 0,
            "the sweep never reclaimed an object between rounds"
        );
    }
}
