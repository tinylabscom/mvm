//! Descriptor-bound catalog reads; paths are never reopened after inspection.

use std::fs::File;
use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use super::CheckpointStore;

// Metadata is small even for checkpoints with many content blobs. Bound both
// the initial size and the read so a concurrently growing file cannot exhaust memory.
const MAX_META_BYTES: u64 = 16 * 1024 * 1024;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy)]
enum MissingMetadata {
    Skip,
    Refuse,
}

pub(super) fn list(store: &CheckpointStore) -> Result<Vec<CheckpointMeta>> {
    list_with_policy(store, MissingMetadata::Skip)
}

/// Destructive guards cannot infer absent dependents from incomplete directories.
pub(super) fn list_for_removal(store: &CheckpointStore) -> Result<Vec<CheckpointMeta>> {
    list_with_policy(store, MissingMetadata::Refuse)
}

fn list_with_policy(
    store: &CheckpointStore,
    missing_metadata: MissingMetadata,
) -> Result<Vec<CheckpointMeta>> {
    // Ancestors remain the caller's trusted prefix. Strip trailing separators
    // and current-directory components so NOFOLLOW checks the catalog itself.
    let root: std::path::PathBuf = store.root.components().collect();
    let root = match rustix::fs::open(&root, DIRECTORY, Mode::empty()) {
        Ok(root) => File::from(root),
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(error) => return Err(error).context("opening checkpoints directory"),
    };
    list_opened(&root, missing_metadata)
}

fn list_opened(root: &File, missing_metadata: MissingMetadata) -> Result<Vec<CheckpointMeta>> {
    let mut records = Vec::new();
    for entry in rustix::fs::Dir::read_from(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes().starts_with(b".") {
            continue;
        }
        // Do not trust d_type: some filesystems return Unknown.
        let stat = rustix::fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            continue;
        }
        let directory = File::from(rustix::fs::openat(root, name, DIRECTORY, Mode::empty())?);
        let file = match rustix::fs::openat(
            &directory,
            "meta.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) if matches!(missing_metadata, MissingMetadata::Skip) => {
                continue;
            }
            Err(error) => return Err(error).context("opening checkpoint metadata"),
        };
        // Ignore unrelated entries before requiring a checkpoint's lossless ID.
        let name = name
            .to_str()
            .context("checkpoint directory id is not UTF-8")?;
        let id = CheckpointId::try_from_path_component(name)?;
        records.push(read_record(file, &id)?);
    }
    records.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    Ok(records)
}

fn read_record(file: File, id: &CheckpointId) -> Result<CheckpointMeta> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "checkpoint metadata is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_META_BYTES,
        "checkpoint metadata exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_META_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_META_BYTES,
        "checkpoint metadata exceeds size limit"
    );
    let record: CheckpointMeta =
        serde_json::from_slice(&bytes).context("parsing checkpoint metadata")?;
    if record.id != *id {
        bail!("checkpoint metadata id does not match directory id {id:?}");
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::CheckpointClass;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    fn seed(root: &std::path::Path, id: &str) -> CheckpointMeta {
        let meta =
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm").build();
        std::fs::create_dir_all(root.join(id)).unwrap();
        CheckpointStore::at(root).write_meta(&meta).unwrap();
        meta
    }

    #[test]
    fn list_preserves_metadata_in_id_order_and_omits_non_checkpoints() {
        let root = tempfile::tempdir().unwrap();
        let z = seed(root.path(), "z");
        let a = seed(root.path(), "a");
        seed(root.path(), ".staging");
        std::fs::create_dir(root.path().join("unfinished")).unwrap();
        std::fs::write(root.path().join("unrelated"), b"not a checkpoint").unwrap();
        symlink(root.path().join("a"), root.path().join("alias")).unwrap();
        assert_eq!(CheckpointStore::at(root.path()).list().unwrap(), vec![a, z]);
        assert!(
            CheckpointStore::at(root.path().join("missing"))
                .list()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn removal_requires_metadata_for_every_visible_directory_but_listing_does_not() {
        let root = tempfile::tempdir().unwrap();
        let parent = seed(root.path(), "parent");
        std::fs::create_dir_all(root.path().join(".staging/incomplete")).unwrap();
        std::fs::write(root.path().join("unrelated"), b"not a directory").unwrap();
        let store = CheckpointStore::at(root.path());
        assert_eq!(list_for_removal(&store).unwrap(), vec![parent.clone()]);
        std::fs::create_dir(root.path().join("unknown")).unwrap();
        assert_eq!(store.list().unwrap(), vec![parent]);
        assert!(list_for_removal(&store).is_err());
    }

    #[test]
    fn root_no_follow_is_independent_of_trailing_path_spelling() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("catalog");
        let expected = seed(&root, "a");
        let link = parent.path().join("alias");
        symlink(&root, &link).unwrap();

        for suffix in ["", "/", "/.", "/./"] {
            let real = format!("{}{suffix}", root.display());
            assert_eq!(
                CheckpointStore::at(&real).list().unwrap(),
                vec![expected.clone()],
                "real directory spelling {real}"
            );
            let alias = format!("{}{suffix}", link.display());
            assert!(
                CheckpointStore::at(&alias).list().is_err(),
                "followed symlink root {alias}"
            );
        }
    }

    #[test]
    fn list_refuses_symlink_root_and_metadata_and_wrong_id() {
        let root = tempfile::tempdir().unwrap();
        seed(root.path(), "a");
        let link = root.path().join("root-link");
        symlink(root.path(), &link).unwrap();
        assert!(CheckpointStore::at(link).list().is_err());
        let meta = root.path().join("a/meta.json");
        std::fs::rename(&meta, root.path().join("outside.json")).unwrap();
        symlink(root.path().join("outside.json"), &meta).unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
        std::fs::remove_file(&meta).unwrap();
        std::fs::create_dir(&meta).unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
        std::fs::remove_dir(&meta).unwrap();
        let mut record = seed(root.path(), "a");
        record.id = CheckpointId::new("other");
        std::fs::write(meta, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[test]
    fn list_refuses_malformed_and_oversize_metadata() {
        let root = tempfile::tempdir().unwrap();
        seed(root.path(), "a");
        let path = root.path().join("a/meta.json");
        std::fs::write(&path, b"{}").unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
        let file = File::create(path).unwrap();
        file.set_len(MAX_META_BYTES + 1).unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[test]
    fn list_refuses_regular_file_roots() {
        let root = tempfile::NamedTempFile::new().unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn list_refuses_fifo_roots_and_metadata_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(CheckpointStore::at(&fifo).list().is_err());
        seed(root.path(), "a");
        let path = root.path().join("a/meta.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(fifo, path).unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[test]
    fn list_uses_held_root_and_record_handles_after_path_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("catalog");
        let original = seed(&root, "a");
        let held = File::from(rustix::fs::open(&root, DIRECTORY, Mode::empty()).unwrap());
        std::fs::rename(&root, parent.path().join("moved")).unwrap();
        symlink(parent.path().join("outside"), &root).unwrap();
        assert_eq!(
            list_opened(&held, MissingMetadata::Skip).unwrap(),
            vec![original.clone()]
        );
        let path = parent.path().join("moved/a/meta.json");
        let file = File::open(&path).unwrap();
        std::fs::rename(&path, path.with_file_name("old.json")).unwrap();
        symlink(parent.path().join("outside"), &path).unwrap();
        assert_eq!(read_record(file, &original.id).unwrap(), original);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn list_filters_non_utf8_unrelated_entries_but_refuses_checkpoint_ids() {
        let root = tempfile::tempdir().unwrap();
        let name = std::ffi::OsString::from_vec(vec![0xff]);
        let path = root.path().join(&name);
        std::fs::write(&path, b"unrelated").unwrap();
        assert!(CheckpointStore::at(root.path()).list().unwrap().is_empty());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(CheckpointStore::at(root.path()).list().unwrap().is_empty());
        std::fs::write(path.join("meta.json"), b"{}").unwrap();
        assert!(CheckpointStore::at(root.path()).list().is_err());
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::create_dir(
            root.path()
                .join(std::ffi::OsString::from_vec(vec![b'.', 0xff])),
        )
        .unwrap();
        assert!(CheckpointStore::at(root.path()).list().unwrap().is_empty());
    }
}
