use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use anyhow::{Context, Result, ensure};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

use super::MAX_META_BYTES;

const FILE_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
const DIRECTORY_FLAGS: libc::c_int = FILE_FLAGS | libc::O_DIRECTORY;

pub(super) fn read(root: &Path, id: &CheckpointId) -> Result<CheckpointMeta> {
    let id = CheckpointId::try_from_path_component(id.as_str())?;
    let root = open_root(root).context("opening checkpoints directory")?;
    let name = CString::new(id.as_str()).context("checkpoint directory name")?;
    let directory =
        open_at(&root, &name, DIRECTORY_FLAGS).context("opening checkpoint directory")?;
    let file =
        open_at(&directory, c"meta.json", FILE_FLAGS).context("opening checkpoint metadata")?;
    read_record(file, &id)
}

pub(super) fn list(root: &Path) -> Result<Vec<CheckpointMeta>> {
    let root = match open_root(root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("opening checkpoints directory"),
    };
    list_opened(&root)
}

fn open_root(root: &Path) -> io::Result<File> {
    // Ancestors are the caller's trusted prefix. Remove trailing separators
    // and current-directory components so O_NOFOLLOW checks the root itself.
    let root: PathBuf = root.components().collect();
    OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY_FLAGS)
        .open(root)
}

fn list_opened(root: &File) -> Result<Vec<CheckpointMeta>> {
    let mut entries = DirectoryEntries::new(root).context("enumerating checkpoints directory")?;
    let mut records = Vec::new();
    while let Some(name) = entries.next_name()? {
        if name.to_bytes().starts_with(b".") {
            continue;
        }
        let directory = match open_at(root, &name, DIRECTORY_FLAGS) {
            Ok(directory) => directory,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("opening checkpoint directory"),
        };
        let file = match open_at(&directory, c"meta.json", FILE_FLAGS) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("opening checkpoint metadata"),
        };
        let name = name
            .to_str()
            .context("checkpoint directory ID is not UTF-8")?;
        let id = CheckpointId::try_from_path_component(name)
            .context("invalid checkpoint directory ID")?;
        records.push(read_record(file, &id)?);
    }
    records.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    Ok(records)
}

fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the directory descriptor and NUL-terminated name remain live for
    // this call. Flags never include O_CREAT, so no mode argument is needed.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor whose ownership transfers here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_record(file: File, id: &CheckpointId) -> Result<CheckpointMeta> {
    let metadata = file.metadata().context("inspecting checkpoint metadata")?;
    ensure!(
        metadata.is_file(),
        "checkpoint metadata is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_META_BYTES,
        "checkpoint metadata exceeds 4 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_META_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading checkpoint metadata")?;
    ensure!(
        u64::try_from(bytes.len())? <= MAX_META_BYTES,
        "checkpoint metadata exceeds 4 MiB"
    );
    let record: CheckpointMeta =
        serde_json::from_slice(&bytes).context("parsing checkpoint metadata")?;
    ensure!(
        record.id == *id,
        "checkpoint metadata id {:?} does not match requested id {:?}",
        record.id.as_str(),
        id.as_str()
    );
    Ok(record)
}

struct DirectoryEntries(NonNull<libc::DIR>);

impl DirectoryEntries {
    fn new(root: &File) -> Result<Self> {
        clear_errno()?;
        // A separate open file description gives each enumeration its own cursor.
        let directory = open_at(root, c".", DIRECTORY_FLAGS)?;
        let fd = directory.into_raw_fd();
        // SAFETY: fd is an owned directory descriptor, transferred to DIR only
        // on success. The failure arm closes it through an owned File.
        let pointer = unsafe { libc::fdopendir(fd) };
        match NonNull::new(pointer) {
            Some(pointer) => Ok(Self(pointer)),
            None => {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed, so fd remains owned by this call.
                drop(unsafe { File::from_raw_fd(fd) });
                Err(error.into())
            }
        }
    }

    fn next_name(&mut self) -> Result<Option<CString>> {
        clear_errno()?;
        // SAFETY: this exclusively borrowed DIR remains live until Drop.
        let entry = unsafe { libc::readdir(self.0.as_ptr()) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(None)
            } else {
                Err(error).context("reading checkpoint directory entry")
            };
        }
        // SAFETY: readdir returned a NUL-terminated name valid until the next
        // call on this DIR. Copy it before that call or closedir can occur.
        Ok(Some(unsafe {
            CStr::from_ptr((*entry).d_name.as_ptr()).to_owned()
        }))
    }
}

impl Drop for DirectoryEntries {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the live DIR and its descriptor.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

#[cfg(any(target_os = "linux", target_os = "hurd", target_os = "dragonfly"))]
fn clear_errno() -> Result<()> {
    // SAFETY: libc returns this thread's writable errno slot.
    unsafe { *libc::__errno_location() = 0 };
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
fn clear_errno() -> Result<()> {
    // SAFETY: libc returns this thread's writable errno slot.
    unsafe { *libc::__errno() = 0 };
    Ok(())
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
fn clear_errno() -> Result<()> {
    // SAFETY: libc returns this thread's writable errno slot.
    unsafe { *libc::__error() = 0 };
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "hurd",
    target_os = "android",
    target_os = "netbsd",
    target_os = "openbsd",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly"
)))]
fn clear_errno() -> Result<()> {
    anyhow::bail!("secure checkpoint catalog enumeration is unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::super::CheckpointStore;
    use super::{DIRECTORY_FLAGS, FILE_FLAGS, list_opened, open_at, open_root, read_record};
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn write_record(root: &Path, directory: &str, id: &str) -> CheckpointMeta {
        let record = CheckpointMeta::builder(
            CheckpointId::new(id),
            CheckpointClass::FsQuick,
            "catalog-fixture".to_owned(),
        )
        .build();
        let directory = root.join(directory);
        std::fs::create_dir_all(&directory).expect("checkpoint directory");
        std::fs::write(
            directory.join("meta.json"),
            serde_json::to_vec(&record).expect("serialize metadata"),
        )
        .expect("write metadata");
        record
    }

    #[test]
    fn listing_refuses_metadata_symlinks_even_when_the_record_id_matches() {
        let root = tempfile::tempdir().expect("catalog");
        let outside = tempfile::tempdir().expect("outside catalog");
        write_record(outside.path(), "alpha", "alpha");
        let directory = root.path().join("alpha");
        std::fs::create_dir(&directory).expect("checkpoint directory");
        std::os::unix::fs::symlink(
            outside.path().join("alpha/meta.json"),
            directory.join("meta.json"),
        )
        .expect("metadata symlink");

        assert!(
            CheckpointStore::at(root.path()).list().is_err(),
            "a matching embedded ID must not authorize following metadata outside the catalog"
        );
        assert!(
            CheckpointStore::at(root.path())
                .read_meta(&CheckpointId::new("alpha"))
                .is_err(),
            "direct reads must enforce the same no-follow rule"
        );
    }

    #[test]
    fn replacing_the_root_does_not_redirect_an_open_catalog() {
        let parent = tempfile::tempdir().expect("catalog parent");
        let outside = tempfile::tempdir().expect("outside catalog");
        let root = parent.path().join("catalog");
        let expected = write_record(&root, "alpha", "alpha");
        write_record(outside.path(), "beta", "beta");
        let held = open_root(&root).expect("open catalog");
        std::fs::rename(&root, parent.path().join("retained")).expect("move original catalog");
        std::os::unix::fs::symlink(outside.path(), &root).expect("replace catalog path");

        assert_eq!(
            list_opened(&held).expect("held catalog"),
            vec![expected.clone()]
        );
        assert_eq!(
            list_opened(&held).expect("fresh enumeration cursor"),
            vec![expected]
        );
        assert!(CheckpointStore::at(&root).list().is_err());
    }

    #[test]
    fn root_no_follow_does_not_depend_on_trailing_slashes_or_dots() {
        let parent = tempfile::tempdir().expect("catalog parent");
        let outside = tempfile::tempdir().expect("outside catalog");
        let expected = write_record(outside.path(), "alpha", "alpha");
        let alias = parent.path().join("alias");
        std::os::unix::fs::symlink(outside.path(), &alias).expect("root symlink");
        for suffix in ["", "/", "/."] {
            let spelling = format!("{}{suffix}", alias.display());
            let store = CheckpointStore::at(&spelling);
            assert!(store.list().is_err(), "followed {spelling}");
            assert!(
                store.read_meta(&expected.id).is_err(),
                "followed {spelling}"
            );

            let real = CheckpointStore::at(format!("{}{suffix}", outside.path().display()));
            assert_eq!(real.list().expect("real directory"), vec![expected.clone()]);
        }
    }

    #[test]
    fn replacing_a_directory_does_not_redirect_its_open_metadata() {
        let root = tempfile::tempdir().expect("catalog");
        let outside = tempfile::tempdir().expect("outside catalog");
        let expected = write_record(root.path(), "alpha", "alpha");
        write_record(outside.path(), "alpha", "outside");
        let held_root = open_root(root.path()).expect("open catalog");
        let held = open_at(&held_root, c"alpha", DIRECTORY_FLAGS).expect("open checkpoint");
        std::fs::rename(root.path().join("alpha"), root.path().join("retained"))
            .expect("move checkpoint directory");
        std::os::unix::fs::symlink(outside.path().join("alpha"), root.path().join("alpha"))
            .expect("replace checkpoint directory");

        let file = open_at(&held, c"meta.json", FILE_FLAGS).expect("open retained metadata");
        assert_eq!(
            read_record(file, &expected.id).expect("read retained record"),
            expected
        );
        assert!(
            CheckpointStore::at(root.path())
                .read_meta(&CheckpointId::new("alpha"))
                .is_err()
        );
    }

    #[test]
    fn replacing_metadata_does_not_redirect_the_open_file() {
        let root = tempfile::tempdir().expect("catalog");
        let outside = tempfile::tempdir().expect("outside catalog");
        let expected = write_record(root.path(), "alpha", "alpha");
        write_record(outside.path(), "alpha", "outside");
        let held_root = open_root(root.path()).expect("open catalog");
        let held = open_at(&held_root, c"alpha", DIRECTORY_FLAGS).expect("open checkpoint");
        let file = open_at(&held, c"meta.json", FILE_FLAGS).expect("open metadata");
        std::fs::rename(
            root.path().join("alpha/meta.json"),
            root.path().join("alpha/retained.json"),
        )
        .expect("move metadata");
        std::os::unix::fs::symlink(
            outside.path().join("alpha/meta.json"),
            root.path().join("alpha/meta.json"),
        )
        .expect("replace metadata");
        assert_eq!(
            read_record(file, &expected.id).expect("read retained file"),
            expected
        );
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).expect("FIFO path");
        // SAFETY: path is a live NUL-terminated pathname in our temporary directory.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn nonregular_roots_and_metadata_are_refused_without_waiting_for_a_writer() {
        let root = tempfile::tempdir().expect("catalog");
        let fifo_root = root.path().join("fifo-root");
        make_fifo(&fifo_root);
        assert!(CheckpointStore::at(&fifo_root).list().is_err());
        let file_root = root.path().join("file-root");
        std::fs::write(&file_root, b"not a directory").expect("file root");
        assert!(CheckpointStore::at(&file_root).list().is_err());

        let directory = root.path().join("alpha");
        std::fs::create_dir(&directory).expect("checkpoint");
        let metadata = directory.join("meta.json");
        make_fifo(&metadata);
        let store = CheckpointStore::at(root.path());
        assert!(store.list().is_err());
        assert!(store.read_meta(&CheckpointId::new("alpha")).is_err());
        std::fs::remove_file(&metadata).expect("remove FIFO");
        std::fs::create_dir(&metadata).expect("nonregular metadata directory");
        assert!(store.list().is_err());
    }

    #[test]
    fn invalid_directory_ids_and_malformed_records_are_refused() {
        let root = tempfile::tempdir().expect("catalog");
        write_record(root.path(), "bad..id", "bad..id");
        assert!(CheckpointStore::at(root.path()).list().is_err());
        let directory = root.path().join("bad..id");
        std::fs::rename(&directory, root.path().join("alpha")).expect("rename checkpoint");
        std::fs::write(root.path().join("alpha/meta.json"), b"{").expect("malformed metadata");
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_names_are_filtered_before_actual_checkpoint_ids_require_utf8() {
        let root = tempfile::tempdir().expect("catalog");
        let stray = std::ffi::OsStr::from_bytes(b"stray-\xff");
        std::fs::write(root.path().join(stray), b"stray").expect("non-UTF8 stray file");
        let stage = std::ffi::OsStr::from_bytes(b".stage-\xff");
        std::fs::create_dir(root.path().join(stage)).expect("non-UTF8 staging directory");
        let id = std::ffi::OsStr::from_bytes(b"checkpoint-\xff");
        let directory = root.path().join(id);
        std::fs::create_dir(&directory).expect("non-UTF8 directory");
        let store = CheckpointStore::at(root.path());
        assert!(
            store
                .list()
                .expect("non-checkpoints are ignored")
                .is_empty()
        );
        std::fs::write(directory.join("meta.json"), b"{}").expect("actual record");
        assert!(
            format!("{:#}", store.list().expect_err("non-UTF8 checkpoint ID"))
                .contains("checkpoint directory ID is not UTF-8")
        );
    }

    #[test]
    fn full_and_legacy_records_keep_their_json_and_digest_contracts() {
        let wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mvm-core/tests/fixtures/checkpoint-list.json"
        )))
        .expect("shared fixture");
        let records: Vec<CheckpointMeta> = serde_json::from_value(wire.clone()).expect("metadata");
        let root = tempfile::tempdir().expect("catalog");
        let store = CheckpointStore::at(root.path());
        for record in records.iter().rev() {
            assert_eq!(record.compute_meta_digest(), record.meta_digest);
            store.write_meta(record).expect("persist metadata");
            assert_eq!(store.read_meta(&record.id).expect("read metadata"), *record);
        }
        let listed = store.list().expect("list");
        assert_eq!(listed, records);
        assert_eq!(serde_json::to_value(listed).expect("serialized list"), wire);
    }

    #[test]
    fn listing_binds_metadata_to_its_directory_id() {
        let root = tempfile::tempdir().expect("catalog");
        write_record(root.path(), "alpha", "other");
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[test]
    fn listing_is_sorted_and_preserves_complete_records() {
        let root = tempfile::tempdir().expect("catalog");
        let zeta = write_record(root.path(), "zeta", "zeta");
        let alpha = write_record(root.path(), "alpha", "alpha");
        assert_eq!(
            CheckpointStore::at(root.path()).list().expect("list"),
            vec![alpha, zeta]
        );
    }

    #[test]
    fn listing_skips_staging_files_and_symlinked_directories() {
        let root = tempfile::tempdir().expect("catalog");
        let outside = tempfile::tempdir().expect("outside catalog");
        write_record(root.path(), ".stage", "hidden");
        write_record(outside.path(), "linked", "linked");
        std::fs::write(root.path().join("stray"), b"not a checkpoint").expect("stray file");
        std::fs::create_dir(root.path().join("unfinished")).expect("unfinished directory");
        std::os::unix::fs::symlink(outside.path().join("linked"), root.path().join("linked"))
            .expect("checkpoint directory symlink");
        assert!(
            CheckpointStore::at(root.path())
                .list()
                .expect("list")
                .is_empty()
        );
        assert!(
            CheckpointStore::at(root.path().join("missing"))
                .list()
                .expect("missing catalog")
                .is_empty()
        );
    }

    #[test]
    fn listing_refuses_oversized_metadata_before_parsing() {
        let root = tempfile::tempdir().expect("catalog");
        let record = write_record(root.path(), "alpha", "alpha");
        let mut bytes = serde_json::to_vec(&record).expect("metadata");
        bytes.resize(4 * 1024 * 1024 + 1, b' ');
        std::fs::write(root.path().join("alpha/meta.json"), bytes).expect("large metadata");
        assert!(CheckpointStore::at(root.path()).list().is_err());
    }

    #[test]
    fn oversized_metadata_is_not_published_or_allowed_to_replace_a_record() {
        let root = tempfile::tempdir().expect("catalog");
        let original = write_record(root.path(), "alpha", "alpha");
        let path = root.path().join("alpha/meta.json");
        let bytes = std::fs::read(&path).expect("original metadata");
        let mut oversized = original;
        oversized.audit_ref = Some("x".repeat(4 * 1024 * 1024));

        assert!(
            CheckpointStore::at(root.path())
                .write_meta(&oversized)
                .is_err()
        );
        assert_eq!(std::fs::read(&path).expect("preserved metadata"), bytes);
        let absent = root.path().join("absent");
        assert!(CheckpointStore::at(&absent).write_meta(&oversized).is_err());
        assert!(
            !absent.exists(),
            "refusal must not create a partial catalog"
        );
    }
}
