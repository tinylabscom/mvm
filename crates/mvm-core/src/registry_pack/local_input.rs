//! Bounded regular input handles shared by registry verification and copying.

use std::fs::File;
use std::io::{self, Read};
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

pub const MAX_METADATA_BYTES: u64 = 1024 * 1024;

/// Atomic directory publication that never replaces even an empty destination.
pub(crate) fn publish_noclobber(source: &Path, output: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            output,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, output);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Read a small local sidecar without following links or blocking on a FIFO.
pub fn read_metadata(path: &Path) -> io::Result<Vec<u8>> {
    let file = open_path(path, false)?;
    regular(&file, None)?;
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(io::Error::other("registry metadata exceeds 1 MiB"));
    }
    Ok(bytes)
}

pub(super) fn open_payload(root: &Path, name: &str, size: u64) -> io::Result<File> {
    let directory = open_path(root, true)?;
    let file = open_beneath(directory, Path::new(name), false)?;
    regular(&file, Some(size))?;
    Ok(file)
}

pub(super) fn open_sized_regular(path: &Path, size: u64) -> io::Result<File> {
    let file = open_path(path, false)?;
    regular(&file, Some(size))?;
    Ok(file)
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    open_path(path, true)?.sync_all()
}

pub(super) fn ensure_unchanged(
    input: &File,
    before: &std::fs::Metadata,
    root: &Path,
    name: &str,
    size: u64,
) -> io::Result<()> {
    let reopened = open_payload(root, name, size)?;
    let after = input.metadata()?;
    let current = reopened.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let fingerprint = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.nlink(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        if fingerprint(before) != fingerprint(&after)
            || fingerprint(before) != fingerprint(&current)
        {
            return Err(io::Error::other(
                "registry payload changed during bounded read",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (before, after, current);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn regular(file: &File, size: Option<u64>) -> io::Result<()> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    let single_link = {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    };
    #[cfg(not(unix))]
    let single_link = false;
    if !metadata.is_file()
        || !single_link
        || size.is_some_and(|size| metadata.len() != size)
        || size.is_none() && metadata.len() > MAX_METADATA_BYTES
    {
        return Err(io::Error::other(
            "input must be a bounded single-link regular file",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_path(path: &Path, directory: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::other(
            "local input path must not be empty or contain parent traversal",
        ));
    }
    let Some(name) = path.file_name() else {
        if !directory || !(path == Path::new("/") || path == Path::new(".")) {
            return Err(io::Error::other("local input path has no final component"));
        }
        return File::open(path);
    };
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Resolve platform aliases such as macOS /tmp -> /private/tmp before
    // anchoring traversal. The final component is still opened relative to
    // that held directory with NOFOLLOW, so a leaf symlink remains refused.
    let canonical_parent = std::fs::canonicalize(parent_path)?;
    let root = File::open("/")?;
    let parent = open_beneath(root, &canonical_parent, true)?;
    let flags = OFlags::RDONLY
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if directory {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
    Ok(File::from(rustix::fs::openat(
        &parent,
        name,
        flags,
        Mode::empty(),
    )?))
}

#[cfg(unix)]
fn open_beneath(mut parent: File, path: &Path, directory: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let components = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir));
    let mut components = components.peekable();
    while let Some(part) = components.next() {
        if matches!(part, Component::CurDir) {
            continue;
        }
        let Component::Normal(name) = part else {
            return Err(io::Error::other(
                "local input path must not contain parent traversal",
            ));
        };
        let is_directory = directory || components.peek().is_some();
        let flags = OFlags::RDONLY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | if is_directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        parent = File::from(rustix::fs::openat(&parent, name, flags, Mode::empty())?);
    }
    Ok(parent)
}

#[cfg(not(unix))]
fn open_path(_path: &Path, _directory: bool) -> io::Result<File> {
    Err(io::Error::other(
        "safe local acquisition requires Unix input handles",
    ))
}

#[cfg(not(unix))]
fn open_beneath(_parent: File, _path: &Path, _directory: bool) -> io::Result<File> {
    Err(io::Error::other(
        "safe local acquisition requires Unix input handles",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn metadata_limits_and_single_link_regular_handles_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest");
        std::fs::write(&path, b"metadata").unwrap();
        assert_eq!(read_metadata(&path).unwrap(), b"metadata");
        std::fs::hard_link(&path, dir.path().join("alias")).unwrap();
        assert!(read_metadata(&path).is_err());
        std::fs::remove_file(dir.path().join("alias")).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_METADATA_BYTES + 1)
            .unwrap();
        assert!(read_metadata(&path).is_err());
        assert!(read_metadata(&dir.path().join("../manifest")).is_err());
    }

    #[test]
    fn ordinary_tmp_symlink_aliases_are_supported_without_following_leaf_links() {
        let canonical_tmp = std::fs::canonicalize("/tmp").unwrap();
        let dir = tempfile::Builder::new()
            .prefix("mvm-local-input-")
            .tempdir_in(&canonical_tmp)
            .unwrap();
        let alias = Path::new("/tmp")
            .join(dir.path().file_name().unwrap())
            .join("manifest");
        std::fs::write(&alias, b"metadata").unwrap();

        assert_eq!(read_metadata(&alias).unwrap(), b"metadata");
        assert!(
            open_path(alias.parent().unwrap(), true)
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );

        let target = alias.with_file_name("target");
        let link = alias.with_file_name("linked-manifest");
        std::fs::write(&target, b"metadata").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_metadata(&link).is_err());
    }

    #[test]
    fn descriptor_walk_refuses_symlink_parents_and_fifo_replacement() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pack")).unwrap();
        let path = dir.path().join("pack/input");
        std::fs::write(&path, b"original").unwrap();
        let mut held = open_payload(dir.path(), "pack/input", 8).unwrap();
        let before = held.metadata().unwrap();
        std::fs::rename(&path, dir.path().join("original")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        // Replacement cannot turn an already-open regular handle into a FIFO;
        // the next copy-open rejects it without waiting for a writer.
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(ensure_unchanged(&held, &before, dir.path(), "pack/input", 8).is_err());
        assert!(open_payload(dir.path(), "pack/input", 8).is_err());
        std::fs::rename(dir.path().join("pack"), dir.path().join("saved-pack")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("saved-pack"), dir.path().join("pack")).unwrap();
        assert!(open_payload(dir.path(), "pack/input", 8).is_err());
    }

    #[test]
    fn no_clobber_publish_preserves_even_an_empty_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("member"), b"signed").unwrap();
        std::fs::create_dir(&destination).unwrap();
        assert!(publish_noclobber(&source, &destination).is_err());
        assert!(source.join("member").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    }
}
