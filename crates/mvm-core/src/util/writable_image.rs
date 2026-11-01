//! Cooperating writer exclusion for an already-open image and its sidecar.
//!
//! These live descriptors are resources, not admission or terminal-state proof.
//! There is deliberately no explicit unlock on drop: an inherited duplicate must
//! keep exclusion until the last owner of the open file description closes it.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::FdFlags;

/// Owns the locked writable backing and its existing sidecar lock together.
///
/// This is advisory exclusion between cooperating openers, not mandatory access
/// control. Paths, timestamps and a successful lock do not establish absence of
/// older writers that do not participate in this protocol.
#[must_use = "retain both descriptors until the actual writer relinquishes them"]
#[derive(Debug)]
pub struct LockedWritableImage {
    backing: File,
    sidecar: File,
}

impl LockedWritableImage {
    /// Open the backing and open/create its sidecar without following final symlinks.
    /// Sidecar creation never creates, truncates, or resizes the backing image.
    pub fn open(backing: &Path, sidecar: &Path) -> io::Result<Self> {
        let open = |path: &Path, extra: OFlags, mode: Mode| {
            rustix::fs::open(
                path,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | extra,
                mode,
            )
            .map(File::from)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("open writable image resource {}: {error}", path.display()),
                )
            })
        };
        let backing = open(backing, OFlags::empty(), Mode::empty())?;
        let sidecar = open(sidecar, OFlags::CREATE, Mode::from_raw_mode(0o600))?;
        Self::acquire(backing, sidecar)
    }

    /// Validate and nonblockingly lock the exact supplied files.
    ///
    /// A sidecar already locked through this same open description is retained,
    /// not explicitly unlocked/relocked. Neither file is reopened or truncated.
    ///
    /// # Errors
    ///
    /// Refuses non-regular, append-mode or non-read-write descriptors, the same
    /// underlying object in both roles, unavailable locks, or flag-setting errors.
    pub fn acquire(backing: File, sidecar: File) -> io::Result<Self> {
        protect_descriptor(&backing)?;
        protect_descriptor(&sidecar)?;
        validate_writable_file(&backing)?;
        validate_writable_file(&sidecar)?;
        if same_object(&backing, &sidecar)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "writable backing and sidecar must be distinct objects",
            ));
        }
        try_lock(&sidecar)?;
        try_lock(&backing)?;
        Ok(Self { backing, sidecar })
    }

    /// Borrow the exact backing for preparation or explicit descriptor transport.
    pub fn backing(&self) -> &File {
        &self.backing
    }

    /// Borrow the bare sidecar descriptor for explicit descriptor transport.
    pub fn sidecar(&self) -> &File {
        &self.sidecar
    }

    /// Transfer both resources to their actual writer without unlocking either.
    ///
    /// The receiver must retain both files through its final writes and flush.
    /// Closing one duplicate is not a terminal event for other descriptor owners.
    pub fn into_files(self) -> (File, File) {
        (self.backing, self.sidecar)
    }
}

/// The stable sidecar name shared with volume materialization.
pub fn sidecar_lock_path(image: &Path) -> PathBuf {
    let mut path = image.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

fn protect_descriptor(file: &File) -> io::Result<()> {
    let flags = rustix::io::fcntl_getfd(file)?;
    rustix::io::fcntl_setfd(file, flags | FdFlags::CLOEXEC)?;
    Ok(())
}

fn validate_writable_file(file: &File) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    if !file.metadata()?.is_file()
        || flags & OFlags::ACCMODE != OFlags::RDWR
        || flags.contains(OFlags::APPEND)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "writable image descriptors must be non-append read-write regular files",
        ));
    }
    Ok(())
}

fn same_object(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok((left.dev(), left.ino()) == (right.dev(), right.ino()))
}

fn try_lock(file: &File) -> io::Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "writable image or sidecar is already locked",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    fn writable(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    #[test]
    fn acquire_preserves_bytes_and_sets_close_on_exec() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let sidecar = tmp.path().join("image.lock");
        std::fs::write(&image, b"existing image bytes").unwrap();
        let held = LockedWritableImage::acquire(writable(&image), writable(&sidecar)).unwrap();
        assert_eq!(std::fs::read(&image).unwrap(), b"existing image bytes");
        for file in [held.backing(), held.sidecar()] {
            assert!(
                rustix::io::fcntl_getfd(file)
                    .unwrap()
                    .contains(FdFlags::CLOEXEC)
            );
        }
    }

    #[test]
    fn hardlink_alias_with_another_sidecar_still_contends() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let alias = tmp.path().join("alias");
        let held = LockedWritableImage::acquire(
            writable(&image),
            writable(&tmp.path().join("image.lock")),
        )
        .unwrap();
        std::fs::hard_link(&image, &alias).unwrap();
        let error = LockedWritableImage::acquire(
            writable(&alias),
            writable(&tmp.path().join("alias.lock")),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(held);
        let _reacquired = LockedWritableImage::acquire(
            writable(&alias),
            writable(&tmp.path().join("alias.lock")),
        )
        .unwrap();
    }

    #[test]
    fn dropping_the_source_guard_does_not_unlock_inherited_descriptions() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let sidecar = tmp.path().join("image.lock");
        let held = LockedWritableImage::acquire(writable(&image), writable(&sidecar)).unwrap();
        let backing_duplicate = held.backing().try_clone().unwrap();
        let sidecar_duplicate = held.sidecar().try_clone().unwrap();

        drop(held);
        assert_eq!(
            LockedWritableImage::acquire(writable(&image), writable(&sidecar))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(backing_duplicate);
        assert_eq!(
            LockedWritableImage::acquire(writable(&image), writable(&sidecar))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(sidecar_duplicate);
        let _reacquired =
            LockedWritableImage::acquire(writable(&image), writable(&sidecar)).unwrap();
    }

    #[test]
    fn invalid_descriptor_roles_are_refused_without_changing_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let sidecar = tmp.path().join("image.lock");
        std::fs::write(&image, b"preserved").unwrap();
        let read_only = File::open(&image).unwrap();
        let append = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&image)
            .unwrap();
        let directory = File::open(tmp.path()).unwrap();
        for invalid in [read_only, append, directory] {
            assert_eq!(
                LockedWritableImage::acquire(invalid, writable(&sidecar))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(std::fs::read(&image).unwrap(), b"preserved");
    }

    #[test]
    fn concurrent_openers_have_one_winner_and_restart_after_last_close() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let sidecar = sidecar_lock_path(&image);
        std::fs::write(&image, b"stable").unwrap();
        std::fs::write(&sidecar, []).unwrap();
        let threads = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads));
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        std::thread::scope(|scope| {
            for _ in 0..threads {
                let barrier = std::sync::Arc::clone(&barrier);
                let results = std::sync::Arc::clone(&results);
                let image = &image;
                let sidecar = &sidecar;
                scope.spawn(move || {
                    barrier.wait();
                    results
                        .lock()
                        .unwrap()
                        .push(LockedWritableImage::open(image, sidecar));
                });
            }
        });
        let mut results = results.lock().unwrap();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        for error in results.iter().filter_map(|result| result.as_ref().err()) {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        let completed = std::mem::take(&mut *results);
        drop(results);
        drop(completed);
        let _restarted = LockedWritableImage::open(&image, &sidecar).unwrap();
    }

    #[test]
    fn open_refuses_a_final_symlink_without_touching_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let sidecar = sidecar_lock_path(&image);
        std::fs::write(&image, b"preserved").unwrap();
        std::fs::write(&sidecar, []).unwrap();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&image, &alias).unwrap();
        assert!(LockedWritableImage::open(&alias, &sidecar).is_err());
        assert_eq!(std::fs::read(&image).unwrap(), b"preserved");
    }

    #[test]
    fn distinct_descriptors_for_the_same_object_cannot_fill_both_roles() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("image");
        let file = writable(&image);
        assert_eq!(
            LockedWritableImage::acquire(file, writable(&image))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
