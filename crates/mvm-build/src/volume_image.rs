//! Persistent ext4 image materialization for user-attached block volumes.

use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};

use crate::builder_vm::BuilderVmError;
use crate::builder_vm_runtime::{
    LockWait, acquire_sidecar_lock_within, sidecar_lock_path, sparse_create_locked_image,
};

/// Host-side guard for a custom persistent disk-image volume.
///
/// A read-write volume holds both its original backing and `<image>.lock`
/// sidecar so concurrent materialization cannot corrupt the image, including
/// through a hardlink alias. Read-only volumes hold no lock.
#[derive(Debug)]
pub struct VolumeImageLock {
    path: PathBuf,
    #[cfg(unix)]
    _lock: Option<mvm_core::util::writable_image::LockedWritableImage>,
    #[cfg(not(unix))]
    _lock: Option<std::fs::File>,
}

impl VolumeImageLock {
    /// Path handed to the hypervisor as a virtio block-device backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Transfer the original materialization resources to the final writer.
    #[cfg(unix)]
    pub fn into_image(
        self,
    ) -> Option<(PathBuf, mvm_core::util::writable_image::LockedWritableImage)> {
        self._lock.map(|image| (self.path, image))
    }
}

/// Materialize and validate a persistent ext4 image, returning its writer locks.
///
/// Missing or empty read-write files are sparse-created and formatted in-process.
/// Read-only files must already exist and are never created or modified. Existing
/// files are never resized or reformatted, and are refused unless their ext4
/// superblock magic is valid.
/// Read-write callers acquire the sidecar before creation/admission and lock the
/// original backing before inspecting, resizing, formatting or validating it.
pub fn ensure_persistent_volume_image(
    host_path: &Path,
    size_bytes: u64,
    read_only: bool,
) -> Result<VolumeImageLock, BuilderVmError> {
    ensure_persistent_volume_image_within(host_path, size_bytes, read_only, LockWait::from_env())
}

/// [`ensure_persistent_volume_image`] with an explicit wait budget for
/// the read-write sidecar lock. Test-facing seam — see
/// [`acquire_sidecar_lock_within`].
pub(crate) fn ensure_persistent_volume_image_within(
    host_path: &Path,
    size_bytes: u64,
    read_only: bool,
    wait: LockWait,
) -> Result<VolumeImageLock, BuilderVmError> {
    if read_only {
        validate_ext4(host_path)?;
        return Ok(VolumeImageLock {
            path: host_path.to_path_buf(),
            _lock: None,
        });
    }

    prepare_private_parent(host_path)?;
    let lock = acquire_sidecar_lock_within(&sidecar_lock_path(host_path), wait)?;
    create_or_admit_private_image(host_path)?;

    #[cfg(unix)]
    let lock = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(host_path)
            .map_err(io_error(host_path))?;
        let image = mvm_core::util::writable_image::LockedWritableImage::acquire(backing, lock)
            .map_err(io_error(host_path))?;
        let needs_format = image
            .backing()
            .metadata()
            .map_err(io_error(host_path))?
            .len()
            == 0;
        sparse_create_locked_image(image.backing(), host_path, size_bytes)?;
        if needs_format {
            let mut backing = image.backing().try_clone().map_err(io_error(host_path))?;
            format_new_ext4_file(host_path, &mut backing)?;
        }
        let mut backing = image.backing().try_clone().map_err(io_error(host_path))?;
        validate_ext4_file(host_path, &mut backing)?;
        let selected = std::fs::symlink_metadata(host_path).map_err(io_error(host_path))?;
        let held = image.backing().metadata().map_err(io_error(host_path))?;
        if !selected.is_file() || (selected.dev(), selected.ino()) != (held.dev(), held.ino()) {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "writable disk image {} changed during materialization",
                host_path.display()
            )));
        }
        image
    };

    #[cfg(not(unix))]
    {
        let needs_format = std::fs::metadata(host_path)
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(true);
        sparse_create_image(host_path, size_bytes)?;
        if needs_format {
            format_new_ext4(host_path)?;
        }
        validate_ext4(host_path)?;
    }

    Ok(VolumeImageLock {
        path: host_path.to_path_buf(),
        _lock: Some(lock),
    })
}

/// Make the image's directory ready without loosening anything the caller
/// owns: a missing directory (and any missing ancestor) is created owner-only;
/// an existing one is used as it is, unless other users could write into it,
/// which would let them swap the image for one of their own.
fn prepare_private_parent(host_path: &Path) -> Result<(), BuilderVmError> {
    let Some(parent) = host_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    match std::fs::metadata(parent) {
        Ok(metadata) if !metadata.is_dir() => Err(BuilderVmError::ExtractionFailed(format!(
            "volume parent {} is not a directory",
            parent.display()
        ))),
        Ok(metadata) => {
            let mode =
                mvm_core::private_fs::mode_bits(parent, &metadata).map_err(io_error(parent))?;
            if mode & 0o022 != 0 {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "refusing to create a writable disk image in {}: other users can write to \
                     that directory (mode {mode:03o}), so they could replace the image. Use a \
                     directory only you can write to (chmod go-w {})",
                    parent.display(),
                    parent.display()
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            mvm_core::private_fs::ensure_private_dir(parent).map_err(|error| {
                BuilderVmError::ExtractionFailed(format!(
                    "creating volume parent dir {} privately: {error}",
                    parent.display()
                ))
            })
        }
        Err(error) => Err(io_error(parent)(error)),
    }
}

/// Create a missing image owner-only (0600) before any byte is written, or
/// admit an existing one only when it is a regular file no other user can
/// read or write. An existing image is never chmodded: it is the caller's
/// file, and its data is what the guest is about to see.
fn create_or_admit_private_image(host_path: &Path) -> Result<(), BuilderVmError> {
    use mvm_core::private_fs::OpenOptionsModeExt as _;
    match std::fs::symlink_metadata(host_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "writable disk image {} must be a regular file (not a symlink or device)",
                    host_path.display()
                )));
            }
            let mode = mvm_core::private_fs::mode_bits(host_path, &metadata)
                .map_err(io_error(host_path))?;
            if mode & 0o077 != 0 {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "refusing to attach writable disk image {}: other users can access it \
                     (mode {mode:03o}), and the guest is about to write into it. Restrict it \
                     with `chmod 600 {}`",
                    host_path.display(),
                    host_path.display()
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open_with_mode(0o600, host_path)
                .map_err(io_error(host_path))?;
            // The umask can only narrow the creation mode; set it exactly.
            mvm_core::private_fs::set_mode(host_path, 0o600).map_err(io_error(host_path))
        }
        Err(error) => Err(io_error(host_path)(error)),
    }
}

fn io_error(path: &Path) -> impl Fn(std::io::Error) -> BuilderVmError + '_ {
    move |error| BuilderVmError::ExtractionFailed(format!("{}: {error}", path.display()))
}

#[cfg(not(unix))]
use crate::builder_vm_runtime::sparse_create_image;

#[cfg(any(not(unix), test))]
fn format_new_ext4(host_path: &Path) -> Result<(), BuilderVmError> {
    let mut image = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(host_path)
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "open new volume image {} for ext4 format: {error}",
                host_path.display()
            ))
        })?;
    format_new_ext4_file(host_path, &mut image)
}

fn format_new_ext4_file(host_path: &Path, image: &mut std::fs::File) -> Result<(), BuilderVmError> {
    let image_bytes = image
        .metadata()
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "metadata new volume image {}: {error}",
                host_path.display()
            ))
        })?
        .len();
    mvm_fs::ext4::mkfs::format_empty_ext4(image, image_bytes).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "format new persistent volume {} as ext4: {error}",
            host_path.display()
        ))
    })?;
    image.sync_all().map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "sync new persistent volume {}: {error}",
            host_path.display()
        ))
    })
}

fn validate_ext4(host_path: &Path) -> Result<(), BuilderVmError> {
    let mut image = std::fs::File::open(host_path).map_err(|error| {
        BuilderVmError::ExtractionFailed(format!(
            "open persistent volume {} for ext4 validation: {error}",
            host_path.display()
        ))
    })?;
    validate_ext4_file(host_path, &mut image)
}

fn validate_ext4_file(host_path: &Path, image: &mut std::fs::File) -> Result<(), BuilderVmError> {
    let magic = image
        .seek(std::io::SeekFrom::Start(1024 + 56))
        .and_then(|_| {
            let mut magic = [0u8; 2];
            image.read_exact(&mut magic)?;
            Ok(magic)
        })
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "read ext4 superblock from persistent volume {}: {error}",
                host_path.display()
            ))
        })?;
    if u16::from_le_bytes(magic) != 0xef53 {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "persistent volume {} is not a valid ext4 filesystem",
            host_path.display()
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    const SIZE: u64 = 16 * 1024 * 1024;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn rw(path: &Path) -> Result<VolumeImageLock, BuilderVmError> {
        ensure_persistent_volume_image_within(path, SIZE, false, LockWait::none())
    }

    #[test]
    fn a_contended_volume_lock_refuses_before_resizing_or_formatting() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        std::fs::write(&image, []).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _original_owner =
            acquire_sidecar_lock_within(&sidecar_lock_path(&image), LockWait::none()).unwrap();
        assert_eq!(std::fs::metadata(&image).unwrap().len(), 0);

        let error = rw(&image).expect_err("the original owner still holds the lock");

        assert_eq!(
            std::fs::metadata(&image).unwrap().len(),
            0,
            "a refused contender must not resize or format the owner's image: {error}"
        );
        assert!(std::fs::read(&image).unwrap().is_empty());
    }

    #[test]
    fn a_hardlink_alias_backing_lock_refuses_before_resizing_or_formatting() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        let alias = scratch.path().join("alias.img");
        std::fs::write(&image, []).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&image, &alias).unwrap();
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&alias)
            .unwrap();
        let sidecar =
            acquire_sidecar_lock_within(&sidecar_lock_path(&alias), LockWait::none()).unwrap();
        let _alias_owner =
            mvm_core::util::writable_image::LockedWritableImage::acquire(backing, sidecar).unwrap();

        rw(&image).expect_err("the alias owner still locks the original backing inode");
        assert_eq!(std::fs::metadata(&image).unwrap().len(), 0);
        assert!(std::fs::read(&image).unwrap().is_empty());
    }

    #[test]
    fn a_contended_volume_lock_refuses_before_creating_the_image() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        let owner =
            acquire_sidecar_lock_within(&sidecar_lock_path(&image), LockWait::none()).unwrap();

        rw(&image).expect_err("the original owner still holds the lock");

        assert!(
            !image.try_exists().unwrap(),
            "a refused contender must not create the owner's image"
        );
        drop(owner);
        let initialized = rw(&image).expect("initialize after the owner releases");
        validate_ext4(initialized.path()).expect("the successful initializer formats ext4");
        assert_eq!(mode(&image), 0o600);
    }

    #[test]
    fn a_contender_reuses_the_owners_initialized_bytes_after_release() {
        use std::io::Write as _;

        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        std::fs::write(&image, []).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner =
            acquire_sidecar_lock_within(&sidecar_lock_path(&image), LockWait::none()).unwrap();
        rw(&image).expect_err("contender observes an unfinished image under another lock");

        // The owner finishes initialization before allowing a contender to retry.
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .unwrap();
        sparse_create_locked_image(&backing, &image, SIZE).unwrap();
        drop(backing);
        format_new_ext4(&image).unwrap();
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap();
        writer.write_all(b"owner-written bytes").unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let expected = std::fs::read(&image).unwrap();

        rw(&image).expect_err("a complete image still requires its owner's lock");
        assert_eq!(std::fs::read(&image).unwrap(), expected);
        let readonly =
            ensure_persistent_volume_image_within(&image, SIZE, true, LockWait::none()).unwrap();
        assert!(readonly._lock.is_none(), "read-only behavior is unchanged");
        drop(readonly);
        drop(owner);

        let _contender = rw(&image).expect("recheck current image state after acquiring the lock");
        assert_eq!(
            std::fs::read(&image).unwrap(),
            expected,
            "a former contender must not reuse an earlier needs-format decision"
        );
        assert_eq!(mode(&image), 0o600);
    }

    #[test]
    fn a_new_image_and_its_missing_parents_are_created_owner_only() {
        let scratch = tempfile::tempdir().unwrap();
        let outer = scratch.path().join("state");
        let image = outer.join("nested").join("data.img");
        let _lock = rw(&image).expect("created");
        assert_eq!(mode(&image), 0o600, "image");
        assert_eq!(mode(&outer), 0o700, "created ancestor");
        assert_eq!(mode(image.parent().unwrap()), 0o700, "created parent");
    }

    #[test]
    fn an_existing_parent_is_used_as_it_is_unless_others_can_write_to_it() {
        let scratch = tempfile::tempdir().unwrap();
        let shared = scratch.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _lock = rw(&shared.join("data.img")).expect("a 0755 parent is fine");
        assert_eq!(
            mode(&shared),
            0o755,
            "an existing directory is never chmodded"
        );

        let loose = scratch.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        let image = loose.join("data.img");
        let message = rw(&image).unwrap_err().to_string();
        assert!(message.contains("other users can write"), "{message}");
        assert!(message.contains("chmod go-w"), "{message}");
        assert!(!image.exists(), "nothing created in a loose directory");
    }

    #[test]
    fn an_existing_image_others_can_access_is_refused_and_left_alone() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        std::fs::write(&image, b"").unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o644)).unwrap();
        let message = rw(&image).unwrap_err().to_string();
        assert!(message.contains("chmod 600"), "{message}");
        assert_eq!(mode(&image), 0o644, "never chmodded");
        assert_eq!(
            std::fs::metadata(&image).unwrap().len(),
            0,
            "never formatted"
        );

        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _lock = rw(&image).expect("an owner-only image is admitted");
    }

    #[test]
    fn a_symlinked_image_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let target = scratch.path().join("target.img");
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = scratch.path().join("data.img");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let message = rw(&link).unwrap_err().to_string();
        assert!(message.contains("must be a regular file"), "{message}");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn materialized_guard_transfers_original_resources_without_reacquisition() {
        use std::os::fd::AsRawFd;

        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        let held = rw(&image).unwrap();
        let original_fd = held._lock.as_ref().unwrap().backing().as_raw_fd();
        let (path, image) = held.into_image().unwrap();
        assert_eq!(path, scratch.path().join("data.img"));
        assert_eq!(image.backing().as_raw_fd(), original_fd);
        assert!(
            mvm_core::util::writable_image::LockedWritableImage::open(
                &path,
                &sidecar_lock_path(&path),
            )
            .is_err(),
            "the original writer resource remains locked after transfer"
        );
        drop(image);
        let _restarted = rw(&path).unwrap();
    }

    #[test]
    fn a_read_only_image_is_neither_created_nor_mode_checked() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("shared.img");
        // Read-only admission is about the guest reading an image the caller
        // already has; nothing is created or written.
        let _ = ensure_persistent_volume_image(&image, SIZE, true).unwrap_err();
        assert!(!image.exists());
    }
}
