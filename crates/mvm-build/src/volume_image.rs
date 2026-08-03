//! Persistent ext4 image materialization for user-attached block volumes.

use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};

use crate::builder_vm::BuilderVmError;
use crate::builder_vm_runtime::{acquire_sidecar_lock, sidecar_lock_path, sparse_create_image};

/// Host-side guard for a custom persistent disk-image volume.
///
/// A read-write volume holds a sidecar `<image>.lock` flock so concurrent
/// materialization cannot corrupt the image. Read-only volumes hold no lock.
/// The image itself stays closed so the hypervisor can open it exclusively.
#[derive(Debug)]
pub struct VolumeImageLock {
    path: PathBuf,
    _lock: Option<std::fs::File>,
}

impl VolumeImageLock {
    /// Path handed to the hypervisor as a virtio block-device backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Materialize and validate a persistent ext4 image, returning its sidecar lock.
///
/// Missing or empty files are sparse-created and formatted in-process. Existing
/// files are never resized or reformatted, and are refused unless their ext4
/// superblock magic is valid.
pub fn ensure_persistent_volume_image(
    host_path: &Path,
    size_bytes: u64,
    read_only: bool,
) -> Result<VolumeImageLock, BuilderVmError> {
    if let Some(parent) = host_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "creating volume parent dir {}: {error}",
                parent.display()
            ))
        })?;
    }

    let needs_format = match std::fs::metadata(host_path) {
        Ok(metadata) => metadata.len() == 0,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "metadata {}: {error}",
                host_path.display()
            )));
        }
    };
    sparse_create_image(host_path, size_bytes)?;
    if needs_format {
        format_new_ext4(host_path)?;
    }
    validate_ext4(host_path)?;

    let lock = if read_only {
        None
    } else {
        Some(acquire_sidecar_lock(&sidecar_lock_path(host_path))?)
    };
    Ok(VolumeImageLock {
        path: host_path.to_path_buf(),
        _lock: lock,
    })
}

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
    let image_bytes = image
        .metadata()
        .map_err(|error| {
            BuilderVmError::ExtractionFailed(format!(
                "metadata new volume image {}: {error}",
                host_path.display()
            ))
        })?
        .len();
    mvm_fs::ext4::mkfs::format_empty_ext4(&mut image, image_bytes).map_err(|error| {
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
