//! Supervisor-owned boot evidence. These are measurements of consumed boot
//! inputs, not measurements of current guest RAM or a guest-tamper guarantee.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifact {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifacts {
    /// Loaded kernel identity; historical observations did not measure it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<RuntimeArtifact>,
    pub initramfs: Option<RuntimeArtifact>,
    /// Only disks actually attached read-only. Writable disks are not evidence.
    pub disks: Vec<RuntimeArtifact>,
    pub kernel_cmdline: String,
    /// Configured Firecracker drive order; absent for other backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firecracker_drives: Option<Vec<FirecrackerDrive>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerDrive {
    pub drive_id: String,
    pub path: PathBuf,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[cfg(unix)]
mod local;
#[cfg(unix)]
pub use local::{ObservationError, Observer, query};

impl RuntimeArtifact {
    /// Hash the slice the loader consumes, not a second read of its pathname.
    pub fn loaded(path: PathBuf, bytes: &[u8]) -> std::io::Result<Self> {
        Ok(Self {
            path,
            sha256: mvm_core::crypto::image_verify::sha256_reader(bytes)?,
        })
    }

    /// Boot-time hash of the held read-only backing, without reopening a path.
    /// Host mutation after measurement is outside this boot-evidence guarantee.
    #[cfg(unix)]
    pub fn disk(
        path: PathBuf,
        disk: &crate::vmm::virtio::DiskImage,
    ) -> std::io::Result<Option<Self>> {
        use std::os::unix::fs::FileExt;
        let crate::vmm::virtio::DiskImage::File {
            file,
            read_only: true,
            ..
        } = disk
        else {
            return Ok(None);
        };
        struct Reader<'a> {
            file: &'a std::fs::File,
            offset: u64,
        }
        impl std::io::Read for Reader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.file.read_at(buf, self.offset)?;
                self.offset += n as u64;
                Ok(n)
            }
        }
        Ok(Some(Self {
            path,
            sha256: mvm_core::crypto::image_verify::sha256_reader(Reader { file, offset: 0 })?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_bytes_not_mutable_path_are_measured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initrd");
        std::fs::write(&path, b"replacement").unwrap();
        let artifact = RuntimeArtifact::loaded(path, b"abc").unwrap();
        assert_eq!(
            artifact.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(unix)]
    #[test]
    fn disk_hash_uses_held_readonly_backing_not_replacement() {
        use crate::vmm::virtio::DiskImage;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk");
        std::fs::write(&path, b"abc").unwrap();
        let disk = DiskImage::open(&path, true).unwrap();
        std::fs::rename(&path, dir.path().join("original")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            RuntimeArtifact::disk(path.clone(), &disk).unwrap().unwrap(),
            RuntimeArtifact::loaded(path.clone(), b"abc").unwrap(),
        );
        assert!(
            RuntimeArtifact::disk(path.clone(), &DiskImage::open(&path, false).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            RuntimeArtifact::disk(path, &DiskImage::mem(b"abc".to_vec()))
                .unwrap()
                .is_none()
        );
    }
}
