//! Raw arm64 Image metadata, loading, and identity of the loaded byte range.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::super::guest_ram::{GuestRam, page_rounded_len};
use super::{BootFault, HvfError};
use crate::vmm::kernel_image;
use mvm_vmm::runtime_artifacts::RuntimeArtifact;

#[derive(Clone, Copy)]
pub(super) enum KernelImageSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
    HeldFile { file: &'a File, label: &'a Path },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct KernelImageMeta {
    pub(super) file_len: usize,
    pub(super) reserved_len: usize,
}

impl KernelImageMeta {
    fn new(file_len: usize, image_size: u64, file_backed: bool) -> Result<Self, HvfError> {
        let image_size =
            usize::try_from(image_size).map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
        let mapped_len = if file_backed {
            page_rounded_len(file_len)?
        } else {
            file_len
        };
        Ok(Self {
            file_len,
            reserved_len: mapped_len.max(image_size),
        })
    }
}

impl KernelImageSource<'_> {
    pub(super) fn metadata(self) -> Result<KernelImageMeta, HvfError> {
        match self {
            Self::Bytes(image) => {
                let hdr = kernel_image::parse(image)
                    .map_err(|_| HvfError::BadBoot(BootFault::KernelNotArm64Image))?;
                KernelImageMeta::new(image.len(), hdr.image_size, false)
            }
            Self::File(path) => {
                let mut file = File::open(path)
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?;
                let mut header = [0_u8; 64];
                file.read_exact(&mut header)
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelRead(e.kind())))?;
                let hdr = kernel_image::parse(&header)
                    .map_err(|_| HvfError::BadBoot(BootFault::KernelNotArm64Image))?;
                let len = file
                    .metadata()
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?
                    .len()
                    .try_into()
                    .map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
                KernelImageMeta::new(len, hdr.image_size, true)
            }
            Self::HeldFile { file, .. } => {
                use std::os::unix::fs::FileExt;
                let mut header = [0_u8; 64];
                file.read_exact_at(&mut header, 0)
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelRead(e.kind())))?;
                let hdr = kernel_image::parse(&header)
                    .map_err(|_| HvfError::BadBoot(BootFault::KernelNotArm64Image))?;
                let len = usize::try_from(
                    file.metadata()
                        .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?
                        .len(),
                )
                .map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
                KernelImageMeta::new(len, hdr.image_size, true)
            }
        }
    }

    pub(super) fn load_into(self, ram: &mut GuestRam, offset: usize) -> Result<usize, HvfError> {
        match self {
            Self::Bytes(image) => {
                ram.copy_at(offset, image)?;
                Ok(image.len())
            }
            Self::File(path) => {
                let meta = self.metadata()?;
                ram.map_private_file_at(offset, path, meta.file_len)?;
                Ok(meta.file_len)
            }
            Self::HeldFile { file, .. } => {
                let meta = self.metadata()?;
                ram.map_private_fd_at(offset, file, 0, meta.file_len)?;
                Ok(meta.file_len)
            }
        }
    }

    /// Measure only the artifact bytes already loaded, never mapping padding or
    /// a reopened pathname. In-memory images have no file artifact evidence.
    pub(super) fn loaded_artifact(
        self,
        ram: &GuestRam,
        offset: usize,
        loaded_len: usize,
    ) -> Result<Option<RuntimeArtifact>, HvfError> {
        let path = match self {
            Self::Bytes(_) => return Ok(None),
            Self::File(path) | Self::HeldFile { label: path, .. } => path,
        };
        // SAFETY: the caller's load_into validated and populated this range;
        // no vCPU exists yet, and ram outlives this immediate measurement.
        let loaded = unsafe { std::slice::from_raw_parts(ram.as_ptr().add(offset), loaded_len) };
        RuntimeArtifact::loaded(path.to_path_buf(), loaded)
            .map(Some)
            .map_err(|_| HvfError::SnapshotState("kernel evidence measurement failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::guest_ram::HVF_PAGE_SIZE;
    use super::*;

    #[test]
    fn held_kernel_maps_verified_clone_after_source_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        mvm_core::config::create_private_dir(directory.path()).unwrap();
        let source = directory.path().join("Image");
        let mut image = vec![0_u8; 4096];
        image[8..16].copy_from_slice(&0x80000_u64.to_le_bytes());
        image[16..24].copy_from_slice(&4096_u64.to_le_bytes());
        image[56..60].copy_from_slice(&0x644d_5241_u32.to_le_bytes());
        std::fs::write(&source, &image).unwrap();
        let held = mvm_vmm::host::restore_image::VerifiedRestoreFile::prepare(
            &source,
            directory.path(),
            &mvm_core::plan::bundle::sha256_hex(&image),
        )
        .unwrap();
        std::fs::remove_file(&source).unwrap();
        std::fs::write(&source, b"substituted after handoff").unwrap();
        let source = KernelImageSource::HeldFile {
            file: held.file(),
            label: &source,
        };
        let mut ram = GuestRam::new(HVF_PAGE_SIZE).unwrap();
        let loaded = source.load_into(&mut ram, 0).unwrap();
        assert_eq!(loaded, image.len());
        let actual = ram.snapshot_bytes();
        assert_eq!(&actual[..image.len()], image);
        assert!(actual[image.len()..].iter().all(|byte| *byte == 0));
        assert!(source.loaded_artifact(&ram, 0, loaded).unwrap().is_some());
    }

    #[test]
    fn byte_image_has_no_file_artifact_evidence() {
        let image = [0_u8; 128];
        let source = KernelImageSource::Bytes(&image);
        let mut ram = GuestRam::new(HVF_PAGE_SIZE).unwrap();
        let loaded_len = source.load_into(&mut ram, 0).unwrap();
        assert!(
            source
                .loaded_artifact(&ram, 0, loaded_len)
                .unwrap()
                .is_none()
        );
    }
}
