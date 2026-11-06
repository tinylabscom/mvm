//! Private read-only DATA custody, not admission or native builder ownership.

use std::fs::File;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::spec::{BlockDev, VmmSpec};
use crate::host::restore_image::verify_private_file;

/// The canonical input.img DATA slot; boot images and output.img use other slots.
pub const INPUT_DATA_SLOT: u8 = 2;

/// Byte expectations supplied by the recipe, not evidence of its authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataDiskExpectation {
    /// Exact byte length of the private DATA image.
    pub len: u64,
    /// SHA-256 of the entire image, including sector padding.
    pub sha256: String,
}

/// The exact private input file bound to one final physical disk recipe.
#[derive(Debug)]
#[must_use = "retain the original DATA file through handoff"]
pub struct PreparedReadOnlyDataDisk {
    block: BlockDev,
    file: File,
    expected: DataDiskExpectation,
}

impl PreparedReadOnlyDataDisk {
    /// Consume an already read-only, unlinked regular file without reopening it.
    ///
    /// A producer may supply `VerifiedRestoreFile::into_file()`. Possession of
    /// this object grants no permission to launch a builder or checked workload.
    ///
    /// # Errors
    /// Refuses noncontiguous/duplicate slots, a missing or writable DATA recipe,
    /// invalid custody or content, and a file without close-on-exec protection.
    pub fn bind(spec: &VmmSpec, file: File, expected: DataDiskExpectation) -> Result<Self> {
        let block = input_block(spec)?.clone();
        require_parent_cloexec(&file)?;
        verify_private_file(&file, expected.len, &expected.sha256)?;
        Ok(Self {
            block,
            file,
            expected,
        })
    }

    /// Refuse any change to the bound DATA recipe; paths are diagnostic only.
    ///
    /// # Errors
    /// Refuses a changed slot layout, source label, access mode, byte content or
    /// loss of parent close-on-exec protection.
    pub fn validate_spec(&self, spec: &VmmSpec) -> Result<()> {
        ensure!(
            input_block(spec)? == &self.block,
            "read-only DATA recipe changed"
        );
        require_parent_cloexec(&self.file)?;
        verify_private_file(&self.file, self.expected.len, &self.expected.sha256)?;
        Ok(())
    }

    /// Borrow the original file, never a path-based duplicate.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// The byte recipe checked on the original private file.
    pub fn expectation(&self) -> &DataDiskExpectation {
        &self.expected
    }
}

fn require_parent_cloexec(file: &File) -> Result<()> {
    // SAFETY: this only inspects the borrowed live descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    ensure!(
        flags >= 0 && flags & libc::FD_CLOEXEC != 0,
        "prepared DATA file must remain close-on-exec in the parent"
    );
    Ok(())
}

fn input_block(spec: &VmmSpec) -> Result<&BlockDev> {
    let mut ordered = spec.blocks.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|block| block.slot);
    ensure!(
        ordered
            .iter()
            .enumerate()
            .all(|(index, block)| usize::from(block.slot) == index),
        "DATA handoff requires exact contiguous physical slots"
    );
    let block = ordered
        .get(usize::from(INPUT_DATA_SLOT))
        .context("input DATA slot is absent")?;
    ensure!(
        block.read_only && !block.ephemeral,
        "input DATA recipe must be read-only and file-served"
    );
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileExt, MetadataExt};

    fn spec() -> VmmSpec {
        VmmSpec {
            name: "data-fixture".into(),
            kernel: super::super::spec::KernelImage::Bundled,
            initramfs: None,
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 64,
            mem_initial_mib: None,
            blocks: (0..4)
                .map(|slot| BlockDev {
                    source: format!("/diagnostic/{slot}").into(),
                    read_only: slot != 3,
                    ephemeral: false,
                    slot,
                })
                .collect(),
            vsock: Vec::new(),
            console: super::super::spec::ConsoleCapture {
                log_path: "/unused".into(),
            },
            shares: Vec::new(),
            trusted_builder: false,
            builder_egress_endpoint: None,
            plan_binding: None,
        }
    }

    fn expected() -> DataDiskExpectation {
        DataDiskExpectation {
            len: 512,
            sha256: mvm_core::plan::bundle::sha256_hex(&[17; 512]),
        }
    }

    fn private_file() -> File {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.img");
        std::fs::write(&path, [17; 512]).unwrap();
        let file = File::open(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        file
    }

    #[test]
    fn readonly_data_keeps_exact_object_without_opening_diagnostic_path() {
        let file = private_file();
        let fd = file.as_raw_fd();
        let inode = file.metadata().unwrap().ino();
        let mut spec = spec();
        spec.blocks.reverse();
        let data = PreparedReadOnlyDataDisk::bind(&spec, file, expected()).unwrap();
        data.validate_spec(&spec).unwrap();
        assert_eq!(data.file().as_raw_fd(), fd);
        assert_eq!(data.file().metadata().unwrap().ino(), inode);
        assert_eq!(data.file().metadata().unwrap().nlink(), 0);
        let mut bytes = [0; 512];
        data.file().read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [17; 512]);
        let json = serde_json::to_vec(data.expectation()).unwrap();
        assert_eq!(
            serde_json::from_slice::<DataDiskExpectation>(&json).unwrap(),
            expected()
        );
    }

    #[test]
    fn readonly_data_refuses_changed_duplicate_missing_and_wrong_access_recipes() {
        let data = PreparedReadOnlyDataDisk::bind(&spec(), private_file(), expected()).unwrap();
        for mutate in [
            |spec: &mut VmmSpec| spec.blocks[2].read_only = false,
            |spec: &mut VmmSpec| spec.blocks[2].ephemeral = true,
            |spec: &mut VmmSpec| spec.blocks[2].source = "/replacement".into(),
            |spec: &mut VmmSpec| spec.blocks[2].slot = 0,
            |spec: &mut VmmSpec| spec.blocks[2].slot = 4,
            |spec: &mut VmmSpec| {
                spec.blocks.remove(2);
            },
        ] {
            let mut changed = spec();
            mutate(&mut changed);
            assert!(data.validate_spec(&changed).is_err(), "recipe {changed:?}");
        }
        for len in [0, 511, 513] {
            let mut wrong = expected();
            wrong.len = len;
            assert!(PreparedReadOnlyDataDisk::bind(&spec(), private_file(), wrong).is_err());
        }
        for hash in ["".to_owned(), "0".repeat(64), "z".repeat(64)] {
            let mut wrong = expected();
            wrong.sha256 = hash;
            assert!(PreparedReadOnlyDataDisk::bind(&spec(), private_file(), wrong).is_err());
        }
    }

    #[test]
    fn readonly_data_refuses_linked_writable_append_and_inheritable_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.img");
        std::fs::write(&path, [17; 512]).unwrap();
        assert!(
            PreparedReadOnlyDataDisk::bind(&spec(), File::open(&path).unwrap(), expected())
                .is_err()
        );
        let writable_files = [
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&path)
                .unwrap(),
        ];
        std::fs::remove_file(path).unwrap();
        for file in writable_files {
            let alias = file.try_clone().unwrap();
            assert!(PreparedReadOnlyDataDisk::bind(&spec(), file, expected()).is_err());
            assert!(
                alias.metadata().is_ok(),
                "refusal must not consume another owner"
            );
        }
        let append = private_file();
        // SAFETY: modifying only the status flags of this synthetic owned fixture.
        assert_eq!(
            unsafe { libc::fcntl(append.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) },
            0
        );
        assert!(PreparedReadOnlyDataDisk::bind(&spec(), append, expected()).is_err());
        let inheritable = private_file();
        // SAFETY: modifying only descriptor flags of this synthetic owned fixture.
        assert_eq!(
            unsafe { libc::fcntl(inheritable.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        assert!(PreparedReadOnlyDataDisk::bind(&spec(), inheritable, expected()).is_err());
    }

    #[test]
    fn readonly_data_revalidation_refuses_cloexec_cleared_after_binding() {
        let data = PreparedReadOnlyDataDisk::bind(&spec(), private_file(), expected()).unwrap();
        // SAFETY: change only descriptor flags on this owned synthetic fixture.
        assert_eq!(
            unsafe { libc::fcntl(data.file().as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        assert!(
            data.validate_spec(&spec()).is_err(),
            "handoff must recheck parent close-on-exec protection"
        );
    }
}
