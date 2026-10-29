//! Private CoW snapshots of authenticated image bytes, not launch authority.
//!
//! This owns bytes under restore_image's same-user trust limitation. It does
//! not prove admission, a parent/native identity, or physical VM consumption.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::Result;
use mvm_core::registry_pack_boot::{AuthenticatedBootImageExpectations, BootImageAsset};

use super::restore_image::VerifiedRestoreFile;

const ROLES: [BootImageAsset; 4] = [
    BootImageAsset::Rootfs,
    BootImageAsset::Verity,
    BootImageAsset::Metadata,
    BootImageAsset::RootHash,
];

/// Original already-open inputs. These locators confer no verification facts.
pub struct BootImageSources<'a> {
    pub rootfs: &'a File,
    pub verity: &'a File,
    pub metadata: &'a File,
    pub root_hash: &'a File,
    pub private_dir: &'a Path,
}

impl BootImageSources<'_> {
    fn file(&self, role: BootImageAsset) -> &File {
        match role {
            BootImageAsset::Rootfs => self.rootfs,
            BootImageAsset::Verity => self.verity,
            BootImageAsset::Metadata => self.metadata,
            BootImageAsset::RootHash => self.root_hash,
        }
    }
}

/// Owns four strict CoW snapshots and their original authenticated facts.
///
/// There is no raw-file/digest constructor or unchecked-files conversion.
/// Root-hash bytes are retained as a fourth file to preserve the same raw
/// signed-member facts; the usable hash comes only from captured expectations,
/// never by reopening or trusting unsigned text.
///
/// ```compile_fail
/// use mvm_vmm::host::boot_images::FrozenBootImageBytes;
/// let _ = FrozenBootImageBytes::default();
/// ```
pub struct FrozenBootImageBytes {
    expectations: AuthenticatedBootImageExpectations,
    files: [VerifiedRestoreFile; 4],
}

impl FrozenBootImageBytes {
    pub fn prepare(
        expectations: AuthenticatedBootImageExpectations,
        sources: BootImageSources<'_>,
    ) -> Result<Self> {
        let files = prepare_fixed_roles(|role| {
            VerifiedRestoreFile::prepare_clone_only(
                sources.file(role),
                sources.private_dir,
                expectations.expected_sha256(role).as_str(),
                expectations.expected_size(role),
            )
        })?;
        // Verify FINAL held files from offset zero. try_clone would share the
        // file cursor; ordinary Read could accidentally validate only a suffix.
        verify_files_from_zero(&files, |role, reader| {
            expectations.verify_reader(role, reader)
        })?;
        Ok(Self {
            expectations,
            files,
        })
    }

    /// Borrow the exact retained readonly snapshot, not an original pathname.
    pub fn file(&self, role: BootImageAsset) -> &File {
        self.files[role_index(role)].file()
    }

    /// Original captured authenticated value, not a caller-provided hash.
    pub fn root_hash(&self) -> &str {
        self.expectations.root_hash()
    }

    /// Digest captured from authenticated declarations, not a reopened pathname.
    pub fn sha256(&self, role: BootImageAsset) -> &str {
        self.expectations.expected_sha256(role).as_str()
    }
}

fn role_index(role: BootImageAsset) -> usize {
    match role {
        BootImageAsset::Rootfs => 0,
        BootImageAsset::Verity => 1,
        BootImageAsset::Metadata => 2,
        BootImageAsset::RootHash => 3,
    }
}

// This private sequencing helper alone provides NO authenticated owner.
fn prepare_fixed_roles<T, E>(
    mut prepare: impl FnMut(BootImageAsset) -> std::result::Result<T, E>,
) -> std::result::Result<[T; 4], E> {
    Ok([
        prepare(BootImageAsset::Rootfs)?,
        prepare(BootImageAsset::Verity)?,
        prepare(BootImageAsset::Metadata)?,
        prepare(BootImageAsset::RootHash)?,
    ])
}

struct PositionalReader<'a> {
    file: &'a File,
    offset: u64,
}

impl Read for PositionalReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buffer, self.offset)?;
        self.offset = self
            .offset
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("image reader offset overflow"))?;
        Ok(n)
    }
}

fn verify_files_from_zero<'a>(
    files: &'a [VerifiedRestoreFile; 4],
    mut verify: impl FnMut(BootImageAsset, PositionalReader<'a>) -> Result<()>,
) -> Result<()> {
    for role in ROLES {
        verify(
            role,
            PositionalReader {
                file: files[role_index(role)].file(),
                offset: 0,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // UNAUTHENTICATED private mechanics only. No opaque core expectation is
    // fabricated here; public authenticated-owner positive coverage is absent
    // until a genuine signed-open fixture is available.
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn unauthenticated_fixed_roles_drop_partial_groups_at_every_failure() {
        for fail_at in 0..4 {
            let drops = Arc::new(AtomicUsize::new(0));
            let mut seen = Vec::new();
            let result = prepare_fixed_roles(|role| {
                let index = role_index(role);
                seen.push(index);
                if index == fail_at {
                    Err(())
                } else {
                    Ok(Guard(Arc::clone(&drops)))
                }
            });
            assert!(result.is_err());
            assert_eq!(seen, (0..=fail_at).collect::<Vec<_>>());
            assert_eq!(drops.load(Ordering::SeqCst), fail_at);
        }
    }

    #[test]
    fn unauthenticated_fixed_roles_publish_one_complete_group() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut seen = Vec::new();
        let group = prepare_fixed_roles::<_, ()>(|role| {
            seen.push(role_index(role));
            Ok(Guard(Arc::clone(&drops)))
        })
        .unwrap();
        assert_eq!(seen, [0, 1, 2, 3]);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(group);
        assert_eq!(drops.load(Ordering::SeqCst), 4);
    }

    #[cfg(target_os = "macos")]
    fn mechanical_files(dir: &Path) -> ([VerifiedRestoreFile; 4], Vec<File>, Vec<Vec<u8>>) {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::PermissionsExt;
        let private = dir.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = vec![
            b"synthetic-root".to_vec(),
            b"synthetic-tree".to_vec(),
            br#"{"synthetic":true}"#.to_vec(),
            format!("{}\n", "a".repeat(64)).into_bytes(),
        ];
        let sources = bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let path = dir.join(format!("source-{index}"));
                std::fs::write(&path, bytes).unwrap();
                let file = File::open(path).unwrap();
                let mut view = &file;
                view.seek(SeekFrom::Start(3)).unwrap();
                file
            })
            .collect::<Vec<_>>();
        let files = prepare_fixed_roles(|role| {
            let index = role_index(role);
            VerifiedRestoreFile::prepare_clone_only(
                &sources[index],
                &private,
                &mvm_core::crypto::image_verify::sha256_reader(bytes[index].as_slice()).unwrap(),
                bytes[index].len() as u64,
            )
        })
        .unwrap();
        (files, sources, bytes)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unauthenticated_final_reads_start_at_zero_and_preserve_shared_cursors() {
        use std::io::{Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let (files, sources, bytes) = mechanical_files(dir.path());
        let mut offsets = Vec::new();
        for (index, file) in files.iter().enumerate() {
            let mut alias = file.file().try_clone().unwrap();
            alias.seek(SeekFrom::Start(2)).unwrap();
            let mut held = file.file();
            assert_eq!(held.stream_position().unwrap(), 2);
            offsets.push(held.stream_position().unwrap());
            std::fs::write(dir.path().join(format!("source-{index}")), b"mutated").unwrap();
        }
        verify_files_from_zero(&files, |role, reader| {
            let index = role_index(role);
            let actual = mvm_core::crypto::image_verify::sha256_reader(reader)?;
            let expected = mvm_core::crypto::image_verify::sha256_reader(bytes[index].as_slice())?;
            anyhow::ensure!(actual == expected, "synthetic role mismatch");
            Ok(())
        })
        .unwrap();
        for (index, file) in files.iter().enumerate() {
            let mut held = file.file();
            assert_eq!(held.stream_position().unwrap(), offsets[index]);
            assert_eq!(sources[index].metadata().unwrap().len(), 7);
            let mut original = &sources[index];
            assert_eq!(original.stream_position().unwrap(), 3);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unauthenticated_zero_origin_rejects_suffix_and_wrong_role_expectations() {
        use std::io::{Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let (files, _sources, bytes) = mechanical_files(dir.path());
        let mut alias = files[0].file().try_clone().unwrap();
        alias.seek(SeekFrom::Start(2)).unwrap();
        assert!(
            verify_files_from_zero(&files, |role, reader| {
                let index = role_index(role);
                let actual = mvm_core::crypto::image_verify::sha256_reader(reader)?;
                let suffix = &bytes[index][2..];
                let expected = mvm_core::crypto::image_verify::sha256_reader(suffix)?;
                anyhow::ensure!(actual == expected, "not a whole-member match");
                Ok(())
            })
            .is_err()
        );
        assert!(
            verify_files_from_zero(&files, |role, reader| {
                let index = role_index(role);
                let actual = mvm_core::crypto::image_verify::sha256_reader(reader)?;
                let expected = mvm_core::crypto::image_verify::sha256_reader(
                    bytes[(index + 1) % 4].as_slice(),
                )?;
                anyhow::ensure!(actual == expected, "wrong role");
                Ok(())
            })
            .is_err()
        );
    }
}
