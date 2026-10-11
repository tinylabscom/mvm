//! Untrusted content-addressed storage for published runtime source archives.
//! Cache membership never establishes authority; offline readers must select a
//! declaration from a freshly authenticated image-set root.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mvm_core::image_set::{ArtifactFormat, MemberArtifact};
use mvm_core::packs::Sha256Hex;
use sha2::{Digest, Sha256};

const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeArchiveError {
    #[error(
        "runtime source archive unavailable: {0}; prepare the accepted published image set before offline boot"
    )]
    Io(#[from] std::io::Error),
    #[error(
        "runtime source archive refused: {0}; prepare the accepted published image set before offline boot"
    )]
    Invalid(String),
}

pub fn runtime_archive_cache() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("image-set-runtime-archives")
}

fn archive_path(cache: &Path, artifact: &MemberArtifact) -> PathBuf {
    cache.join(artifact.sha256.as_str())
}

pub(crate) fn regular_file(path: &Path) -> Result<File, RuntimeArchiveError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(RuntimeArchiveError::Invalid("not a regular file".into()));
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(RuntimeArchiveError::Invalid("not a regular file".into()));
    }
    Ok(file)
}

fn copy_checked(
    source: &Path,
    artifact: &MemberArtifact,
    output: &mut impl Write,
) -> Result<(), RuntimeArchiveError> {
    if artifact.format != ArtifactFormat::TarGz
        || artifact.size == 0
        || artifact.size > MAX_ARCHIVE_BYTES
    {
        return Err(RuntimeArchiveError::Invalid(
            "invalid format or archive size".into(),
        ));
    }
    let file = regular_file(source)?;
    if file.metadata()?.len() != artifact.size {
        return Err(RuntimeArchiveError::Invalid("archive size mismatch".into()));
    }
    let mut reader = file.take(artifact.size + 1);
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > artifact.size {
            return Err(RuntimeArchiveError::Invalid(
                "archive grew during read".into(),
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    if count != artifact.size || hex::encode(hasher.finalize()) != artifact.sha256.as_str() {
        return Err(RuntimeArchiveError::Invalid(
            "archive size or digest mismatch".into(),
        ));
    }
    Ok(())
}

/// Retain exact bytes after preparation. This checks content, not publisher
/// authority, and deliberately returns no authenticated attachment value.
pub fn retain_runtime_archive(
    cache: &Path,
    source: &Path,
    artifact: &MemberArtifact,
) -> Result<(), RuntimeArchiveError> {
    std::fs::create_dir_all(cache)?;
    let path = archive_path(cache, artifact);
    let mut staged = tempfile::NamedTempFile::new_in(cache)?;
    copy_checked(source, artifact, &mut staged)?;
    match mvm_core::util::atomic_io::atomic_persist_new(staged, &path) {
        Ok(()) => {
            mvm_core::util::atomic_io::sync_dir(cache)
                .map_err(|error| RuntimeArchiveError::Invalid(error.to_string()))?;
            Ok(())
        }
        Err(error) if mvm_core::util::atomic_io::is_already_exists(&error) => {
            copy_checked(&path, artifact, &mut std::io::sink())
        }
        Err(error) => Err(RuntimeArchiveError::Invalid(error.to_string())),
    }
}

/// Return a private snapshot so extraction never reopens a mutable cache path.
pub(crate) fn snapshot(
    cache: &Path,
    artifact: &MemberArtifact,
) -> Result<tempfile::NamedTempFile, RuntimeArchiveError> {
    let mut staged = tempfile::NamedTempFile::new()?;
    let path = archive_path(cache, artifact);
    copy_checked(&path, artifact, &mut staged).map_err(|error| {
        RuntimeArchiveError::Invalid(format!("{} at {}: {error}", artifact.name, path.display()))
    })?;
    staged.seek(SeekFrom::Start(0))?;
    Ok(staged)
}

/// Hash a final file through a no-follow regular-file handle and a size bound.
pub(crate) fn file_identity(path: &Path) -> Result<(Sha256Hex, u64), RuntimeArchiveError> {
    let file = regular_file(path)?;
    let size = file.metadata()?.len();
    if size > crate::release_archive::MAX_EXTRACTED_BYTES {
        return Err(RuntimeArchiveError::Invalid(
            "attachment exceeds size limit".into(),
        ));
    }
    let mut reader = file.take(size + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        count += read as u64;
    }
    if count != size {
        return Err(RuntimeArchiveError::Invalid(
            "attachment changed size".into(),
        ));
    }
    let hash = Sha256Hex::new(hex::encode(digest.finalize()))
        .map_err(|error| RuntimeArchiveError::Invalid(error.to_string()))?;
    Ok((hash, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::ArtifactName;

    #[cfg(unix)]
    #[test]
    fn cache_symlinks_and_directories_do_not_establish_archive_authority() {
        let dir = tempfile::tempdir().unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"synthetic").unwrap();
        let artifact = MemberArtifact {
            name: ArtifactName::new("synthetic.tar.gz").unwrap(),
            format: ArtifactFormat::TarGz,
            sha256: Sha256Hex::from_bytes(b"synthetic"),
            size: 9,
        };
        let path = archive_path(dir.path(), &artifact);
        std::os::unix::fs::symlink(source.path(), &path).unwrap();
        assert!(snapshot(dir.path(), &artifact).is_err());
        assert!(retain_runtime_archive(dir.path(), source.path(), &artifact).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(snapshot(dir.path(), &artifact).is_err());
    }

    #[test]
    fn synthetic_retention_is_atomic_bounded_and_collision_refusing() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let cache = dir.path().join("cache");
        std::fs::write(&source, b"synthetic, not a release archive").unwrap();
        let artifact = MemberArtifact {
            name: ArtifactName::new("synthetic.tar.gz").unwrap(),
            format: ArtifactFormat::TarGz,
            sha256: Sha256Hex::from_bytes(b"synthetic, not a release archive"),
            size: 32,
        };
        let artifact = MemberArtifact {
            size: std::fs::metadata(&source).unwrap().len(),
            ..artifact
        };
        retain_runtime_archive(&cache, &source, &artifact).unwrap();
        retain_runtime_archive(&cache, &source, &artifact).unwrap();
        assert!(snapshot(&cache, &artifact).is_ok());
        std::fs::write(archive_path(&cache, &artifact), b"poison").unwrap();
        assert!(retain_runtime_archive(&cache, &source, &artifact).is_err());
        assert_eq!(
            std::fs::read(archive_path(&cache, &artifact)).unwrap(),
            b"poison"
        );
        assert!(snapshot(&cache, &artifact).is_err());
        for changed in [
            MemberArtifact {
                size: MAX_ARCHIVE_BYTES + 1,
                ..artifact.clone()
            },
            MemberArtifact {
                size: artifact.size + 1,
                ..artifact.clone()
            },
            MemberArtifact {
                sha256: Sha256Hex::from_bytes(b"wrong"),
                ..artifact.clone()
            },
            MemberArtifact {
                format: ArtifactFormat::Ext4,
                ..artifact.clone()
            },
        ] {
            assert!(retain_runtime_archive(&cache, &source, &changed).is_err());
        }
        let interrupted = tempfile::NamedTempFile::new_in(&cache).unwrap();
        std::fs::write(interrupted.path(), b"partial").unwrap();
        let absent = MemberArtifact {
            sha256: Sha256Hex::from_bytes(b"missing"),
            ..artifact
        };
        assert!(snapshot(&cache, &absent).is_err());
    }
}
