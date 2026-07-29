//! Universal initramfs cache resolution.
//!
//! The content-addressed initramfs produced by `nix/images/initramfs/flake.nix`
//! lives under `<cache_root>/<version>/<arch>/`. This module validates that a
//! cached directory contains the expected files and version.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Expected files in an initramfs cache directory.
pub const INITRAMFS_IMAGE_FILE: &str = "initramfs.cpio.gz";
pub const INITRAMFS_HASH_FILE: &str = "initramfs.hash";
pub const INITRAMFS_SIZE_FILE: &str = "initramfs.size";
pub const VERSION_FILE: &str = "VERSION";

/// A resolved, validated universal initramfs artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitramfsArtifact {
    /// Path to `initramfs.cpio.gz`.
    pub image_path: PathBuf,
    /// Path to `initramfs.hash`.
    pub hash_path: PathBuf,
    /// Path to `initramfs.size`.
    pub size_path: PathBuf,
    /// Version string read from `VERSION`.
    pub version: String,
}

/// Failure modes for initramfs cache resolution.
#[derive(Debug, Error)]
pub enum InitramfsError {
    /// The requested cache directory does not exist.
    #[error("initramfs cache missing: {0}")]
    Missing(PathBuf),

    /// A required file is missing or not a regular file.
    #[error("initramfs cache entry missing: {0}")]
    MissingEntry(PathBuf),

    /// The `VERSION` file does not match the expected version.
    #[error("initramfs version mismatch: expected {expected}, got {got:?}")]
    VersionMismatch {
        expected: String,
        got: Option<String>,
    },

    /// The compressed image size does not match `initramfs.size`.
    #[error("initramfs size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },

    /// An I/O error occurred while reading cache metadata.
    #[error("initramfs cache io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve a universal initramfs from the cache.
#[derive(Debug, Clone)]
pub struct InitramfsResolver {
    cache_root: PathBuf,
    version: String,
}

impl InitramfsResolver {
    /// Create a resolver for the given cache root and artifact version.
    pub fn new(cache_root: impl Into<PathBuf>, version: impl Into<String>) -> Self {
        Self {
            cache_root: cache_root.into(),
            version: version.into(),
        }
    }

    /// Directory where the artifact for `(version, arch)` is expected, where
    /// `arch` is the cache directory-name segment (e.g. `"aarch64"`).
    pub fn artifact_dir(&self, arch: &str) -> PathBuf {
        self.cache_root.join(&self.version).join(arch)
    }

    /// Return the validated artifact paths if the cache entry exists and is
    /// well-formed. Returns [`InitramfsError::Missing`] when the directory is
    /// absent so callers can distinguish "not cached" from "corrupt".
    pub fn resolve(&self, arch: &str) -> Result<InitramfsArtifact, InitramfsError> {
        let dir = self.artifact_dir(arch);
        if !dir.is_dir() {
            return Err(InitramfsError::Missing(dir));
        }

        let image_path = dir.join(INITRAMFS_IMAGE_FILE);
        let hash_path = dir.join(INITRAMFS_HASH_FILE);
        let size_path = dir.join(INITRAMFS_SIZE_FILE);
        let version_path = dir.join(VERSION_FILE);

        for path in [&image_path, &hash_path, &size_path, &version_path] {
            if !path.is_file() {
                return Err(InitramfsError::MissingEntry(path.clone()));
            }
        }

        let got_version = std::fs::read_to_string(&version_path)?.trim().to_string();
        if got_version != self.version {
            return Err(InitramfsError::VersionMismatch {
                expected: self.version.clone(),
                got: Some(got_version),
            });
        }

        let expected_size: u64 = std::fs::read_to_string(&size_path)?
            .trim()
            .parse()
            .map_err(|e| {
                InitramfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("initramfs.size is not a valid u64: {e}"),
                ))
            })?;
        let actual_size = std::fs::metadata(&image_path)?.len();
        if expected_size != actual_size {
            return Err(InitramfsError::SizeMismatch {
                expected: expected_size,
                actual: actual_size,
            });
        }

        Ok(InitramfsArtifact {
            image_path,
            hash_path,
            size_path,
            version: got_version,
        })
    }
}

/// Read an artifact directly from a directory without constructing a resolver.
pub fn read_initramfs_artifact_from_dir(dir: &Path) -> Result<InitramfsArtifact, InitramfsError> {
    let image_path = dir.join(INITRAMFS_IMAGE_FILE);
    let hash_path = dir.join(INITRAMFS_HASH_FILE);
    let size_path = dir.join(INITRAMFS_SIZE_FILE);
    let version_path = dir.join(VERSION_FILE);

    for path in [&image_path, &hash_path, &size_path, &version_path] {
        if !path.is_file() {
            return Err(InitramfsError::MissingEntry(path.clone()));
        }
    }

    let version = std::fs::read_to_string(&version_path)?.trim().to_string();

    Ok(InitramfsArtifact {
        image_path,
        hash_path,
        size_path,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_returns_missing_for_absent_cache() {
        let resolver = InitramfsResolver::new("/nonexistent/cache", "0.18.0");
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(matches!(err, InitramfsError::Missing(_)));
    }

    #[test]
    fn resolver_validates_cache_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("initramfs");
        let artifact_dir = cache.join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_IMAGE_FILE), b"image").unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_HASH_FILE), b"hash").unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_SIZE_FILE), "5").unwrap();
        std::fs::write(artifact_dir.join(VERSION_FILE), "0.18.0").unwrap();

        let resolver = InitramfsResolver::new(&cache, "0.18.0");
        let artifact = resolver.resolve("aarch64").unwrap();
        assert_eq!(artifact.version, "0.18.0");
        assert_eq!(artifact.image_path, artifact_dir.join(INITRAMFS_IMAGE_FILE));
    }

    #[test]
    fn resolver_rejects_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("initramfs");
        let artifact_dir = cache.join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        for name in [
            INITRAMFS_IMAGE_FILE,
            INITRAMFS_HASH_FILE,
            INITRAMFS_SIZE_FILE,
            VERSION_FILE,
        ] {
            std::fs::write(artifact_dir.join(name), b"x").unwrap();
        }
        std::fs::write(artifact_dir.join(VERSION_FILE), "0.17.0").unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_SIZE_FILE), "1").unwrap();

        let resolver = InitramfsResolver::new(&cache, "0.18.0");
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(matches!(err, InitramfsError::VersionMismatch { .. }));
    }

    #[test]
    fn resolver_rejects_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("initramfs");
        let artifact_dir = cache.join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_IMAGE_FILE), b"image").unwrap();
        std::fs::write(artifact_dir.join(VERSION_FILE), "0.18.0").unwrap();

        let resolver = InitramfsResolver::new(&cache, "0.18.0");
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(matches!(err, InitramfsError::MissingEntry(_)));
    }

    #[test]
    fn resolver_rejects_size_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("initramfs");
        let artifact_dir = cache.join("0.18.0").join("aarch64");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_IMAGE_FILE), b"image").unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_HASH_FILE), b"hash").unwrap();
        std::fs::write(artifact_dir.join(INITRAMFS_SIZE_FILE), "99").unwrap();
        std::fs::write(artifact_dir.join(VERSION_FILE), "0.18.0").unwrap();

        let resolver = InitramfsResolver::new(&cache, "0.18.0");
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(matches!(err, InitramfsError::SizeMismatch { .. }));
    }

    #[test]
    fn read_from_dir_returns_artifact() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(INITRAMFS_IMAGE_FILE), b"image").unwrap();
        std::fs::write(dir.path().join(INITRAMFS_HASH_FILE), b"hash").unwrap();
        std::fs::write(dir.path().join(INITRAMFS_SIZE_FILE), "5").unwrap();
        std::fs::write(dir.path().join(VERSION_FILE), "0.18.0").unwrap();

        let artifact = read_initramfs_artifact_from_dir(dir.path()).unwrap();
        assert_eq!(artifact.version, "0.18.0");
    }
}
