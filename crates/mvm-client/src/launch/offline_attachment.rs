//! Retained signed archives for offline runtime attachments.
//!
//! During preparation, exact archive bytes are retained content-addressed
//! by the authenticated source artifact digest. On offline attachment the
//! accepted signed root and mandatory revocation policy are reauthenticated
//! before the retained bytes are served to the runtime.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

/// Content-addressed cache directory for retained archive bytes.
const RETAINED_ARCHIVES_DIR: &str = "retained-archives";

/// A retained archive whose bytes are content-addressed by the
/// authenticated source artifact digest.
#[derive(Debug, Clone)]
pub struct RetainedArchive {
    /// The sha256 digest that identifies this archive.
    pub digest: String,
    /// Path to the retained copy on disk.
    pub path: PathBuf,
    /// Size in bytes of the retained archive.
    pub size: u64,
}

/// Retain exact archive bytes content-addressed by the authenticated
/// source artifact digest.
///
/// The archive is copied to a content-addressed path under `cache_root`.
/// If a file already exists at that path with matching size, it is
/// re-verified rather than re-copied.
pub fn retain_archive(
    source: &Path,
    digest: &str,
    size: u64,
    cache_root: &Path,
) -> Result<RetainedArchive> {
    let dir = cache_root.join(RETAINED_ARCHIVES_DIR);
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating retained archive dir {}", dir.display()))?;

    let retained_path = dir.join(digest);

    // If already retained with correct size, verify digest and reuse.
    if retained_path.exists() {
        let existing_size = fs::metadata(&retained_path)
            .with_context(|| format!("reading retained archive {}", retained_path.display()))?
            .len();
        if existing_size == size {
            let existing_digest = mvm_core::crypto::image_verify::sha256_file(&retained_path)
                .with_context(|| {
                    format!("verifying retained archive {}", retained_path.display())
                })?;
            if existing_digest == digest {
                return Ok(RetainedArchive {
                    digest: digest.to_string(),
                    path: retained_path,
                    size,
                });
            }
        }
        // Size or digest mismatch — remove and re-copy.
        let _ = fs::remove_file(&retained_path);
    }

    // Copy and authenticate.
    let copied_size = fs::copy(source, &retained_path)
        .with_context(|| format!("retaining archive from {}", source.display()))?;
    ensure!(
        copied_size == size,
        "retained archive size mismatch: expected {size}, copied {copied_size}"
    );
    let copied_digest =
        mvm_core::crypto::image_verify::sha256_file(&retained_path).with_context(|| {
            format!(
                "computing digest of retained archive {}",
                retained_path.display()
            )
        })?;
    ensure!(
        copied_digest == digest,
        "retained archive digest mismatch after copy"
    );

    // Restrict permissions to owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&retained_path, fs::Permissions::from_mode(0o600));
    }

    Ok(RetainedArchive {
        digest: digest.to_string(),
        path: retained_path,
        size,
    })
}

/// Reauthenticate a retained archive against its expected digest and size.
///
/// Returns the path to the authenticated bytes, or an error if the
/// retained archive is missing, has been modified, or doesn't match
/// the expected identity.
pub fn reauthenticate_retained_archive(
    digest: &str,
    expected_size: u64,
    cache_root: &Path,
) -> Result<RetainedArchive> {
    let retained_path = cache_root.join(RETAINED_ARCHIVES_DIR).join(digest);
    ensure!(
        retained_path.exists(),
        "retained archive {} is not present; re-prepare the offline attachment",
        digest
    );

    let size = fs::metadata(&retained_path)
        .with_context(|| format!("reading retained archive {}", retained_path.display()))?
        .len();
    ensure!(
        size == expected_size,
        "retained archive size changed: expected {expected_size}, found {size}"
    );

    let actual_digest = mvm_core::crypto::image_verify::sha256_file(&retained_path)
        .with_context(|| format!("verifying retained archive {}", retained_path.display()))?;
    ensure!(
        actual_digest == digest,
        "retained archive digest changed: expected {digest}, found {actual_digest}"
    );

    Ok(RetainedArchive {
        digest: digest.to_string(),
        path: retained_path,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(path: &Path, contents: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    #[test]
    fn retain_and_reauthenticate_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.tar.gz");
        let contents = b"test archive contents for retention";
        write_file(&source, contents);

        let digest = mvm_core::crypto::image_verify::sha256_file(&source).unwrap();
        let size = contents.len() as u64;

        let cache = tmp.path().join("cache");
        let retained =
            retain_archive(&source, &digest, size, &cache).expect("retain should succeed");
        assert_eq!(retained.digest, digest);
        assert_eq!(retained.size, size);
        assert!(retained.path.exists());

        // Reauthenticate.
        let reauth = reauthenticate_retained_archive(&digest, size, &cache)
            .expect("reauthenticate should succeed");
        assert_eq!(reauth.digest, digest);
        assert_eq!(reauth.path, retained.path);
    }

    #[test]
    fn reauthenticate_detects_tampered_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.tar.gz");
        let contents = b"original bytes";
        write_file(&source, contents);

        let digest = mvm_core::crypto::image_verify::sha256_file(&source).unwrap();
        let size = contents.len() as u64;

        let cache = tmp.path().join("cache");
        retain_archive(&source, &digest, size, &cache).unwrap();

        // Tamper with the retained copy.
        let retained_path = cache.join(RETAINED_ARCHIVES_DIR).join(&digest);
        write_file(&retained_path, b"tampered bytes!!");

        let err = reauthenticate_retained_archive(&digest, size, &cache)
            .expect_err("should detect tamper");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("digest changed") || msg.contains("size changed"),
            "got: {msg}"
        );
    }

    #[test]
    fn reauthenticate_detects_missing_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let err = reauthenticate_retained_archive(
            "0000000000000000000000000000000000000000000000000000000000000000",
            100,
            tmp.path(),
        )
        .expect_err("should detect missing");
        assert!(format!("{err:#}").contains("not present"), "got: {err:#}");
    }

    #[test]
    fn retain_reuses_existing_valid_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.tar.gz");
        let contents = b"reuse test contents";
        write_file(&source, contents);

        let digest = mvm_core::crypto::image_verify::sha256_file(&source).unwrap();
        let size = contents.len() as u64;

        let cache = tmp.path().join("cache");
        let first = retain_archive(&source, &digest, size, &cache).unwrap();

        // Remove source and retain again — should reuse the cached copy.
        fs::remove_file(&source).unwrap();
        let second = retain_archive(
            &first.path, // point at the retained copy itself
            &digest,
            size,
            &cache,
        )
        .unwrap();
        assert_eq!(first.path, second.path);
    }
}
