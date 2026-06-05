//! Per-file AES-256-GCM at-rest for non-Linux volumes.
//!
//! Linux gets a block-level encrypted volume from LUKS2
//! (`mvm/src/security/encryption.rs`). macOS has no equivalent without a
//! loopback / device-mapper dependency, and an mvm volume is small
//! app-deps content rather than a block device — so on non-Linux we seal
//! each file in place with the same chunked AES-256-GCM the snapshot
//! pipeline uses ([`crate::crypto::snapshot_encryption`], which since plan
//! 122 A1 funnels through [`crate::crypto::aead`]). Reusing that path buys
//! the atomic in-place rename, large-file chunking, and `MVSE`-magic probe
//! for free instead of re-deriving a whole-file sealer here.
//!
//! Which arm runs — LUKS2 or this — is plan 123's `StorageProvider`
//! decision; this module is only the macOS/non-Linux half.
//!
//! Compiled out on Linux: the LUKS2 path owns that target.
#![cfg(not(target_os = "linux"))]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::crypto::snapshot_encryption;

/// Seal every regular file under `dir` in place with `key` (a 32-byte
/// AES-256 key).
///
/// Idempotent: a file already carrying the `MVSE` magic is skipped, so a
/// re-seal after a partial run finishes the remainder rather than
/// double-encrypting. Symlinks are skipped, not followed — a sealed
/// volume should not contain them, and following one could escape `dir`.
pub fn seal_dir(dir: &Path, key: &[u8]) -> Result<()> {
    for path in walk_files(dir)? {
        if snapshot_encryption::probe(&path)?.is_some() {
            continue; // already sealed
        }
        snapshot_encryption::encrypt_file_in_place(&path, key)
            .with_context(|| format!("sealing {}", path.display()))?;
    }
    Ok(())
}

/// Inverse of [`seal_dir`]: decrypt every sealed file under `dir` in
/// place. Files without the `MVSE` magic are left untouched, so it is
/// safe to run on a partially-opened volume.
pub fn open_dir(dir: &Path, key: &[u8]) -> Result<()> {
    for path in walk_files(dir)? {
        if snapshot_encryption::probe(&path)?.is_none() {
            continue; // not sealed
        }
        snapshot_encryption::decrypt_file_in_place(&path, key)
            .with_context(|| format!("opening {}", path.display()))?;
    }
    Ok(())
}

/// Collect regular files under `dir`, recursing into subdirectories.
/// Symlinks are not followed (see [`seal_dir`]).
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in
            std::fs::read_dir(&d).with_context(|| format!("reading dir {}", d.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                out.push(entry.path());
            }
            // symlinks and other node types: skip.
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn key() -> [u8; 32] {
        [0x5Au8; 32]
    }

    #[test]
    fn seal_dir_roundtrips_and_hides_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("a.txt"), b"RECOGNIZABLE_TOP_LEVEL").unwrap();
        fs::write(root.join("sub/b.txt"), b"RECOGNIZABLE_NESTED").unwrap();

        seal_dir(root, &key()).unwrap();

        // On disk every file is ciphertext: the markers are gone and each
        // file starts with the MVSE magic.
        let a = fs::read(root.join("a.txt")).unwrap();
        let b = fs::read(root.join("sub/b.txt")).unwrap();
        assert!(!a.windows(11).any(|w| w == b"RECOGNIZABLE"));
        assert!(!b.windows(11).any(|w| w == b"RECOGNIZABLE"));
        assert_eq!(&a[0..4], snapshot_encryption::MAGIC);
        assert_eq!(&b[0..4], snapshot_encryption::MAGIC);

        open_dir(root, &key()).unwrap();
        assert_eq!(
            fs::read(root.join("a.txt")).unwrap(),
            b"RECOGNIZABLE_TOP_LEVEL"
        );
        assert_eq!(
            fs::read(root.join("sub/b.txt")).unwrap(),
            b"RECOGNIZABLE_NESTED"
        );
    }

    #[test]
    fn open_dir_with_wrong_key_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("secret.bin"), b"sensitive volume bytes").unwrap();
        seal_dir(root, &key()).unwrap();

        let mut wrong = key();
        wrong[0] ^= 0xFF;
        assert!(open_dir(root, &wrong).is_err());
    }

    #[test]
    fn seal_dir_is_idempotent_and_open_dir_ignores_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("f.bin"), b"payload").unwrap();

        seal_dir(root, &key()).unwrap();
        let once = fs::read(root.join("f.bin")).unwrap();
        // Second seal must not double-encrypt the already-sealed file.
        seal_dir(root, &key()).unwrap();
        assert_eq!(fs::read(root.join("f.bin")).unwrap(), once);

        // A stray plaintext file is left alone by open_dir.
        fs::write(root.join("plain.txt"), b"not sealed").unwrap();
        open_dir(root, &key()).unwrap();
        assert_eq!(fs::read(root.join("plain.txt")).unwrap(), b"not sealed");
        assert_eq!(fs::read(root.join("f.bin")).unwrap(), b"payload");
    }
}
