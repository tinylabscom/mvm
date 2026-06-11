//! Content-addressed store — blobs keyed by their SHA-256 digest.
//!
//! Identical content lands at the same path and is written once, so a
//! golden rootfs/memfile shared by many warm-start clones costs one copy on
//! disk — the storage half of the diff-snapshot. The
//! digest is the name, so the store is immutable: a put either finds the
//! object already present or writes it atomically.

use std::path::PathBuf;

use mvm_core::volume::VolumeError;
use sha2::{Digest, Sha256};

/// SHA-256 content digest. The lowercase-hex form is the on-disk filename.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Stores blobs under `root/<digest-hex>`. Dedups by digest: putting the
/// same bytes twice writes a single object.
pub struct ContentAddressedStore {
    root: PathBuf,
}

impl ContentAddressedStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Path an object with `digest` would occupy (whether or not present).
    pub fn path(&self, digest: &ContentDigest) -> PathBuf {
        self.root.join(digest.hex())
    }

    /// Store `bytes`, returning their digest. Idempotent: if an object with
    /// the same digest already exists it is left untouched (dedup).
    pub fn put(&self, bytes: &[u8]) -> Result<ContentDigest, VolumeError> {
        let digest = ContentDigest::of(bytes);
        let path = self.path(&digest);
        if !path.exists() {
            std::fs::create_dir_all(&self.root)?;
            // Atomic: write a temp sibling then rename, so a concurrent
            // reader never observes a half-written object.
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, bytes)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(digest)
    }

    /// Read a stored object by digest.
    pub fn get(&self, digest: &ContentDigest) -> Result<Vec<u8>, VolumeError> {
        Ok(std::fs::read(self.path(digest))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressed_dedups_identical_content_by_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::new(tmp.path());

        let d1 = cas.put(b"golden layer bytes").unwrap();
        let d2 = cas.put(b"golden layer bytes").unwrap();
        assert_eq!(d1, d2, "identical content must share a digest");

        // Dedup: identical content is a single on-disk object.
        let objects = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(objects, 1, "identical content must be stored once");

        // Distinct content → distinct digest + a second object.
        let d3 = cas.put(b"different bytes").unwrap();
        assert_ne!(d1, d3);
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);

        assert_eq!(cas.get(&d1).unwrap(), b"golden layer bytes");
        assert_eq!(cas.get(&d3).unwrap(), b"different bytes");
    }

    #[test]
    fn digest_hex_is_64_lowercase_chars() {
        let d = ContentDigest::of(b"x");
        let hex = d.hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
