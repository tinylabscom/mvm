//! Content-addressing for the snapshot store.
//!
//! A snapshot's identity is the SHA-256 of its content: for a file, the
//! hash of its bytes (reusing [`crate::overlay::compute_file_sha256`] so
//! file hashing has exactly one implementation in this crate); for a
//! directory, the hash of a deterministic manifest enumerating every entry.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::overlay::compute_file_sha256;

/// Compute the content hash of `source` (a regular file or a directory).
/// Returns the lowercase 64-hex-digit SHA-256 digest.
pub fn hash_source(source: &Path) -> io::Result<String> {
    let meta = fs::symlink_metadata(source)?;
    if meta.is_dir() {
        hash_dir(source)
    } else if meta.is_file() {
        compute_file_sha256(source)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "hash source must be a regular file or directory: {}",
                source.display()
            ),
        ))
    }
}

/// Hash a directory as a deterministic manifest: one line per entry in
/// sorted relative-path order, `"{relpath}\0{kind}\0{payload}\n"` where
/// `kind` is `f`/`d`/`l` and `payload` is the entry's sha256 hex (`f`),
/// symlink target (`l`), or empty (`d`). Sorting by relative path (rather
/// than trusting readdir order, which varies by filesystem) makes the hash
/// stable across runs and hosts.
fn hash_dir(root: &Path) -> io::Result<String> {
    let mut entries: Vec<(String, &'static str, String)> = Vec::new();
    walk_relative(root, Path::new(""), &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (relpath, kind, payload) in &entries {
        hasher.update(relpath.as_bytes());
        hasher.update(b"\0");
        hasher.update(kind.as_bytes());
        hasher.update(b"\0");
        hasher.update(payload.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

fn walk_relative(
    abs_dir: &Path,
    rel_dir: &Path,
    out: &mut Vec<(String, &'static str, String)>,
) -> io::Result<()> {
    for entry in fs::read_dir(abs_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let abs_path = entry.path();
        let rel_path: PathBuf = rel_dir.join(entry.file_name());
        let rel_str = rel_path.to_string_lossy().into_owned();

        if file_type.is_dir() {
            out.push((rel_str, "d", String::new()));
            walk_relative(&abs_path, &rel_path, out)?;
        } else if file_type.is_file() {
            let digest = compute_file_sha256(&abs_path)?;
            out.push((rel_str, "f", digest));
        } else if file_type.is_symlink() {
            let target = fs::read_link(&abs_path)?;
            out.push((rel_str, "l", target.to_string_lossy().into_owned()));
        }
        // Other inode types (fifo/socket/device) have no stable content to
        // hash and are skipped, mirroring `clone::reflink_or_copy_dir`.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_hash_is_deterministic_and_content_sensitive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = tmp.path().join("a.bin");
        fs::write(&a, b"hello").unwrap();
        let b = tmp.path().join("b.bin");
        fs::write(&b, b"hello").unwrap();
        let c = tmp.path().join("c.bin");
        fs::write(&c, b"world").unwrap();

        assert_eq!(hash_source(&a).unwrap(), hash_source(&a).unwrap());
        assert_eq!(
            hash_source(&a).unwrap(),
            hash_source(&b).unwrap(),
            "identical bytes hash identically regardless of path"
        );
        assert_ne!(hash_source(&a).unwrap(), hash_source(&c).unwrap());
    }

    #[test]
    fn dir_hash_is_deterministic_and_content_sensitive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mk = |root: &Path, tweak: &[u8]| {
            fs::create_dir_all(root.join("sub")).unwrap();
            fs::write(root.join("top.txt"), b"top").unwrap();
            fs::write(root.join("sub").join("nested.txt"), tweak).unwrap();
        };

        let dir1 = tmp.path().join("dir1");
        mk(&dir1, b"nested");
        let dir2 = tmp.path().join("dir2");
        mk(&dir2, b"nested");
        let dir3 = tmp.path().join("dir3");
        mk(&dir3, b"different");

        assert_eq!(
            hash_source(&dir1).unwrap(),
            hash_source(&dir2).unwrap(),
            "identical directory trees hash identically"
        );
        assert_ne!(hash_source(&dir1).unwrap(), hash_source(&dir3).unwrap());
    }
}
