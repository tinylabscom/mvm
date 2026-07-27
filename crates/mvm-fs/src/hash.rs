//! Content-addressing for the snapshot store.
//!
//! A snapshot's identity is the SHA-256 of its content: for a file, the
//! hash of its bytes (reusing [`crate::overlay::compute_file_sha256`] so
//! file hashing has exactly one implementation in this crate); for a
//! directory, the hash of a deterministic manifest enumerating every entry.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;

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
/// stable across runs and hosts. Path/target components are hashed as raw
/// bytes (see [`os_str_bytes`]) rather than through a lossy UTF-8
/// conversion, so distinct non-UTF-8 filenames never collide.
fn hash_dir(root: &Path) -> io::Result<String> {
    let mut entries: Vec<(Vec<u8>, &'static str, Vec<u8>)> = Vec::new();
    walk_relative(root, &[], &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (relpath, kind, payload) in &entries {
        hasher.update(relpath);
        hasher.update(b"\0");
        hasher.update(kind.as_bytes());
        hasher.update(b"\0");
        hasher.update(payload);
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

fn walk_relative(
    abs_dir: &Path,
    rel_prefix: &[u8],
    out: &mut Vec<(Vec<u8>, &'static str, Vec<u8>)>,
) -> io::Result<()> {
    for entry in fs::read_dir(abs_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let abs_path = entry.path();
        let rel_bytes = join_relative(rel_prefix, &entry.file_name());

        if file_type.is_dir() {
            out.push((rel_bytes.clone(), "d", Vec::new()));
            walk_relative(&abs_path, &rel_bytes, out)?;
        } else if file_type.is_file() {
            let digest = compute_file_sha256(&abs_path)?;
            out.push((rel_bytes, "f", digest.into_bytes()));
        } else if file_type.is_symlink() {
            let target = fs::read_link(&abs_path)?;
            out.push((rel_bytes, "l", os_str_bytes(target.as_os_str())));
        }
        // Other inode types (fifo/socket/device) have no stable content to
        // hash and are skipped, mirroring `clone::reflink_or_copy_dir`.
    }
    Ok(())
}

/// Append one path component (as raw bytes) to a `/`-joined relative path.
fn join_relative(rel_prefix: &[u8], name: &OsStr) -> Vec<u8> {
    let name_bytes = os_str_bytes(name);
    if rel_prefix.is_empty() {
        return name_bytes;
    }
    let mut out = Vec::with_capacity(rel_prefix.len() + 1 + name_bytes.len());
    out.extend_from_slice(rel_prefix);
    out.push(b'/');
    out.extend_from_slice(&name_bytes);
    out
}

/// The raw bytes of a path component. On unix this is exact (any byte
/// sequence is a valid filename); elsewhere there's no such guarantee, so
/// a lossy UTF-8 conversion is the best available fallback.
#[cfg(unix)]
fn os_str_bytes(s: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_str_bytes(s: &OsStr) -> Vec<u8> {
    s.to_string_lossy().into_owned().into_bytes()
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

    /// Two distinct non-UTF-8 byte sequences that `to_string_lossy` would
    /// both mangle to the same U+FFFD-substituted string — proving
    /// `os_str_bytes` keeps them distinct instead of hashing a lossy
    /// string that would collide. Exercised in-memory (not via real
    /// files) because APFS rejects non-UTF-8 filenames outright, so a
    /// filesystem-backed version of this test wouldn't run on macOS.
    #[cfg(unix)]
    #[test]
    fn os_str_bytes_preserves_non_utf8_sequences_without_lossy_collision() {
        use std::os::unix::ffi::OsStrExt;

        let a = OsStr::from_bytes(b"f\xFF");
        let b = OsStr::from_bytes(b"f\xFE");

        assert_eq!(
            a.to_string_lossy(),
            b.to_string_lossy(),
            "precondition: both collide under lossy UTF-8 conversion"
        );
        assert_ne!(
            os_str_bytes(a),
            os_str_bytes(b),
            "raw-byte hashing must keep them distinct"
        );
    }
}
