//! Shared test fixtures for the OCI unpack attack-surface
//! integration tests. Builds in-memory tarballs with `tar::Builder`
//! so each hostile-input class can be constructed once and asserted
//! against `ImageStaging::apply_layer`.
//!
//! Not a real `#[test]` file — just helpers re-exported into the
//! attack-class tests via `mod oci_unpack_common;` at the top of
//! each.

#![allow(dead_code)]

use std::path::Path;
use tar::{Builder, EntryType, Header};

/// Append one regular file entry to `builder` at `path` with
/// `contents`. Mode defaults to 0644.
pub fn add_file(builder: &mut Builder<Vec<u8>>, path: &str, contents: &[u8]) {
    add_file_with_mode(builder, path, contents, 0o644);
}

pub fn add_file_with_mode(builder: &mut Builder<Vec<u8>>, path: &str, contents: &[u8], mode: u32) {
    let mut header = Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(mode);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, path, contents)
        .expect("append regular file");
}

/// Append one directory entry with `mode`.
pub fn add_directory(builder: &mut Builder<Vec<u8>>, path: &str, mode: u32) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(mode);
    header.set_entry_type(EntryType::Directory);
    header.set_cksum();
    builder
        .append_data(&mut header, path, std::io::empty())
        .expect("append directory");
}

/// Append a symlink entry `link` -> `target`.
pub fn add_symlink(builder: &mut Builder<Vec<u8>>, link: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(EntryType::Symlink);
    header.set_link_name(target).expect("set symlink target");
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_data(&mut header, link, std::io::empty())
        .expect("append symlink");
}

/// Append a hardlink entry `link` -> `target_in_staging`.
pub fn add_hardlink(builder: &mut Builder<Vec<u8>>, link: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(EntryType::Link);
    header.set_link_name(target).expect("set hardlink target");
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, link, std::io::empty())
        .expect("append hardlink");
}

/// Append a tar entry of arbitrary type. Used to inject
/// unsupported entry types (block, char, fifo) for negative
/// tests.
pub fn add_entry_of_type(builder: &mut Builder<Vec<u8>>, path: &str, entry_type: EntryType) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(entry_type);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, path, std::io::empty())
        .expect("append typed entry");
}

/// Finish the tar builder and return the in-memory bytes.
pub fn finish(builder: Builder<Vec<u8>>) -> Vec<u8> {
    builder.into_inner().expect("finish tar")
}

/// Build a single-entry tar with one regular file.
pub fn simple_file_tar(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut b = Builder::new(Vec::new());
    add_file(&mut b, path, contents);
    finish(b)
}

/// Construct an in-memory tar from a list of unchecked entries.
/// `tar::Builder::append_data` deliberately rejects `..` and
/// absolute paths — which is the right safety property for
/// callers building real archives, but a problem for tests that
/// need to assert mvm's unpacker handles hostile inputs.
///
/// Each [`RawEntry`] is appended via the low-level `append` API
/// after the path is set via `set_path_bytes`, which does NOT
/// validate. The resulting tar is the kind of thing a malicious
/// registry would actually serve.
pub fn build_unchecked_tar(entries: &[RawEntry]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_size(entry.contents.len() as u64);
        header.set_mode(entry.mode);
        header.set_entry_type(entry.entry_type);

        // Direct byte-level write into the `name` field bypasses
        // `tar::Header::set_path`'s `..` / absolute-path
        // validation, which is exactly what we need to reproduce
        // a malicious registry's tar stream.
        write_old_name(&mut header, entry.path.as_bytes());
        if let Some(target) = entry.link_target {
            write_old_linkname(&mut header, target.as_bytes());
        }

        header.set_cksum();
        builder
            .append(&header, entry.contents)
            .expect("append unchecked");
    }
    finish(builder)
}

fn write_old_name(header: &mut Header, bytes: &[u8]) {
    let old = header.as_old_mut();
    old.name.fill(0);
    let n = bytes.len().min(old.name.len());
    old.name[..n].copy_from_slice(&bytes[..n]);
}

fn write_old_linkname(header: &mut Header, bytes: &[u8]) {
    let old = header.as_old_mut();
    old.linkname.fill(0);
    let n = bytes.len().min(old.linkname.len());
    old.linkname[..n].copy_from_slice(&bytes[..n]);
}

/// One entry in a hostile-tar fixture. `link_target` is used only
/// for symlinks and hardlinks; `contents` is the body for regular
/// files (empty for everything else).
pub struct RawEntry<'a> {
    pub path: &'a str,
    pub mode: u32,
    pub entry_type: EntryType,
    pub link_target: Option<&'a str>,
    pub contents: &'a [u8],
}

impl<'a> RawEntry<'a> {
    pub fn file(path: &'a str, contents: &'a [u8]) -> Self {
        Self {
            path,
            mode: 0o644,
            entry_type: EntryType::Regular,
            link_target: None,
            contents,
        }
    }

    pub fn hardlink(path: &'a str, target: &'a str) -> Self {
        Self {
            path,
            mode: 0o644,
            entry_type: EntryType::Link,
            link_target: Some(target),
            contents: &[],
        }
    }
}

/// Assert that the staging directory contains exactly the
/// regular-file entries listed in `expected` (path → bytes).
/// Anything else under the root fails the assertion. Useful for
/// post-conditions on positive-path tests.
pub fn assert_staging_files(staging_root: &Path, expected: &[(&str, &[u8])]) {
    let mut found = std::collections::BTreeMap::new();
    walk(staging_root, staging_root, &mut found);
    assert_eq!(
        found.len(),
        expected.len(),
        "expected {} files, found {} in staging dir {:?}: {:?}",
        expected.len(),
        found.len(),
        staging_root,
        found.keys().collect::<Vec<_>>(),
    );
    for (path, expected_bytes) in expected {
        let actual = found.get(*path).unwrap_or_else(|| {
            panic!(
                "missing expected staging file {path:?}; found {:?}",
                found.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(actual, expected_bytes, "bytes mismatch for {path}");
    }
}

fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            walk(root, &path, out);
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(&path).unwrap();
            out.insert(relative, bytes);
        }
    }
}
