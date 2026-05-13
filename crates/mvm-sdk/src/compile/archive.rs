//! Deterministic gzipped-tar archiver for `mvmforge compile`.
//!
//! Per ADR-0012, `mvmforge compile --out path.tar.gz` produces a single
//! `.tar.gz` containing the same logical contents the directory mode
//! emits today: `flake.nix`, `launch.json`, `source/...`, and (during
//! the W4 transition) `nix/factories/...`. The archive is byte-
//! reproducible across runs of the same IR — same input always
//! produces the same `sha256sum` — by:
//!
//! - sorting entries by their normalized POSIX path,
//! - zeroing all timestamps (mtime = 0, ctime = 0, atime = 0),
//! - clearing uid/gid/uname/gname,
//! - normalizing file modes to 0o755 (executables, directories) and
//!   0o644 (regular files),
//! - using `flate2`'s default gzip compression with no
//!   filename / mtime metadata in the gzip header.
//!
//! The output is a pax-extended ustar archive (the `tar` crate's
//! default), which all `tar` implementations on Linux/macOS read.

use flate2::Compression;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ArchiveError(pub io::Error);

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "archive write failed: {}", self.0)
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(e: io::Error) -> Self {
        Self(e)
    }
}

/// Write a deterministic gzipped tar of `staging_dir` to `out`. Paths
/// inside the archive are POSIX-relative to `staging_dir` (so
/// `flake.nix` not `<staging>/flake.nix`).
pub fn archive_dir(staging_dir: &Path, out: &Path) -> Result<(), ArchiveError> {
    let mut entries = collect_entries(staging_dir)?;
    // Sort lexicographically by normalized path for byte-identity
    // across filesystems whose readdir ordering differs.
    entries.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));

    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let file = fs::File::create(out)?;
    // GzBuilder with a fixed compression level + no filename header
    // ensures the gzip stream is reproducible.
    let gz = flate2::GzBuilder::new()
        .filename("")
        .mtime(0)
        .write(file, Compression::default());
    let mut builder = tar::Builder::new(gz);
    builder.mode(tar::HeaderMode::Deterministic);

    for entry in &entries {
        write_entry(&mut builder, staging_dir, entry)?;
    }

    let gz = builder.into_inner()?;
    gz.finish()?;
    Ok(())
}

#[derive(Debug)]
struct Entry {
    abs_path: PathBuf,
    archive_path: String,
    is_dir: bool,
    is_executable: bool,
}

fn collect_entries(root: &Path) -> Result<Vec<Entry>, ArchiveError> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, cur: &Path, out: &mut Vec<Entry>) -> Result<(), ArchiveError> {
    let mut children: Vec<_> = fs::read_dir(cur)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    for child in children {
        let meta = fs::symlink_metadata(&child)?;
        let rel = child
            .strip_prefix(root)
            .expect("walked under root")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if meta.is_dir() {
            out.push(Entry {
                abs_path: child.clone(),
                archive_path: rel.clone(),
                is_dir: true,
                is_executable: false,
            });
            walk(root, &child, out)?;
        } else if meta.is_file() {
            let mode = meta.permissions().mode();
            out.push(Entry {
                abs_path: child,
                archive_path: rel,
                is_dir: false,
                is_executable: (mode & 0o111) != 0,
            });
        } else if meta.file_type().is_symlink() {
            // Symlinks aren't expected inside the staged artifact —
            // `compile.rs` resolves source-tree symlinks at copy
            // time. If one shows up, fall back to copying its target
            // contents (defensive; should not trigger in practice).
            let resolved = fs::read_link(&child)?;
            let abs = if resolved.is_absolute() {
                resolved
            } else {
                child.parent().unwrap_or(root).join(resolved)
            };
            let target_meta = fs::metadata(&abs)?;
            if target_meta.is_file() {
                let mode = target_meta.permissions().mode();
                out.push(Entry {
                    abs_path: abs,
                    archive_path: rel,
                    is_dir: false,
                    is_executable: (mode & 0o111) != 0,
                });
            }
        }
    }
    Ok(())
}

fn write_entry(
    builder: &mut tar::Builder<impl io::Write>,
    _root: &Path,
    entry: &Entry,
) -> Result<(), ArchiveError> {
    let mut header = tar::Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_username("").ok();
    header.set_groupname("").ok();
    header.set_mtime(0);

    if entry.is_dir {
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_size(0);
        // Directory paths in tar conventionally end in `/`.
        let path = format!("{}/", entry.archive_path);
        builder.append_data(&mut header, path, io::empty())?;
    } else {
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(if entry.is_executable { 0o755 } else { 0o644 });
        let data = fs::read(&entry.abs_path)?;
        header.set_size(data.len() as u64);
        builder.append_data(&mut header, &entry.archive_path, &data[..])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn sha256(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let bytes = fs::read(path).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("{:x}", h.finalize())
    }

    fn build_sample(root: &Path) {
        write(&root.join("flake.nix"), b"{ description = \"x\"; }\n");
        write(&root.join("launch.json"), b"{}\n");
        write(&root.join("source").join("app.py"), b"x = 1\n");
        write(
            &root.join("source").join("subdir").join("helper.py"),
            b"y = 2\n",
        );
    }

    #[test]
    fn archive_is_byte_reproducible_across_runs() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        build_sample(&staging);

        let a = dir.path().join("a.tar.gz");
        let b = dir.path().join("b.tar.gz");
        archive_dir(&staging, &a).unwrap();
        archive_dir(&staging, &b).unwrap();
        assert_eq!(
            sha256(&a),
            sha256(&b),
            "archive output must be byte-identical"
        );
    }

    #[test]
    fn archive_preserves_executable_bit() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        let bin = staging.join("bin").join("run.sh");
        write(&bin, b"#!/bin/sh\necho hi\n");
        let mut perms = fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin, perms).unwrap();

        let out = dir.path().join("out.tar.gz");
        archive_dir(&staging, &out).unwrap();

        // Round-trip: extract and verify the bit survives.
        let extract = dir.path().join("extract");
        fs::create_dir_all(&extract).unwrap();
        let f = fs::File::open(&out).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut a = tar::Archive::new(gz);
        a.unpack(&extract).unwrap();
        let extracted = extract.join("bin").join("run.sh");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "executable bit lost during round-trip");
    }

    #[test]
    fn archive_round_trips_contents() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        build_sample(&staging);
        let out = dir.path().join("out.tar.gz");
        archive_dir(&staging, &out).unwrap();

        let extract = dir.path().join("extract");
        fs::create_dir_all(&extract).unwrap();
        let f = fs::File::open(&out).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut a = tar::Archive::new(gz);
        a.unpack(&extract).unwrap();

        assert_eq!(
            fs::read(extract.join("flake.nix")).unwrap(),
            b"{ description = \"x\"; }\n"
        );
        assert_eq!(
            fs::read(extract.join("source").join("app.py")).unwrap(),
            b"x = 1\n"
        );
        assert_eq!(
            fs::read(extract.join("source").join("subdir").join("helper.py")).unwrap(),
            b"y = 2\n"
        );
    }
}
