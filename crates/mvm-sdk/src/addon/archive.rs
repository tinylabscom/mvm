//! Deterministic `.tar.gz` packaging of an addon directory.
//!
//! Mirrors the determinism guarantees of the compile pipeline's
//! `archive_dir`: sorted entries, `mtime = 0`, mode normalized to
//! `0o644 / 0o755`, gzip with no filename header. Produces bytes
//! in-memory so the caller can sha256 + sign + ship without intermediate
//! files. The signature payload is over these bytes.

use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Outcome of building an addon tarball: bytes + sha256.
pub struct AddonArchive {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Pack an addon directory deterministically. Returns the canonical-form
/// tarball bytes and their sha256.
///
/// Determinism rules:
/// - entries sorted by normalized POSIX path,
/// - all timestamps zeroed (mtime/ctime/atime = 0),
/// - uid/gid/uname/gname cleared,
/// - file modes normalized to `0o644` (regular) / `0o755` (executable),
/// - gzip header has no filename and `mtime = 0`.
///
/// Symlinks inside the addon directory aren't expected — addon bundles
/// declare their content explicitly. Symlinks are followed defensively
/// when they target a regular file inside the same tree; out-of-tree
/// symlinks return `ErrorKind::InvalidInput`.
pub fn pack_addon_dir(dir: &Path) -> io::Result<AddonArchive> {
    let mut entries = collect_entries(dir)?;
    entries.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));

    let mut buf = Vec::<u8>::new();
    {
        let gz = flate2::GzBuilder::new()
            .filename("")
            .mtime(0)
            .write(&mut buf, Compression::default());
        let mut builder = tar::Builder::new(gz);
        builder.mode(tar::HeaderMode::Deterministic);
        for entry in &entries {
            write_entry(&mut builder, entry)?;
        }
        let gz = builder.into_inner()?;
        gz.finish()?;
    }
    let sha256 = sha256_hex(&buf);
    Ok(AddonArchive { bytes: buf, sha256 })
}

/// Compute sha256 of arbitrary bytes (the canonical tarball or SBOM).
/// Returned as 64 lowercase hex chars to match the IR field shape.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[derive(Debug)]
struct Entry {
    abs_path: PathBuf,
    archive_path: String,
    is_dir: bool,
    is_executable: bool,
}

fn collect_entries(root: &Path) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, cur: &Path, out: &mut Vec<Entry>) -> io::Result<()> {
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
            // Defensive: addon directories shouldn't carry symlinks,
            // but if one resolves to a file inside the addon root we
            // follow it. Out-of-tree targets fail loudly.
            let target = fs::read_link(&child)?;
            let abs = if target.is_absolute() {
                target
            } else {
                child.parent().unwrap_or(root).join(target)
            };
            let canonical = abs.canonicalize()?;
            let root_canonical = root.canonicalize()?;
            if !canonical.starts_with(&root_canonical) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "symlink {child:?} resolves outside the addon directory ({canonical:?})"
                    ),
                ));
            }
            let target_meta = fs::metadata(&canonical)?;
            if target_meta.is_file() {
                let mode = target_meta.permissions().mode();
                out.push(Entry {
                    abs_path: canonical,
                    archive_path: rel,
                    is_dir: false,
                    is_executable: (mode & 0o111) != 0,
                });
            }
        }
    }
    Ok(())
}

fn write_entry(builder: &mut tar::Builder<impl io::Write>, entry: &Entry) -> io::Result<()> {
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
    use tempfile::tempdir;

    fn write(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn build_sample_addon(root: &Path) {
        write(
            &root.join("addon.toml"),
            b"manifest_version = \"0\"\n[addon]\nname = \"x\"\nversion = \"0.1.0\"\ndescription = \"x\"\ntier = \"separate\"\n[[addon.exports]]\nlogical_name = \"main\"\nprotocol = \"x\"\ndefault_port = 1\nenv_var = \"X_URL\"\ncredentials = \"generated\"\ncredential_format = \"none\"\n",
        );
        write(&root.join("workload.py"), b"import mvm\n");
        write(&root.join("README.md"), b"# x\n");
    }

    #[test]
    fn sha256_hex_is_64_lowercase_hex() {
        let s = sha256_hex(b"hello, addons");
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
        );
    }

    #[test]
    fn pack_is_byte_reproducible_across_runs() {
        let dir = tempdir().unwrap();
        let addon = dir.path().join("addon");
        build_sample_addon(&addon);

        let a = pack_addon_dir(&addon).unwrap();
        let b = pack_addon_dir(&addon).unwrap();
        assert_eq!(a.bytes, b.bytes, "tarball bytes must be byte-identical");
        assert_eq!(a.sha256, b.sha256, "sha256 must match across runs");
    }

    #[test]
    fn pack_round_trips_contents() {
        let dir = tempdir().unwrap();
        let addon = dir.path().join("addon");
        build_sample_addon(&addon);
        let archive = pack_addon_dir(&addon).unwrap();

        let extract = dir.path().join("extract");
        fs::create_dir_all(&extract).unwrap();
        let gz = flate2::read::GzDecoder::new(&archive.bytes[..]);
        let mut a = tar::Archive::new(gz);
        a.unpack(&extract).unwrap();

        assert_eq!(
            fs::read(extract.join("workload.py")).unwrap(),
            b"import mvm\n"
        );
        assert_eq!(fs::read(extract.join("README.md")).unwrap(), b"# x\n");
    }

    #[test]
    fn pack_preserves_executable_bit() {
        let dir = tempdir().unwrap();
        let addon = dir.path().join("addon");
        let bin = addon.join("scripts").join("init.sh");
        write(&bin, b"#!/bin/sh\necho init\n");
        let mut perms = fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin, perms).unwrap();
        write(&addon.join("addon.toml"), b"manifest_version=\"0\"\n");

        let archive = pack_addon_dir(&addon).unwrap();
        let extract = dir.path().join("extract");
        fs::create_dir_all(&extract).unwrap();
        let gz = flate2::read::GzDecoder::new(&archive.bytes[..]);
        let mut a = tar::Archive::new(gz);
        a.unpack(&extract).unwrap();

        let extracted = extract.join("scripts").join("init.sh");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "executable bit lost during round-trip");
    }

    #[test]
    fn pack_orders_entries_lexicographically() {
        // Build two trees with files added in different orders; the
        // resulting archive bytes must be byte-identical because we
        // sort by archive_path before emitting.
        let dir = tempdir().unwrap();
        let a_root = dir.path().join("a");
        write(&a_root.join("z.txt"), b"z\n");
        write(&a_root.join("a.txt"), b"a\n");
        write(&a_root.join("m.txt"), b"m\n");

        let b_root = dir.path().join("b");
        write(&b_root.join("a.txt"), b"a\n");
        write(&b_root.join("m.txt"), b"m\n");
        write(&b_root.join("z.txt"), b"z\n");

        let a = pack_addon_dir(&a_root).unwrap();
        let b = pack_addon_dir(&b_root).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }
}
