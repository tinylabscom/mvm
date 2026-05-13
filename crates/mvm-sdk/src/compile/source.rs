//! Source-tree bundling per ADR-0008.
//!
//! Walks `app.source.path`, applies include/exclude globs, copies files into
//! `<staging>/src/` deterministically, and computes a stable `tree_hash` over
//! the resulting tree. Symlinks are preserved in-tree and rejected out-of-tree.
//! Devices/sockets/FIFOs are skipped silently. `.git/` is unconditionally
//! excluded.

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum SourceError {
    PathNotFound(PathBuf),
    PathNotDir(PathBuf),
    Copy(PathBuf, io::Error),
    GlobInvalid(String, String),
    OutOfTreeSymlink { link: PathBuf, target: PathBuf },
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotFound(p) => write!(f, "source path not found: {}", p.display()),
            Self::PathNotDir(p) => write!(f, "source path is not a directory: {}", p.display()),
            Self::Copy(p, e) => write!(f, "source copy failed at {}: {e}", p.display()),
            Self::GlobInvalid(pat, msg) => write!(f, "invalid glob {pat:?}: {msg}"),
            Self::OutOfTreeSymlink { link, target } => write!(
                f,
                "symlink {} resolves out-of-tree to {}",
                link.display(),
                target.display()
            ),
        }
    }
}

impl std::error::Error for SourceError {}

#[derive(Debug, Clone, Serialize)]
pub struct SourcePlan {
    pub kind: &'static str,
    pub subdir: &'static str,
    pub file_count: u32,
    pub tree_hash: String,
}

/// Re-walk an already-staged source directory and produce a fresh
/// `SourcePlan` reflecting its current contents. Used after bundler
/// reachability scoping (plan-0007 §Phase 2) prunes unreachable
/// files — the tree_hash needs to reflect what's actually shipped.
pub fn rehash(out_dir: &Path) -> Result<SourcePlan, SourceError> {
    if !out_dir.is_dir() {
        return Err(SourceError::PathNotDir(out_dir.to_path_buf()));
    }
    let mut entries: Vec<TreeEntry> = Vec::new();
    rehash_walk(out_dir, out_dir, &mut entries)?;
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    let file_count = entries
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::File))
        .count() as u32;
    let tree_hash = compute_tree_hash(&entries);
    Ok(SourcePlan {
        kind: "local_path",
        subdir: "src",
        file_count,
        tree_hash,
    })
}

fn rehash_walk(root: &Path, cur: &Path, entries: &mut Vec<TreeEntry>) -> Result<(), SourceError> {
    let mut dir_entries: Vec<_> = fs::read_dir(cur)
        .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?;
    dir_entries.sort_by_key(|e| e.file_name());
    for entry in dir_entries {
        let abs = entry.path();
        let relative = abs.strip_prefix(root).expect("walked under root");
        let relative_str = path_to_relative_str(relative);
        let file_type = entry
            .file_type()
            .map_err(|e| SourceError::Copy(abs.clone(), e))?;
        if file_type.is_symlink() {
            let target = fs::read_link(&abs).map_err(|e| SourceError::Copy(abs.clone(), e))?;
            entries.push(TreeEntry {
                relative_path: relative_str,
                kind: EntryKind::Symlink,
                mode: 0o120,
                content_record: target.to_string_lossy().into_owned().into_bytes(),
            });
        } else if file_type.is_dir() {
            rehash_walk(root, &abs, entries)?;
        } else if file_type.is_file() {
            let content = fs::read(&abs).map_err(|e| SourceError::Copy(abs.clone(), e))?;
            let metadata = fs::metadata(&abs).map_err(|e| SourceError::Copy(abs.clone(), e))?;
            let mode = metadata.permissions().mode() & 0o7777;
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let hash_hex = hex(&hasher.finalize());
            entries.push(TreeEntry {
                relative_path: relative_str,
                kind: EntryKind::File,
                mode,
                content_record: hash_hex.into_bytes(),
            });
        }
    }
    Ok(())
}

/// Copy `src_root` into `out_dir`, applying globs, and return a `SourcePlan`
/// summarizing the result. The output includes a content-addressed `tree_hash`
/// per ADR-0008 §6.
pub fn copy_source(
    src_root: &Path,
    out_dir: &Path,
    include: &[String],
    exclude: &[String],
) -> Result<SourcePlan, SourceError> {
    if !src_root.exists() {
        return Err(SourceError::PathNotFound(src_root.to_path_buf()));
    }
    if !src_root.is_dir() {
        return Err(SourceError::PathNotDir(src_root.to_path_buf()));
    }

    let canonical_root = src_root
        .canonicalize()
        .map_err(|e| SourceError::Copy(src_root.to_path_buf(), e))?;

    let include_set = build_glob_set(include, &["**".to_string()])?;
    let exclude_set = build_glob_set(exclude, &[])?;

    fs::create_dir_all(out_dir).map_err(|e| SourceError::Copy(out_dir.to_path_buf(), e))?;

    let mut entries: Vec<TreeEntry> = Vec::new();
    walk_dir(
        &canonical_root,
        &canonical_root,
        out_dir,
        &include_set,
        &exclude_set,
        &mut entries,
    )?;

    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let file_count = entries
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::File))
        .count() as u32;
    let tree_hash = compute_tree_hash(&entries);

    Ok(SourcePlan {
        kind: "local_path",
        subdir: "src",
        file_count,
        tree_hash,
    })
}

fn build_glob_set(patterns: &[String], default: &[String]) -> Result<GlobSet, SourceError> {
    let effective: &[String] = if patterns.is_empty() {
        default
    } else {
        patterns
    };
    let mut builder = GlobSetBuilder::new();
    for p in effective {
        let glob = Glob::new(p).map_err(|e| SourceError::GlobInvalid(p.clone(), e.to_string()))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| SourceError::GlobInvalid(String::new(), e.to_string()))
}

#[derive(Clone)]
enum EntryKind {
    File,
    Symlink,
    /// Reserved for future use; ADR-0008 §6 admits a `d` kind in `tree_hash`
    /// but v0.1 does not emit directory entries (empty dirs are not preserved).
    #[allow(dead_code)]
    Directory,
}

struct TreeEntry {
    relative_path: String,
    kind: EntryKind,
    mode: u32,
    /// SHA-256 hex for files, target string for symlinks, empty for dirs.
    content_record: Vec<u8>,
}

fn walk_dir(
    root: &Path,
    cur: &Path,
    out_root: &Path,
    include: &GlobSet,
    exclude: &GlobSet,
    entries: &mut Vec<TreeEntry>,
) -> Result<(), SourceError> {
    let mut dir_entries: Vec<_> = fs::read_dir(cur)
        .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?;
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let abs = entry.path();
        let relative = abs.strip_prefix(root).expect("walked under root");
        if relative.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        let relative_str = path_to_relative_str(relative);

        let file_type = entry
            .file_type()
            .map_err(|e| SourceError::Copy(abs.clone(), e))?;

        if file_type.is_symlink() {
            handle_symlink(
                &abs,
                &relative_str,
                root,
                out_root,
                include,
                exclude,
                entries,
            )?;
        } else if file_type.is_dir() {
            // Recurse but do NOT eagerly create the destination directory.
            // Directories appear in the output only if a file inside survives
            // the filter (lazy creation via `handle_file`'s parent.create_dir_all).
            // Empty directories are not preserved in v0.1 (file/symlink-only tree_hash).
            walk_dir(root, &abs, out_root, include, exclude, entries)?;
        } else if file_type.is_file() {
            if !include.is_match(&relative_str) || exclude.is_match(&relative_str) {
                continue;
            }
            handle_file(&abs, &relative_str, out_root, entries)?;
        }
        // device/socket/fifo: skip silently
    }
    Ok(())
}

fn handle_file(
    abs: &Path,
    relative_str: &str,
    out_root: &Path,
    entries: &mut Vec<TreeEntry>,
) -> Result<(), SourceError> {
    let content = fs::read(abs).map_err(|e| SourceError::Copy(abs.to_path_buf(), e))?;
    let metadata = fs::metadata(abs).map_err(|e| SourceError::Copy(abs.to_path_buf(), e))?;
    let mode = metadata.permissions().mode() & 0o7777;

    let dest = out_root.join(relative_str);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| SourceError::Copy(parent.to_path_buf(), e))?;
    }
    fs::write(&dest, &content).map_err(|e| SourceError::Copy(dest.clone(), e))?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(mode))
        .map_err(|e| SourceError::Copy(dest.clone(), e))?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash_hex = hex(&hasher.finalize());

    entries.push(TreeEntry {
        relative_path: relative_str.to_string(),
        kind: EntryKind::File,
        mode,
        content_record: hash_hex.into_bytes(),
    });
    Ok(())
}

fn handle_symlink(
    abs: &Path,
    relative_str: &str,
    root: &Path,
    out_root: &Path,
    include: &GlobSet,
    exclude: &GlobSet,
    entries: &mut Vec<TreeEntry>,
) -> Result<(), SourceError> {
    if !include.is_match(relative_str) || exclude.is_match(relative_str) {
        return Ok(());
    }
    let target = fs::read_link(abs).map_err(|e| SourceError::Copy(abs.to_path_buf(), e))?;
    let resolved_target = if target.is_absolute() {
        target.clone()
    } else {
        abs.parent().unwrap_or(root).join(&target)
    };
    let canonical_target = resolved_target
        .canonicalize()
        .map_err(|e| SourceError::Copy(resolved_target.clone(), e))?;
    if !canonical_target.starts_with(root) {
        return Err(SourceError::OutOfTreeSymlink {
            link: abs.to_path_buf(),
            target: canonical_target,
        });
    }

    let dest = out_root.join(relative_str);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| SourceError::Copy(parent.to_path_buf(), e))?;
    }
    if dest.exists() {
        let _ = fs::remove_file(&dest);
    }
    std::os::unix::fs::symlink(&target, &dest).map_err(|e| SourceError::Copy(dest.clone(), e))?;

    entries.push(TreeEntry {
        relative_path: relative_str.to_string(),
        kind: EntryKind::Symlink,
        mode: 0o120,
        content_record: target.to_string_lossy().into_owned().into_bytes(),
    });
    Ok(())
}

fn compute_tree_hash(entries: &[TreeEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in entries {
        let kind_byte = match entry.kind {
            EntryKind::File => b'f',
            EntryKind::Symlink => b'l',
            EntryKind::Directory => b'd',
        };
        hasher.update([kind_byte, b' ']);
        hasher.update(format!("{:04o}", entry.mode).as_bytes());
        hasher.update(b" ");
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0u8]);
        hasher.update(&entry.content_record);
        hasher.update([b'\n']);
    }
    hex(&hasher.finalize())
}

fn path_to_relative_str(p: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for component in p.components() {
        if let Component::Normal(s) = component {
            parts.push(s.to_string_lossy().into_owned());
        }
    }
    parts.join("/")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_src(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (rel, content) in files {
            let p = dir.path().join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
        }
        dir
    }

    #[test]
    fn copies_files_and_reports_count() {
        let src = make_src(&[("a.py", "print(1)\n"), ("sub/b.py", "print(2)\n")]);
        let out = TempDir::new().unwrap();
        let plan = copy_source(src.path(), &out.path().join("src"), &[], &[]).unwrap();
        assert_eq!(plan.file_count, 2);
        assert!(out.path().join("src/a.py").is_file());
        assert!(out.path().join("src/sub/b.py").is_file());
    }

    #[test]
    fn tree_hash_is_deterministic() {
        let src = make_src(&[("a", "1"), ("b", "2"), ("nested/c", "3")]);
        let out_a = TempDir::new().unwrap();
        let out_b = TempDir::new().unwrap();
        let plan_a = copy_source(src.path(), &out_a.path().join("src"), &[], &[]).unwrap();
        let plan_b = copy_source(src.path(), &out_b.path().join("src"), &[], &[]).unwrap();
        assert_eq!(plan_a.tree_hash, plan_b.tree_hash);
        assert_eq!(plan_a.tree_hash.len(), 64);
    }

    #[test]
    fn different_content_yields_different_hash() {
        let src1 = make_src(&[("a", "1")]);
        let src2 = make_src(&[("a", "2")]);
        let out1 = TempDir::new().unwrap();
        let out2 = TempDir::new().unwrap();
        let p1 = copy_source(src1.path(), &out1.path().join("src"), &[], &[]).unwrap();
        let p2 = copy_source(src2.path(), &out2.path().join("src"), &[], &[]).unwrap();
        assert_ne!(p1.tree_hash, p2.tree_hash);
    }

    #[test]
    fn excludes_dot_git_unconditionally() {
        let src = make_src(&[("a", "ok"), (".git/HEAD", "ref"), (".git/sub/x", "y")]);
        let out = TempDir::new().unwrap();
        let plan = copy_source(src.path(), &out.path().join("src"), &[], &[]).unwrap();
        assert_eq!(plan.file_count, 1);
        assert!(!out.path().join("src/.git").exists());
    }

    #[test]
    fn applies_include_and_exclude_globs() {
        let src = make_src(&[("a.py", "x"), ("b.txt", "y"), ("vendor/z.py", "z")]);
        let out = TempDir::new().unwrap();
        let plan = copy_source(
            src.path(),
            &out.path().join("src"),
            &["**/*.py".into()],
            &["vendor/**".into()],
        )
        .unwrap();
        assert_eq!(plan.file_count, 1);
        assert!(out.path().join("src/a.py").is_file());
        assert!(!out.path().join("src/b.txt").exists());
        assert!(!out.path().join("src/vendor").exists());
    }

    #[test]
    fn rejects_out_of_tree_symlink() {
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("evil"), "secret").unwrap();
        let src = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path().join("evil"), src.path().join("link")).unwrap();
        let out = TempDir::new().unwrap();
        let err = copy_source(src.path(), &out.path().join("src"), &[], &[]).unwrap_err();
        assert!(matches!(err, SourceError::OutOfTreeSymlink { .. }));
    }

    #[test]
    fn preserves_in_tree_symlink() {
        let src = make_src(&[("real.py", "x")]);
        std::os::unix::fs::symlink("real.py", src.path().join("link.py")).unwrap();
        let out = TempDir::new().unwrap();
        let plan = copy_source(src.path(), &out.path().join("src"), &[], &[]).unwrap();
        assert_eq!(plan.file_count, 1);
        let dest_link = out.path().join("src/link.py");
        let meta = fs::symlink_metadata(&dest_link).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(fs::read_link(&dest_link).unwrap(), Path::new("real.py"));
    }

    #[test]
    fn errors_on_missing_path() {
        let out = TempDir::new().unwrap();
        let err = copy_source(
            Path::new("/definitely/not/a/path"),
            &out.path().join("src"),
            &[],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SourceError::PathNotFound(_)));
    }

    #[test]
    fn errors_on_invalid_glob() {
        let src = make_src(&[("a", "x")]);
        let out = TempDir::new().unwrap();
        let err = copy_source(
            src.path(),
            &out.path().join("src"),
            &["[unterminated".into()],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SourceError::GlobInvalid(_, _)));
    }
}
