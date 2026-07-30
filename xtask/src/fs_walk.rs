//! Recursive file walking, shared by the source-scanning gates.
//!
//! Four gates had each hand-rolled the same `std::fs::read_dir` recursion
//! with the same skip list. One copy is enough.
//!
//! Traversal order is deterministic. `check-mutation-witnesses` commits its
//! resolved surface to a file, so two runs over the same tree have to agree;
//! the other callers emit error lists that are simply nicer to read stable.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Directories never worth descending into: build output and VCS metadata.
const SKIP_DIRS: [&str; 3] = ["target", ".git", "node_modules"];

/// Visit every file under `dir`, recursively, in sorted order.
///
/// A missing `dir` is not an error — a gate that scans an optional tree
/// should stay silent rather than fail when the tree is absent.
pub fn walk_files(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if SKIP_DIRS.contains(&name) {
                continue;
            }
            walk_files(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

/// Visit the path and text of every file under `dir` whose extension matches
/// `ext` (or of every file when `ext` is `None`).
///
/// Files that are not valid UTF-8 are skipped: a gate that greps source has
/// nothing to say about a binary blob.
pub fn for_each_file(dir: &Path, ext: Option<&str>, cb: &mut dyn FnMut(&Path, &str)) -> Result<()> {
    walk_files(dir, &mut |path| {
        let matches_ext = match ext {
            Some(want) => path.extension().and_then(|e| e.to_str()) == Some(want),
            None => true,
        };
        if matches_ext && let Ok(content) = std::fs::read_to_string(path) {
            cb(path, &content);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dir_is_not_an_error() {
        let mut seen = 0;
        let r = walk_files(Path::new("/nonexistent/xtask/probe"), &mut |_| seen += 1);
        assert!(r.is_ok());
        assert_eq!(seen, 0);
    }

    #[test]
    fn walk_recurses_skips_build_dirs_and_is_ordered() {
        let tmp = std::env::temp_dir().join(format!("xtask-fs-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src/inner")).unwrap();
        std::fs::create_dir_all(tmp.join("target/debug")).unwrap();
        std::fs::write(tmp.join("src/b.rs"), "b").unwrap();
        std::fs::write(tmp.join("src/a.rs"), "a").unwrap();
        std::fs::write(tmp.join("src/inner/c.rs"), "c").unwrap();
        std::fs::write(tmp.join("target/debug/skipped.rs"), "x").unwrap();

        let mut names: Vec<String> = Vec::new();
        walk_files(&tmp, &mut |p| {
            names.push(p.file_name().unwrap().to_string_lossy().into_owned());
        })
        .unwrap();

        // Sorted, not merely present: the mutation surface is committed.
        assert_eq!(names, vec!["a.rs".to_string(), "b.rs".to_string(), "c.rs".to_string()]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn for_each_file_filters_by_extension_and_passes_the_path() {
        let tmp = std::env::temp_dir().join(format!("xtask-fs-text-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("keep.rs"), "KEEP").unwrap();
        std::fs::write(tmp.join("drop.md"), "DROP").unwrap();

        let mut seen = Vec::new();
        for_each_file(&tmp, Some("rs"), &mut |p, t| {
            seen.push((p.file_name().unwrap().to_string_lossy().into_owned(), t.to_string()));
        })
        .unwrap();

        assert_eq!(seen, vec![("keep.rs".to_string(), "KEEP".to_string())]);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
