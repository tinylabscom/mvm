//! `xtask check-file-size` — asserts no non-test source file carries an
//! oversized production body.
//!
//! "Production lines" are those before a file's first top-level `#[cfg(test)]`
//! attribute (this repo's trailing-tests convention: inline unit tests live in
//! one `#[cfg(test)] mod tests` at the end of the file). Inline test modules
//! therefore don't count, so a test-heavy file with a small production body
//! passes — the gate is about how much *production* code one file holds, not
//! how many tests sit beside it. Dedicated test/fixture files are exempt by
//! path so they don't false-positive.
//!
//! The threshold keeps files small enough to hold in one reading; when a file
//! trips it, decompose its production body into a module tree and move each
//! inline test with the code it exercises.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// Maximum production (non-test) lines a single source file may carry.
const MAX_PROD_LINES: usize = 1500;

pub fn run(workspace: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_rs_files(&workspace.join("crates"), &mut files)?;
    files.sort();

    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_exempt(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(file)?;
        let prod = production_lines(&src);
        if prod > MAX_PROD_LINES {
            violations.push((rel, prod));
        }
    }

    if !violations.is_empty() {
        violations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let list = violations
            .iter()
            .map(|(f, n)| format!("  {n:>5}  {f}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "check-file-size: {} file(s) exceed {MAX_PROD_LINES} production lines \
             (counted before the first top-level `#[cfg(test)]`). Decompose the \
             production body into a module tree and move each inline test with the \
             code it exercises:\n{list}",
            violations.len()
        );
    }

    println!(
        "check-file-size: clean ({} files scanned, all \u{2264}{MAX_PROD_LINES} production lines)",
        files.len()
    );
    Ok(())
}

/// Files that are entirely test/fixture/generated code and carry no production
/// body of their own.
fn is_exempt(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("/fuzz/")
        || rel.contains("/benches/")
        || rel.contains("/examples/")
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
}

/// Production lines = everything before the file's first top-level
/// `#[cfg(test)]` attribute, or the whole file if it has none.
fn production_lines(src: &str) -> usize {
    for (i, line) in src.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            return i;
        }
    }
    src.lines().count()
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (rel_path, content) in files {
            let full = dir.path().join(rel_path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, content).unwrap();
        }
        dir
    }

    fn body(prod: usize, tests: usize) -> String {
        let mut s = "// header\n".repeat(prod);
        s.push_str("#[cfg(test)]\nmod tests {\n");
        s.push_str(&"    // t\n".repeat(tests));
        s.push_str("}\n");
        s
    }

    #[test]
    fn oversized_production_body_fails() {
        let tree = make_tree(&[("crates/x/src/big.rs", &body(1600, 10))]);
        let err = run(tree.path()).expect_err("1600 production lines must fail");
        assert!(err.to_string().contains("big.rs"), "{err}");
    }

    #[test]
    fn test_heavy_small_production_passes() {
        // 200 production lines, 6000 lines of trailing tests — must pass.
        let tree = make_tree(&[("crates/x/src/probe.rs", &body(200, 6000))]);
        run(tree.path()).expect("small production body must pass regardless of test size");
    }

    #[test]
    fn dedicated_test_file_is_exempt() {
        // A `tests.rs` that is all code (no #[cfg(test)] inside) must not count.
        let tree = make_tree(&[("crates/x/src/tests.rs", &"let _ = 1;\n".repeat(2000))]);
        run(tree.path()).expect("tests.rs is exempt by name");
    }

    #[test]
    fn production_line_count_stops_at_first_cfg_test() {
        assert_eq!(production_lines("a\nb\n#[cfg(test)]\nmod t { x }\n"), 2);
        assert_eq!(production_lines("a\nb\nc\n"), 3);
        assert_eq!(production_lines("    #[cfg(test)]\nmod t {}\n"), 0);
    }
}
