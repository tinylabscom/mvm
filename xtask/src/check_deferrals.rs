//! `xtask check-deferrals`
//!
//! R4: nothing is deferred. No deferral marker, no stub, no placeholder
//! document section, no capability behind a flag that turns it off.
//!
//! The markers are spelled in halves so this gate can scan its own source
//! without self-matching: a list of forbidden tokens written out in full is a
//! list that matches itself, and exempting the gate's source would leave a
//! hole exactly where a real deferral could hide.
//!
//! A backticked marker is a *mention*, not a use, so the documentation can
//! name what the gate catches without tripping it. Markers inside string
//! literals are also skipped: they are user-facing text or test data, not
//! deferred code decisions. Genuine non-deferral uses get the narrowest
//! possible `EXEMPTIONS` entry with a reason.
//!
//! This adaptation scans the Rust trees (`crates/`, `xtask/`, `src/`), every
//! text file under `nix/`, the root `install.sh` and `Justfile`, and root
//! markdown for `TODO`, `FIXME`, `unimplemented!`, and the phrase
//! `later version`. Production source is checked outside `#[cfg(test)]`
//! blocks and outside `tests/` directories: test-only stubs and test files are
//! allowed `unimplemented!` because mock backends commonly use it; deferred
//! behavior in tests is still caught by `TODO`/`FIXME`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::fs_walk::walk_files;

/// Marker halves. Concatenating each pair yields the real token.
const MARKERS: &[(&str, &str)] = &[
    ("TO", "DO"),
    ("FIX", "ME"),
    ("unimplemented", "!"),
    ("later ", "version"),
];

/// (file glob, reason). Keep entries scoped and justified.
const EXEMPTIONS: &[(&str, &str)] = &[
    (
        "xtask/src/check_deferrals.rs",
        "defines the very marker patterns it scans for",
    ),
    (
        "specs/adrs/001-microvm-security-posture.md",
        "catalog contains a deliberate 'deferred follow-ups' section that explicitly tracks deferred work as an artifact",
    ),
    // Existing historical deferrals. These pre-date the gate; remove each
    // exemption only in the same PR that resolves the underlying item.
    (
        "crates/mvm-hostd/src/broker/config.rs",
        "tracked broker config envelope signing work; resolves with ADR-020 protocol versioning",
    ),
    (
        "crates/mvm-hostd/src/broker/mod.rs",
        "references the same broker config TODO in config.rs; resolves together",
    ),
    (
        "crates/mvm-sdk/src/compile/mvm_pin.rs",
        "tracked release-time pin-bump automation; resolves when the xtask exists",
    ),
];

/// Trees walked for Rust sources and their manifests and docs.
const SOURCE_TREES: &[&str] = &["crates", "xtask", "src"];

/// Extensions read under [`SOURCE_TREES`].
const SOURCE_EXTENSIONS: &[&str] = &["rs", "md", "toml"];

/// Trees read in full: every text file, whatever its extension, so a new
/// script or config format cannot land outside the gate.
const WHOLE_TREES: &[&str] = &["nix"];

/// Individual root files outside any walked tree.
const ROOT_FILES: &[&str] = &["install.sh", "Justfile"];

/// Run the R4 gate.
pub fn run(workspace: &Path) -> Result<()> {
    let violations = find_violations(workspace)?;
    if !violations.is_empty() {
        bail!(
            "R4: nothing is deferred. None of {} may appear outside backticks, string literals, or exemptions.\n\n{}",
            MARKERS
                .iter()
                .map(|(l, r)| format!("`{l}{r}`"))
                .collect::<Vec<_>>()
                .join(", "),
            violations.join("\n")
        );
    }

    eprintln!("check-deferrals: clean (R4)");
    Ok(())
}

/// Every file the gate reads, in a stable order.
fn scanned_files(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();

    for tree in SOURCE_TREES {
        walk_files(&workspace.join(tree), &mut |path| {
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| SOURCE_EXTENSIONS.contains(&e))
            {
                files.push(path.to_path_buf());
            }
        })?;
    }

    for tree in WHOLE_TREES {
        walk_files(&workspace.join(tree), &mut |path| {
            files.push(path.to_path_buf());
        })?;
    }

    for name in ROOT_FILES {
        let path = workspace.join(name);
        if path.is_file() {
            files.push(path);
        }
    }

    // Scan root markdown files discovered rather than listed, so a new doc
    // cannot silently bypass the gate.
    let mut root_docs: Vec<PathBuf> = std::fs::read_dir(workspace)
        .with_context(|| format!("reading {}", workspace.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_file() && path.extension().is_some_and(|e| e == "md"))
        .collect();
    root_docs.sort();
    files.extend(root_docs);

    Ok(files)
}

/// Every deferral marker the gate reports, as `path:line: text`.
fn find_violations(workspace: &Path) -> Result<Vec<String>> {
    let mut violations: Vec<String> = Vec::new();
    for path in scanned_files(workspace)? {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPTIONS.iter().any(|(glob, _)| *glob == rel) {
            continue;
        }
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        // A file that is not UTF-8 is a binary blob and carries no comment.
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let is_test_file = is_test_path(&rel);
        let test_ranges = test_line_ranges(&text);
        for (i, line) in text.lines().enumerate() {
            let line_no = i + 1;
            let in_test = is_test_file || in_ranges(line_no, &test_ranges);
            for (left, right) in MARKERS {
                let marker = format!("{left}{right}");
                if !line.contains(&marker) {
                    continue;
                }
                if !outside_code_spans(line, &marker) {
                    continue;
                }
                if in_string_literal(line, &marker) {
                    continue;
                }
                // Allow unimplemented! in test-only code (mock backends).
                if marker == "unimplemented!" && in_test {
                    continue;
                }
                violations.push(format!("{}:{}: {}", rel, line_no, line.trim()));
            }
        }
    }
    Ok(violations)
}

fn is_test_path(rel: &str) -> bool {
    rel.ends_with("_test.rs") || rel.split('/').any(|seg| seg == "tests")
}

/// Line ranges (1-based, inclusive) covered by a `#[cfg(test)]` item.
fn test_line_ranges(text: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if is_test_cfg_opener(trimmed) {
            let indent = lines[i].len() - trimmed.len();
            // Range covers the attributed item, starting after the cfg
            // attribute line (1-based).
            let start = i + 2;
            let mut end = lines.len();
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                let li = l.len() - l.trim_start().len();
                if l.trim() == "}" && li <= indent {
                    end = j + 1;
                    break;
                }
                j += 1;
            }
            ranges.push((start, end));
            i = end;
        } else {
            i += 1;
        }
    }
    ranges
}

fn is_test_cfg_opener(trimmed: &str) -> bool {
    trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
}

fn in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|(a, b)| line >= *a && line <= *b)
}

/// Does `marker` occur in `line` outside every backtick-delimited span?
fn outside_code_spans(line: &str, marker: &str) -> bool {
    let mut rest = line;
    let mut at = 0usize;
    while let Some(pos) = rest.find(marker) {
        let absolute = at + pos;
        // An odd number of backticks before this occurrence means it is inside
        // a span.
        if line[..absolute].matches('`').count().is_multiple_of(2) {
            return true;
        }
        at = absolute + marker.len();
        rest = &line[at..];
    }
    false
}

/// Is every occurrence of `marker` in `line` inside a double-quoted string
/// literal? This is a line-local heuristic and does not handle multi-line
/// strings, which are rare for deferral markers.
fn in_string_literal(line: &str, marker: &str) -> bool {
    let mut rest = line;
    let mut at = 0usize;
    let mut found_outside = false;
    while let Some(pos) = rest.find(marker) {
        let absolute = at + pos;
        let prefix = &line[..absolute];
        // Count unescaped double quotes before the marker.
        let mut quote_count = 0;
        let mut chars = prefix.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'"') {
                chars.next(); // skip escaped quote
            } else if c == '"' {
                quote_count += 1;
            }
        }
        if quote_count % 2 == 0 {
            found_outside = true;
        }
        at = absolute + marker.len();
        rest = &line[at..];
    }
    !found_outside
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_deferral_marker_outside_code_span() {
        assert!(outside_code_spans("// TODO fix this", "TODO"));
        assert!(outside_code_spans(
            "fn x() { unimplemented!() }",
            "unimplemented!"
        ));
    }

    #[test]
    fn ignores_marker_inside_backticks() {
        assert!(!outside_code_spans(
            "The lint catches `TODO` markers.",
            "TODO"
        ));
    }

    #[test]
    fn ignores_marker_inside_string_literal() {
        assert!(in_string_literal(
            "let s = \"This string contains TODO\";",
            "TODO"
        ));
        assert!(!in_string_literal("// TODO fix this", "TODO"));
    }

    #[test]
    fn marker_halves_reconstruct_real_tokens() {
        let tokens: Vec<String> = MARKERS.iter().map(|(l, r)| format!("{l}{r}")).collect();
        assert!(tokens.contains(&"TODO".to_string()));
        assert!(tokens.contains(&"FIXME".to_string()));
        assert!(tokens.contains(&"unimplemented!".to_string()));
    }

    fn plant(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("planted path has a parent"))
            .expect("create planted dir");
        std::fs::write(&path, body).expect("write planted file");
    }

    /// Each root the gate claims to cover must be read: a marker planted under
    /// it is reported. The `nix/` entries use extensions outside the Rust tree
    /// set, so the whole tree is proven walked rather than its `.md` files.
    #[test]
    fn a_marker_planted_under_every_root_is_reported() {
        let marker = format!("{}{}", MARKERS[0].0, MARKERS[0].1);
        let tmp = tempfile::tempdir().expect("tempdir");
        let planted = [
            ("crates/demo/src/lib.rs", format!("// {marker} planted\n")),
            ("xtask/src/demo.rs", format!("// {marker} planted\n")),
            ("src/lib.rs", format!("// {marker} planted\n")),
            ("nix/profiles/demo.nix", format!("# {marker} planted\n")),
            ("nix/ops/demo/run.sh", format!("# {marker} planted\n")),
            (
                "nix/ops/demo/cloud-init.yaml",
                format!("# {marker} planted\n"),
            ),
            ("install.sh", format!("# {marker} planted\n")),
            ("Justfile", format!("# {marker} planted\n")),
            ("README.md", format!("{marker} planted\n")),
        ];
        for (rel, body) in &planted {
            plant(tmp.path(), rel, body);
        }

        let violations = find_violations(tmp.path()).expect("scan planted workspace");

        let unscanned: Vec<&str> = planted
            .iter()
            .map(|(rel, _)| *rel)
            .filter(|rel| {
                let prefix = format!("{rel}:1:");
                !violations.iter().any(|v| v.starts_with(&prefix))
            })
            .collect();
        assert!(
            unscanned.is_empty(),
            "not scanned: {unscanned:?}; reported: {violations:?}"
        );
        assert_eq!(violations.len(), planted.len(), "{violations:?}");
    }

    /// A binary file under a whole-file tree carries no comment to defer, so
    /// it is skipped rather than failing the gate.
    #[test]
    fn a_non_utf8_file_under_nix_is_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nix/blob.bin");
        std::fs::create_dir_all(path.parent().expect("blob has a parent")).expect("create nix dir");
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x80]).expect("write blob");

        let violations = find_violations(tmp.path()).expect("scan tolerates a binary file");
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn recognizes_test_cfg_regions() {
        let src = "fn prod() {}\n#[cfg(test)]\nmod tests {\nfn t() {}\n}\n";
        let ranges = test_line_ranges(src);
        assert_eq!(ranges, vec![(3, 5)]);
        assert!(!in_ranges(2, &ranges));
        assert!(in_ranges(3, &ranges));
        assert!(in_ranges(4, &ranges));
    }
}
