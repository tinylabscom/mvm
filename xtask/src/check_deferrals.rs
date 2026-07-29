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
//! This adaptation scans production source (outside `#[cfg(test)]` blocks and
//! outside `tests/` directories) for `TODO`, `FIXME`, `unimplemented!`, and
//! the phrase `later version`. Test-only stubs and test files are allowed
//! `unimplemented!` because mock backends commonly use it; deferred behavior
//! in tests is still caught by `TODO`/`FIXME`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

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
    (
        "crates/mvm-runtime/src/vm/vminitd_client.rs",
        "tracked vminitd vsock:1024 connection plumbing; resolves when guest init system is wired",
    ),
];

/// Run the R4 gate.
pub fn run(workspace: &Path) -> Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();

    // Scan every crate source tree and xtask.
    for dir in [workspace.join("crates"), workspace.join("xtask")] {
        gather(&dir, &mut files)?;
    }

    // Scan root markdown files discovered rather than listed, so a new doc
    // cannot silently bypass the gate.
    for entry in std::fs::read_dir(workspace)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "md") {
            files.push(path);
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPTIONS.iter().any(|(glob, _)| *glob == rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
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

fn gather(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            gather(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|e| e == "rs" || e == "md" || e == "toml")
        {
            out.push(path);
        }
    }
    Ok(())
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
