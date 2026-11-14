//! `xtask check-text-reading-tests`
//!
//! A test that reads workflow, recipe, script, nix or source text proves the
//! text, not the behaviour. Each such test file is allowed only through
//! `xtask/data/text-reading-tests.txt`, which records the most tests it may
//! hold and the gate it owns. A new file, or a new test in a listed file,
//! fails until the entry is added or raised in review.

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

const ALLOWLIST: &str = "xtask/data/text-reading-tests.txt";

/// Whether a gate-text path literal sits within eight lines of a file read.
/// Line-granular, so a literal that merely appears in a fixture elsewhere in
/// the file does not count.
fn reads_gate_text(text: &str) -> bool {
    let read = Regex::new(r"include_str!|read_to_string|fs::read\(").unwrap();
    let target =
        Regex::new(r#""(?:\.\./)*(?:\.github/|Justfile|just/|scripts/|nix/|install\.sh)[^"\n]*""#)
            .unwrap();
    let lines: Vec<&str> = text.lines().collect();
    (0..lines.len())
        .filter(|&i| target.is_match(lines[i]))
        .any(|i| {
            let near = &lines[i.saturating_sub(8)..(i + 9).min(lines.len())];
            near.iter().any(|l| read.is_match(l))
        })
}

/// Files under `tests/` and `crates/*/tests/` that read gate text, with their `#[test]` count.
fn text_readers(workspace: &Path) -> Vec<(String, usize)> {
    let mut roots = vec![workspace.join("tests")];
    if let Ok(crates) = std::fs::read_dir(workspace.join("crates")) {
        roots.extend(crates.flatten().map(|c| c.path().join("tests")));
    }
    let mut found = Vec::new();
    while let Some(dir) = roots.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                roots.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                let tests = text.matches("#[test]").count();
                if tests > 0 && reads_gate_text(&text) {
                    let rel = path.strip_prefix(workspace).unwrap_or(&path);
                    found.push((rel.to_string_lossy().replace('\\', "/"), tests));
                }
            }
        }
    }
    found.sort();
    found
}

/// `path<TAB>max tests<TAB>owned gate`, blank lines and `#` comments skipped.
fn parse(allowlist: &str) -> Result<BTreeMap<String, (usize, String)>> {
    let mut map = BTreeMap::new();
    for line in allowlist
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.splitn(3, '\t').collect();
        let [path, max, gate] = cols[..] else {
            bail!("malformed allowlist line (want path<TAB>max<TAB>gate): {line}");
        };
        if gate.trim().is_empty() {
            bail!("{path} names no owned gate");
        }
        map.insert(path.into(), (max.trim().parse()?, gate.trim().into()));
    }
    Ok(map)
}

fn problems(found: &[(String, usize)], allowed: &BTreeMap<String, (usize, String)>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, tests) in found {
        match allowed.get(path) {
            None => out.push(format!(
                "{path}: reads gate text ({tests} tests) with no allowlist entry"
            )),
            Some((max, _)) if tests > max => {
                out.push(format!("{path}: {tests} tests exceed the allowed {max}"));
            }
            Some(_) => {}
        }
    }
    for path in allowed
        .keys()
        .filter(|p| !found.iter().any(|(f, _)| f == *p))
    {
        out.push(format!(
            "{path}: allowlisted but no longer reads gate text; drop the entry"
        ));
    }
    out
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let allowed = parse(&std::fs::read_to_string(workspace.join(ALLOWLIST))?)?;
    let found = text_readers(workspace);
    let problems = problems(&found, &allowed);
    if !problems.is_empty() {
        bail!(
            "check-text-reading-tests (replace with a behavioural test, or list the owned gate in {ALLOWLIST}):\n  {}",
            problems.join("\n  ")
        );
    }
    eprintln!(
        "check-text-reading-tests: {} files allowlisted",
        found.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlisted_reader_and_a_grown_file_are_reported() {
        let allowed = parse("tests/a.rs\t2\tci.yml lint job\n").unwrap();
        let found = vec![("tests/a.rs".into(), 3), ("tests/new.rs".into(), 1)];
        let found = problems(&found, &allowed);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("exceed") && found[1].contains("no allowlist entry"));
    }

    #[test]
    fn a_path_literal_far_from_any_read_is_not_a_text_reader() {
        let fixture = "let w = \".github/workflows/a.yml\";\n".to_string()
            + &"\n".repeat(20)
            + "std::fs::read_to_string(p);\n";
        assert!(!reads_gate_text(&fixture));
        assert!(reads_gate_text("fs::read_to_string(\"../Justfile\")"));
    }

    #[test]
    fn an_entry_without_a_gate_is_refused() {
        assert!(parse("tests/a.rs\t2\t \n").is_err());
    }
}
