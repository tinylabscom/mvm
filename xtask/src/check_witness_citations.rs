//! `xtask check-witness-citations`
//!
//! Prose that names a witness must name one that exists.
//!
//! `check-claim-catalog` already verifies the witnesses in ADR-001's table.
//! Nothing verified the ones cited *around* it, and that is where the drift
//! went: `CLAUDE.md` cited a claim-12 witness that exists nowhere in the tree
//! and was believed for months, and a CI job was "corrected" to a name no
//! workflow defines. Both read as evidence. Neither was.
//!
//! ## The check
//!
//! In the prose files that make claims, every backticked identifier shaped
//! like a Rust test name (`snake_case`, no spaces) or a CI job name
//! (`kebab-case`) must appear *somewhere* in the sources or workflows. That is
//! deliberately weaker than "is a witness": it asks only whether the name
//! denotes anything at all.
//!
//! Weak is the point. A stricter rule — every cited test must be a declared
//! witness — would fire on the many legitimate mentions of ordinary functions
//! and fields, and a gate that cries wolf gets deleted. This one has no false
//! positives worth the name: a real symbol appears in the tree, and a
//! fabricated one does not.
//!
//! ## What it does not catch
//!
//! A citation naming a real symbol that is not actually a witness for the
//! claim beside it. That needs semantics this cannot have. What it catches is
//! the failure that actually happened twice: a name nobody ever wrote.

use anyhow::{Result, bail};
use std::collections::HashSet;
use std::path::Path;

/// Prose that makes claims, and is therefore worth holding to its citations.
const PROSE: &[&str] = &[
    "CLAUDE.md",
    "README.md",
    "AGENTS.md",
    "specs/adrs/001-microvm-security-posture.md",
    "specs/adrs/035-workload-stream-plane.md",
];

/// Minimum length for a citation to be worth checking. Short snake_case words
/// (`plan_id`, `vm_name`) are field names, not witnesses, and they are common
/// enough that including them buys noise rather than coverage.
const MIN_LEN: usize = 12;

/// Words that look like identifiers but are prose, config keys, or paths.
const IGNORED: &[&str] = &[
    "cargo-mutants",
    "workflow_dispatch",
    "pull_request",
    "merge_group",
    "continue-on-error",
    "ubuntu-latest",
    "macos-latest",
    "windows-latest",
    "actions-rs",
    "dtolnay-rust-toolchain",
    "no-default-features",
    "all-features",
    "deny-warnings",
];

/// Whether `s` is shaped like a Rust test name.
fn is_snake_ident(s: &str) -> bool {
    s.len() >= MIN_LEN
        && s.contains('_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.ends_with('_')
}

/// Whether `s` is shaped like a CI job name.
fn is_kebab_job(s: &str) -> bool {
    s.len() >= MIN_LEN
        && s.contains('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// Backticked spans in `text`, each with the line it sat on.
///
/// The line matters for kebab-case: a job citation says "job" beside it, while
/// `rust-version` and `cargo-semver-checks` are a manifest key and a tool that
/// claim no enforcement.
fn backticked_with_line(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        for token in backticked(line) {
            out.push((line.to_string(), token));
        }
    }
    out
}

/// Backticked spans in `text`.
fn backticked(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '`' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != '`' && bytes[j] != '\n' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == '`' {
                out.push(bytes[start..j].iter().collect());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Read every file under `dir` with one of `exts` into one haystack.
fn haystack(root: &Path, dirs: &[&str], exts: &[&str]) -> String {
    let mut buf = String::new();
    for dir in dirs {
        let mut stack = vec![root.join(dir)];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if entry.file_name() == "target" {
                        continue;
                    }
                    stack.push(path);
                } else if exts
                    .iter()
                    .any(|e| path.extension().is_some_and(|x| x == *e))
                    && let Ok(src) = std::fs::read_to_string(&path)
                {
                    buf.push_str(&src);
                    buf.push('\n');
                }
            }
        }
    }
    buf
}

/// Run the gate.
///
/// # Errors
///
/// When a prose file cites a test- or job-shaped name that appears nowhere in
/// the sources or workflows.
pub fn run(root: &Path) -> Result<()> {
    let sources = haystack(root, &["crates", "xtask", "src"], &["rs"]);
    let workflows = haystack(root, &[".github"], &["yml", "yaml"]);
    let ignored: HashSet<&str> = IGNORED.iter().copied().collect();

    let mut errors = Vec::new();
    let mut checked = 0usize;

    for rel in PROSE {
        let path = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut seen: HashSet<String> = HashSet::new();
        for (line, token) in backticked_with_line(&text) {
            let token = token.trim();
            if ignored.contains(token) || !seen.insert(token.to_string()) {
                continue;
            }
            if is_snake_ident(token) {
                checked += 1;
                if !sources.contains(token) {
                    errors.push(format!(
                        "{rel}: cites `{token}`, which appears nowhere in the Rust sources. If it \
                         is a witness, it does not exist; if it was renamed, the prose still \
                         names the old one."
                    ));
                }
            } else if is_kebab_job(token) && line.contains("job") {
                checked += 1;
                if !workflows.contains(token) && !sources.contains(token) {
                    errors.push(format!(
                        "{rel}: cites `{token}`, which no workflow defines. A job name that \
                         resolves to nothing reads as enforcement that is not there."
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!(
            "check-witness-citations: {} citation(s) name something that does not exist",
            errors.len()
        );
    }

    println!("check-witness-citations: clean ({checked} citations resolved)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_are_recognised() {
        assert!(is_snake_ident("audit_chain_carries_no_payload_bytes"));
        assert!(is_kebab_job("prod-agent-runentry-contract"));
        // Too short to be worth checking: a field, not a witness.
        assert!(!is_snake_ident("plan_id"));
        assert!(!is_kebab_job("read-only"));
        // Mixed case is a type or a path, not a test name.
        assert!(!is_snake_ident("ExecutionPlan"));
        assert!(!is_snake_ident("crates/mvm-core"));
    }

    #[test]
    fn backticked_spans_are_extracted_without_crossing_lines() {
        let found = backticked("see `first_symbol_here` and `second-symbol-here`\n`third`");
        assert_eq!(
            found,
            vec!["first_symbol_here", "second-symbol-here", "third"]
        );
        // An unterminated backtick must not swallow the rest of the document.
        assert_eq!(backticked("`unclosed\nnext line"), Vec::<String>::new());
    }

    /// The exact drift this exists for: a witness name that was cited for
    /// months and never existed.
    #[test]
    fn a_fabricated_witness_name_is_the_shape_that_gets_checked() {
        assert!(
            is_snake_ident("audit_chain_carries_no_payload_bytes"),
            "the name that survived in CLAUDE.md must be one this gate inspects"
        );
    }

    /// The gate must pass on the tree as it stands.
    #[test]
    fn the_prose_in_the_tree_resolves() {
        run(&crate::workspace_root()).expect("cited witnesses resolve");
    }
}
