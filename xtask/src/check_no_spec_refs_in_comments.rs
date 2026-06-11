//! `xtask check-no-spec-refs-in-comments`
//!
//! Implementation-process references — a plan, PR, sprint, ADR, or
//! workstream by number — are scaffolding from the build process. They
//! belong in `specs/`, commit messages, and PR descriptions, never in
//! shipped source comments, where they age into noise the moment the
//! plan merges. This lint keeps them out: it extracts COMMENT text only
//! (skipping string literals, so a token that is data survives) and
//! fails on any canonical citation token.
//!
//! Two files are exempt because they document the very patterns they
//! scan for: `check_adr_coverage.rs` and `check_doc_claims.rs`.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::Path;

/// Files whose own job is to recognise these tokens; they must keep them.
const EXEMPT: &[&str] = &[
    "xtask/src/check_adr_coverage.rs",
    "xtask/src/check_doc_claims.rs",
    "xtask/src/check_no_spec_refs_in_comments.rs",
];

pub fn run(workspace: &Path) -> Result<()> {
    let token = canonical_regex();
    let mut hits: Vec<String> = Vec::new();

    for root in ["crates", "xtask", "nix", "src"] {
        walk(&workspace.join(root), &mut |path| {
            scan_file(workspace, path, &token, &mut hits);
        })?;
    }
    let build_rs = workspace.join("build.rs");
    if build_rs.is_file() {
        scan_file(workspace, &build_rs, &token, &mut hits);
    }

    if !hits.is_empty() {
        bail!(
            "check-no-spec-refs-in-comments: {} comment(s) cite a plan/PR/ADR/sprint/workstream.\n\
             Those are process artifacts — keep the reasoning, drop the citation (move it to the commit/PR).\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
    eprintln!("check-no-spec-refs-in-comments: clean (no process citations in source comments)");
    Ok(())
}

/// The single source of truth for the citation token set (kept in lockstep
/// with Plan 180's T1 match set).
fn canonical_regex() -> Regex {
    Regex::new(
        r"(?x)
        \b[Pp]lan\ \d+
        | \bADR[-\ ]\d+
        | \bW\d+\.[A-Z0-9]
        | \b[Ss]print\ \d+
        | \bPR\ \#?\d+
        | \#\d{2,}
        ",
    )
    .expect("canonical token regex is valid")
}

fn scan_file(workspace: &Path, path: &Path, token: &Regex, hits: &mut Vec<String>) {
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if EXEMPT.contains(&rel.as_str()) {
        return;
    }
    let style = match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => CommentStyle::Rust,
        Some("nix") | Some("sh") | Some("toml") => CommentStyle::Hash,
        _ => return,
    };
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    for (lineno, text) in comment_lines(&src, style) {
        if token.is_match(&text) {
            hits.push(format!("  {rel}:{lineno}: {}", text.trim()));
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum CommentStyle {
    Rust,
    Hash,
}

/// Extract comment text as (1-based line number, comment string) pairs,
/// skipping string literals so tokens that are data are not reported.
fn comment_lines(src: &str, style: CommentStyle) -> Vec<(usize, String)> {
    match style {
        CommentStyle::Rust => rust_comments(src),
        CommentStyle::Hash => hash_comments(src),
    }
}

/// Rust: `//`, `///`, `//!`, and `/* … */` (nested) comments. Skips `"…"`,
/// `r#*"…"#*` raw strings, and `'…'` char literals so their contents
/// (including any embedded `#`/`//`) are never treated as comments.
fn rust_comments(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < n {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        // Raw string: r, optional #*, then "
        if c == b'r' && i + 1 < n && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let after = j + 1;
                if let Some(pos) = src[after..].find(&close) {
                    let span = &src[i..after + pos + close.len()];
                    line += span.matches('\n').count();
                    i = after + pos + close.len();
                    continue;
                }
                break;
            }
        }
        // Normal string
        if c == b'"' {
            i += 1;
            while i < n {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'\n' {
                    line += 1;
                }
                if b[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Char literal (best-effort; ignores lifetimes which carry no quote)
        if c == b'\'' && i + 1 < n {
            if b[i + 1] == b'\\' && i + 3 < n && b[i + 3] == b'\'' {
                i += 4;
                continue;
            }
            if i + 2 < n && b[i + 2] == b'\'' {
                i += 3;
                continue;
            }
        }
        // Line comment
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let start = i;
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            out.push((line, src[start..i].to_string()));
            continue;
        }
        // Block comment (nested)
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let start = i;
            let start_line = line;
            i += 2;
            let mut depth = 1;
            while i < n && depth > 0 {
                if b[i] == b'\n' {
                    line += 1;
                    i += 1;
                } else if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            out.push((start_line, src[start..i.min(n)].to_string()));
            continue;
        }
        i += 1;
    }
    out
}

/// `#` line comments for nix / sh / toml. Skips `"…"` and `'…'` strings
/// and nix `''…''` strings so a `#` inside a string is not a comment.
fn hash_comments(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        if let Some(comment) = hash_comment_on_line(raw) {
            out.push((idx + 1, comment));
        }
    }
    out
}

/// Return the `#`-comment portion of a single line, or None. A `#` only
/// starts a comment when it is outside any single-line string. (Multi-line
/// strings are not tracked; a stray false negative is acceptable for a
/// regression gate, a false positive is not.)
fn hash_comment_on_line(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_dquote = false;
    let mut in_squote = false;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\\' if in_dquote => {
                i += 2;
                continue;
            }
            b'"' if !in_squote => in_dquote = !in_dquote,
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'#' if !in_dquote && !in_squote => {
                return Some(line[i..].to_string());
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            walk(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust_hits(src: &str) -> usize {
        let token = canonical_regex();
        rust_comments(src)
            .into_iter()
            .filter(|(_, t)| token.is_match(t))
            .count()
    }

    #[test]
    fn flags_plan_ref_in_line_comment() {
        assert_eq!(rust_hits("// Plan 99 wires the thing\nlet x = 1;\n"), 1);
        assert_eq!(rust_hits("/// ADR-002 §3 — the invariant\nfn f() {}\n"), 1);
        assert_eq!(rust_hits("// W4.3 regression guard\n"), 1);
    }

    #[test]
    fn ignores_token_inside_string_literal() {
        assert_eq!(rust_hits(r#"let s = "Plan 99 is data";"#), 0);
        assert_eq!(rust_hits(r#"bail!("predates ADR-002 W1.4b");"#), 0);
    }

    #[test]
    fn ignores_token_inside_raw_string() {
        let src = "let nix = r##\"\n# Built per ADR-0010 §3.\n# Plan 0003 phase 4.\n\"##;\n";
        assert_eq!(rust_hits(src), 0);
    }

    #[test]
    fn flags_comment_after_raw_string_closes() {
        let src = "let nix = r##\"# ADR-0010\"##;\n// Plan 7 follows\n";
        assert_eq!(rust_hits(src), 1);
    }

    #[test]
    fn hash_comment_skips_string_hash() {
        let token = canonical_regex();
        let count = |s: &str| {
            hash_comments(s)
                .into_iter()
                .filter(|(_, t)| token.is_match(t))
                .count()
        };
        assert_eq!(count("foo = \"#640 in a string\";\n"), 0);
        assert_eq!(count("# Plan 71 — one-line helper\n"), 1);
        assert_eq!(count("buildInputs = []; # ADR-051 overlay\n"), 1);
    }

    #[test]
    fn keeps_descriptive_claim_word() {
        // "claim N" is not in the token set — it names a security property.
        assert_eq!(rust_hits("// claim 10 deny-by-default holds here\n"), 0);
    }
}
