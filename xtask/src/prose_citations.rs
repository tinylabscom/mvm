//! One resolver for the gates that ask whether prose names something real.
//!
//! Two gates ask opposite questions about the same tokens.
//! `check-witness-citations` asks whether a cited identifier exists;
//! `check-asserted-absence` asks whether a named identifier is still gone.
//! A separate resolver for each would drift, and the drift would be invisible
//! until one of them was wrong — the same reasoning `check-declared-backing`
//! gives for reusing the citation resolver instead of growing its own.
//!
//! # What counts as existing
//!
//! A token resolves when it appears in workspace **code** or in a workflow —
//! not when it appears in a comment or inside a string literal. That
//! distinction is not pedantry. `audit_chain_carries_no_payload_bytes` is a
//! witness name `CLAUDE.md` says was never written, and it resolved anyway:
//! its only two occurrences in the tree were string literals inside
//! `check-witness-citations`' own tests, asserting that the name has the shape
//! the gate inspects. The gate's fixture was making the citation resolve. A
//! resolver that reads literals can be fed its own answer.
//!
//! So the Rust haystack is run through
//! [`crate::rust_source::blank_comments_and_strings`] first. Each file's path
//! is appended as well, so a token naming a file (`fuzz_service_call.rs`)
//! resolves against the tree rather than against whatever the file happens to
//! contain.

use std::collections::HashSet;
use std::path::Path;

use crate::rust_source::blank_comments_and_strings;

/// Prose that makes claims, and is therefore worth holding to its citations.
pub const PROSE: &[&str] = &[
    "CLAUDE.md",
    "README.md",
    "AGENTS.md",
    "specs/adrs/001-microvm-security-posture.md",
    "specs/adrs/035-workload-stream-plane.md",
];

/// Minimum length for a token to be worth checking. Short snake_case words
/// (`plan_id`, `vm_name`) are field names, not witnesses, and they are common
/// enough that including them buys noise rather than coverage.
pub const MIN_LEN: usize = 12;

/// Words that look like identifiers but are prose, config keys, or paths.
pub const IGNORED: &[&str] = &[
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
#[must_use]
pub fn is_snake_ident(s: &str) -> bool {
    s.len() >= MIN_LEN
        && s.contains('_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.ends_with('_')
}

/// Whether `s` is shaped like a CI job name.
#[must_use]
pub fn is_kebab_job(s: &str) -> bool {
    s.len() >= MIN_LEN
        && s.contains('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// Whether `s` is shaped like an environment variable.
///
/// Only [`crate::check_asserted_absence`] uses this. The citation gate does
/// not: requiring every backticked `MVM_*` in prose to resolve is a much wider
/// rule than "a cited witness exists", and widening it is a separate decision
/// from making absence claims mechanical.
#[must_use]
pub fn is_screaming_env(s: &str) -> bool {
    s.len() >= MIN_LEN
        && s.contains('_')
        && s.starts_with(|c: char| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !s.ends_with('_')
}

/// Strip a trailing Rust source extension so a token naming a file is checked
/// under the same shape rules as a bare identifier.
///
/// `fuzz_service_call.rs` is a claim about a target that does or does not
/// exist, and it is worth the same scrutiny as a function name.
#[must_use]
pub fn strip_rs_suffix(token: &str) -> &str {
    token.strip_suffix(".rs").unwrap_or(token)
}

/// Spans delimited by `delim` in `text`, never crossing a newline.
fn delimited(text: &str, delim: char) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == delim {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() && chars[j] != delim && chars[j] != '\n' {
                j += 1;
            }
            if j < chars.len() && chars[j] == delim {
                out.push(chars[start..j].iter().collect());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Backticked spans in `text`.
#[must_use]
pub fn backticked(text: &str) -> Vec<String> {
    delimited(text, '`')
}

/// Double-quoted spans in `text`.
///
/// Prose asserting that a name was never written cannot backtick it —
/// `CLAUDE.md` says so itself, "because backticks assert a real identifier".
/// So the absence gate has to read the quoted form too.
#[must_use]
pub fn quoted(text: &str) -> Vec<String> {
    delimited(text, '"')
}

/// Backticked spans in `text`, each with its 1-based line number and the line
/// it sat on.
///
/// The line matters for kebab-case: a job citation says "job" beside it, while
/// `rust-version` and `cargo-semver-checks` are a manifest key and a tool that
/// claim no enforcement. The number matters because a caller has to know
/// whether the token fell inside an absence region.
#[must_use]
pub fn backticked_with_line(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        for token in backticked(line) {
            out.push((idx + 1, line.to_string(), token));
        }
    }
    out
}

/// The haystacks a citation can resolve against.
///
/// Two kinds of name need two kinds of evidence, and conflating them is what
/// produced both of this resolver's failure modes.
///
/// A **symbol** — a test or function name — is code. It is declared as
/// `fn name`, so requiring it in blanked Rust is exactly right, and it is the
/// rule that stops a gate's own string fixtures answering for it.
///
/// A **gate or job name** is not code anywhere. `check-no-spec-refs-in-comments`
/// is a real gate whose kebab spelling exists only as a string literal in the
/// dispatch table and as a key in YAML. Holding it to the blanked haystack
/// would report a live gate as fabricated — the opposite error, and the one
/// that gets a gate deleted.
pub struct Resolver {
    /// Workspace Rust with comments and literals blanked, plus every scanned
    /// path.
    rust_code: String,
    /// Workspace Rust verbatim, plus every scanned path.
    rust_raw: String,
    /// Non-Rust workspace source and workflow YAML, verbatim.
    ///
    /// The Python SDK is source we ship; `python_image` is one of its public
    /// entry points and prose cites it. There is no Python lexer here, so
    /// these are matched raw — a name mentioned only in a docstring resolves,
    /// which is weaker than the Rust rule and is the price of not writing a
    /// second lexer.
    other: String,
}

impl Resolver {
    /// Read the workspace once.
    #[must_use]
    pub fn build(root: &Path) -> Self {
        let rust_dirs = ["crates", "xtask", "src"];
        let mut other = raw_haystack(root, &rust_dirs, &["py"]);
        other.push_str(&raw_haystack(root, &[".github"], &["yml", "yaml"]));
        Self {
            rust_code: code_haystack(root, &rust_dirs),
            rust_raw: raw_haystack(root, &rust_dirs, &["rs"]),
            other,
        }
    }

    /// Whether `token` appears as code — the rule for a cited symbol.
    #[must_use]
    pub fn in_code(&self, token: &str) -> bool {
        self.rust_code.contains(token) || self.other.contains(token)
    }

    /// Whether `token` appears anywhere at all, literals and YAML included —
    /// the rule for a gate or job name.
    #[must_use]
    pub fn anywhere(&self, token: &str) -> bool {
        self.rust_raw.contains(token) || self.other.contains(token)
    }

    /// Whether `token` denotes anything, choosing the haystack from its shape.
    ///
    /// This is the single predicate both gates ask. `check-witness-citations`
    /// fails when it is false for a cited name; `check-asserted-absence` fails
    /// when it is true for a name claimed absent. Sharing it is what makes the
    /// two gates incapable of contradicting each other — with a predicate
    /// each, a name could be simultaneously required to exist and required
    /// not to, and nothing would say so.
    #[must_use]
    pub fn resolves(&self, token: &str) -> bool {
        if is_kebab_job(token) {
            self.anywhere(token)
        } else {
            self.in_code(token)
        }
    }
}

/// The set of tokens this module declines to judge.
#[must_use]
pub fn ignored_set() -> HashSet<&'static str> {
    IGNORED.iter().copied().collect()
}

/// Every `.rs` file under `dirs`, blanked of comments and literals, with each
/// file's relative path appended.
fn code_haystack(root: &Path, dirs: &[&str]) -> String {
    let mut buf = String::new();
    walk(root, dirs, &["rs"], &mut |rel, src| {
        buf.push_str(rel);
        buf.push('\n');
        buf.push_str(&blank_comments_and_strings(src));
        buf.push('\n');
    });
    buf
}

/// Every file under `dirs` with one of `exts`, verbatim.
fn raw_haystack(root: &Path, dirs: &[&str], exts: &[&str]) -> String {
    let mut buf = String::new();
    walk(root, dirs, exts, &mut |rel, src| {
        buf.push_str(rel);
        buf.push('\n');
        buf.push_str(src);
        buf.push('\n');
    });
    buf
}

/// Call `visit` with the root-relative path and contents of every file under
/// `dirs` carrying one of `exts`.
fn walk(root: &Path, dirs: &[&str], exts: &[&str], visit: &mut dyn FnMut(&str, &str)) {
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
                    let rel = path.strip_prefix(root).unwrap_or(&path);
                    visit(&rel.to_string_lossy(), &src);
                }
            }
        }
    }
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

    #[test]
    fn quoted_spans_are_extracted_without_crossing_lines() {
        assert_eq!(
            quoted("named \"first_symbol_here\" and \"second_symbol_here\""),
            vec!["first_symbol_here", "second_symbol_here"]
        );
        assert_eq!(quoted("\"unclosed\nnext line"), Vec::<String>::new());
    }

    #[test]
    fn a_file_named_token_is_checked_as_an_identifier() {
        assert!(!is_snake_ident("fuzz_service_call.rs"));
        assert!(is_snake_ident(strip_rs_suffix("fuzz_service_call.rs")));
        assert_eq!(strip_rs_suffix("plain_identifier"), "plain_identifier");
    }

    /// The circularity this resolver exists to break: a name whose only
    /// occurrences in the tree are string literals in a gate's own test.
    #[test]
    fn a_name_that_only_appears_in_a_string_literal_does_not_resolve() {
        let blanked = blank_comments_and_strings(
            "fn shape() { assert!(is_snake_ident(\"audit_chain_carries_no_payload_bytes\")); }",
        );
        assert!(
            !blanked.contains("audit_chain_carries_no_payload_bytes"),
            "a literal must not make a citation resolve"
        );
        assert!(
            blanked.contains("is_snake_ident"),
            "surrounding code must survive blanking"
        );
    }
}
