//! `xtask check-doc-claims`
//!
//! Plan 74 W0 — claims hygiene lint. Reject marketing phrases that
//! over-claim mvm's runtime posture in public docs. Each gated phrase
//! maps to a claim id from ADR-041 §"The seven target claims"
//! (`specs/adrs/048-claim-safe-sandbox-parity.md`). A phrase is only
//! allowed in a file that either (a) marks the corresponding claim
//! `Shipped` via a machine marker, (b) carries an inline opt-out
//! comment, or (c) sits on the path allow-list.
//!
//! ## Scan scope
//!
//! `public/src/content/docs/**/*.{md,mdx}` plus the repo-root
//! `README.md`. Deliberately narrow:
//!
//! - `specs/`, `CLAUDE.md`, `AGENTS.md`, and crate-level `*.md` are
//!   contributor-facing, not user-facing. We don't lint them.
//! - The status table page itself
//!   (`public/src/content/docs/security/sandbox-parity-status.md`)
//!   must quote every gated phrase — it's the source of truth — so
//!   it's path-allowed.
//! - The migration guide
//!   (`public/src/content/docs/guides/mvmforge-migration.md`) is a
//!   deliberate historical archive and stays path-allowed.
//!
//! ## Machine markers
//!
//! Files can declare a claim's status with an HTML comment:
//!
//! ```text
//! <!-- claim:cold-start status:Shipped -->
//! ```
//!
//! A gated phrase whose claim id has `status:Shipped` in the same
//! file is allowed without an inline opt-out.
//!
//! ## Inline opt-out
//!
//! `<!-- allow(doc-claim:<claim_id>): <reason> -->` on the same line
//! or up to two lines above the offending phrase suppresses the
//! finding. Keyed by claim id (not phrase slug) so a single comment
//! covers every variant of the same claim. Matches the
//! `allow(audit-positional)` / `allow(secret-debug)` convention used
//! elsewhere in the workspace.
//!
//! ## Why the lint reads raw source
//!
//! HTML comments are not stripped before scanning. A banned phrase
//! buried inside an arbitrary `<!-- ... -->` block still counts as a
//! finding unless the author adds the explicit opt-out marker. This
//! prevents commented-out copy-paste from sneaking past the gate.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const DOCS_DIR: &str = "public/src/content/docs";
const README: &str = "README.md";

/// Files where a gated phrase is allowed regardless of status or
/// opt-out. These are pages whose job is to *talk about* the gated
/// phrases — the status table itself, and the deliberate migration
/// archive.
const PATH_ALLOW_LIST: &[&str] = &[
    "public/src/content/docs/security/sandbox-parity-status.md",
    "public/src/content/docs/guides/mvmforge-migration.md",
];

/// Gated phrase → claim id. Each entry is a regex compiled once at
/// run time. Keep the list small enough that a human can review it.
const GATED: &[(&str, &str)] = &[
    (r"(?i)\bany\s+OCI\s+images?\b", "oci-ingest"),
    (r"(?i)\barbitrary\s+OCI\s+images?\b", "oci-ingest"),
    (r"(?i)\bsecrets?\s+cannot\s+leak\b", "secret-non-leakage"),
    (r"(?i)never\s+enters?\s+the\s+guest", "secret-non-leakage"),
    (r"(?i)<\s*100\s*ms\b", "cold-start"),
    (r"(?i)\bsub-?\s*100\s*ms\b", "cold-start"),
];

#[derive(Debug, Clone)]
struct Finding {
    path: PathBuf,
    line: usize,
    claim_id: String,
    snippet: String,
}

/// Run the lint over `public/src/content/docs/**/*.{md,mdx}` and the
/// repo-root `README.md` rooted at `workspace`.
pub fn run(workspace: &Path) -> Result<()> {
    let docs_dir = workspace.join(DOCS_DIR);
    if !docs_dir.is_dir() {
        bail!("expected docs dir at {}; got nothing", docs_dir.display());
    }

    let patterns = compile_patterns()?;

    let mut findings: Vec<Finding> = Vec::new();

    visit_doc_files(&docs_dir, &mut |path| -> Result<()> {
        if is_path_allowed(workspace, path) {
            return Ok(());
        }
        let source =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        findings.extend(lint_source(path, &source, &patterns));
        Ok(())
    })?;

    let readme = workspace.join(README);
    if readme.is_file() && !is_path_allowed(workspace, &readme) {
        let source = std::fs::read_to_string(&readme)
            .with_context(|| format!("reading {}", readme.display()))?;
        findings.extend(lint_source(&readme, &source, &patterns));
    }

    if findings.is_empty() {
        eprintln!(
            "check-doc-claims: clean (scanned {}/**/*.{{md,mdx}} and {})",
            DOCS_DIR, README
        );
        return Ok(());
    }

    eprintln!(
        "check-doc-claims: {} gated-phrase finding(s) — flip the \
         claim row to Shipped in the status table, add an \
         `<!-- allow(doc-claim:<id>): <reason> -->` opt-out, or \
         reword the phrase",
        findings.len()
    );
    for f in &findings {
        eprintln!(
            "  {}:{} — claim:{} — {}",
            f.path.display(),
            f.line,
            f.claim_id,
            f.snippet
        );
    }
    std::process::exit(1);
}

fn compile_patterns() -> Result<Vec<(Regex, &'static str)>> {
    GATED
        .iter()
        .map(|(pat, claim)| {
            Regex::new(pat)
                .with_context(|| format!("compiling gated regex {pat}"))
                .map(|re| (re, *claim))
        })
        .collect()
}

fn is_path_allowed(workspace: &Path, path: &Path) -> bool {
    let rel = match path.strip_prefix(workspace) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    PATH_ALLOW_LIST.iter().any(|allowed| rel_str == *allowed)
}

fn visit_doc_files(dir: &Path, cb: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if matches!(name, "target" | "node_modules" | ".git") {
                continue;
            }
            visit_doc_files(&path, cb)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e, "md" | "mdx"))
            .unwrap_or(false)
        {
            cb(&path)?;
        }
    }
    Ok(())
}

/// Discover `<!-- claim:<id> status:<word> -->` markers in the file
/// and return a map from claim id to status string (lower-cased).
fn discover_claim_statuses(source: &str) -> HashMap<String, String> {
    let marker_re = Regex::new(
        r"(?i)<!--\s*claim:\s*([A-Za-z0-9_-]+)\s+status:\s*([A-Za-z][A-Za-z _-]*?)\s*-->",
    )
    .expect("static claim marker regex compiles");

    let mut statuses = HashMap::new();
    for cap in marker_re.captures_iter(source) {
        let claim = cap[1].to_string();
        let status = cap[2].trim().to_lowercase();
        statuses.insert(claim, status);
    }
    statuses
}

/// True when a window of up to two lines before `idx` (and the
/// matching line itself) carries an inline opt-out for `claim_id`.
fn has_allow_in_window(lines: &[&str], idx: usize, claim_id: &str) -> bool {
    let start = idx.saturating_sub(2);
    let end = (idx + 1).min(lines.len());
    let needle = format!("allow(doc-claim:{claim_id})");
    lines[start..end].iter().any(|l| l.contains(&needle))
}

fn lint_source(path: &Path, source: &str, patterns: &[(Regex, &'static str)]) -> Vec<Finding> {
    let statuses = discover_claim_statuses(source);
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();

    for (i, raw) in lines.iter().enumerate() {
        for (re, claim_id) in patterns {
            if !re.is_match(raw) {
                continue;
            }
            if statuses
                .get(*claim_id)
                .map(|s| s == "shipped")
                .unwrap_or(false)
            {
                continue;
            }
            if has_allow_in_window(&lines, i, claim_id) {
                continue;
            }
            findings.push(Finding {
                path: path.to_path_buf(),
                line: i + 1,
                claim_id: (*claim_id).to_string(),
                snippet: raw.trim().to_string(),
            });
            // One finding per line is enough; if multiple phrases
            // match the same line they almost always cite the same
            // claim id and the author will fix them together.
            break;
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns() -> Vec<(Regex, &'static str)> {
        compile_patterns().expect("static patterns compile")
    }

    #[test]
    fn clean_doc_is_clean() {
        let src = "# Heading\n\nNothing controversial here.\n";
        let findings = lint_source(Path::new("ok.md"), src, &patterns());
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn raw_sub_100ms_fires() {
        let src = "Boot time is <100ms today.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim_id, "cold-start");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn inline_allow_suppresses() {
        let src = "<!-- allow(doc-claim:cold-start): example only -->\n\
                   Boot time is <100ms today.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert!(
            findings.is_empty(),
            "opt-out should suppress; got {findings:?}"
        );
    }

    #[test]
    fn allow_on_same_line_suppresses() {
        let src = "Boot time is <100ms <!-- allow(doc-claim:cold-start): pre-merge demo -->\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert!(findings.is_empty(), "same-line opt-out should suppress");
    }

    #[test]
    fn shipped_status_marker_unlocks_claim() {
        let src = "<!-- claim:cold-start status:Shipped -->\n\
                   p95 fresh-boot is now <100ms.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert!(
            findings.is_empty(),
            "Shipped marker should unlock; got {findings:?}"
        );
    }

    #[test]
    fn planned_status_marker_does_not_unlock() {
        let src = "<!-- claim:cold-start status:Planned -->\n\
                   We will eventually hit <100ms.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim_id, "cold-start");
    }

    #[test]
    fn html_comment_does_not_hide_phrase() {
        // A banned phrase buried in a regular comment is still a
        // finding — only the explicit allow marker bypasses.
        let src = "<!-- TODO: rewrite the sub-100ms pitch later -->\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim_id, "cold-start");
    }

    #[test]
    fn variant_spelling_catches_oci_phrases() {
        let cases = &[
            ("We accept any OCI image.", "oci-ingest"),
            ("Run arbitrary OCI images locally.", "oci-ingest"),
        ];
        for (src, expected_claim) in cases {
            let findings = lint_source(Path::new("x.md"), src, &patterns());
            assert_eq!(findings.len(), 1, "case {src:?}");
            assert_eq!(findings[0].claim_id, *expected_claim, "case {src:?}");
        }
    }

    #[test]
    fn variant_spelling_catches_secret_phrases() {
        let cases = &[
            ("Secrets cannot leak.", "secret-non-leakage"),
            (
                "The secret cannot leak from the guest.",
                "secret-non-leakage",
            ),
            ("The value never enters the guest.", "secret-non-leakage"),
            ("Real secrets never enter the guest.", "secret-non-leakage"),
        ];
        for (src, expected_claim) in cases {
            let findings = lint_source(Path::new("x.md"), src, &patterns());
            assert_eq!(findings.len(), 1, "case {src:?}");
            assert_eq!(findings[0].claim_id, *expected_claim, "case {src:?}");
        }
    }

    #[test]
    fn variant_spelling_catches_cold_start_phrases() {
        let cases = &[
            "Boot in sub-100ms.",
            "Boot in sub 100 ms.",
            "Boot in <100ms.",
            "Boot in <  100  ms.",
        ];
        for src in cases {
            let findings = lint_source(Path::new("x.md"), src, &patterns());
            assert_eq!(findings.len(), 1, "case {src:?}");
            assert_eq!(findings[0].claim_id, "cold-start", "case {src:?}");
        }
    }

    #[test]
    fn allow_marker_keyed_by_claim_covers_all_variants() {
        let src = "<!-- allow(doc-claim:cold-start): all variants -->\n\
                   Boot in sub-100ms. Or <100ms. Or sub 100 ms.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert!(
            findings.is_empty(),
            "claim-id-keyed allow should cover variants; got {findings:?}"
        );
    }

    #[test]
    fn allow_marker_for_wrong_claim_does_not_suppress() {
        let src = "<!-- allow(doc-claim:oci-ingest): wrong claim -->\n\
                   Boot in sub-100ms.\n";
        let findings = lint_source(Path::new("x.md"), src, &patterns());
        assert_eq!(findings.len(), 1, "wrong claim id should not suppress");
        assert_eq!(findings[0].claim_id, "cold-start");
    }

    #[test]
    fn status_marker_is_case_insensitive_on_value() {
        let src_shipped = "<!-- claim:cold-start status:shipped -->\n\
                           Boot in <100ms.\n";
        assert!(
            lint_source(Path::new("x.md"), src_shipped, &patterns()).is_empty(),
            "lower-case 'shipped' should match"
        );

        let src_mixed = "<!-- claim:cold-start status:SHIPPED -->\n\
                         Boot in <100ms.\n";
        assert!(
            lint_source(Path::new("x.md"), src_mixed, &patterns()).is_empty(),
            "upper-case 'SHIPPED' should match"
        );
    }
}
