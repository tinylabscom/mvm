//! The claims ledger: one parser for the machine-checked claim →
//! witness map embedded in `specs/adrs/001-microvm-security-posture.md`.
//!
//! Two gates read this table and they must agree on what it says.
//! `check-claim-catalog` asserts every named witness still exists;
//! `check-mutation-witnesses` derives the mutation surface from the same
//! rows. A second parser would let the two disagree about which claims
//! exist, which is precisely the drift the ledger is meant to prevent.
//!
//! Row shape (a 5-column markdown table):
//!   | # | Claim | Witnesses | Authority | Status |
//! `Witnesses` is a comma-separated list of typed tokens:
//!   - `fn:NAME` — a `fn NAME(` must exist under `crates/`.
//!   - `ci:NAME` — NAME must appear literally in some `.github/workflows/*`.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub const BEGIN_MARKER: &str = "<!-- claims-catalog:begin -->";
pub const END_MARKER: &str = "<!-- claims-catalog:end -->";

pub struct Row {
    pub number: u32,
    pub claim: String,
    pub witnesses: Vec<Witness>,
    pub authority: String,
    pub status: String,
}

#[derive(Clone)]
pub enum Witness {
    /// `fn:NAME` — resolves to `fn NAME(` anywhere under `crates/`.
    Fn(String),
    /// `ci:NAME` — resolves to the literal NAME in any workflow file.
    Ci(String),
}

impl Witness {
    pub fn token(&self) -> String {
        match self {
            Self::Fn(n) => format!("fn:{n}"),
            Self::Ci(n) => format!("ci:{n}"),
        }
    }
}

/// The ADR that carries the ledger.
pub fn ledger_path(workspace: &Path) -> PathBuf {
    workspace
        .join("specs")
        .join("adrs")
        .join("001-microvm-security-posture.md")
}

/// Read and parse the ledger rows.
pub fn load(workspace: &Path) -> Result<Vec<Row>> {
    let path = ledger_path(workspace);
    let source =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let ledger = extract_ledger_section(&source).with_context(|| {
        format!(
            "locating the claims ledger between `{BEGIN_MARKER}` and `{END_MARKER}` in {}",
            path.display()
        )
    })?;
    parse_rows(ledger)
        .with_context(|| format!("parsing the claims ledger table in {}", path.display()))
}

/// Slice out the text strictly between the begin and end markers. The ADR
/// carries several other markdown tables (STRIDE threat-model rows,
/// compliance mappings) with their own pipe-delimited rows; scoping to the
/// marker-delimited region keeps those from ever being mistaken for
/// claim-catalog rows.
pub fn extract_ledger_section(source: &str) -> Result<&str> {
    let start = source
        .find(BEGIN_MARKER)
        .ok_or_else(|| anyhow::anyhow!("begin marker not found"))?
        + BEGIN_MARKER.len();
    let end = source[start..]
        .find(END_MARKER)
        .ok_or_else(|| anyhow::anyhow!("end marker not found"))?;
    Ok(&source[start..start + end])
}

pub fn parse_rows(source: &str) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = split_row(line);
        if cells.len() != 5 {
            continue; // prose pipe or malformed line — not a catalog row
        }
        if is_separator(&cells) || cells[0].eq_ignore_ascii_case("#") {
            continue;
        }
        let Ok(number) = cells[0].parse::<u32>() else {
            continue; // header variants / non-numeric first cell
        };
        let witnesses = parse_witnesses(&cells[2])
            .with_context(|| format!("claim {number}: bad witnesses cell"))?;
        rows.push(Row {
            number,
            claim: cells[1].clone(),
            witnesses,
            authority: cells[3].clone(),
            status: cells[4].clone(),
        });
    }
    if rows.is_empty() {
        bail!("no data rows found (expected a 5-column markdown table)");
    }
    Ok(rows)
}

/// Split a `| a | b |` line into trimmed inner cells.
fn split_row(line: &str) -> Vec<String> {
    let t = line.strip_prefix('|').unwrap_or(line);
    let t = t.strip_suffix('|').unwrap_or(t);
    t.split('|').map(|c| c.trim().to_string()).collect()
}

/// True for a `|---|---|` markdown separator row.
fn is_separator(cells: &[String]) -> bool {
    cells.iter().all(|c| {
        !c.is_empty()
            && c.chars()
                .all(|ch| ch == '-' || ch == ':' || ch.is_whitespace())
    })
}

pub fn parse_witnesses(cell: &str) -> Result<Vec<Witness>> {
    let mut out = Vec::new();
    for tok in cell.split(',') {
        let tok = tok.trim().trim_matches('`').trim();
        if tok.is_empty() {
            continue;
        }
        let (kind, name) = tok.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("witness {tok:?} missing a `kind:` prefix (want fn:NAME or ci:NAME)")
        })?;
        let name = name.trim();
        if name.is_empty() {
            bail!("witness {tok:?} has an empty name");
        }
        match kind.trim() {
            "fn" => out.push(Witness::Fn(name.to_string())),
            "ci" => out.push(Witness::Ci(name.to_string())),
            other => bail!("witness {tok:?}: unknown kind {other:?} (expected fn or ci)"),
        }
    }
    Ok(out)
}

/// Walk `dir` recursively, calling `cb` with the path and text of every
/// file whose extension matches `ext`. Re-exported from `fs_walk`, which
/// owns the one traversal all the source-scanning gates share.
pub use crate::fs_walk::for_each_file;

/// The exact names a `ci:` witness may resolve to: a job key, or a token
/// written in parentheses inside a step name.
///
/// This used to be a substring search over the whole file, so a witness
/// matched a mention in a comment as happily as a live job — `ci:fuzz`
/// resolved against the word "fuzz" anywhere in any workflow, including the
/// prose explaining why the job exists. A deleted job kept its witness green.
///
/// Matching is by equality, not containment, which is what makes a rename
/// visible. A job's descriptive `name:` — say `Supply chain — cargo-deny
/// (with a bracketed spec citation)` — deliberately does *not* anchor
/// `cargo-deny`; only the `cargo-deny:` key does. Renaming that key now
/// fails the gate even though the words survive in the display name.
///
/// The parenthesised form exists because the ledger points at steps as well
/// as jobs, and the repo already has a convention for it: a step backing a
/// claim carries its token in parentheses, as in
/// `Fuzz bounded DNS codec (fuzz-dns-codec)`.
pub fn ci_anchors(content: &str) -> Vec<String> {
    let mut anchors = Vec::new();
    let mut in_jobs = false;
    for line in content.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if in_jobs && !line.trim().is_empty() && !line.starts_with(' ') {
            in_jobs = false;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if in_jobs
            && let Some(key) = line.strip_prefix("  ")
            && !key.starts_with(' ')
            && let Some(name) = key.strip_suffix(':')
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            anchors.push(name.to_string());
        }
        let step_name = trimmed
            .strip_prefix("- name:")
            .or_else(|| trimmed.strip_prefix("name:"));
        if let Some(rest) = step_name {
            anchors.extend(parenthesised_tokens(rest));
        }

        // The policy driver runs every gate in one step, so the step name
        // cannot carry sixty-three parenthesised tokens. It anchors them
        // all instead, read from the same table it executes.
        //
        // Without this, collapsing the lane's per-gate steps would have
        // silently unbacked every claim citing one — the witness would
        // stop resolving while the gate kept running, which is the
        // opposite of what this ledger is for.
        if trimmed.strip_prefix("run:").is_some_and(|run| {
            run.split_whitespace()
                .eq(["cargo", "run", "-p", "xtask", "--", "check-all"])
        }) {
            anchors.extend(
                crate::check_all::GATES
                    .iter()
                    .map(|(name, _)| name.to_string()),
            );
        }
    }
    anchors
}

/// Tokens written `(like-this)` inside a step name. Only bare
/// identifier-shaped contents count, so a bracketed spec citation with
/// spaces and punctuation contributes nothing.
pub fn parenthesised_tokens(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = name;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else { break };
        let inner = &after[..close];
        if !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            out.push(inner.to_string());
        }
        rest = &after[close + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = r#"name: Security
# A comment mentioning ghost-job and fuzz-in-prose.
on:
  schedule:
    - cron: "17 4 * * *"
jobs:
  cargo-deny:
    name: Supply chain — cargo-deny
    steps:
      - name: cargo deny check
        run: cargo deny check
  fuzz:
    name: Fuzz — parsers
    steps:
      - name: Fuzz bounded DNS codec (fuzz-dns-codec)
        run: cargo fuzz run fuzz_dns_codec
"#;

    #[test]
    fn a_job_key_is_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(a.iter().any(|x| x == "cargo-deny"), "{a:?}");
        assert!(a.iter().any(|x| x == "fuzz"), "{a:?}");
    }

    #[test]
    fn a_parenthesised_step_token_is_an_anchor() {
        assert!(ci_anchors(WORKFLOW).iter().any(|x| x == "fuzz-dns-codec"));
    }

    /// A job's descriptive name must not anchor its key. This is what makes
    /// renaming `cargo-deny:` visible even though the words survive in
    /// `name: Supply chain — cargo-deny`.
    #[test]
    fn a_descriptive_name_does_not_anchor_the_key() {
        let a = ci_anchors("jobs:\n  renamed:\n    name: Supply chain — cargo-deny (ADR-001)\n");
        assert!(a.iter().any(|x| x == "renamed"), "{a:?}");
        assert!(
            !a.iter().any(|x| x == "cargo-deny"),
            "the display name must not stand in for the key: {a:?}"
        );
    }

    /// Only identifier-shaped parentheticals count, so citation text is not
    /// mistaken for a witness token.
    #[test]
    fn non_identifier_parentheticals_are_ignored() {
        assert!(parenthesised_tokens("Supply chain (ADR-001 §W5.2)").is_empty());
        assert_eq!(
            parenthesised_tokens("Codec (fuzz-dns-codec)"),
            vec!["fuzz-dns-codec".to_string()]
        );
    }

    /// The whole point. A witness naming a job that does not exist used to
    /// resolve against the word appearing in a comment.
    #[test]
    fn a_comment_mention_is_not_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(
            !a.iter().any(|x| x.contains("ghost-job")),
            "a comment must not anchor a witness: {a:?}"
        );
    }

    /// `run:` bodies are not anchors either — otherwise renaming a step but
    /// keeping its command would still look witnessed.
    #[test]
    fn a_run_body_is_not_an_anchor() {
        let a = ci_anchors(WORKFLOW);
        assert!(!a.iter().any(|x| x.starts_with("cargo fuzz run")), "{a:?}");
    }

    /// Top-level keys that merely sit at some indent are not job keys.
    #[test]
    fn only_keys_inside_jobs_count() {
        let a = ci_anchors(WORKFLOW);
        assert!(!a.iter().any(|x| x == "schedule"), "{a:?}");
    }

    const TABLE: &str = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | First claim | fn:foo_one, ci:lane-a | seccomp | Shipped |
| 2 | Second claim | fn:bar_two | Ed25519 | Shipped |
";

    #[test]
    fn parses_data_rows_and_skips_header_and_separator() {
        let rows = parse_rows(TABLE).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].number, 1);
        assert_eq!(rows[0].claim, "First claim");
        assert_eq!(rows[0].witnesses.len(), 2);
        assert_eq!(rows[1].status, "Shipped");
    }

    #[test]
    fn witness_kinds_route_by_prefix() {
        let ws = parse_witnesses("fn:foo, ci:my-lane, `fn:baz`").unwrap();
        assert!(matches!(ws[0], Witness::Fn(ref n) if n == "foo"));
        assert!(matches!(ws[1], Witness::Ci(ref n) if n == "my-lane"));
        assert!(matches!(ws[2], Witness::Fn(ref n) if n == "baz"));
    }

    #[test]
    fn witness_rejects_unknown_kind_and_missing_prefix() {
        assert!(parse_witnesses("wat:foo").is_err());
        assert!(parse_witnesses("nokind").is_err());
        assert!(parse_witnesses("fn:").is_err());
    }

    #[test]
    fn witness_token_round_trips_its_prefix() {
        assert_eq!(Witness::Fn("a".into()).token(), "fn:a");
        assert_eq!(Witness::Ci("b".into()).token(), "ci:b");
    }

    #[test]
    fn extract_section_requires_both_markers() {
        let src = format!("pre {BEGIN_MARKER} body {END_MARKER} post");
        assert_eq!(extract_ledger_section(&src).unwrap().trim(), "body");
        assert!(extract_ledger_section("no markers").is_err());
        assert!(extract_ledger_section(&format!("{BEGIN_MARKER} unterminated")).is_err());
    }

    #[test]
    fn split_row_drops_outer_pipes() {
        assert_eq!(split_row("| a | b |"), vec!["a", "b"]);
    }

    #[test]
    fn parse_rows_rejects_a_table_with_no_data_rows() {
        assert!(parse_rows("| # | Claim | Witnesses | Authority | Status |\n").is_err());
    }

    #[test]
    fn walker_yields_paths_in_deterministic_order() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("crates");
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["c.rs", "a.rs", "b.rs", "skip.txt"] {
            std::fs::write(dir.join(name), "fn x() {}").unwrap();
        }
        let mut seen = Vec::new();
        for_each_file(&dir, Some("rs"), &mut |path, _| {
            seen.push(path.file_name().unwrap().to_string_lossy().to_string());
        })
        .unwrap();
        assert_eq!(seen, ["a.rs", "b.rs", "c.rs"]);
    }
}
