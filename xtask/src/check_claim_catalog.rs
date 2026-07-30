//! `xtask check-claim-catalog`
//!
//! mvm's security claims (CLAUDE.md §"Security model") are each backed
//! by named tests and CI lanes. Prose drifts: a witness gets renamed,
//! the claim paragraph still names the old one, and nothing notices.
//! This lint makes the claims ledger table embedded in
//! `specs/adrs/001-microvm-security-posture.md` the machine-checked map
//! from each claim to its witnesses and fails when a named witness no
//! longer exists in the tree — the same "catalog can't outrun reality"
//! discipline an arc42 Ch.10 architecture doc enforces, scoped to what
//! is mechanically checkable.
//!
//! The table parser lives in `claims_ledger`, shared with
//! `check-mutation-witnesses`, which derives its mutation surface from
//! the same rows. This gate asserts a witness *exists*; that one asks
//! whether the witness can actually detect the property breaking.
//!
//! The ledger also carries degenerate claim frontmatter (status
//! `Shipped`, no gated phrases) so `check-no-overclaim` — which scans
//! `specs/adrs/**/*.md` for embedded claim frontmatter blocks — treats
//! it as an inert, already-shipped claim rather than choking on missing
//! frontmatter.

use crate::claims_ledger::{self, Row, Witness};
use anyhow::{Result, bail};
use std::path::Path;

const KNOWN_STATUSES: [&str; 4] = ["Shipped", "Preview", "Planned", "Not-claimed"];

pub fn run(workspace: &Path) -> Result<()> {
    let rows = claims_ledger::load(workspace)?;

    let mut errors: Vec<String> = Vec::new();
    structural_checks(&rows, &mut errors);

    let mut needles: Vec<Needle> = Vec::new();
    for row in &rows {
        for w in &row.witnesses {
            needles.push(Needle::new(row.number, w));
        }
    }

    resolve_fn_needles(workspace, &mut needles)?;
    resolve_ci_needles(workspace, &mut needles)?;

    for n in &needles {
        if !n.found {
            errors.push(format!(
                "claim {}: witness `{}` not found in the tree",
                n.claim, n.token
            ));
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-claim-catalog: {} problem(s) in the claims ledger (specs/adrs/001-microvm-security-posture.md)",
            errors.len()
        );
    }

    eprintln!(
        "check-claim-catalog: clean ({} claims, {} witnesses verified)",
        rows.len(),
        needles.len()
    );
    Ok(())
}

struct Needle {
    claim: u32,
    token: String,
    /// The literal substring that must be present in the relevant files.
    search: String,
    kind: Kind,
    found: bool,
}

enum Kind {
    Fn,
    Ci,
}

impl Needle {
    fn new(claim: u32, w: &Witness) -> Self {
        let (search, kind) = match w {
            Witness::Fn(name) => (format!("fn {name}("), Kind::Fn),
            Witness::Ci(name) => (name.clone(), Kind::Ci),
        };
        Self {
            claim,
            token: w.token(),
            search,
            kind,
            found: false,
        }
    }
}

fn structural_checks(rows: &[Row], errors: &mut Vec<String>) {
    let mut nums: Vec<u32> = rows.iter().map(|r| r.number).collect();
    nums.sort_unstable();
    for pair in nums.windows(2) {
        if pair[0] == pair[1] {
            errors.push(format!("duplicate claim number {}", pair[0]));
        }
    }
    // Claim numbers must form a contiguous 1..=N run — a gap means a
    // claim was dropped without renumbering, or a row is mis-typed.
    for (i, n) in nums.iter().enumerate() {
        let expected = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if *n != expected {
            errors.push(format!(
                "claim numbers are not contiguous 1..={}: expected {expected}, found {n}",
                rows.len()
            ));
            break;
        }
    }
    for r in rows {
        if r.claim.is_empty() {
            errors.push(format!("claim {}: empty claim statement", r.number));
        }
        if r.authority.is_empty() {
            errors.push(format!("claim {}: empty authority column", r.number));
        }
        if r.witnesses.is_empty() {
            errors.push(format!("claim {}: no witnesses", r.number));
        }
        if !KNOWN_STATUSES.contains(&r.status.as_str()) {
            errors.push(format!(
                "claim {}: unknown status {:?} (expected one of {KNOWN_STATUSES:?})",
                r.number, r.status
            ));
        }
    }
}

fn resolve_fn_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Fn)) {
        return Ok(());
    }
    let crates = workspace.join("crates");
    claims_ledger::for_each_file(&crates, Some("rs"), &mut |_, content| {
        mark(needles, Kind::Fn, content);
    })?;
    Ok(())
}

fn resolve_ci_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Ci)) {
        return Ok(());
    }
    let workflows = workspace.join(".github").join("workflows");
    claims_ledger::for_each_file(&workflows, None, &mut |_, content| {
        mark(needles, Kind::Ci, content);
    })?;
    Ok(())
}

fn mark(needles: &mut [Needle], kind: Kind, content: &str) {
    let want = matches!(kind, Kind::Fn);
    for n in needles.iter_mut() {
        if matches!(n.kind, Kind::Fn) == want && !n.found && content.contains(&n.search) {
            n.found = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims_ledger::{extract_ledger_section, parse_rows};

    #[test]
    fn structural_flags_noncontiguous_and_bad_status() {
        let src = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | a | fn:x | auth | Shipped |
| 3 | b | fn:y | auth | Cheese |
";
        let rows = parse_rows(src).unwrap();
        let mut errors = Vec::new();
        structural_checks(&rows, &mut errors);
        assert!(errors.iter().any(|e| e.contains("not contiguous")));
        assert!(errors.iter().any(|e| e.contains("unknown status")));
    }

    #[test]
    fn structural_flags_duplicate_numbers() {
        let src = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | a | fn:x | auth | Shipped |
| 1 | b | fn:y | auth | Shipped |
";
        let rows = parse_rows(src).unwrap();
        let mut errors = Vec::new();
        structural_checks(&rows, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate claim number 1"))
        );
    }

    #[test]
    fn fn_needle_resolves_against_a_source_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("crates").join("demo").join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("lib.rs"),
            "pub fn foo_one() {}\n#[test]\nfn bar_two() {}\n",
        )
        .unwrap();

        let mut needles = vec![
            Needle::new(1, &Witness::Fn("foo_one".into())),
            Needle::new(1, &Witness::Fn("missing_fn".into())),
        ];
        resolve_fn_needles(tmp.path(), &mut needles).unwrap();
        assert!(needles[0].found, "foo_one should resolve");
        assert!(!needles[1].found, "missing_fn should not resolve");
    }

    #[test]
    fn ci_needle_resolves_against_workflow_files() {
        let tmp = tempfile::tempdir().unwrap();
        let wf = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("ci.yml"), "jobs:\n  my-lane:\n    name: My Lane\n").unwrap();

        let mut needles = vec![
            Needle::new(1, &Witness::Ci("my-lane".into())),
            Needle::new(1, &Witness::Ci("ghost-lane".into())),
        ];
        resolve_ci_needles(tmp.path(), &mut needles).unwrap();
        assert!(needles[0].found);
        assert!(!needles[1].found);
    }

    #[test]
    fn extract_ledger_section_slices_between_markers() {
        let source = "# ADR\n\nsome prose\n\n<!-- claims-catalog:begin -->\nTABLE HERE\n<!-- claims-catalog:end -->\n\nmore prose\n";
        let section = extract_ledger_section(source).unwrap();
        assert_eq!(section, "\nTABLE HERE\n");
    }

    #[test]
    fn extract_ledger_section_ignores_unrelated_tables_outside_markers() {
        let source = "\
| ID | STRIDE | Adv. | Threat | Mitigation |
| --- | --- | --- | --- | --- |
| X-S1 | S | G | some threat | some mitigation |

<!-- claims-catalog:begin -->
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | First claim | fn:foo_one | seccomp | Shipped |
<!-- claims-catalog:end -->
";
        let section = extract_ledger_section(source).unwrap();
        let rows = parse_rows(section).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].number, 1);
    }

    #[test]
    fn extract_ledger_section_errors_without_markers() {
        assert!(extract_ledger_section("no markers here").is_err());
    }
}
