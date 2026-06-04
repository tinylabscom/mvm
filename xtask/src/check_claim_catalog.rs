//! `xtask check-claim-catalog`
//!
//! mvm's security claims (CLAUDE.md §"Security model") are each backed
//! by named tests and CI lanes. Prose drifts: a witness gets renamed,
//! the claim paragraph still names the old one, and nothing notices.
//! This lint makes `specs/claims/catalog.md` the machine-checked map
//! from each claim to its witnesses and fails when a named witness no
//! longer exists in the tree — the same "catalog can't outrun reality"
//! discipline an arc42 Ch.10 architecture doc enforces, scoped to what's
//! mechanically checkable.
//!
//! Catalog row shape (a 5-column markdown table):
//!   | # | Claim | Witnesses | Authority | Status |
//! `Witnesses` is a comma-separated list of typed tokens:
//!   - `fn:NAME` — must appear as `fn NAME(` somewhere under `crates/`
//!     (a test fn or the impl symbol the claim exercises).
//!   - `ci:NAME` — must appear literally in some `.github/workflows/*`.
//!
//! `catalog.md` also carries degenerate claim frontmatter (status
//! `Shipped`, no gated phrases) so `check-no-overclaim` — which parses
//! every `specs/claims/*.md` — treats it as an inert, already-shipped
//! claim rather than choking on missing frontmatter.

use anyhow::{Context, Result, bail};
use std::path::Path;

const KNOWN_STATUSES: [&str; 4] = ["Shipped", "Preview", "Planned", "Not-claimed"];

pub fn run(workspace: &Path) -> Result<()> {
    let catalog_path = workspace.join("specs").join("claims").join("catalog.md");
    let source = std::fs::read_to_string(&catalog_path)
        .with_context(|| format!("reading {}", catalog_path.display()))?;

    let rows = parse_rows(&source)
        .with_context(|| format!("parsing the table in {}", catalog_path.display()))?;

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
            "check-claim-catalog: {} problem(s) in specs/claims/catalog.md",
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

struct Row {
    number: u32,
    claim: String,
    witnesses: Vec<Witness>,
    authority: String,
    status: String,
}

#[derive(Clone)]
enum Witness {
    /// `fn:NAME` — resolves to `fn NAME(` anywhere under `crates/`.
    Fn(String),
    /// `ci:NAME` — resolves to the literal NAME in any workflow file.
    Ci(String),
}

impl Witness {
    fn token(&self) -> String {
        match self {
            Self::Fn(n) => format!("fn:{n}"),
            Self::Ci(n) => format!("ci:{n}"),
        }
    }
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

fn parse_rows(source: &str) -> Result<Vec<Row>> {
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

fn parse_witnesses(cell: &str) -> Result<Vec<Witness>> {
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

fn resolve_fn_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Fn)) {
        return Ok(());
    }
    let crates = workspace.join("crates");
    for_each_file(&crates, Some("rs"), &mut |content| {
        mark(needles, Kind::Fn, content);
    })?;
    Ok(())
}

fn resolve_ci_needles(workspace: &Path, needles: &mut [Needle]) -> Result<()> {
    if !needles.iter().any(|n| matches!(n.kind, Kind::Ci)) {
        return Ok(());
    }
    let workflows = workspace.join(".github").join("workflows");
    for_each_file(&workflows, None, &mut |content| {
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

/// Walk `dir` recursively, calling `cb` with the text of every file
/// whose extension matches `ext` (or every file when `ext` is `None`).
/// Skips heavy build/VCS dirs. Missing dirs are not an error.
fn for_each_file(dir: &Path, ext: Option<&str>, cb: &mut dyn FnMut(&str)) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            for_each_file(&path, ext, cb)?;
        } else {
            let matches_ext = match ext {
                Some(want) => path.extension().and_then(|e| e.to_str()) == Some(want),
                None => true,
            };
            if matches_ext && let Ok(content) = std::fs::read_to_string(&path) {
                cb(&content);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
| # | Claim | Witnesses | Authority | Status |
|---|-------|-----------|-----------|--------|
| 1 | First claim | fn:foo_one, ci:lane-a | seccomp | Shipped |
| 2 | Second claim | fn:bar_two | Ed25519 | Shipped |
";

    fn rows() -> Vec<Row> {
        parse_rows(TABLE).unwrap()
    }

    #[test]
    fn parses_data_rows_and_skips_header_and_separator() {
        let rows = rows();
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
    fn split_row_drops_outer_pipes() {
        assert_eq!(split_row("| a | b |"), vec!["a", "b"]);
    }
}
