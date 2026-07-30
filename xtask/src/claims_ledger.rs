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
/// file whose extension matches `ext` (or every file when `ext` is
/// `None`). Skips heavy build/VCS dirs. Missing dirs are not an error.
pub fn for_each_file(dir: &Path, ext: Option<&str>, cb: &mut dyn FnMut(&Path, &str)) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    // Deterministic order: the mutation surface is committed to a file, so
    // two runs on the same tree must resolve witnesses identically.
    entries.sort();
    for path in entries {
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
                cb(&path, &content);
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
