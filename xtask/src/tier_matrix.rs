//! The per-backend tier matrix: one parser for the machine-checked
//! L1–L5 symbol table embedded in `specs/adrs/001-microvm-security-posture.md`.
//!
//! `check-tier-matrix` derives the expected symbol for every cell from
//! `BackendSecurityProfile::for_kind` and fails when the published table
//! drifts from what the code declares.
//!
//! Row shape (a 7-column markdown table):
//!   | Backend | L1 | L2 | L3 | L4 | L5 | Notes |
//! Each layer cell is an emoji symbol (`✅`, `⚠️`, `❌`) optionally followed
//! by qualifier prose. The Notes column is parsed for structure only — the
//! gate asserts nothing about its content.
//!
//! This module also owns the small parser for the claim→layer tags in the
//! ADR's claims table (`| # | Claim | Layer | Enforcement |`): a claim
//! tagged to a layer is what turns that layer's cell from `✅` to `⚠️` when
//! the backend drops the claim.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) const BEGIN_MARKER: &str = "<!-- tier-matrix:begin -->";
pub(crate) const END_MARKER: &str = "<!-- tier-matrix:end -->";

/// The header line of the claims table whose Layer column carries the
/// claim→layer tags the gate derives its overlay from.
const CLAIMS_TABLE_HEADER: &str = "| # | Claim | Layer | Enforcement |";

pub(crate) struct Row {
    /// The Backend cell, verbatim — the gate prefix-matches it against a
    /// known label per `BackendKind`.
    pub backend: String,
    /// The five layer cells (L1..L5), raw text including any qualifier.
    pub cells: [String; 5],
}

/// The ADR that carries the tier matrix.
pub(crate) fn adr_path(workspace: &Path) -> PathBuf {
    workspace
        .join("specs")
        .join("adrs")
        .join("001-microvm-security-posture.md")
}

/// Read the ADR source.
pub(crate) fn load_adr(workspace: &Path) -> Result<String> {
    let path = adr_path(workspace);
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// Slice out the text strictly between the begin and end markers. The ADR
/// carries several other markdown tables; scoping to the marker-delimited
/// region keeps those from ever being mistaken for tier-matrix rows.
pub(crate) fn extract_section(source: &str) -> Result<&str> {
    let start = source
        .find(BEGIN_MARKER)
        .ok_or_else(|| anyhow::anyhow!("begin marker not found"))?
        + BEGIN_MARKER.len();
    let end = source[start..]
        .find(END_MARKER)
        .ok_or_else(|| anyhow::anyhow!("end marker not found"))?;
    Ok(&source[start..start + end])
}

/// Parse the matrix rows. Unlike the claims ledger, a pipe line inside the
/// marker-delimited section that is neither the header nor a separator and
/// does not split into exactly 7 cells is an error: nothing else may live
/// in this section, so a mangled row must fail loudly rather than vanish.
pub(crate) fn parse_rows(source: &str) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells = split_row(line);
        if cells.len() != 7 {
            bail!(
                "malformed tier-matrix row (expected 7 cells, found {}): {line}",
                cells.len()
            );
        }
        if is_separator(&cells) || cells[0].eq_ignore_ascii_case("backend") {
            continue;
        }
        rows.push(Row {
            backend: cells[0].clone(),
            cells: [
                cells[1].clone(),
                cells[2].clone(),
                cells[3].clone(),
                cells[4].clone(),
                cells[5].clone(),
            ],
        });
    }
    if rows.is_empty() {
        bail!("no data rows found (expected a 7-column markdown table)");
    }
    Ok(rows)
}

/// Claim numbers (1-indexed) tagged to each Matryoshka layer, from the
/// ADR's claims table. Only `L1`..`L5` tags count — `supply chain`,
/// `cross-cutting`, and `data containment` rows enforce claims but pin no
/// layer, so a backend dropping one of them never turns a matrix cell.
pub(crate) fn claim_layers(source: &str) -> Result<BTreeMap<u8, Vec<String>>> {
    let header_at = source
        .find(CLAIMS_TABLE_HEADER)
        .ok_or_else(|| anyhow::anyhow!("claims table header not found"))?;
    let table = &source[header_at + CLAIMS_TABLE_HEADER.len()..];
    let mut map = BTreeMap::new();
    for line in table.lines().skip(1) {
        let line = line.trim();
        if !line.starts_with('|') {
            break; // table ended
        }
        let cells = split_row(line);
        if cells.len() != 4 {
            continue; // prose pipe, not a claims row
        }
        let Ok(number) = cells[0].parse::<u8>() else {
            continue;
        };
        let tags: Vec<String> = cells[2]
            .split('/')
            .map(str::trim)
            .filter(|t| matches!(*t, "L1" | "L2" | "L3" | "L4" | "L5"))
            .map(str::to_string)
            .collect();
        map.insert(number, tags);
    }
    if map.is_empty() {
        bail!("claims table carried no layer-tagged claims");
    }
    Ok(map)
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECTION: &str = "\
<!-- tier-matrix:begin -->
| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | Tier 1 notes |
| HVF / Hypervisor.framework (macOS 26+ Apple Silicon) | ✅ | ✅ | ⚠️ block+ext4 verified boot only | ✅ | ✅ | Tier 2 notes |
| `wasm-sandbox` (browser / WASI preview) | ❌ | ❌ | ❌ | ❌ | ❌ | Off the scale |
<!-- tier-matrix:end -->
";

    #[test]
    fn parse_rows_reads_symbols_and_strips_nothing() {
        let rows = parse_rows(extract_section(SECTION).unwrap()).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].backend, "Firecracker (Linux + KVM)");
        assert!(rows[0].cells.iter().all(|c| c == "✅"));
        assert_eq!(rows[1].cells[2], "⚠️ block+ext4 verified boot only");
        assert!(rows[2].cells.iter().all(|c| c == "❌"));
    }

    #[test]
    fn extract_section_ignores_unrelated_tables_outside_markers() {
        let source = "\
| ID | STRIDE | Adv. |
|----|--------|------|
| X-S1 | S | G |

<!-- tier-matrix:begin -->
| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| QEMU (Linux KVM/TCG) | ✅ | ⚠️ larger device-model TCB | ⚠️ partial verified boot | ✅ | ✅ | notes |
<!-- tier-matrix:end -->
";
        let rows = parse_rows(extract_section(source).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].backend, "QEMU (Linux KVM/TCG)");
    }

    #[test]
    fn extract_section_requires_both_markers() {
        assert!(extract_section("no markers").is_err());
        assert!(extract_section(&format!("{BEGIN_MARKER} unterminated")).is_err());
        assert!(extract_section(&format!("orphan {END_MARKER}")).is_err());
    }

    #[test]
    fn parse_rows_rejects_a_malformed_pipe_line_in_the_section() {
        let src = "\
| Backend | L1 | L2 | L3 | L4 | L5 | Notes |
|---|---|---|---|---|---|---|
| Firecracker (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | notes |
| broken row | ✅ |
";
        assert!(parse_rows(src).is_err());
    }

    #[test]
    fn parse_rows_rejects_a_table_with_no_data_rows() {
        let src = "| Backend | L1 | L2 | L3 | L4 | L5 | Notes |\n";
        assert!(parse_rows(src).is_err());
    }

    const CLAIMS_TABLE: &str = "\
| # | Claim | Layer | Enforcement |
|---|---|---|---|
| 1 | No host-fs access | L2/L5 | seccomp |
| 2 | No uid 0 | L2/L4 | setpriv |
| 3 | Tampered rootfs fails | L3 | dm-verity |
| 6 | Image hash verified | supply chain | sig |
| 7 | Deps audited | supply chain | deny |
";

    #[test]
    fn claim_layers_keeps_only_matryoshka_tags() {
        let map = claim_layers(CLAIMS_TABLE).unwrap();
        assert_eq!(map[&1], vec!["L2".to_string(), "L5".to_string()]);
        assert_eq!(map[&3], vec!["L3".to_string()]);
        assert!(map[&6].is_empty(), "supply chain pins no layer");
        assert!(map[&7].is_empty());
    }

    #[test]
    fn claim_layers_errors_without_the_claims_table() {
        assert!(claim_layers("no table here").is_err());
    }
}
