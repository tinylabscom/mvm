//! `xtask check-trust-gradient`
//!
//! Asserts the trust-gradient ledger stays true: tier ranks strictly decrease
//! down the layers, the workload row forbids the host-only authorities, and
//! every named witness still exists in the tree.

use anyhow::{Context, Result, bail};
use std::path::Path;

const REQUIRED_WORKLOAD_FORBIDDEN: [&str; 3] = ["signing-key", "plan-admission", "audit-writer"];

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace
        .join("specs")
        .join("claims")
        .join("trust-gradient.md");
    let source =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let rows = parse_rows(&source).with_context(|| format!("parsing {}", path.display()))?;

    let mut errors: Vec<String> = Vec::new();
    structural_checks(&rows, &mut errors);

    for row in &rows {
        for token in &row.witnesses {
            if !witness_exists(workspace, token)? {
                errors.push(format!(
                    "{}: witness `{token}` not found in the tree",
                    row.layer
                ));
            }
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-trust-gradient: {} problem(s) in specs/claims/trust-gradient.md",
            errors.len()
        );
    }
    eprintln!("check-trust-gradient: clean ({} rows)", rows.len());
    Ok(())
}

pub(crate) struct Row {
    tier: i64,
    layer: String,
    forbidden: Vec<String>,
    witnesses: Vec<String>,
}

pub(crate) fn parse_rows(md: &str) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if cells.len() != 5 || cells[0].eq_ignore_ascii_case("tier") || cells[0].starts_with("---")
        {
            continue;
        }
        let tier: i64 = cells[0]
            .parse()
            .with_context(|| format!("tier `{}` not an integer", cells[0]))?;
        let split = |s: &str| -> Vec<String> {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty() && !t.starts_with("(none"))
                .collect()
        };
        rows.push(Row {
            tier,
            layer: cells[1].clone(),
            forbidden: split(&cells[3]),
            witnesses: split(&cells[4]),
        });
    }
    if rows.is_empty() {
        bail!("no ledger rows parsed");
    }
    Ok(rows)
}

pub(crate) fn structural_checks(rows: &[Row], errors: &mut Vec<String>) {
    for pair in rows.windows(2) {
        if pair[1].tier >= pair[0].tier {
            errors.push(format!(
                "tiers must be monotonic decreasing: `{}` (tier {}) is not below `{}` (tier {})",
                pair[1].layer, pair[1].tier, pair[0].layer, pair[0].tier
            ));
        }
    }
    if let Some(workload) = rows.iter().find(|r| r.layer == "workload") {
        for required in REQUIRED_WORKLOAD_FORBIDDEN {
            if !workload.forbidden.iter().any(|f| f == required) {
                errors.push(format!("workload row must forbid `{required}`"));
            }
        }
    } else {
        errors.push("ledger has no `workload` row".to_string());
    }
}

fn witness_exists(workspace: &Path, token: &str) -> Result<bool> {
    if let Some(name) = token.strip_prefix("fn:") {
        let needle = format!("fn {name}(");
        return grep_tree(workspace, &needle);
    }
    if let Some(name) = token.strip_prefix("ci:") {
        return grep_tree(&workspace.join(".github").join("workflows"), name);
    }
    bail!("unknown witness token `{token}` (expected fn: or ci:)")
}

fn grep_tree(root: &Path, needle: &str) -> Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    for entry in walkdir(root)? {
        if let Ok(text) = std::fs::read_to_string(&entry)
            && text.contains(needle)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn walkdir(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(md: &str) -> Vec<Row> {
        parse_rows(md).expect("parse")
    }

    #[test]
    fn monotonic_tiers_pass() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 2 | host | control-daemon | (none) | fn:foo |\n\
                  | 0 | workload | guest-agent | signing-key, plan-admission, audit-writer | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn non_decreasing_tiers_fail() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 0 | host | control-daemon | (none) | fn:foo |\n\
                  | 2 | workload | guest-agent | signing-key, plan-admission, audit-writer | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(errs.iter().any(|e| e.contains("monotonic")), "{errs:?}");
    }

    #[test]
    fn workload_missing_forbidden_authority_fails() {
        let md = "| Tier | Layer | Daemon | Forbidden authorities | Witnesses |\n\
                  | --- | --- | --- | --- | --- |\n\
                  | 2 | host | control-daemon | (none) | fn:foo |\n\
                  | 0 | workload | guest-agent | signing-key | ci:bar |\n";
        let mut errs = Vec::new();
        structural_checks(&rows(md), &mut errs);
        assert!(
            errs.iter().any(|e| e.contains("plan-admission")),
            "{errs:?}"
        );
    }
}
