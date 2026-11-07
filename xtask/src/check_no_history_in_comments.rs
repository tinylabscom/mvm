//! `xtask check-no-history-in-comments`
//!
//! A comment states what holds and what breaks, not how the code got here.
//! Phrases such as "used to", "formerly" or "was renamed" narrate history
//! the diff and commit log already carry, and they go stale the moment the
//! context they describe is forgotten. Process citations (plan, PR, ADR,
//! sprint) are rejected outright by `check-no-spec-refs-in-comments`; this
//! gate covers the phrasing that carries no number.
//!
//! The existing narration is recorded per file in `HISTORY_BASELINE`. It is a
//! ratchet: a file may not exceed its recorded count, and a file under it
//! fails until the baseline is lowered with `--write-baseline`, so the total
//! only goes down. Reaching an empty baseline is the end state.

use crate::check_no_spec_refs_in_comments::{hash_comments, rust_comments};
use anyhow::{Result, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

const HISTORY_BASELINE: &str = "xtask/history-comments-baseline.txt";

/// Files that define or test the phrases themselves.
const EXEMPT: &[&str] = &["xtask/src/check_no_history_in_comments.rs"];

fn history_regex() -> Regex {
    Regex::new(
        r"(?ix)
        \b(formerly|until\ recently)\b
        | \bpreviously\ (was|were|did|had|called|named|lived|lived\ in|returned|used)\b
        | \b(it|that|which|this|they|we|was|were)\ used\ to\b
        | \b(was|were)\ (briefly|renamed)\b
        | \b(since|after|before)\ the\ (refactor|rewrite|migration|cutover|split)\b
        | \bwe\ (removed|replaced|deleted|renamed|moved)\b
        ",
    )
    .expect("history regex is valid")
}

/// Count history-narrating comment lines per workspace-relative file.
fn count_hits(workspace: &Path) -> Result<BTreeMap<String, usize>> {
    let re = history_regex();
    let mut counts = BTreeMap::new();
    let mut scan = |path: &Path| {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPT.contains(&rel.as_str()) {
            return;
        }
        let comments = match path.extension().and_then(|e| e.to_str()) {
            Some("rs") => rust_comments as fn(&str) -> Vec<(usize, String)>,
            Some("sh") | Some("nix") => hash_comments,
            _ => return,
        };
        let Ok(src) = std::fs::read_to_string(path) else {
            return;
        };
        let n = hits_in(&re, &comments(&src));
        if n > 0 {
            counts.insert(rel, n);
        }
    };
    for root in ["crates", "xtask", "nix", "src", "scripts"] {
        crate::fs_walk::walk_files(&workspace.join(root), &mut scan)?;
    }
    Ok(counts)
}

fn hits_in(re: &Regex, comments: &[(usize, String)]) -> usize {
    comments.iter().filter(|(_, t)| re.is_match(t)).count()
}

fn parse_baseline(text: &str) -> BTreeMap<String, usize> {
    text.lines()
        .filter_map(|l| {
            let (n, path) = l.split_once(' ')?;
            Some((path.trim().to_string(), n.parse().ok()?))
        })
        .collect()
}

fn render_baseline(counts: &BTreeMap<String, usize>) -> String {
    counts.iter().map(|(p, n)| format!("{n} {p}\n")).collect()
}

/// Files whose count differs from the baseline: `(path, baseline, now)`.
fn diff(
    base: &BTreeMap<String, usize>,
    now: &BTreeMap<String, usize>,
) -> Vec<(String, usize, usize)> {
    let mut paths: Vec<&String> = base.keys().chain(now.keys()).collect();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .filter_map(|p| {
            let (b, n) = (
                base.get(p).copied().unwrap_or(0),
                now.get(p).copied().unwrap_or(0),
            );
            (b != n).then(|| (p.clone(), b, n))
        })
        .collect()
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let now = count_hits(workspace)?;
    let base = parse_baseline(&std::fs::read_to_string(workspace.join(HISTORY_BASELINE))?);
    let changed = diff(&base, &now);
    let grew: Vec<_> = changed.iter().filter(|(_, b, n)| n > b).collect();
    if !grew.is_empty() {
        let lines: Vec<String> = grew
            .iter()
            .map(|(p, b, n)| format!("  {p}: {n} history-narrating comment line(s), baseline {b}"))
            .collect();
        bail!(
            "check-no-history-in-comments: new history narration in comments. State the invariant \
             or failure mode instead of how the code changed.\n{}",
            lines.join("\n")
        );
    }
    if !changed.is_empty() {
        bail!(
            "check-no-history-in-comments: the baseline is out of date (counts only go down). \
             Run `cargo run -p xtask -- check-no-history-in-comments --write-baseline`.\n{}",
            changed
                .iter()
                .map(|(p, b, n)| format!("  {p}: baseline {b}, now {n}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let total: usize = now.values().sum();
    eprintln!("check-no-history-in-comments: {total} line(s) remain in the baseline, none new");
    Ok(())
}

/// Rewrite the baseline to the current counts, refusing to raise any file.
pub(crate) fn write_baseline(workspace: &Path) -> Result<()> {
    let now = count_hits(workspace)?;
    let path = workspace.join(HISTORY_BASELINE);
    // A missing baseline is the first generation; once it exists counts only fall.
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Some((p, b, n)) = diff(&parse_baseline(&text), &now)
            .into_iter()
            .find(|(_, b, n)| n > b)
    {
        bail!("refusing to raise the baseline: {p} went from {b} to {n}");
    }
    std::fs::write(&path, render_baseline(&now))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(src: &str) -> usize {
        hits_in(&history_regex(), &rust_comments(src))
    }

    #[test]
    fn flags_history_phrases_in_comments() {
        assert_eq!(n("// This previously did the work on Lima\n"), 1);
        assert_eq!(n("/// The flag was renamed during the refactor\n"), 1);
        assert_eq!(n("// it used to return None\n"), 1);
    }

    #[test]
    fn keeps_invariant_wording_and_strings() {
        assert_eq!(
            n("// Used to key the cache; never reused across hosts\n"),
            0
        );
        assert_eq!(n("// The buffer is used to hold one frame\n"), 0);
        assert_eq!(n("let s = \"formerly\";\n"), 0);
        assert_eq!(n("// A proof issued earlier no longer verifies here\n"), 0);
        assert_eq!(n("// Phase 1: read the header\n"), 0);
    }

    #[test]
    fn ratchet_rejects_growth_and_stale_baseline() {
        let base = parse_baseline("2 a.rs\n1 b.rs\n");
        let now = BTreeMap::from([("a.rs".to_string(), 3), ("b.rs".to_string(), 1)]);
        assert_eq!(diff(&base, &now), vec![("a.rs".to_string(), 2, 3)]);
        let shrunk = BTreeMap::from([("a.rs".to_string(), 2)]);
        assert_eq!(diff(&base, &shrunk), vec![("b.rs".to_string(), 1, 0)]);
        assert_eq!(parse_baseline(&render_baseline(&base)), base);
    }
}
