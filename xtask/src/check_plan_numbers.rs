//! `xtask check-plan-numbers`
//!
//! Assert no *new* `specs/plans/` number is used by two plans (a ratchet).
//!
//! A plan number is how one document refers to another — a workstream
//! citation, the rollup in `specs/REFACTOR-STATUS.md`, the delivery notes under
//! `specs/sprint/delivery/`. When two plans share a number those references
//! stop resolving to one document, and the reader cannot tell which was meant.
//!
//! This is not hypothetical and not rare: 18 numbers were already doubled when
//! this gate was written, and `REFACTOR-STATUS.md` carries two entries under
//! one number. So the gate stops the set from *growing* and ratchets down as
//! the existing collisions are resolved, rather than demanding uniqueness the
//! tree does not have today.
//!
//! Why it keeps happening is worth stating, because the gate does not fix it:
//! the natural way to pick a number — list `specs/plans/` and take the next
//! free one — cannot see a number claimed by an unmerged branch. Two plans on
//! one branch collided that way while their PR sat in the merge queue. This
//! gate catches the collision at CI time; picking well in the first place needs
//! a scan of open PRs too.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

/// Plan numbers known to be used by more than one plan today. Baseline
/// captured 2026-08-15 from `specs/plans/`.
///
/// Remove an entry freely once the collision is resolved — the gate flags a
/// stale entry and this list is meant to shrink. Adding one admits a new
/// ambiguous cross-reference and must be justified in the PR that does it;
/// renumbering the newer plan is nearly always cheaper, because it is the one
/// nothing refers to yet.
const ALLOWLIST: &[u32] = &[
    254, 255, 266, 269, 284, 285, 295, 297, 298, 304, 308, 315, 316, 322, 325, 326, 327, 329,
];

pub fn run(workspace: &Path) -> Result<()> {
    let plans = workspace.join("specs/plans");
    let numbered = numbered_plans(&plans)?;
    let found = duplicate_numbers(&numbered);

    let regressions = regressions(&found, ALLOWLIST);
    if !regressions.is_empty() {
        let detail = regressions
            .iter()
            .map(|number| {
                let files = numbered
                    .get(number)
                    .map(|names| names.join(", "))
                    .unwrap_or_default();
                format!("  {number}: {files}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "check-plan-numbers: {} plan number(s) are newly used by more than one plan:\n{detail}\n\n\
             A shared number breaks every `Plan <n>` cross-reference that names it — the reader \
             cannot tell which document is meant. Renumber the newer plan (it is the one nothing \
             refers to yet), remembering to rename its delivery note under specs/sprint/delivery/ \
             and fix its entry in specs/REFACTOR-STATUS.md. Pick the next number free on `main` \
             *and* across open PRs: a number claimed by an unmerged branch is invisible to a \
             local listing.",
            regressions.len()
        );
    }

    let stale = stale_allowlist(&found, ALLOWLIST);
    if stale.is_empty() {
        println!(
            "check-plan-numbers: clean ({} plans, {} known collisions, all allowlisted)",
            numbered.values().map(Vec::len).sum::<usize>(),
            found.len()
        );
    } else {
        println!(
            "check-plan-numbers: clean ({} known collisions); {} allowlist entry(ies) no longer \
             collide — drop from ALLOWLIST: {}",
            found.len(),
            stale.len(),
            stale
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Plan filenames grouped by their leading number.
///
/// A plan whose name does not start with digits is skipped rather than being
/// an error: `specs/plans/` holds the occasional dated recovery note, and this
/// gate has nothing to say about a file that never claimed a number.
fn numbered_plans(dir: &Path) -> Result<BTreeMap<u32, Vec<String>>> {
    let mut out: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            continue;
        }
        let Ok(number) = digits.parse::<u32>() else {
            continue;
        };
        out.entry(number).or_default().push(name.to_string());
    }
    for names in out.values_mut() {
        names.sort();
    }
    Ok(out)
}

/// Numbers claimed by more than one plan.
fn duplicate_numbers(numbered: &BTreeMap<u32, Vec<String>>) -> Vec<u32> {
    numbered
        .iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(number, _)| *number)
        .collect()
}

/// Collisions not covered by the allowlist (regressions).
fn regressions(found: &[u32], allow: &[u32]) -> Vec<u32> {
    found
        .iter()
        .copied()
        .filter(|number| !allow.contains(number))
        .collect()
}

/// Allowlist entries that no longer collide (ratchet-down hint).
fn stale_allowlist(found: &[u32], allow: &[u32]) -> Vec<u32> {
    allow
        .iter()
        .copied()
        .filter(|number| !found.contains(number))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(u32, &[&str])]) -> BTreeMap<u32, Vec<String>> {
        pairs
            .iter()
            .map(|(n, names)| (*n, names.iter().map(|s| (*s).to_string()).collect()))
            .collect()
    }

    #[test]
    fn a_number_used_once_is_not_a_duplicate() {
        let numbered = map(&[(1, &["1-a.md"]), (2, &["2-b.md"])]);
        assert!(duplicate_numbers(&numbered).is_empty());
    }

    #[test]
    fn a_number_used_twice_is_a_duplicate() {
        let numbered = map(&[(1, &["1-a.md", "1-b.md"])]);
        assert_eq!(duplicate_numbers(&numbered), vec![1]);
    }

    #[test]
    fn an_allowlisted_collision_is_not_a_regression() {
        assert!(regressions(&[254], &[254]).is_empty());
    }

    #[test]
    fn a_new_collision_is_a_regression() {
        assert_eq!(regressions(&[254, 336], &[254]), vec![336]);
    }

    #[test]
    fn an_allowlist_entry_that_stopped_colliding_is_stale() {
        assert_eq!(stale_allowlist(&[254], &[254, 255]), vec![255]);
    }

    /// The gate has to survive `specs/plans/` holding a file that never claimed
    /// a number — there is one such recovery note in the tree.
    #[test]
    fn an_unnumbered_plan_is_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("recovery-open-work.md"), "x").expect("write");
        std::fs::write(dir.path().join("300-real-plan.md"), "x").expect("write");
        let numbered = numbered_plans(dir.path()).expect("scan");
        assert_eq!(numbered.len(), 1);
        assert!(numbered.contains_key(&300));
    }

    /// Non-markdown files sitting beside the plans are not plans.
    #[test]
    fn a_non_markdown_file_is_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("300-notes.txt"), "x").expect("write");
        assert!(numbered_plans(dir.path()).expect("scan").is_empty());
    }

    /// The committed baseline must describe the tree it ships with, or the gate
    /// is either failing on arrival or carrying entries that mean nothing.
    #[test]
    fn the_allowlist_matches_this_tree() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let numbered = numbered_plans(&workspace.join("specs/plans")).expect("scan plans");
        let found = duplicate_numbers(&numbered);
        assert!(
            regressions(&found, ALLOWLIST).is_empty(),
            "unallowlisted plan-number collisions: {:?}",
            regressions(&found, ALLOWLIST)
        );
        assert!(
            stale_allowlist(&found, ALLOWLIST).is_empty(),
            "ALLOWLIST entries that no longer collide: {:?}",
            stale_allowlist(&found, ALLOWLIST)
        );
    }
}
