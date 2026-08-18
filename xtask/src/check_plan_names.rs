//! `xtask check-plan-names`
//!
//! A new plan under `specs/plans/` must be named by slug, not by number.
//!
//! ## Why the numbers had to stop
//!
//! A plan number is a sequential identifier allocated at *authoring* time. This
//! repo adds roughly three plans a day across many concurrent branches, so two
//! authors routinely pick the same next-free number, and neither can see the
//! other: the number a branch has claimed is invisible until its PR opens. 18
//! numbers were already shared by two plans when this gate was written, and
//! `specs/REFACTOR-STATUS.md` carries two entries under one number.
//!
//! A helper that scanned open PRs before picking was considered and is not
//! enough. Measured against the two collisions that prompted this: one rival
//! PR was already open when the number was picked (a scan catches it), the
//! other opened two hours later (nothing catches it). Any pick-time check
//! closes half the window, because the other half is a branch that has claimed
//! a number and not yet published the claim.
//!
//! A slug cannot collide with a slug chosen for different work, so the failure
//! mode is removed rather than narrowed.
//!
//! ## What this gate enforces
//!
//! The 108 plans that already carry numbers are frozen in
//! `legacy_numbered_plans.txt` and left alone — renaming them would invalidate
//! 689 "Plan NNN" references across the tree for no benefit. Any *other*
//! number-named plan is a new one and fails.
//!
//! This subsumes the duplicate-number problem instead of sitting beside it: if
//! no new numbered plan can be added, no new collision can occur. The frozen
//! list is allowed to shrink (a plan may be retired or renamed) and never to
//! grow; a stale entry is reported so it can be dropped.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

/// The plans that carried numbers when the slug convention landed. Frozen: this
/// list may shrink as plans are retired, never grow. Adding to it re-opens the
/// collision problem the convention exists to remove.
const LEGACY_NUMBERED: &str = include_str!("legacy_numbered_plans.txt");

pub fn run(workspace: &Path) -> Result<()> {
    let dir = workspace.join("specs/plans");
    let legacy: BTreeSet<&str> = LEGACY_NUMBERED
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let present = plan_files(&dir)?;
    let offenders: Vec<&String> = present
        .iter()
        .filter(|name| is_number_named(name) && !legacy.contains(name.as_str()))
        .collect();

    if !offenders.is_empty() {
        let list = offenders
            .iter()
            .map(|name| format!("  {name}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "check-plan-names: {} plan(s) are named by number:\n{list}\n\n\
             Plans are named by slug now, because a sequential number picked while other \
             branches hold unpublished claims on the same number collides — it already \
             happened 18 times. Rename to a date-prefixed slug, e.g. \
             `2026-08-15-sdk-surface-generated-from-rust.md`, and refer to the plan by its \
             path or title rather than a bare number. The numbered plans that predate the \
             convention are frozen in xtask/src/legacy_numbered_plans.txt and stay as they are.",
            offenders.len()
        );
    }

    let stale: Vec<&str> = legacy
        .iter()
        .copied()
        .filter(|name| !present.iter().any(|p| p == name))
        .collect();
    if stale.is_empty() {
        println!(
            "check-plan-names: clean ({} plans, {} legacy-numbered, {} slug-named)",
            present.len(),
            legacy.len(),
            present.len() - legacy.len()
        );
    } else {
        println!(
            "check-plan-names: clean; {} legacy entry(ies) no longer present — drop from \
             xtask/src/legacy_numbered_plans.txt: {}",
            stale.len(),
            stale.join(", ")
        );
    }
    Ok(())
}

/// Every markdown file directly under `specs/plans/`.
fn plan_files(dir: &Path) -> Result<Vec<String>> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    let mut out: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("md"))
        .filter_map(|path| path.file_name()?.to_str().map(str::to_string))
        .collect();
    out.sort();
    Ok(out)
}

/// Whether a filename claims a plan *number* — leading digits then `-`.
///
/// A date-prefixed slug also starts with digits, so it is excluded first —
/// a leading year is part of the date, not a plan number.
fn is_number_named(name: &str) -> bool {
    if is_date_prefixed(name) {
        return false;
    }
    let digits = name.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && name[digits..].starts_with('-')
}

/// `YYYY-MM-DD-` — the recommended slug prefix, which keeps plans sorting in
/// the chronological order the numbers used to give.
fn is_date_prefixed(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 11 {
        return false;
    }
    let digits_at = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    digits_at(0..4)
        && bytes[4] == b'-'
        && digits_at(5..7)
        && bytes[7] == b'-'
        && digits_at(8..10)
        && bytes[10] == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_number_prefix_is_number_named() {
        assert!(is_number_named("332-open-work-register.md"));
        assert!(is_number_named("13-ws11-wasm-egress-poc.md"));
        assert!(is_number_named("2167-agent-session-contract.md"));
    }

    #[test]
    fn a_date_prefix_is_a_slug_not_a_number() {
        assert!(!is_number_named("2026-08-15-sdk-surface-generated.md"));
        assert!(is_date_prefixed("2026-08-15-x.md"));
    }

    #[test]
    fn a_word_prefix_is_a_slug() {
        assert!(!is_number_named("recovery-open-work-2026-08-12.md"));
        assert!(!is_number_named("sdk-surface-generated-from-rust.md"));
    }

    /// `2026-8-15-x.md` is not a valid date prefix, so it must not smuggle a
    /// number-named plan past the check.
    #[test]
    fn a_malformed_date_is_not_treated_as_a_date() {
        assert!(!is_date_prefixed("2026-8-15-x.md"));
        assert!(is_number_named("2026-8-15-x.md"));
    }

    #[test]
    fn digits_without_a_separator_are_not_a_plan_number() {
        assert!(!is_number_named("332open.md"));
    }

    /// The frozen list must describe the tree it ships with, or the gate is
    /// either failing on arrival or carrying entries that mean nothing.
    #[test]
    fn the_legacy_list_matches_this_tree() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let present = plan_files(&workspace.join("specs/plans")).expect("scan plans");
        let legacy: BTreeSet<&str> = LEGACY_NUMBERED
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();

        let unfrozen: Vec<&String> = present
            .iter()
            .filter(|n| is_number_named(n) && !legacy.contains(n.as_str()))
            .collect();
        assert!(
            unfrozen.is_empty(),
            "number-named plans missing from the legacy list: {unfrozen:?}"
        );

        let stale: Vec<&str> = legacy
            .iter()
            .copied()
            .filter(|n| !present.iter().any(|p| p == n))
            .collect();
        assert!(
            stale.is_empty(),
            "legacy entries no longer present: {stale:?}"
        );
    }

    /// Every frozen entry must actually be number-named — a slug in that list
    /// would be silently pointless.
    #[test]
    fn the_legacy_list_holds_only_numbered_names() {
        for name in LEGACY_NUMBERED
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            assert!(is_number_named(name), "{name} is not number-named");
        }
    }
}
