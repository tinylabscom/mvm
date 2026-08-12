//! `xtask check-sprint-append`
//!
//! Keeps `specs/SPRINT.md` from going back to being a shared append target.
//!
//! The delivery log used to be one section that every session appended to at
//! the same insertion point. Git cannot merge concurrent inserts at one point,
//! so it conflicted on essentially every rebase — at a rate set by how
//! productive the team was, which is the worst possible thing to couple it to.
//! The delay was the small half of the cost: each rebase forces a full re-gate
//! of code that did not change, and hand-merging the same prose over and over
//! is how an entry quietly goes missing. One PR was evicted from the merge
//! queue by a documentation conflict alone.
//!
//! Entries now live one-per-file under `specs/sprint/delivery/`, which cannot
//! collide. This gate exists because the old section is still in the file as
//! history, and a convention that only lives in prose gets followed until
//! someone is in a hurry — the failure mode is silent, because appending there
//! *works* and only hurts the next person to rebase.
//!
//! So the archive is pinned by entry count. Editing a historical entry (a typo,
//! a corrected link) is fine; adding one is not.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// Heading whose entries are frozen.
const ARCHIVE_HEADING: &str = "## Delivered (archive — closed to new entries)";

/// Top-level delivery entries present when the archive was closed.
///
/// A count rather than a hash so that fixing a typo in a historical entry stays
/// a one-line edit instead of a ritual. What must not change is how *many*
/// there are.
const FROZEN_ENTRY_COUNT: usize = 82;

/// Where new entries go instead.
const DELIVERY_DIR: &str = "specs/sprint/delivery";

pub fn run(workspace: &Path) -> Result<()> {
    let sprint_path = workspace.join("specs").join("SPRINT.md");
    let sprint = std::fs::read_to_string(&sprint_path)
        .with_context(|| format!("reading {}", sprint_path.display()))?;

    let mut errors: Vec<String> = Vec::new();

    if !workspace.join(DELIVERY_DIR).is_dir() {
        errors.push(format!(
            "{DELIVERY_DIR}/ is missing — it is where delivery entries live now"
        ));
    }

    match archive_entry_count(&sprint) {
        None => errors.push(format!(
            "specs/SPRINT.md has no `{ARCHIVE_HEADING}` heading. If the section was \
             renamed, update this gate deliberately: it is the only thing keeping the \
             file from becoming a shared append target again."
        )),
        Some(found) if found > FROZEN_ENTRY_COUNT => errors.push(format!(
            "specs/SPRINT.md's archive section has {found} entries, up from the frozen \
             {FROZEN_ENTRY_COUNT}.\n         Move your entry into its own file — \
             {DELIVERY_DIR}/<issue>-<slug>.md — and delete it from SPRINT.md.\n         \
             That is the fix, not raising this number: appending here conflicts with \
             every other session's rebase and costs each of them a full re-gate of code \
             that did not change. Moving it also removes the conflict from your own \
             branch. See {DELIVERY_DIR}/README.md and issue #2353."
        )),
        Some(found) if found < FROZEN_ENTRY_COUNT => errors.push(format!(
            "specs/SPRINT.md's archive section has {found} entries, down from the frozen \
             {FROZEN_ENTRY_COUNT}. Deleting delivered history is not a rebase resolution; \
             if it was intentional, lower FROZEN_ENTRY_COUNT in this gate and say why."
        )),
        Some(_) => {}
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!("check-sprint-append: {} problem(s)", errors.len());
    }

    eprintln!(
        "check-sprint-append: clean (archive frozen at {FROZEN_ENTRY_COUNT} entries, \
         new entries land in {DELIVERY_DIR}/)"
    );
    Ok(())
}

/// Count top-level delivery bullets under the archive heading.
///
/// Only column-zero `- [ ]`/`- [x]`/`- [~]` bullets count. Nested bullets and
/// wrapped continuation lines are part of an entry, not entries themselves, and
/// counting them would make the number move whenever someone reflowed a
/// paragraph.
fn archive_entry_count(sprint: &str) -> Option<usize> {
    let start = sprint.find(ARCHIVE_HEADING)?;
    let body = &sprint[start + ARCHIVE_HEADING.len()..];
    // Stop at the next top-level heading so the count covers this section only.
    let end = body.find("\n## ").unwrap_or(body.len());
    Some(
        body[..end]
            .lines()
            .filter(|l| is_top_level_entry(l))
            .count(),
    )
}

fn is_top_level_entry(line: &str) -> bool {
    matches!(
        line.get(..6),
        Some("- [ ] ") | Some("- [x] ") | Some("- [~] ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(entries: &str) -> String {
        format!("# Sprint\n\n{ARCHIVE_HEADING}\n\n{entries}\n## Next section\n\n- [x] unrelated\n")
    }

    #[test]
    fn counts_only_top_level_entries() {
        let s = section(
            "- [x] one\n      wrapped continuation, not an entry\n  - [x] nested, not an entry\n- [~] two\n- [ ] three\n",
        );
        assert_eq!(archive_entry_count(&s), Some(3));
    }

    /// The count must not move when someone reflows a paragraph or fixes a
    /// typo, or the gate becomes noise and gets bumped reflexively — which is
    /// exactly how a frozen thing unfreezes.
    #[test]
    fn rewrapping_an_entry_does_not_change_the_count() {
        let before = section("- [x] a single line entry\n");
        let after =
            section("- [x] a single line entry that has now\n      been wrapped over two lines\n");
        assert_eq!(archive_entry_count(&before), archive_entry_count(&after));
    }

    /// The whole point: the count stops at the section boundary, so entries in
    /// later sections neither inflate it nor let an append hide in them.
    #[test]
    fn the_count_stops_at_the_next_heading() {
        let s = section("- [x] only mine\n");
        assert_eq!(archive_entry_count(&s), Some(1));
    }

    #[test]
    fn a_missing_heading_is_reported_rather_than_counted_as_zero() {
        assert_eq!(archive_entry_count("# Sprint\n\n- [x] loose entry\n"), None);
    }
}
