//! Keep mutable work state out of `specs/`.
//!
//! Plans dated on or before the migration are historical inputs. New plans are
//! exceptional immutable design attachments: one issue link, no progress
//! ledger. The cutoff makes the legacy set finite without maintaining a second
//! hand-edited inventory.
//!
//! Every tracked path under `specs/` must also be on the allow-list: the PRD,
//! the README, `adrs/` and `contracts/` permanently, plus the shrinking
//! transitional list the cleanup is retiring.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::Path;

const LEGACY_CUTOFF: &str = "2026-09-30";
const LEGACY_NUMBERED: &str = include_str!("legacy_numbered_plans.txt");
const RETIRED_DASHBOARDS: &[&str] = &["SPRINT.md", "REFACTOR-STATUS.md"];
const TRANSITIONAL: &str = include_str!("specs_transitional.txt");
/// The transitional list may only shrink. Lower this as stages delete entries.
#[cfg(test)]
const TRANSITIONAL_CEILING: usize = 12;
const PERMANENT: &[&str] = &[
    "specs/README.md",
    "specs/prd.md",
    "specs/adrs/",
    "specs/contracts/",
];

pub fn run(workspace: &Path) -> Result<()> {
    let plans = workspace.join("specs/plans");
    let mut violations = Vec::new();
    for entry in
        std::fs::read_dir(&plans).with_context(|| format!("reading {}", plans.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("md") || is_legacy_plan(&path)
        {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        check_new_plan(&path, &text, &mut violations);
    }

    for path in [
        workspace.join("AGENTS.md"),
        workspace.join("specs/README.md"),
        workspace.join("public/src/content/docs/contributing/ai-coding-workflow.md"),
    ] {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        for dashboard in RETIRED_DASHBOARDS {
            if text.contains(dashboard) {
                violations.push(format!(
                    "{}: active guidance references retired dashboard {dashboard}",
                    relative(workspace, &path).display()
                ));
            }
        }
    }

    for path in tracked_spec_paths(workspace)? {
        if !is_allowed(&path) {
            violations.push(format!(
                "{path}: not allowed under specs/ (it holds the PRD, README, adrs/ and contracts/)"
            ));
        }
    }

    if violations.is_empty() {
        println!("check-spec-hygiene: clean");
        return Ok(());
    }
    bail!("check-spec-hygiene:\n  {}", violations.join("\n  "))
}

fn transitional_entries() -> impl Iterator<Item = &'static str> {
    TRANSITIONAL
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn is_allowed(path: &str) -> bool {
    PERMANENT
        .iter()
        .copied()
        .chain(transitional_entries())
        .any(|entry| path == entry || (entry.ends_with('/') && path.starts_with(entry)))
}

fn tracked_spec_paths(workspace: &Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "-z", "specs"])
        .current_dir(workspace)
        .output()
        .context("run git ls-files specs")?;
    if !output.status.success() {
        bail!("git ls-files specs failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

fn is_legacy_plan(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if LEGACY_NUMBERED.lines().any(|legacy| legacy.trim() == name) {
        return true;
    }
    let Some(prefix) = name.get(..10) else {
        return false;
    };
    prefix <= LEGACY_CUTOFF && looks_like_date(prefix)
}

fn looks_like_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

fn check_new_plan(path: &Path, text: &str, violations: &mut Vec<String>) {
    let display = path.display();
    let required = [("kind", "design"), ("status", "accepted")];
    if !text.starts_with("---\n") {
        violations.push(format!("{display}: missing YAML frontmatter"));
    }
    for (key, value) in required {
        if !text.lines().any(|line| line == format!("{key}: {value}")) {
            violations.push(format!("{display}: requires `{key}: {value}`"));
        }
    }
    let issue = Regex::new(r"(?m)^issue: https://github\.com/[^/\s]+/[^/\s]+/issues/\d+$")
        .expect("valid issue regex");
    if !issue.is_match(text) {
        violations.push(format!(
            "{display}: requires one canonical GitHub issue URL"
        ));
    }
    let checkbox = Regex::new(r"(?m)^\s*[-*]\s+\[[ xX]\]").expect("valid checkbox regex");
    if checkbox.is_match(text) {
        violations.push(format!("{display}: task checkboxes belong in the issue"));
    }
    let mutable = Regex::new(
        r"(?im)^(?:\*\*)?(?:progress|remaining work|owner|assignee|branch|delivery status)(?:\*\*)?\s*:",
    )
    .expect("valid mutable-state regex");
    if mutable.is_match(text) {
        violations.push(format!("{display}: contains mutable work state"));
    }
}

fn relative<'a>(workspace: &'a Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(workspace).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(text: &str) -> Vec<String> {
        let mut violations = Vec::new();
        check_new_plan(Path::new("specs/plans/new.md"), text, &mut violations);
        violations
    }

    #[test]
    fn accepted_design_attachment_is_clean() {
        let text = "---\nkind: design\nissue: https://github.com/acme/mvm/issues/42\nstatus: accepted\n---\n# Design\n";
        assert!(check(text).is_empty());
    }

    #[test]
    fn progress_ledger_is_rejected() {
        let text = "---\nkind: design\nissue: https://github.com/acme/mvm/issues/42\nstatus: accepted\n---\n- [ ] ship\nRemaining work: tests\n";
        let violations = check(text).join("\n");
        assert!(violations.contains("task checkboxes"));
        assert!(violations.contains("mutable work state"));
    }

    #[test]
    fn permanent_areas_are_allowed() {
        for path in [
            "specs/prd.md",
            "specs/README.md",
            "specs/adrs/001-microvm-security-posture.md",
            "specs/contracts/policy-approval-v1.md",
        ] {
            assert!(is_allowed(path), "{path}");
        }
    }

    #[test]
    fn a_new_area_is_refused() {
        for path in [
            "specs/sprint/delivery/new.md",
            "specs/01-project.md",
            "specs/ideas.md",
            "specs/adrs-extra/x.md",
        ] {
            assert!(!is_allowed(path), "{path}");
        }
    }

    #[test]
    fn an_exact_file_entry_does_not_admit_a_sibling_prefix() {
        assert!(is_allowed("specs/VERIFICATION.md"));
        assert!(!is_allowed("specs/VERIFICATION.md.bak"));
    }

    #[test]
    fn the_transitional_list_only_shrinks() {
        assert!(transitional_entries().count() <= TRANSITIONAL_CEILING);
    }

    #[test]
    fn dated_plans_before_the_cutoff_are_legacy() {
        assert!(is_legacy_plan(Path::new("specs/plans/2026-09-28-old.md")));
        assert!(!is_legacy_plan(Path::new("specs/plans/2026-10-01-new.md")));
    }
}
