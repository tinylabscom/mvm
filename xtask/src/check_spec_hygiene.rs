//! Keep mutable work state out of `specs/`.
//!
//! Plans dated on or before the migration are historical inputs. New plans are
//! exceptional immutable design attachments: one issue link, no progress
//! ledger. The cutoff makes the legacy set finite without maintaining a second
//! hand-edited inventory.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::Path;

const LEGACY_CUTOFF: &str = "2026-09-30";
const LEGACY_NUMBERED: &str = include_str!("legacy_numbered_plans.txt");
const RETIRED_DASHBOARDS: &[&str] = &["SPRINT.md", "REFACTOR-STATUS.md"];

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

    if violations.is_empty() {
        println!("check-spec-hygiene: clean");
        return Ok(());
    }
    bail!("check-spec-hygiene:\n  {}", violations.join("\n  "))
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
    fn dated_plans_before_the_cutoff_are_legacy() {
        assert!(is_legacy_plan(Path::new("specs/plans/2026-09-28-old.md")));
        assert!(!is_legacy_plan(Path::new("specs/plans/2026-10-01-new.md")));
    }
}
