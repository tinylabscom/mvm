//! Keep mutable work state out of `specs/`.
//!
//! Every tracked path under `specs/` must be on the allow-list: the PRD, the
//! README, `adrs/` and `contracts/`. Active guidance must not point at the
//! retired progress dashboards.

use anyhow::{Context, Result, bail};
use std::path::Path;

const RETIRED_DASHBOARDS: &[&str] = &[
    "SPRINT.md",
    "REFACTOR-STATUS.md",
    "cleanup-active-work.md",
    "cleanup-preservation-ledger.md",
];
const PERMANENT: &[&str] = &[
    "specs/README.md",
    "specs/prd.md",
    "specs/adrs/",
    "specs/contracts/",
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut violations = Vec::new();

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

    for path in tracked_paths(workspace, "specs")? {
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

fn is_allowed(path: &str) -> bool {
    PERMANENT
        .iter()
        .any(|entry| path == *entry || (entry.ends_with('/') && path.starts_with(entry)))
}

/// Paths git tracks under `pathspec`, relative to the workspace root.
pub(crate) fn tracked_paths(workspace: &Path, pathspec: &str) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "-z", pathspec])
        .current_dir(workspace)
        .output()
        .context("run git ls-files")?;
    if !output.status.success() {
        bail!("git ls-files {pathspec} failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

fn relative<'a>(workspace: &'a Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(workspace).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_directory_entry_does_not_admit_a_sibling_prefix() {
        assert!(is_allowed("specs/adrs/001-x.md"));
        assert!(!is_allowed("specs/adrs-extra/x.md"));
        assert!(!is_allowed("specs/prd.md.bak"));
    }

    #[test]
    fn the_retired_areas_stay_retired() {
        for path in [
            "specs/plans/new.md",
            "specs/notes/new.md",
            "specs/research/new.md",
            "specs/telemetry/new.toml",
            "specs/evidence/new.json",
            "specs/sprint/delivery/new.md",
        ] {
            assert!(!is_allowed(path), "{path}");
        }
    }
}
