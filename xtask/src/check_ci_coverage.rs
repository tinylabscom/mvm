//! `xtask check-ci-coverage`
//!
//! Two ways CI coverage disappears without a red build: a job that owned a
//! coverage class is deleted or renamed, and a workflow keeps calling an
//! xtask gate that the policy driver no longer runs.
//!
//! `CLASSES` names the job that owns each class. It is job-granular: it
//! proves the job still exists as a live key (`ci_anchors`, so a comment does
//! not count), not that the job still contains the right step.

use crate::check_all::{GATES, NOT_IN_LINT_LANE};
use crate::claims_ledger::ci_anchors;
use anyhow::{Result, bail};
use std::path::Path;

/// (coverage class, workflow file, owning job key)
const CLASSES: &[(&str, &str, &str)] = &[
    ("supply-chain", "security.yml", "cargo-deny"),
    ("supply-chain", "security.yml", "cargo-audit"),
    ("fuzz", "security.yml", "fuzz"),
    ("ebpf", "ci-main.yml", "test-ebpf-telemetry"),
    ("wasm", "ci-main.yml", "test-workspace-extras"),
    ("release", "release.yml", "verify-release"),
    ("release", "release.yml", "build"),
    ("platform-windows", "ci.yml", "lint-windows"),
    ("platform-aarch64", "ci-main.yml", "test-workspace-aarch64"),
    ("platform-macos", "e2e-docs.yml", "e2e-docs-macos"),
];

/// Classes whose owning job is absent from `read(workflow)`.
fn missing_jobs(read: impl Fn(&str) -> Option<String>) -> Vec<String> {
    CLASSES
        .iter()
        .filter(|(_, file, job)| {
            !read(file).is_some_and(|text| ci_anchors(&text).iter().any(|a| a == job))
        })
        .map(|(class, file, job)| format!("{class}: {file} has no job `{job}`"))
        .collect()
}

/// `check-*` gates a workflow's `xtask` lines invoke that nothing runs.
fn unowned_gates(workflow: &str) -> Vec<String> {
    workflow
        .lines()
        .filter(|l| l.contains("xtask") && !l.trim_start().starts_with('#'))
        .flat_map(|l| l.split_whitespace())
        .filter(|t| t.starts_with("check-"))
        .map(|t| t.trim_end_matches(|c: char| !c.is_ascii_lowercase()))
        .filter(|t| {
            !GATES.iter().any(|(n, _)| n == t) && !NOT_IN_LINT_LANE.iter().any(|(n, _)| n == t)
        })
        .map(String::from)
        .collect()
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let dir = workspace.join(".github/workflows");
    let mut problems = missing_jobs(|f| std::fs::read_to_string(dir.join(f)).ok());
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for gate in unowned_gates(&text) {
            problems.push(format!(
                "{} invokes `{gate}`, which is neither in check-all nor excluded",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    if !problems.is_empty() {
        bail!("check-ci-coverage:\n  {}", problems.join("\n  "));
    }
    eprintln!("check-ci-coverage: {} coverage jobs present", CLASSES.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removed_lane_is_reported_with_its_class() {
        let wf = "jobs:\n  cargo-audit:\n    runs-on: x\n  fuzz:\n    runs-on: x\n";
        let found = missing_jobs(|f| (f == "security.yml").then(|| wf.to_string()));
        assert!(found.contains(&"supply-chain: security.yml has no job `cargo-deny`".into()));
        assert!(!found.iter().any(|m| m.contains("`fuzz`")));
        assert!(found.iter().any(|m| m.starts_with("ebpf:")), "{found:?}");
    }

    #[test]
    fn a_commented_job_does_not_own_a_class() {
        let wf = "jobs:\n  # fuzz:\n  other:\n    runs-on: x\n";
        let found = missing_jobs(|f| (f == "security.yml").then(|| wf.to_string()));
        assert!(found.iter().any(|m| m.contains("`fuzz`")));
    }

    #[test]
    fn a_workflow_gate_nothing_runs_is_reported() {
        let wf = "      - run: cargo run -p xtask -- check-all\n      - run: cargo xtask check-ghost-gate\n      # xtask check-other\n";
        assert_eq!(unowned_gates(wf), vec!["check-ghost-gate"]);
    }
}
