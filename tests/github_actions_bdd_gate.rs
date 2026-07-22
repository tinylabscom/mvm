use std::fs;
use std::path::Path;

const WORKFLOWS: &str = ".github/workflows";

fn workflow(name: &str) -> String {
    fs::read_to_string(Path::new(WORKFLOWS).join(name))
        .unwrap_or_else(|error| panic!("failed to read {name}: {error}"))
}

fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
    let marker = format!("  {job}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow is missing the {job} job"));
    let rest_start = start + marker.len();
    let rest = &workflow[rest_start..];
    let end = rest
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let line = rest[offset + 1..].lines().next()?;
            (!line.starts_with("    ") && line.ends_with(':')).then_some(rest_start + offset)
        })
        .unwrap_or(workflow.len());
    &workflow[start..end]
}

fn assert_reuses_bdd_gate(workflow_name: &str) {
    let contents = workflow(workflow_name);
    let bdd = job_block(&contents, "bdd");
    assert!(
        bdd.contains("uses: ./.github/workflows/bdd.yml"),
        "{workflow_name} must reuse the canonical BDD workflow"
    );
}

fn assert_job_needs_bdd(workflow_name: &str, job: &str) {
    let contents = workflow(workflow_name);
    let block = job_block(&contents, job);
    let needs_line = block
        .lines()
        .find(|line| line.trim_start().starts_with("needs:"))
        .unwrap_or_else(|| panic!("{workflow_name}'s {job} job must declare needs"));
    assert!(
        needs_line.contains("bdd"),
        "{workflow_name}'s {job} job must depend on the BDD gate"
    );
}

fn assert_job_contains(workflow_name: &str, job: &str, expected: &str) {
    let contents = workflow(workflow_name);
    let block = job_block(&contents, job);
    assert!(
        block.contains(expected),
        "{workflow_name}'s {job} job must contain {expected:?}"
    );
}

#[test]
fn canonical_bdd_workflow_runs_the_full_suite() {
    let contents = workflow("bdd.yml");
    assert!(contents.contains("  workflow_call:"));
    assert!(contents.contains("run: just bdd"));
}

#[test]
fn runtime_release_publication_needs_bdd() {
    assert_reuses_bdd_gate("release.yml");
    assert_job_needs_bdd("release.yml", "release");
    assert_job_contains("release.yml", "release", "needs.bdd.result == 'success'");
}

#[test]
fn kernel_release_asset_publication_needs_bdd() {
    assert_reuses_bdd_gate("kernel-build.yml");
    assert_job_contains(
        "kernel-build.yml",
        "bdd",
        "startsWith(github.ref, 'refs/tags/v')",
    );
    assert_job_needs_bdd("kernel-build.yml", "kernel");
    assert_job_contains(
        "kernel-build.yml",
        "kernel",
        "needs.bdd.result == 'success' || needs.bdd.result == 'skipped'",
    );
}

#[test]
fn sdk_registry_publication_needs_bdd() {
    assert_reuses_bdd_gate("publish-sdk.yml");
    assert_job_needs_bdd("publish-sdk.yml", "publish_pypi_release");
    assert_job_needs_bdd("publish-sdk.yml", "publish_npm_release");
}

#[test]
fn crates_io_publication_needs_bdd() {
    assert_reuses_bdd_gate("publish-crates.yml");
    assert_job_needs_bdd("publish-crates.yml", "publish");
}
