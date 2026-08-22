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
fn canonical_bdd_workflow_runs_a_kvm_live_witness_in_the_merge_queue() {
    let contents = workflow("bdd.yml");
    let live = job_block(&contents, "bdd-live");

    for expected in [
        "github.event_name == 'merge_group'",
        "github.event_name == 'workflow_dispatch'",
        "runs-on: ubuntu-latest",
        "FC_VERSION: v1.14.1",
        "MVM_KERNEL_SOURCE: download",
        "packages: libcap-ng-dev lld qemu-system-x86 qemu-utils",
        "sudo chmod 666 /dev/kvm",
        "run: just bdd-live-ci",
    ] {
        assert!(
            live.contains(expected),
            "the merge-queue live BDD job must contain {expected:?}"
        );
    }
}

#[test]
fn live_bdd_recipe_opts_in_and_selects_only_the_fast_ci_witness() {
    let justfile = fs::read_to_string("Justfile").expect("read Justfile");
    let recipe = justfile
        .split("\nbdd-live-ci:\n")
        .nth(1)
        .expect("Justfile must define bdd-live-ci")
        .split("\n\n")
        .next()
        .expect("bdd-live-ci recipe has a body");

    assert!(recipe.contains("MVM_BDD_LIVE=1"));
    assert!(recipe.contains("MVM_BDD_CI_LIVE_ONLY=1"));
    assert!(recipe.contains("cargo build --bin mvmctl --features user"));
    assert!(recipe.contains("CARGO_BIN_EXE_mvmctl=\"${CARGO_TARGET_DIR:-target}/debug/mvmctl\""));
    assert!(!recipe.contains("--tags"));
}

#[test]
fn fast_live_witness_executes_the_readme_persistent_machine_path() {
    let feature =
        fs::read_to_string("features/suites/s8_readme_contract/persistent_machine_live.feature")
            .expect("read the fast README live feature");

    assert!(feature.contains("@live @firecracker @ci_live"));
    for command in [
        "machine create bdd-readme-web --image nginx --cpus 2 --memory 512M",
        "machine start bdd-readme-web",
        "machine exec bdd-readme-web -- nginx -v",
        "machine logs bdd-readme-web",
        "machine inspect bdd-readme-web",
        "machine stop bdd-readme-web --yes",
        "machine rm bdd-readme-web --yes",
    ] {
        assert!(
            feature.contains(command),
            "the live README witness must execute {command:?}"
        );
    }
}

#[test]
fn canonical_bdd_workflow_uses_bounded_apt_action() {
    let contents = workflow("bdd.yml");
    assert!(
        contents.contains("uses: ./.github/actions/apt-deps"),
        "BDD setup must inherit the shared mirror replacement, timeouts, and retries"
    );
    assert!(
        !contents.contains("sudo apt-get"),
        "BDD setup must not bypass the bounded apt action"
    );
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
