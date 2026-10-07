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
    assert!(contents.contains("run: just bdd::run"));
}

#[test]
fn live_bdd_witness_runs_in_extended_ci_not_the_merge_queue() {
    let required = workflow("bdd.yml");
    assert!(
        !required.contains("bdd-live:") && !required.contains("just bdd::live-ci"),
        "the long-running live lifecycle must not serialize the merge queue"
    );

    let extended = workflow("ci-full.yml");
    let live = job_block(&extended, "bdd-live-readme");

    for expected in [
        "runs-on: ubuntu-latest",
        "witness: ci_live",
        "witness: tool_live",
        "timeout: 60",
        "timeout-minutes: ${{ matrix.timeout }}",
        "FC_VERSION: v1.17.0",
        "MVM_KERNEL_SOURCE: download",
        "packages: libcap-ng-dev lld qemu-system-x86 qemu-utils",
        "sudo chmod 666 /dev/kvm",
        "run: just bdd::live-ci ${{ matrix.witness }}",
    ] {
        assert!(
            live.contains(expected),
            "the nightly live BDD job must contain {expected:?}"
        );
    }
}

#[test]
fn live_ci_budget_covers_cold_setup_and_measured_lifecycle() {
    let extended = workflow("ci-full.yml");
    let live = job_block(&extended, "bdd-live-readme");
    let lifecycle = live
        .split("- witness: ci_live\n")
        .nth(1)
        .expect("the lifecycle witness must remain in the matrix")
        .split("- witness:")
        .next()
        .expect("the lifecycle witness has a matrix entry");
    let job_minutes: u32 = lifecycle
        .lines()
        .find_map(|line| line.trim().strip_prefix("timeout:"))
        .expect("the lifecycle witness must declare its own job budget")
        .trim()
        .parse()
        .expect("the job budget must be a number");
    let cold_setup_minutes = 35;
    let measured_lifecycle_minutes = 40;
    assert!(
        job_minutes >= cold_setup_minutes + measured_lifecycle_minutes,
        "the job budget ({job_minutes}m) must cover cold compilation and the \
         measured lifecycle, or GitHub cancels progressing scenarios"
    );
}

#[test]
fn live_bdd_recipe_opts_in_and_selects_one_strict_witness() {
    let bdd_mod = fs::read_to_string("just/bdd/mod.just").expect("read bdd module");
    let recipe = bdd_mod
        .split("\nlive-ci TAG=\"ci_live\":\n")
        .nth(1)
        .expect("bdd module must define live-ci")
        .split("\n\n")
        .next()
        .expect("live-ci recipe has a body");

    assert!(recipe.contains("MVM_BDD_LIVE=1"));
    assert!(recipe.contains("MVM_BDD_ONLY_TAG={{ TAG }}"));
    assert!(recipe.contains("MVM_BDD_STRICT_SKIPS=1"));
    assert!(recipe.contains("MVM_BDD_ALLOWED_SKIPS=outside-selected-tag"));
    assert!(recipe.contains("cargo build --bin mvmctl --features user"));
    assert!(recipe.contains("CARGO_BIN_EXE_mvmctl=\"${CARGO_TARGET_DIR:-target}/debug/mvmctl\""));
    assert!(!recipe.contains("--tags"));
}

#[test]
fn docs_bdd_recipe_selects_the_docs_features_and_refuses_an_empty_run() {
    let bdd_mod = fs::read_to_string("just/bdd/mod.just").expect("read bdd module");
    let recipe = bdd_mod
        .split("\ndocs:\n")
        .nth(1)
        .expect("bdd module must define docs")
        .split("\n\n")
        .next()
        .expect("docs recipe has a body");

    assert!(recipe.contains("MVM_BDD_ONLY_TAG=docs"));
    // Selection goes through the harness so capability gates still apply.
    assert!(!recipe.contains("--tags"));
    assert!(recipe.contains("--test doc_rust_examples"));
    assert!(recipe.contains("cargo build --bin mvmctl --features user"));
    assert!(
        recipe.contains("scenarios? \\("),
        "the recipe must fail when the tag selects no scenario"
    );
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
fn tool_live_witness_checks_mediation_after_restart_and_audit_chain() {
    let feature =
        fs::read_to_string("features/suites/s8_readme_contract/persistent_machine_live.feature")
            .expect("read the persistent-machine live feature");

    assert!(feature.contains("@live @firecracker @tool_live"));
    assert!(
        feature.contains(
            "I run mvmctl in an isolated live home with \"machine create bdd-tool-command"
        )
    );
    for command in [
        "machine create bdd-tool-command --image alpine --policy",
        "machine exec bdd-tool-command --tool shell",
        "machine restart bdd-tool-command",
        "machine exec bdd-tool-command --tool unlisted",
        "trust audit tail --chain",
        "trust audit verify",
    ] {
        assert!(
            feature.contains(command),
            "the live tool witness must execute {command:?}"
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
