//! Regression checks for the CI gate that compiles workspace-excluded fuzz crates.

/// `ci-full.yml` used to be the second entry here. It was deleted after
/// running zero times since it was written: a gate that lives only in a
/// workflow nobody triggers is not a gate, and asserting on its text made
/// it look like one.
const WORKFLOWS: [&str; 1] = [include_str!("../.github/workflows/ci.yml")];

#[test]
fn fuzz_compile_gates_use_committed_lockfiles() {
    for workflow in WORKFLOWS {
        let step = workflow
            .split("- name: cargo-fuzz crates still compile")
            .nth(1)
            .expect("workflow must compile workspace-excluded fuzz crates");
        let command = step
            .lines()
            .find(|line| line.contains("cargo check ") && line.contains("--manifest-path"))
            .expect("fuzz compile step must contain cargo check");

        assert!(
            command.contains("--locked"),
            "fuzz compile gate must reject stale lockfiles: {command}"
        );
    }
}

#[test]
fn pull_request_fuzz_detection_compares_the_fetched_trees() {
    let workflow = WORKFLOWS[0];
    let step = workflow
        .split("- name: Detect fuzz-crate changes")
        .nth(1)
        .expect("pull-request workflow must detect fuzz-crate changes");
    let command = step
        .lines()
        .find(|line| line.contains("git diff --name-only"))
        .expect("fuzz change detector must compare the base and head trees");

    assert!(
        command.contains("\"$BASE_SHA\" HEAD"),
        "depth-one checkouts must compare trees without finding a merge base: {command}"
    );
}
