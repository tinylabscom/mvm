//! Regression checks for the CI gate that compiles workspace-excluded fuzz crates.

const WORKFLOWS: [&str; 2] = [
    include_str!("../.github/workflows/ci.yml"),
    include_str!("../.github/workflows/ci-full.yml"),
];

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
