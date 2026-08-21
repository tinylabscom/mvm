//! Regression checks for the aarch64 no-KVM smoke's binary build contract.

use std::fs;

const EXPECTED_BUILD: &str =
    "cargo build --release -p mvmctl --features user,release-artifact-bootstrap";
const LIBRARY_ONLY_BUILD: &str =
    "cargo build --release -p mvm-cli --features release-artifact-bootstrap";

#[test]
fn aarch64_no_kvm_smokes_build_the_mvmctl_binary_they_execute() {
    let workflow = fs::read_to_string(".github/workflows/ci.yml").expect("read CI workflow");
    let job = workflow
        .split("  aarch64-no-kvm-smoke:\n")
        .nth(1)
        .expect("CI workflow must define the aarch64 no-KVM smoke job");
    let script = fs::read_to_string("scripts/local-aarch64-no-kvm-smoke.sh")
        .expect("read local aarch64 no-KVM smoke script");

    for (source, contents) in [
        ("CI workflow", job),
        ("local smoke script", script.as_str()),
    ] {
        assert!(
            contents.contains(EXPECTED_BUILD),
            "{source} must build the root mvmctl package before executing target/release/mvmctl"
        );
        assert!(
            !contents.contains(LIBRARY_ONLY_BUILD),
            "{source} must not build only the mvm-cli library"
        );
    }
}
