//! Cross-language machine-verb conformance for the Rust SDK.
//!
//! `sdks/machine-fixtures/*.argv` is the shared golden contract for the argv
//! every SDK hands to `mvmctl machine`. The CLI parser round-trips these
//! fixtures (source of truth), and the Python (`_machine_*_argv`) and
//! TypeScript (`machine*Argv`) builders already assert against them. This test
//! makes the Rust builders (`MachineRunBuilder::machine_args` et al.) a
//! first-class participant in the same contract, so all three SDKs plus the CLI
//! provably emit byte-identical argv for the covered verbs.
//!
//! When you add a fixture case, add the matching assertion here (and in the
//! Python/TS conformance tests) — a fixture with no Rust assertion is a silent
//! coverage hole, exactly the drift this harness exists to catch.

use mvm_sdk::{MachineCheckArtifact, MachineCreate, MachineRun};

/// Read a shared SDK argv fixture, one argument per line. Mirrors the CLI's
/// `sdk_machine_fixture` and Python/TS `_fixture`/`readArgvFixture` helpers so
/// every language resolves the same file.
fn fixture(name: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdks/machine-fixtures")
        .join(format!("{name}.argv"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read shared machine fixture {}: {e}", path.display()))
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn run_default_matches_shared_fixture() {
    let argv = MachineRun::builder()
        .image("alpine:latest")
        .command(["true"])
        .json(true)
        .dry_run(true)
        .machine_args()
        .expect("run-default argv");
    assert_eq!(argv, fixture("run-default"));
}

#[test]
fn run_allow_host_receipt_matches_shared_fixture() {
    let argv = MachineRun::builder()
        .image("alpine:latest")
        .allow_host("api.example.com")
        .receipt("/tmp/mvm-sdk-machine.receipt.json")
        .json(true)
        .dry_run(true)
        .command(["true"])
        .machine_args()
        .expect("run-allow-host-receipt argv");
    assert_eq!(argv, fixture("run-allow-host-receipt"));
}

#[test]
fn run_admission_matches_shared_fixture() {
    // Env order is significant: the fixture lists TOKEN before MODE, so the
    // builder must preserve insertion order across all languages.
    let argv = MachineRun::builder()
        .image("alpine:latest")
        .allow_host("api.example.com")
        .cpus(4)
        .memory("1G")
        .profile("dev")
        .volume("/tmp/mvm-sdk-src:/workspace:ro")
        .env("TOKEN=secret")
        .env("MODE=test")
        .timeout(30)
        .receipt("/tmp/mvm-sdk-machine.receipt.json")
        .json(true)
        .dry_run(true)
        .command(["sh", "-lc", "echo ok"])
        .machine_args()
        .expect("run-admission argv");
    assert_eq!(argv, fixture("run-admission"));
}

#[test]
fn create_manifest_matches_shared_fixture() {
    let argv = MachineCreate::builder("web")
        .manifest("mvm.toml")
        .profile("dev")
        .force(true)
        .json(true)
        .machine_args()
        .expect("create-manifest argv");
    assert_eq!(argv, fixture("create-manifest"));
}

#[test]
fn check_artifact_matches_shared_fixture() {
    let argv = MachineCheckArtifact::builder("/tmp/app.mvm")
        .key("/tmp/app.pub")
        .json(true)
        .machine_args()
        .expect("check-artifact argv");
    assert_eq!(argv, fixture("check-artifact"));
}

/// Coverage manifest: the shared fixture directory and the Rust builder set are
/// audited against each other so neither drifts silently. Every `*.argv`
/// fixture must have a Rust assertion above (else the fixture is unenforced in
/// Rust), and this list documents which builders exist without a shared fixture
/// yet — the current cross-language coverage gap.
#[test]
fn fixture_coverage_is_accounted_for() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdks/machine-fixtures");
    let mut fixtures: Vec<String> = std::fs::read_dir(&dir)
        .expect("read machine-fixtures dir")
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension()? == "argv").then(|| p.file_stem()?.to_str().map(str::to_string))?
        })
        .collect();
    fixtures.sort();

    // Every fixture asserted by a test above. Adding a fixture without adding
    // its Rust assertion (and here) fails this test — the tripwire that keeps
    // Rust conformance complete.
    let asserted = [
        "check-artifact",
        "create-manifest",
        "run-admission",
        "run-allow-host-receipt",
        "run-default",
    ];
    assert_eq!(
        fixtures, asserted,
        "shared machine fixtures changed; add/remove the matching Rust assertion above"
    );

    // Rust builders with a pure `machine_args()` but no shared fixture yet.
    // These verbs' argv are NOT cross-language conformance-checked — closing
    // this gap means adding CLI-anchored fixtures for them (start/exec/shell/
    // stop) and matching assertions in every SDK.
    let uncovered_builders = ["start", "exec", "shell", "stop"];
    assert_eq!(uncovered_builders.len(), 4);
}
