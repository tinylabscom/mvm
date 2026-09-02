//! Steps driving `mvmctl build address` over the workload-identity fixtures.
//!
//! Each `When` runs the real binary against a fixture and records the raw
//! `Output` (so failing-exit scenarios can still assert). On a zero exit it
//! parses the `--json` report and stashes the workload address + ir-hash by
//! fixture name, which the `Then` steps compare.

use std::path::PathBuf;

use cucumber::{then, when};

use crate::steps::cli::mvmctl_command;
use crate::world::CliWorld;

/// Absolute path to a fixture under this suite, resolved from the crate
/// manifest dir (two levels below the repo-root `features/` tree) so the run
/// is independent of the process working directory.
fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("features")
        .join("suites")
        .join("s7_workload_identity")
        .join("fixtures")
        .join(name)
}

#[when(expr = "I compute the workload address of fixture {string}")]
fn compute_address(world: &mut CliWorld, fixture: String) {
    let path = fixture_path(&fixture);
    let mut cmd = mvmctl_command();
    let output = cmd
        .args(["build", "address", "--from-ir"])
        .arg(&path)
        .arg("--json")
        .output()
        .expect("failed to spawn mvmctl");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("build address --json did not emit valid JSON ({e}); stdout:\n{stdout}")
        });
        let addr = report["workload_address"]
            .as_str()
            .expect("report carries a string workload_address")
            .to_string();
        let ih = report["ir_hash"]
            .as_str()
            .expect("report carries a string ir_hash")
            .to_string();
        world.addresses.insert(fixture.clone(), addr);
        world.ir_hashes.insert(fixture.clone(), ih);
    }
    world.last_run = Some(output);
}

#[then(expr = "the workload address of {string} equals {string}")]
fn address_equals(world: &mut CliWorld, a: String, b: String) {
    assert_eq!(
        world.address_of(&a),
        world.address_of(&b),
        "expected {a:?} and {b:?} to share a workload address"
    );
}

#[then(expr = "the workload address of {string} differs from {string}")]
fn address_differs(world: &mut CliWorld, a: String, b: String) {
    assert_ne!(
        world.address_of(&a),
        world.address_of(&b),
        "expected {a:?} and {b:?} to have different workload addresses"
    );
}

#[then(expr = "the workload address of {string} matches its ir-hash")]
fn workload_address_matches_ir_hash(world: &mut CliWorld, fixture: String) {
    let addr = world.address_of(&fixture);
    let ih = world
        .ir_hashes
        .get(&fixture)
        .unwrap_or_else(|| panic!("no ir-hash recorded for {fixture:?}"));
    assert_eq!(
        addr.strip_prefix("sha256:"),
        Some(ih.as_str()),
        "workload address {addr:?} must be sha256: + ir-hash {ih:?}"
    );
}
