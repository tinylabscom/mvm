//! CLI surface tests for `mvmctl reconcile` (Plan 169 WS-A).

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn mvmctl")
}

#[test]
fn reconcile_help_lists_dry_run_and_json_flags() {
    let out = mvmctl(&["reconcile", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("--dry-run"),
        "`mvmctl reconcile --help` missing --dry-run; got:\n{stdout}"
    );
    assert!(
        stdout.contains("--json"),
        "`mvmctl reconcile --help` missing --json; got:\n{stdout}"
    );
}

#[test]
fn reconcile_appears_in_top_level_help() {
    let out = mvmctl(&["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("reconcile"),
        "top-level help missing `reconcile`; got:\n{stdout}"
    );
}

#[test]
fn reconcile_rejects_unknown_flag() {
    let out = mvmctl(&["reconcile", "--bogus"]);
    assert!(
        !out.status.success(),
        "unknown flag must be a clap parse error"
    );
}

#[test]
fn reconcile_dry_run_json_runs_against_isolated_dirs() {
    // Point all state at throwaway dirs so the run can't touch the host's
    // real registry. Dry-run + empty registry → clean, valid JSON report.
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = |s: &str| tmp.path().join(s).to_string_lossy().into_owned();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(["reconcile", "--dry-run", "--json"])
        .env("MVM_SHARE_DIR", p("share"))
        .env("MVM_DATA_DIR", p("data"))
        .env("MVM_STATE_DIR", p("state"))
        .output()
        .expect("spawn mvmctl");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}"));
    // The ConvergeReport shape: arrays for each classification bucket.
    assert!(parsed.get("dead_process_reaped").is_some(), "got: {parsed}");
    assert!(parsed.get("stale_record_dropped").is_some(), "got: {parsed}");
    assert!(parsed.get("orphan_state_reaped").is_some(), "got: {parsed}");
}
