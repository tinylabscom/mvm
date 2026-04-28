use super::harness::mvmctl;
use predicates::prelude::*;
use std::time::Duration;

/// `uninstall --dry-run --yes` should exit 0 and print what would be removed.
#[test]
fn uninstall_dry_run_exits_ok() {
    mvmctl()
        .args(["uninstall", "--dry-run", "--yes"])
        .assert()
        .success();
}

/// Dry-run output should mention the /var/lib/mvm state directory.
#[test]
fn uninstall_dry_run_mentions_state_dir() {
    mvmctl()
        .args(["uninstall", "--dry-run", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("/var/lib/mvm"));
}

/// `--all --dry-run --yes` should also mention ~/.mvm and the binary path.
#[test]
fn uninstall_all_dry_run_mentions_config_and_binary() {
    let assert = mvmctl()
        .args(["uninstall", "--all", "--dry-run", "--yes"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains(".mvm") || stdout.contains("config"),
        "dry-run --all should mention config dir, got: {stdout}"
    );
    assert!(
        stdout.contains("mvmctl") || stdout.contains("/usr/local/bin"),
        "dry-run --all should mention binary path, got: {stdout}"
    );
}

/// `uninstall` without `--yes` and without a tty should prompt (may fail
/// gracefully but must not crash with exit 2).
#[ignore]
#[test]
fn uninstall_no_yes_parses_ok() {
    let code = mvmctl()
        .timeout(Duration::from_secs(2))
        .args(["uninstall"])
        .assert()
        .get_output()
        .status
        .code()
        .unwrap_or(-1);
    assert_ne!(
        code, 2,
        "uninstall without --yes should not be a parse error"
    );
}
