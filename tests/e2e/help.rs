use super::harness::mvmctl;
use predicates::prelude::*;

#[test]
fn bootstrap_help_exits_successfully() {
    mvmctl()
        .args(["bootstrap", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Homebrew"));
}

#[test]
fn status_help_exits_successfully() {
    mvmctl()
        .args(["status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("status").or(predicate::str::contains("Lima")));
}

#[test]
fn cleanup_orphans_help_exits_successfully() {
    mvmctl()
        .args(["cleanup-orphans", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("orphan"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn uninstall_help_exits_successfully() {
    mvmctl()
        .args(["uninstall", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yes"))
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn top_level_help_lists_uninstall() {
    mvmctl()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("uninstall"));
}

#[test]
fn audit_tail_help_exits_successfully() {
    mvmctl()
        .args(["audit", "tail", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--lines"))
        .stdout(predicate::str::contains("--follow"));
}

#[test]
fn top_level_help_lists_audit() {
    mvmctl()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit"));
}
