/// Shared test helpers for E2E tests.
///
/// E2E tests spawn the actual `mvmctl` binary via `assert_cmd` and inspect
/// its stdout/stderr and exit codes.  They do NOT call library functions.
use assert_cmd::Command;

/// Returns an `assert_cmd::Command` targeting the workspace `mvmctl` binary.
pub fn mvmctl() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl").unwrap()
}
