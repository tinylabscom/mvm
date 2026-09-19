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

/// Assert that a set of CLI arguments is parsed successfully (exit code != 2).
///
/// Exit code 2 is Clap's parse-error code.  A runtime failure (exit 1) is
/// acceptable in E2E tests running without a Lima VM present.
pub fn assert_parse_ok(args: &[&str]) {
    let assert = mvmctl().args(args).assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert_ne!(
        code,
        2,
        "Argument parsing failed for `mvmctl {}` (exit code {})",
        args.join(" "),
        code
    );
}
