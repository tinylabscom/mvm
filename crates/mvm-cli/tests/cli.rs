//! `mvmctl` CLI flag contract tests — fast, no VM boot required.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

/// The `--stdin` flag was removed from `machine run`; piped stdin is
/// auto-detected from the host pipe at dispatch instead.
///
/// Verify two properties:
///   1. `machine run --help` does not list `--stdin` as a recognised option.
///   2. When `--stdin` is passed as a CLI argument the command exits non-zero
///      (the flag is absorbed into argv by trailing_var_arg and the shell
///      rejects the resulting command — it is not silently accepted as a
///      valid machine-run option).
#[test]
fn machine_run_rejects_removed_stdin_flag() {
    // Property 1: --stdin absent from help.
    #[allow(deprecated)]
    let help_out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "run", "--help"])
        .output()
        .unwrap();
    let help_stdout = String::from_utf8_lossy(&help_out.stdout);
    assert!(
        help_out.status.success(),
        "machine run --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&help_out.stderr)
    );
    assert!(
        !help_stdout.contains("--stdin"),
        "machine run --help must not list --stdin (flag was removed); got:\n{help_stdout}"
    );

    // Property 2: passing --stdin results in a non-zero exit.
    #[allow(deprecated)]
    let run_out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args([
            "machine", "run", "--image", "alpine", "--stdin", "-", "--", "/bin/cat",
        ])
        .output()
        .unwrap();
    assert!(
        !run_out.status.success(),
        "machine run with --stdin should exit non-zero; \
         the flag was removed and must not be silently accepted as a valid option"
    );
}
