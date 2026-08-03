//! `mvmctl` CLI flag contract tests — fast, no VM boot required.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

/// Regression guard: `--stdin` was removed from `machine run`; piped stdin is
/// auto-detected from the host TTY state at dispatch instead.
/// This test locks the public contract: the flag must not reappear in help.
#[test]
fn machine_run_help_has_no_stdin_flag() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "run", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "machine run --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !help.contains("--stdin"),
        "help still advertises --stdin:\n{help}"
    );
    assert!(
        help.contains("--entrypoint"),
        "help is missing --entrypoint (truncated or empty render):\n{help}"
    );
}

/// `prepare --help` parses and advertises `--dry-run`.
#[test]
fn prepare_help_lists_dry_run_flag() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["prepare", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prepare --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--dry-run"),
        "help is missing --dry-run:\n{help}"
    );
}

/// `prepare --dry-run` parses as a valid invocation (parse-only — this test
/// does not assert on the runtime-pack-cache-dependent output).
#[test]
fn prepare_dry_run_flag_parses() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["prepare", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prepare --dry-run must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn explain_help_lists_run_id_and_json() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["explain", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "explain --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("RUN_ID") || help.contains("run_id") || help.contains("<RUN_ID>"),
        "help is missing the run_id positional:\n{help}"
    );
    assert!(
        help.contains("--tenant"),
        "help is missing --tenant:\n{help}"
    );
    assert!(help.contains("--json"), "help is missing --json:\n{help}");
}

#[test]
fn explain_with_json_flag_parses() {
    // Parsing only — no audit chain is guaranteed to exist for "local"
    // on a fresh test host, so this asserts argument parsing succeeds
    // rather than a specific exit code.
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["explain", "someid", "--json"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unrecognized") && !stderr.contains("error: unexpected argument"),
        "explain someid --json must parse cleanly, stderr: {stderr}"
    );
}

/// `pack --help` advertises all five lifecycle subcommands.
#[test]
fn pack_help_lists_all_subcommands() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["pack", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pack --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for verb in ["list", "rollback", "prune", "download", "update"] {
        assert!(help.contains(verb), "help is missing '{verb}':\n{help}");
    }
}

/// `pack list --json` parses and exits cleanly on a fresh/empty pack cache.
#[test]
fn pack_list_json_parses_cleanly() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["pack", "list", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pack list --json must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("pack list --json must emit valid JSON");
}

#[test]
fn machine_reconfigure_help_lists_patch_flags() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "reconfigure", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "machine reconfigure --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for flag in [
        "--net",
        "--no-net",
        "--allow-host",
        "--cpus",
        "--memory",
        "--mem-initial",
    ] {
        assert!(text.contains(flag), "help missing {flag}");
    }
}

/// Reading a machine's captured console is a host-side operation. It must not
/// depend on the Linux builder/dev VM being available on macOS.
#[test]
fn machine_logs_reads_host_state_without_dev_vm() {
    let mvm_home = tempfile::tempdir().unwrap();
    let state_dir = mvm_core::config::vm_state_dir_at(mvm_home.path(), "log-test");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("console.log"),
        "old line\nrecent line one\nrecent line two\n",
    )
    .unwrap();
    // Reconcile-on-entry preserves only state owned by a live supervisor.
    std::fs::write(state_dir.join("hvf.pid"), std::process::id().to_string()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["machine", "logs", "log-test", "--lines", "2"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "machine logs must read host state; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "recent line one\nrecent line two"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("dev VM"),
        "machine logs must not try to start or connect to a dev VM"
    );
}

/// Regression guard: the `ops bench` verb was removed — benchmarking is a
/// dev/CI concern, not a shipped end-user command.
#[test]
fn ops_help_no_longer_lists_bench() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["ops", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("bench"),
        "ops help still lists the removed bench verb:\n{text}"
    );
}

/// `machine warm-restore --help` advertises the expected usage.
#[test]
fn machine_warm_restore_help_lists_args() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "warm-restore", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "machine warm-restore --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("warm-restore"));
    assert!(help.contains("CHECKPOINT_ID"));
    assert!(help.contains("--name"));
    assert!(help.contains("--json"));
}

/// A non-existent checkpoint id fails gracefully rather than panicking.
#[test]
fn machine_warm_restore_rejects_missing_checkpoint() {
    let tmp = std::env::temp_dir().join(format!("mvm-warm-restore-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", &tmp)
        .env("MVM_HOME", &tmp)
        .args(["machine", "warm-restore", "no-such-checkpoint"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "warm-restore must fail for a missing checkpoint; stderr: {stderr}"
    );
    assert!(!stderr.contains("panic"), "warm-restore panicked: {stderr}");
    assert!(
        !stderr.contains("thread panicked"),
        "warm-restore panicked: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The `--json` output flag is accepted by the parser.
#[test]
fn machine_warm_restore_json_flag_parses() {
    let tmp =
        std::env::temp_dir().join(format!("mvm-warm-restore-json-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", &tmp)
        .env("MVM_HOME", &tmp)
        .args(["machine", "warm-restore", "no-such-checkpoint", "--json"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
        "--json must parse cleanly, stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
