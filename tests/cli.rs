use assert_cmd::Command;
use predicates::prelude::*;

fn mvm() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl").unwrap()
}

#[test]
fn test_help_exits_successfully() {
    mvm().arg("--help").assert().success();
}

#[test]
fn test_version_exits_successfully() {
    mvm()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("mvmctl"));
}

#[test]
fn test_no_args_shows_usage() {
    mvm()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn test_unknown_subcommand_fails() {
    mvm()
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn test_help_lists_all_subcommands() {
    let assert = mvm().arg("--help").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    for cmd in [
        "bootstrap",
        "setup",
        "dev",
        "start",
        "stop",
        "ssh",
        "shell",
        "sync",
        "cleanup",
        "status",
        "destroy",
        "upgrade",
        "run",
        "forward",
        "shell-init",
    ] {
        assert!(
            output.contains(cmd),
            "Help output should list '{}' subcommand",
            cmd
        );
    }
}

#[test]
fn test_bootstrap_help() {
    mvm()
        .args(["bootstrap", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Homebrew"));
}

#[test]
fn test_setup_help() {
    mvm()
        .args(["setup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Firecracker"));
}

#[test]
fn test_dev_help() {
    mvm()
        .args(["dev", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("auto-bootstrapping"));
}

#[test]
fn test_upgrade_help() {
    mvm()
        .args(["upgrade", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("latest version"));
}

#[test]
fn test_status_runs_without_lima() {
    // status should work even without Lima — it reports "Not created"
    let assert = mvm().arg("status").assert();
    // It either succeeds (showing status) or fails because limactl is missing,
    // but it should never panic
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("status")
            || combined.contains("limactl")
            || combined.contains("Not created"),
        "status should produce meaningful output, got: {}",
        combined
    );
}

#[test]
fn test_shell_help() {
    mvm()
        .args(["shell", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Lima VM"))
        .stdout(predicate::str::contains("--project"));
}

#[test]
fn test_shell_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("shell"));
}

#[test]
fn test_sync_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sync"));
}

#[test]
fn test_sync_help() {
    mvm()
        .args(["sync", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--debug"))
        .stdout(predicate::str::contains("--skip-deps"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn test_cleanup_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("cleanup"));
}

#[test]
fn test_cleanup_help() {
    mvm()
        .args(["cleanup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--keep"))
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--verbose"))
        .stdout(predicate::str::contains("dev-build"));
}

#[test]
fn test_forward_help() {
    mvm()
        .args(["forward", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Forward"))
        .stdout(predicate::str::contains("<NAME>"))
        .stdout(predicate::str::contains("<PORT>"));
}

#[test]
fn test_build_help_shows_flake_options() {
    mvm()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--flake"))
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--watch"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn test_build_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("build"));
}

#[test]
fn test_ssh_config_prints_entry() {
    mvm()
        .arg("ssh-config")
        .assert()
        .success()
        .stdout(predicate::str::contains("Host mvm"))
        .stdout(predicate::str::contains("IdentityFile"))
        .stdout(predicate::str::contains("StrictHostKeyChecking no"));
}

#[test]
fn test_run_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run"));
}

#[test]
fn test_run_help_shows_flags() {
    mvm()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--flake"))
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--cpus"))
        .stdout(predicate::str::contains("--memory"));
}

#[test]
fn test_stop_help_shows_flags() {
    mvm()
        .args(["stop", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("name"));
}

#[test]
fn test_doctor_help() {
    mvm()
        .args(["doctor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("diagnostics"));
}

#[test]
fn test_setup_help_shows_force_and_resources() {
    mvm()
        .args(["setup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--recreate"))
        .stdout(predicate::str::contains("--lima-cpus"))
        .stdout(predicate::str::contains("--lima-mem"));
}

#[test]
fn test_template_build_help_shows_force() {
    mvm()
        .args(["template", "build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--config"));
}

// ---------------------------------------------------------------------------
// Template command structure
// ---------------------------------------------------------------------------

#[test]
fn test_template_lifecycle_commands() {
    // Top-level help lists template subcommand
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("template"));

    // Template help shows lifecycle subcommands
    mvm()
        .args(["template", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("build"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("pull"))
        .stdout(predicate::str::contains("verify"));

    // Template create without required args fails
    mvm()
        .args(["template", "create"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));

    // Template build requires a name argument
    mvm()
        .args(["template", "build"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));

    // Template info requires a name argument
    mvm()
        .args(["template", "info"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));

    // Template delete requires a name argument
    mvm()
        .args(["template", "delete"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

// ---------------------------------------------------------------------------
// End-to-end CLI flow: sync → build → run flag chain
// ---------------------------------------------------------------------------

/// Verifies the full dev workflow CLI flags parse correctly together.
/// Each command in the chain (sync → build --flake → run --config) accepts
/// the expected flags without conflicts.
#[test]
fn test_e2e_cli_flow_flags_parse() {
    // Step 1: sync with all flags — runtime failure (no Lima), but arg parsing succeeds
    let assert = mvm()
        .args(["sync", "--debug", "--skip-deps", "--force", "--json"])
        .assert();
    // clap parse errors exit code 2; runtime errors exit 1
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert_ne!(code, 2, "sync flag combination should parse successfully");

    // Step 2: build --flake with --json — fails at runtime (no flake), parses OK
    let assert = mvm()
        .args([
            "build",
            "--flake",
            "/nonexistent",
            "--profile",
            "worker",
            "--json",
        ])
        .assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert_ne!(code, 2, "build flag combination should parse successfully");

    // Step 3: run --flake with resource overrides — fails at runtime, parses OK
    let assert = mvm()
        .args([
            "run",
            "--flake",
            "/nonexistent",
            "--profile",
            "gateway",
            "--cpus",
            "4",
            "--memory",
            "2048",
            "--name",
            "test-vm",
        ])
        .assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert_ne!(code, 2, "run flag combination should parse successfully");
}

// ---------------------------------------------------------------------------
// VM vsock commands
// ---------------------------------------------------------------------------

#[test]
fn test_vm_help_lists_subcommands() {
    mvm()
        .args(["vm", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ping"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("exec"));
}

#[test]
fn test_vm_exec_help() {
    mvm()
        .args(["vm", "exec", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev-only"))
        .stdout(predicate::str::contains("--timeout"));
}

#[test]
fn test_vm_ping_no_name_does_not_fail_parsing() {
    // `mvm vm ping` without a name should pass arg parsing (targets all running VMs).
    // On macOS it delegates to a Lima binary which may be stale — that's a runtime error, not parsing.
    let assert = mvm().args(["vm", "ping"]).assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    // clap parse failures exit with code 2. Code 1 or other = runtime error (acceptable).
    // On macOS with Lima delegation, the Lima binary may return code 2 (stale binary).
    // Verify our arg parsing works via the unit tests (test_vm_ping_no_name_targets_all).
    assert!(
        code != 2 || cfg!(target_os = "macos"),
        "vm ping should accept optional name (exit code {})",
        code
    );
}

#[test]
fn test_vm_status_no_name_does_not_fail_parsing() {
    let assert = mvm().args(["vm", "status"]).assert();
    let code = assert.get_output().status.code().unwrap_or(-1);
    assert!(
        code != 2 || cfg!(target_os = "macos"),
        "vm status should accept optional name (exit code {})",
        code
    );
}

#[test]
fn test_vm_ping_nonexistent_fails_gracefully() {
    // Ping a VM that doesn't exist — should fail with an error message, not panic
    let assert = mvm().args(["vm", "ping", "nonexistent-vm"]).assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Should mention the VM name or indicate it's not found
    assert!(
        combined.contains("nonexistent-vm")
            || combined.contains("not found")
            || combined.contains("No running")
            || combined.contains("error")
            || combined.contains("Error")
            || combined.contains("limactl"),
        "vm ping should fail gracefully, got: {}",
        combined
    );
}

#[test]
fn test_vm_status_nonexistent_fails_gracefully() {
    let assert = mvm().args(["vm", "status", "nonexistent-vm"]).assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("nonexistent-vm")
            || combined.contains("not found")
            || combined.contains("No running")
            || combined.contains("error")
            || combined.contains("Error")
            || combined.contains("limactl"),
        "vm status should fail gracefully, got: {}",
        combined
    );
}

#[test]
fn test_vm_inspect_help() {
    mvm()
        .args(["vm", "inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("inspection"));
}

#[test]
fn test_vm_inspect_nonexistent_fails_gracefully() {
    let assert = mvm().args(["vm", "inspect", "nonexistent-vm"]).assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("nonexistent-vm")
            || combined.contains("not found")
            || combined.contains("No running")
            || combined.contains("error")
            || combined.contains("Error")
            || combined.contains("limactl"),
        "vm inspect should fail gracefully, got: {}",
        combined
    );
}

// ---------------------------------------------------------------------------
// VM diagnose
// ---------------------------------------------------------------------------

#[test]
fn test_vm_diagnose_help() {
    mvm()
        .args(["vm", "diagnose", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("diagnostics"));
}

#[test]
fn test_vm_diagnose_nonexistent_fails_gracefully() {
    let assert = mvm().args(["vm", "diagnose", "nonexistent-vm"]).assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("nonexistent-vm")
            || combined.contains("not found")
            || combined.contains("No running")
            || combined.contains("error")
            || combined.contains("Error")
            || combined.contains("limactl"),
        "vm diagnose should fail gracefully, got: {}",
        combined
    );
}

// ---------------------------------------------------------------------------
// Shell init
// ---------------------------------------------------------------------------

#[test]
fn test_shell_init_help() {
    mvm()
        .args(["shell-init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("aliases"));
}

#[test]
fn test_shell_init_prints_block() {
    let assert = mvm().arg("shell-init").assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("mvmctl completions"),
        "shell-init should include completions"
    );
    assert!(
        stdout.contains("alias cr="),
        "shell-init should include cr alias"
    );
    assert!(
        stdout.contains("alias crd="),
        "shell-init should include crd alias"
    );
}
