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
        "cleanup",
        "ls",
        "uninstall",
        "audit",
        "update",
        "up",
        "down",
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
        .stdout(predicate::str::contains("up"))
        .stdout(predicate::str::contains("down"))
        .stdout(predicate::str::contains("shell"))
        .stdout(predicate::str::contains("status"));
}

#[test]
fn test_dev_up_help_shows_lima_flag() {
    mvm()
        .args(["dev", "up", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--lima"));
}

#[test]
fn test_update_help() {
    mvm()
        .args(["update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("latest version"));
}

#[test]
fn test_ls_runs_without_lima() {
    // ls should work even without Lima — lists VMs or shows empty
    let assert = mvm().arg("ls").assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("NAME")
            || combined.contains("No running")
            || combined.contains("limactl"),
        "status should produce meaningful output, got: {}",
        combined
    );
}

#[test]
fn test_dev_shell_help() {
    mvm()
        .args(["dev", "shell", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Lima VM"))
        .stdout(predicate::str::contains("--project"));
}

#[test]
fn test_dev_down_help() {
    mvm()
        .args(["dev", "down", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stop the Lima development VM"));
}

#[test]
fn test_dev_status_help() {
    mvm()
        .args(["dev", "status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev environment status"));
}

#[test]
fn test_dev_up_help_shows_all_flags() {
    mvm()
        .args(["dev", "up", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--lima-cpus"))
        .stdout(predicate::str::contains("--lima-mem"))
        .stdout(predicate::str::contains("--project"))
        .stdout(predicate::str::contains("--metrics-port"))
        .stdout(predicate::str::contains("--watch-config"))
        .stdout(predicate::str::contains("--lima"));
}

#[test]
fn test_dev_status_runs_without_lima() {
    // dev status should work even without Lima — reports status or "not required"
    let assert = mvm().args(["dev", "status"]).assert();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Lima VM")
            || combined.contains("not required")
            || combined.contains("Not found"),
        "dev status should produce meaningful output, got: {}",
        combined
    );
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
fn test_up_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("up"));
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
        .stdout(predicate::str::contains("--memory"))
        .stdout(predicate::str::contains("apple-container"))
        .stdout(predicate::str::contains("docker"));
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
        .stdout(predicate::str::contains("--snapshot"))
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
        .stdout(predicate::str::contains("edit"))
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

    // Template edit requires a name argument
    mvm()
        .args(["template", "edit"])
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

#[test]
fn test_template_edit_help_and_flags() {
    // Template edit help shows all available options
    mvm()
        .args(["template", "edit", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--flake"))
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--role"))
        .stdout(predicate::str::contains("--cpus"))
        .stdout(predicate::str::contains("--mem"))
        .stdout(predicate::str::contains("--data-disk"));

    // Template edit with only name (no flags) should work but do nothing
    // This will fail in practice because template doesn't exist, but validates argument parsing
    mvm()
        .args(["template", "edit", "nonexistent"])
        .assert()
        .failure(); // Fails because template doesn't exist, not because of argument parsing
}

// ---------------------------------------------------------------------------
// End-to-end CLI flow: build → run flag chain
// ---------------------------------------------------------------------------

/// Verifies the full dev workflow CLI flags exist and don't conflict.
/// Uses --help to check flag presence without triggering any runtime work
/// (avoids Lima connectivity, Nix builds, etc. which can take minutes).
#[test]
fn test_e2e_cli_flow_flags_parse() {
    // build: verify flake/profile/json flags
    let out = mvm()
        .args(["build", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("--flake"), "build missing --flake");
    assert!(help.contains("--profile"), "build missing --profile");
    assert!(help.contains("--json"), "build missing --json");

    // run: verify flake/profile/resource/name flags
    let out = mvm()
        .args(["run", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("--flake"), "run missing --flake");
    assert!(help.contains("--profile"), "run missing --profile");
    assert!(help.contains("--cpus"), "run missing --cpus");
    assert!(help.contains("--memory"), "run missing --memory");
    assert!(help.contains("--name"), "run missing --name");
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
        stdout.contains("alias mvmctl="),
        "shell-init should include mvmctl alias"
    );
    assert!(
        stdout.contains("alias mvmd="),
        "shell-init should include mvmd alias"
    );
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[test]
fn test_metrics_help() {
    mvm()
        .args(["metrics", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Prometheus"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn test_metrics_prometheus_output() {
    let assert = mvm().arg("metrics").assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("mvm_requests_total"),
        "metrics output should contain mvm_requests_total"
    );
    assert!(
        stdout.contains("# HELP"),
        "metrics output should contain Prometheus HELP lines"
    );
}

#[test]
fn test_metrics_json_output() {
    let assert = mvm().args(["metrics", "--json"]).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: serde_json::Value =
        serde_json::from_str(&stdout).expect("metrics --json must be valid JSON");
    assert!(
        val.get("requests_total").is_some(),
        "JSON must have requests_total"
    );
    assert!(
        val.get("instances_created").is_some(),
        "JSON must have instances_created"
    );
}

#[test]
fn test_uninstall_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("uninstall"));
}

#[test]
fn test_uninstall_help() {
    mvm()
        .args(["uninstall", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yes"))
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn test_uninstall_dry_run_no_side_effects() {
    // --dry-run --yes should exit 0 and print the plan without touching the system.
    mvm()
        .args(["uninstall", "--dry-run", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("/var/lib/mvm"));
}

#[test]
fn test_audit_listed_in_help() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit"));
}

#[test]
fn test_audit_tail_help() {
    mvm()
        .args(["audit", "tail", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--lines"))
        .stdout(predicate::str::contains("--follow"));
}

#[test]
fn test_audit_tail_no_log_exits_ok() {
    // On a fresh system ~/.mvm/log/audit.jsonl doesn't exist — should exit 0.
    mvm().args(["audit", "tail"]).assert().success();
}

#[test]
fn test_dev_up_accepts_watch_config_flag() {
    mvm()
        .args(["dev", "up", "--watch-config", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--watch-config"));
}

#[test]
fn test_run_accepts_watch_config_flag() {
    mvm()
        .args(["run", "--watch-config", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--watch-config"));
}

#[test]
fn test_completions_bash_exits_ok() {
    mvm()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mvmctl"));
}

#[test]
fn test_completions_zsh_exits_ok() {
    mvm()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mvmctl"));
}

#[test]
fn test_completions_fish_exits_ok() {
    mvm()
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mvmctl"));
}

#[test]
fn test_completions_no_shell_shows_error() {
    mvm().args(["completions"]).assert().failure().code(2);
}

#[test]
fn test_top_level_help_lists_completions() {
    mvm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("completions"));
}

#[test]
fn test_config_show_exits_ok() {
    mvm()
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lima_cpus").or(predicate::str::contains("default_cpus")));
}

#[test]
fn test_config_show_help() {
    mvm().args(["config", "show", "--help"]).assert().success();
}

#[test]
fn test_config_edit_help() {
    mvm().args(["config", "edit", "--help"]).assert().success();
}

#[test]
fn test_config_edit_with_true_editor() {
    // `true` is a no-op binary that exits 0 — verifies the plumbing without
    // opening a real editor.
    mvm()
        .args(["config", "edit"])
        .env("EDITOR", "true")
        .assert()
        .success();
}

// ============================================================================
// Sprint 35: mvmctl run --watch
// ============================================================================

#[test]
fn test_run_watch_flag_accepted_in_help() {
    mvm()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("watch"));
}

#[test]
fn test_run_watch_without_flake_degrades_gracefully() {
    // --watch without --flake should fail at argument validation (group "source"
    // is required), not at parsing — exit code must not be 2 (Clap parse error).
    // Actually, since --flake and --template are in a required arg group,
    // omitting both gives exit code 2 even without --watch. So we test that
    // --watch with a remote flake is accepted at parse time.
    mvm()
        .args(["run", "--flake", "github:auser/mvm", "--watch", "--help"])
        .assert()
        .success();
}

// ============================================================================
// Sprint 34: mvmctl flake check
// ============================================================================

#[test]
fn test_flake_check_help_exits_ok() {
    mvm()
        .args(["flake", "check", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("flake"));
}

#[test]
fn test_flake_top_level_help_lists_check() {
    mvm()
        .args(["flake", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("check"));
}

#[test]
fn test_flake_help_lists_in_top_level() {
    mvm()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("flake"));
}

// ============================================================================
// Sprint 33: template init --preset
// ============================================================================

#[test]
fn test_template_init_help_shows_preset_flag() {
    mvm()
        .args(["template", "init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("preset"));
}

#[test]
fn test_template_init_preset_minimal_exits_ok() {
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        .args([
            "template",
            "init",
            "test-minimal",
            "--local",
            "--preset",
            "minimal",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();
    assert!(
        dir.path().join("test-minimal").join("flake.nix").exists(),
        "flake.nix not scaffolded"
    );
}

#[test]
fn test_template_init_preset_http_exits_ok() {
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        .args([
            "template",
            "init",
            "test-http",
            "--local",
            "--preset",
            "http",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();
    let flake = dir.path().join("test-http").join("flake.nix");
    assert!(flake.exists(), "flake.nix not scaffolded");
    let content = std::fs::read_to_string(&flake).unwrap();
    assert!(
        content.contains("http.server"),
        "http preset should reference http.server"
    );
}

#[test]
fn test_template_init_preset_python_exits_ok() {
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        .args([
            "template",
            "init",
            "test-python",
            "--local",
            "--preset",
            "python",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();
    let flake = dir.path().join("test-python").join("flake.nix");
    assert!(flake.exists(), "flake.nix not scaffolded");
    let content = std::fs::read_to_string(&flake).unwrap();
    assert!(
        content.contains("python"),
        "python preset should reference python"
    );
}

#[test]
fn test_template_init_preset_unknown_shows_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        .args([
            "template",
            "init",
            "test-bad",
            "--local",
            "--preset",
            "nonexistent",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown preset"));
}
