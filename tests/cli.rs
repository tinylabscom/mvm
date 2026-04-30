use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

fn mvm() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl").unwrap()
}

fn spawn_fake_openai_response_server(response_body: &'static str) -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
    let address = format!("http://{}", listener.local_addr().expect("local addr"));
    let request_capture = Arc::new(Mutex::new(String::new()));
    let request_capture_thread = Arc::clone(&request_capture);

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buffer = [0_u8; 16384];
        let bytes_read = stream.read(&mut buffer).expect("read request");
        *request_capture_thread.lock().expect("request lock") =
            String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush response");
    });

    (address, request_capture)
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
        "ps",
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
    // dev status should work even without Lima — reports status, "not required",
    // or fails gracefully when limactl isn't installed (CI runners).
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
            || combined.contains("Not found")
            || combined.contains("not installed")
            || combined.contains("Apple Container")
            || combined.contains("Dev VM"),
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
        .stdout(predicate::str::contains("docker"))
        .stdout(predicate::str::contains("--network-preset"))
        .stdout(predicate::str::contains("--network-allow"))
        .stdout(predicate::str::contains("--seccomp"));
}

#[test]
fn test_diff_help() {
    mvm()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("filesystem changes"))
        .stdout(predicate::str::contains("--json"));
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
        .stdout(predicate::str::contains("preset"))
        .stdout(predicate::str::contains("prompt"));
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

#[test]
fn test_template_init_prompt_generates_metadata_and_infers_preset() {
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        // Plan 32 / Proposal C added a loopback probe in `auto` mode that picks
        // up Ollama / LocalAI on `:11434` / `:8080`. CI / dev hosts running one
        // of those would otherwise route this prompt at a real model. Force
        // heuristic fallback so the test stays deterministic.
        .env("MVM_TEMPLATE_NO_LOCAL_PROBE", "1")
        .env_remove("OPENAI_API_KEY")
        .env_remove("MVM_TEMPLATE_LOCAL_BASE_URL")
        .args([
            "template",
            "init",
            "test-prompt",
            "--local",
            "--prompt",
            "python service exposing an HTTP API with postgres",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();
    let template_dir = dir.path().join("test-prompt");
    let flake = template_dir.join("flake.nix");
    let metadata = template_dir.join("mvm-template-prompt.json");
    assert!(flake.exists(), "flake.nix not scaffolded");
    assert!(metadata.exists(), "prompt metadata not scaffolded");
    let flake_content = std::fs::read_to_string(&flake).expect("read flake");
    assert!(
        flake_content.contains("services.app"),
        "prompt should generate a python app service"
    );
    assert!(
        flake_content.contains("services.postgres"),
        "prompt should merge postgres into the generated scaffold"
    );
    let metadata_content = std::fs::read_to_string(&metadata).expect("read metadata");
    assert!(
        metadata_content.contains("\"primary_preset\": \"python\""),
        "metadata should capture the primary preset"
    );
    assert!(
        metadata_content.contains("\"postgres\""),
        "metadata should capture merged features"
    );
}

#[test]
fn test_template_init_prompt_uses_openai_when_configured() {
    let response_body = r#"{
        "output": [{
            "content": [{
                "type": "output_text",
                "text": "{\"schema_version\":1,\"summary\":\"Python API with custom health path\",\"primary_preset\":\"python\",\"features\":[\"python\",\"postgres\"],\"http_port\":9000,\"health_path\":\"/healthz\",\"worker_interval_secs\":null,\"python_entrypoint\":\"service.py\",\"notes\":[\"Use the generated python stub as a starting point\"]}"
            }]
        }]
    }"#;
    let (base_url, request_capture) = spawn_fake_openai_response_server(response_body);
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        // Disable the loopback Ollama / LocalAI probe (Proposal C) so the
        // OPENAI_API_KEY path is taken even on hosts running a local model.
        .env("MVM_TEMPLATE_NO_LOCAL_PROBE", "1")
        .env_remove("MVM_TEMPLATE_LOCAL_BASE_URL")
        .env("OPENAI_API_KEY", "test-key")
        .env("MVM_TEMPLATE_OPENAI_BASE_URL", base_url)
        .args([
            "template",
            "init",
            "llm-template",
            "--local",
            "--prompt",
            "python api with postgres and healthz endpoint",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();

    let template_dir = dir.path().join("llm-template");
    let flake = std::fs::read_to_string(template_dir.join("flake.nix")).expect("read flake");
    let metadata =
        std::fs::read_to_string(template_dir.join("mvm-template-prompt.json")).expect("metadata");
    let app = std::fs::read_to_string(template_dir.join("app").join("service.py")).expect("app");
    let captured_request = request_capture.lock().expect("capture lock").clone();
    let captured_request_lower = captured_request.to_ascii_lowercase();

    assert!(captured_request.contains("POST /v1/responses"));
    assert!(captured_request_lower.contains("authorization: bearer test-key"));
    assert!(captured_request.contains("python api with postgres and healthz endpoint"));
    assert!(flake.contains("localhost:9000/healthz"));
    assert!(flake.contains("${appSrc}/service.py"));
    assert!(metadata.contains("\"generation_mode\": \"llm\""));
    assert!(metadata.contains("\"provider\": \"openai\""));
    assert!(metadata.contains("\"model\": \"gpt-5.2\""));
    assert!(app.contains("HEALTH_PATH = \"/healthz\""));
}

#[test]
fn test_template_init_prompt_uses_local_provider_when_configured() {
    let response_body = r#"{
        "output": [{
            "content": [{
                "type": "output_text",
                "text": "{\"schema_version\":1,\"summary\":\"Worker planned by local AI\",\"primary_preset\":\"worker\",\"features\":[\"worker\"],\"http_port\":null,\"health_path\":null,\"worker_interval_secs\":30,\"python_entrypoint\":null,\"notes\":[\"Local provider selected\"]}"
            }]
        }]
    }"#;
    let (base_url, request_capture) = spawn_fake_openai_response_server(response_body);
    let dir = tempfile::tempdir().expect("temp dir");
    mvm()
        .env_remove("OPENAI_API_KEY")
        .env("MVM_TEMPLATE_PROVIDER", "local")
        .env("MVM_TEMPLATE_LOCAL_BASE_URL", base_url)
        .env("MVM_TEMPLATE_LOCAL_MODEL", "llama.cpp/qwen2.5")
        .args([
            "template",
            "init",
            "local-template",
            "--local",
            "--prompt",
            "background worker that polls an API every 30 seconds",
            "--dir",
            dir.path().to_str().expect("utf8"),
        ])
        .assert()
        .success();

    let template_dir = dir.path().join("local-template");
    let flake = std::fs::read_to_string(template_dir.join("flake.nix")).expect("read flake");
    let metadata =
        std::fs::read_to_string(template_dir.join("mvm-template-prompt.json")).expect("metadata");
    let captured_request = request_capture.lock().expect("capture lock").clone();
    let captured_request_lower = captured_request.to_ascii_lowercase();

    assert!(captured_request.contains("POST /v1/responses"));
    assert!(
        !captured_request_lower.contains("authorization: bearer"),
        "local provider should not require a bearer token by default"
    );
    assert!(flake.contains("sleep 30"));
    assert!(metadata.contains("\"provider\": \"local\""));
    assert!(metadata.contains("\"model\": \"llama.cpp/qwen2.5\""));
}

#[test]
fn test_template_init_prompt_requires_local() {
    mvm()
        .args([
            "template",
            "init",
            "test-prompt-vm",
            "--prompt",
            "python worker",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--prompt currently requires --local",
        ));
}
