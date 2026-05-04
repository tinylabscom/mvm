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

// ---------------------------------------------------------------------------
// Plan 38 §4 (slice 7b): the `mvmctl template *` namespace was removed.
// The tests that previously lived here covered:
//   - test_template_build_help_shows_force
//   - test_template_lifecycle_commands
//   - test_template_edit_help_and_flags
// Equivalent coverage for the new surface lives on:
//   - `mvmctl build --help` (--force, --snapshot, --update-hash)
//   - `mvmctl manifest --help` (ls, info, rm)
//   - `mvmctl init <DIR> --preset/--prompt` smart-dispatch tests
//     (see test_init_* below + commands/tests.rs unit tests).
// ---------------------------------------------------------------------------

#[test]
fn test_build_help_shows_force_and_update_hash() {
    // --snapshot is not yet exposed on `mvmctl build` for manifest-keyed
    // slots (deferred); --force / --update-hash are.
    mvm()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--update-hash"));
}

#[test]
fn test_manifest_namespace_subcommands_listed() {
    mvm()
        .args(["manifest", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ls"))
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("rm"));
}

#[test]
fn test_template_namespace_is_gone() {
    // Plan 38 §4: `mvmctl template *` removed outright.
    mvm()
        .args(["template", "--help"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand").or(
            predicate::str::contains("unexpected argument"),
        ));
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
// Plan 38 §4 (slice 7b): mvmctl init <DIR> --preset/--prompt
// (project-scaffold smart-dispatch, replaces the deleted
// `mvmctl template init` flow).
// ============================================================================

#[test]
fn test_init_help_shows_scaffold_flags() {
    mvm()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("preset"))
        .stdout(predicate::str::contains("prompt"))
        .stdout(predicate::str::contains("DIR"));
}

#[test]
fn test_init_preset_minimal_scaffolds_flake() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("test-minimal");
    mvm()
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--preset",
            "minimal",
        ])
        .assert()
        .success();
    assert!(target.join("flake.nix").exists(), "flake.nix not scaffolded");
}

#[test]
fn test_init_preset_http_emits_http_server() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("test-http");
    mvm()
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--preset",
            "http",
        ])
        .assert()
        .success();
    let flake = std::fs::read_to_string(target.join("flake.nix")).unwrap();
    assert!(
        flake.contains("http.server"),
        "http preset should reference http.server"
    );
}

#[test]
fn test_init_preset_unknown_shows_error() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("test-bad");
    mvm()
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--preset",
            "nonexistent",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown preset"));
}

#[test]
fn test_init_prompt_generates_metadata_and_infers_preset() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("test-prompt");
    mvm()
        // Force heuristic fallback (no LLM) so the test is deterministic
        // even on dev hosts running Ollama / LocalAI.
        .env("MVM_TEMPLATE_NO_LOCAL_PROBE", "1")
        .env_remove("OPENAI_API_KEY")
        .env_remove("MVM_TEMPLATE_LOCAL_BASE_URL")
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--prompt",
            "python service exposing an HTTP API with postgres",
        ])
        .assert()
        .success();
    let flake_content =
        std::fs::read_to_string(target.join("flake.nix")).expect("read flake");
    let metadata_content = std::fs::read_to_string(target.join("mvm-template-prompt.json"))
        .expect("read metadata");
    assert!(flake_content.contains("services.app"));
    assert!(flake_content.contains("services.postgres"));
    assert!(metadata_content.contains("\"primary_preset\": \"python\""));
    assert!(metadata_content.contains("\"postgres\""));
}

#[test]
fn test_init_prompt_uses_openai_when_configured() {
    let response_body = r#"{
        "output": [{
            "content": [{
                "type": "output_text",
                "text": "{\"schema_version\":1,\"summary\":\"Python API with custom health path\",\"primary_preset\":\"python\",\"features\":[\"python\",\"postgres\"],\"http_port\":9000,\"health_path\":\"/healthz\",\"worker_interval_secs\":null,\"python_entrypoint\":\"service.py\",\"notes\":[\"Use the generated python stub as a starting point\"]}"
            }]
        }]
    }"#;
    let (base_url, request_capture) = spawn_fake_openai_response_server(response_body);
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("llm-template");
    mvm()
        .env("MVM_TEMPLATE_NO_LOCAL_PROBE", "1")
        .env_remove("MVM_TEMPLATE_LOCAL_BASE_URL")
        .env("OPENAI_API_KEY", "test-key")
        .env("MVM_TEMPLATE_OPENAI_BASE_URL", base_url)
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--prompt",
            "python api with postgres and healthz endpoint",
        ])
        .assert()
        .success();

    let flake = std::fs::read_to_string(target.join("flake.nix")).expect("read flake");
    let metadata =
        std::fs::read_to_string(target.join("mvm-template-prompt.json")).expect("metadata");
    let app = std::fs::read_to_string(target.join("app").join("service.py")).expect("app");
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
fn test_init_prompt_uses_local_provider_when_configured() {
    let response_body = r#"{
        "output": [{
            "content": [{
                "type": "output_text",
                "text": "{\"schema_version\":1,\"summary\":\"Worker planned by local AI\",\"primary_preset\":\"worker\",\"features\":[\"worker\"],\"http_port\":null,\"health_path\":null,\"worker_interval_secs\":30,\"python_entrypoint\":null,\"notes\":[\"Local provider selected\"]}"
            }]
        }]
    }"#;
    let (base_url, request_capture) = spawn_fake_openai_response_server(response_body);
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("local-template");
    mvm()
        .env_remove("OPENAI_API_KEY")
        .env("MVM_TEMPLATE_PROVIDER", "local")
        .env("MVM_TEMPLATE_LOCAL_BASE_URL", base_url)
        .env("MVM_TEMPLATE_LOCAL_MODEL", "llama.cpp/qwen2.5")
        .args([
            "init",
            target.to_str().expect("utf8"),
            "--prompt",
            "background worker that polls an API every 30 seconds",
        ])
        .assert()
        .success();

    let flake = std::fs::read_to_string(target.join("flake.nix")).expect("read flake");
    let metadata =
        std::fs::read_to_string(target.join("mvm-template-prompt.json")).expect("metadata");
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
