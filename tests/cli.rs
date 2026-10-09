//! `mvmctl` CLI flag contract tests — fast, no VM boot required.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

#[test]
fn build_compile_help_advertises_pinned_publication_input() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["build", "compile", "--help"])
        .output()
        .expect("run build compile help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--mvm-revision"), "{stdout}");
    assert!(stdout.contains("COMMIT"), "{stdout}");
}

#[test]
fn build_compile_rejects_invalid_pin_before_reading_source() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args([
            "build",
            "compile",
            "/does/not/exist.py",
            "--mvm-revision",
            "main",
        ])
        .output()
        .expect("run build compile with invalid revision");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("40-character hexadecimal"), "{stderr}");
    assert!(!stderr.contains("does/not/exist.py"), "{stderr}");
}

#[test]
fn machine_workspace_apply_verbs_are_discoverable() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["machine", "--help"])
        .output()
        .expect("run machine help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in ["apply", "undo", "redo"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(verb)),
            "machine help missing {verb}: {stdout}"
        );
    }
}

#[test]
fn artifact_pack_takes_the_arguments_of_bundle_export() {
    let help = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .args(args)
            .output()
            .expect("run help");
        assert!(out.status.success(), "{args:?} --help failed");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let pack = help(&["artifact", "pack", "--help"]);
    let export = help(&["bundle", "export", "--help"]);
    for flag in [
        "<TEMPLATE>",
        "--out",
        "--cmdline",
        "--posture",
        "--allow-egress",
        "--allow-volumes",
        "--allow-unauthenticated",
    ] {
        assert!(
            pack.contains(flag),
            "artifact pack help missing {flag}: {pack}"
        );
        assert!(
            export.contains(flag),
            "bundle export help missing {flag}: {export}"
        );
    }
    assert!(pack.contains("Alias of `mvmctl bundle export`"), "{pack}");
}

#[test]
fn bundle_export_refuses_an_allow_flag_without_a_posture() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args([
            "bundle",
            "export",
            "tmpl",
            "--out",
            "/tmp/never.mvmpkg",
            "--allow-egress",
        ])
        .output()
        .expect("run bundle export");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--posture"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn machine_check_artifact_help_names_bundle_verification_controls() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["machine", "check-artifact", "--help"])
        .output()
        .expect("run machine check-artifact help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for expected in [".mvmpkg", "--trust-store", "--backend"] {
        assert!(
            stdout.contains(expected),
            "help missing {expected}: {stdout}"
        );
    }
}

/// `mvmctl <argv>`'s stdout with runs of whitespace collapsed to one space.
fn help_text(argv: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(argv)
        .output()
        .expect("run mvmctl help");
    assert!(
        out.status.success(),
        "help must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `build guest-bins` produces mvmctl's guest-runtime archive; its help names
/// the output directory, the per-architecture selector, and whose archive it
/// is, and its long help says mvm-images is not a consumer.
#[test]
fn build_guest_bins_help_names_output_and_arch_controls() {
    let short = help_text(&["build", "guest-bins", "--help"]);
    for expected in [
        "--out",
        "--arch",
        "mvm-guest-bins-v",
        "mvmctl's guest-runtime archive",
    ] {
        assert!(short.contains(expected), "help missing {expected}: {short}");
    }
    let long = help_text(&["help", "build", "guest-bins"]);
    assert!(
        long.contains("Its consumer is mvmctl; mvm-images does not consume it"),
        "{long}"
    );
}

/// An unknown architecture is a parse error, not a silent fallback to the
/// host's: a published artifact must carry exactly what was asked for.
#[test]
fn build_guest_bins_rejects_an_unknown_arch() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["build", "guest-bins", "--arch", "riscv64"])
        .output()
        .expect("run build guest-bins with a bad arch");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("riscv64"),
        "the refusal names the bad value: {stderr}"
    );
}

#[test]
fn ops_mcp_help_advertises_the_stdio_transport() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["ops", "mcp", "--help"])
        .output()
        .expect("run mvmctl ops mcp --help");
    assert!(
        out.status.success(),
        "mcp help must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("stdio"));
}

/// The README's persistent-machine form uses a positional name. Creating the
/// spec is host-only and must succeed without booting or contacting a VM.
#[test]
fn machine_create_readme_form_persists_the_named_spec() {
    let mvm_home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "machine", "create", "web", "--image", "nginx", "--cpus", "2", "--memory", "512M",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "README machine create command must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let spec: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("machine create --json emits a machine spec");
    assert_eq!(spec["name"], "web");
    assert_eq!(spec["image"], "nginx");
    assert_eq!(spec["cpus"], 2);
    assert_eq!(spec["memory"], "512M");
}

/// `deployments ls` inventories the local-first deploy store
/// (`<mvm_home>/deployments/<ir-hash>/deploy.json`) without contacting a
/// control plane, and `--workload` filters to one workload.
#[test]
fn deployments_ls_inventories_local_deploy_store() {
    let mvm_home = tempfile::tempdir().unwrap();
    let record_dir = mvm_home.path().join("deployments").join("aaaa");
    std::fs::create_dir_all(&record_dir).unwrap();
    let hex64 = "ab".repeat(32);
    std::fs::write(
        record_dir.join("deploy.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "workload_id": "wl-a",
            "ir_hash": "aaaa",
            "image": {"blake3": hex64, "sha256": hex64, "size_bytes": 3},
            "boot_artifact": {
                "kind": "rootfs.ext4",
                "blake3": hex64,
                "sha256": hex64,
                "size_bytes": 1
            },
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["deployments", "ls", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "deployments ls must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("ls --json emits rows");
    assert_eq!(rows.as_array().expect("rows").len(), 1);
    assert_eq!(rows[0]["workload_id"], "wl-a");
    assert_eq!(rows[0]["ir_hash"], "aaaa");

    let filtered = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["deployments", "ls", "--workload", "wl-missing", "--json"])
        .output()
        .unwrap();
    assert!(filtered.status.success());
    let rows: serde_json::Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(rows.as_array().expect("rows").len(), 0);
}

/// Regression guard on how `machine run` takes stdin.
///
/// This previously asserted `--stdin` must never appear, because piped stdin
/// is auto-detected from the host TTY state and a flag that only re-stated
/// that was noise. Auto-detection is unchanged and still the default — omit
/// the flag and a pipe is read to the end and sent as one payload.
///
/// The flag is back for the one request auto-detection cannot serve.
/// Streaming stdin into a running workload needs `host.stream.v1` on the
/// signed plan, and a grant inferred from "stdin happens to be a pipe" would
/// not be a grant at all — it would make the input plane's default-deny turn
/// on the shape of the caller's shell. So the property worth locking is not
/// the flag's absence but that the cheap path stayed cheap: streaming is
/// requested explicitly, and everything else still needs no flag.
#[test]
fn machine_run_stdin_is_auto_detected_and_streaming_is_explicit() {
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
        help.contains("--stdin"),
        "help must advertise --stdin, which is how streaming is requested:\n{help}"
    );
    assert!(
        help.contains("`-` to stream yours"),
        "the summary must say `-` is the streaming form, since that is the \
         only thing the flag exists to request:\n{help}"
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
    assert!(
        help.contains("egress refusals"),
        "help does not say explain reports egress refusals:\n{help}"
    );
}

/// Following a machine's output is where its egress refusals appear live, so
/// the flag that does it says so.
#[test]
fn machine_logs_follow_help_mentions_egress_refusals() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "logs", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("Follow output and egress refusals live"),
        "`machine logs --help` does not say --follow shows egress refusals:\n{help}"
    );
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

#[test]
fn why_help_lists_every_query_and_policy_source() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["why", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--host",
        "--method",
        "--request-path",
        "--path",
        "--tool",
        "--secret",
        "--profile",
        "--plan",
        "--project",
        "--json",
    ] {
        assert!(help.contains(flag), "why help is missing {flag}:\n{help}");
    }
}

#[test]
fn machine_exec_help_lists_declared_tool_option() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["machine", "exec", "--help"])
        .output()
        .expect("machine exec help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--tool"), "machine exec help: {help}");
}

#[test]
fn why_empty_project_answers_default_deny_as_json_without_booting() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_HOME", home.path())
        .env("HOME", home.path())
        .args([
            "why",
            "--host",
            "api.example.com",
            "--project",
            project.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "why must not boot or need runtime state: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(answer["allowed"], false);
    assert_eq!(answer["subject"], "host");
    assert_eq!(answer["value"], "api.example.com:443");
}

#[test]
fn why_discovers_the_project_policy_from_a_nested_directory() {
    let project = tempfile::tempdir().unwrap();
    let nested = project.path().join("src/nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        project.path().join("mvm.toml"),
        "[network]\nallow_hosts = [\"api.example.com:443\"]\n",
    )
    .unwrap();
    let home = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .current_dir(&nested)
        .env("MVM_HOME", home.path())
        .env("HOME", home.path())
        .args(["why", "--host", "api.example.com", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "why must resolve the containing project: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(answer["allowed"], true);
    assert_eq!(answer["matched"], "network.allow = \"api.example.com:443\"");
}

#[test]
fn why_routed_host_requires_request_context_and_reports_the_matching_rule() {
    let dir = tempfile::tempdir().unwrap();
    let plan = dir.path().join("resolved.json");
    std::fs::write(
        &plan,
        r#"{"policy":{"network":{"allow":["api.example.com:443"],"routes":[{"id":"api","host":"api.example.com","rules":[{"id":"read","method":"GET","path":"/public/**","outcome":"allow"}],"otherwise":"deny","intercept":true}]}}}"#,
    )
    .unwrap();
    let query = |extra: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mvmctl"));
        command
            .env("MVM_HOME", dir.path())
            .env("HOME", dir.path())
            .args(["why", "--host", "api.example.com", "--plan"])
            .arg(&plan);
        command.args(extra).arg("--json");
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_eq!(query(&[])["allowed"], false);
    let allowed = query(&["--method", "GET", "--request-path", "/public/x"]);
    assert_eq!(allowed["allowed"], true);
    assert_eq!(allowed["matched"], "network.routes.api.read");
    assert_eq!(
        query(&["--method", "POST", "--request-path", "/public/x"])["allowed"],
        false
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
    for verb in [
        "ls", "rm", "system", "list", "rollback", "prune", "download", "update",
    ] {
        assert!(help.contains(verb), "help is missing '{verb}':\n{help}");
    }
}

/// `pack list --json` parses and exits cleanly on a fresh/empty pack cache.
#[test]
fn pack_list_json_parses_cleanly() {
    let mvm_home = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
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
    assert!(help.contains("--secret"));
    assert!(help.contains("--allow-secret-drop"));
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

/// `machine fork --help` advertises the expected child naming options.
#[test]
fn machine_fork_help_lists_args() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "fork", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "machine fork --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("fork"));
    assert!(help.contains("PARENT"));
    assert!(help.contains("--as"));
    assert!(help.contains("--branch"));
    assert!(help.contains("--secret"));
    assert!(help.contains("--allow-secret-drop"));
    assert!(help.contains("--json"));
}

/// `machine restore --help` advertises the expected child naming options.
#[test]
fn machine_restore_help_lists_args() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "restore", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "machine restore --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("restore"));
    assert!(help.contains("CHECKPOINT_ID"));
    assert!(help.contains("--as"));
    assert!(help.contains("--branch"));
    assert!(help.contains("--secret"));
    assert!(help.contains("--allow-secret-drop"));
    assert!(help.contains("--json"));
}

/// A non-existent checkpoint id fails gracefully from `machine restore`.
#[test]
fn machine_restore_rejects_missing_checkpoint() {
    let tmp = std::env::temp_dir().join(format!("mvm-restore-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", &tmp)
        .env("MVM_HOME", &tmp)
        .args(["machine", "restore", "no-such-checkpoint", "--as", "child"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "restore must fail for a missing checkpoint; stderr: {stderr}"
    );
    assert!(!stderr.contains("panic"), "restore panicked: {stderr}");
    assert!(
        !stderr.contains("thread panicked"),
        "restore panicked: {stderr}"
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

/// A mistyped flag must be named here, not shipped to the guest as argv where
/// it surfaces as `/bin/sh: exec: illegal option --` after a boot the caller
/// already paid for.
#[test]
fn machine_run_names_an_unknown_flag_instead_of_booting() {
    let tmp = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", tmp.path())
        .env("MVM_HOME", tmp.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "machine",
            "run",
            "--image",
            "alpine",
            "--no-such-flag",
            "8080:80",
            "--",
            "uname",
            "-a",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "an unknown flag must not run");
    assert!(
        stderr.contains("--no-such-flag"),
        "the error must name the flag, stderr: {stderr}"
    );
    assert!(
        !stderr.contains("illegal option"),
        "the flag must never reach a guest shell, stderr: {stderr}"
    );
}

/// Runs `mvmctl` host-only in `cwd` with an isolated state root and returns
/// whether it succeeded plus its stderr.
fn mvmctl_in(cwd: &std::path::Path, args: &[&str]) -> (bool, String) {
    let home = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .current_dir(cwd)
        .env("HOME", home.path())
        .env("MVM_HOME", home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A verb's own flag placed right after `--` is refused by the verb that
/// declares it: `--name` exists only on `machine run`, and `--image=alpine`
/// is the `=` spelling of a shared flag on `run`.
#[test]
fn a_verbs_own_flag_right_after_double_dash_is_refused_by_that_verb() {
    let cwd = tempfile::tempdir().unwrap();

    let (ok, stderr) = mvmctl_in(
        cwd.path(),
        &["machine", "run", "--image", "alpine", "--", "--name", "web"],
    );
    assert!(!ok, "a misplaced --name must not run");
    assert!(
        stderr.contains("`--name` is an `mvmctl machine run` flag"),
        "the error must name the flag, stderr: {stderr}"
    );

    let (ok, stderr) = mvmctl_in(cwd.path(), &["run", "--", "--image=alpine", "sh"]);
    assert!(!ok, "a misplaced --image=alpine must not run");
    assert!(
        stderr.contains("`--image` is an `mvmctl run` flag"),
        "the error must name the flag, stderr: {stderr}"
    );
}

/// An SDK-mode run is checked too, before the script is launched: its
/// argv[0] is the script path, which a flag-shaped word never is.
#[test]
fn an_sdk_mode_run_refuses_a_flag_right_after_double_dash() {
    let cwd = tempfile::tempdir().unwrap();
    let (ok, stderr) = mvmctl_in(
        cwd.path(),
        &["run", "--mode", "live", "--", "--image=alpine"],
    );
    assert!(!ok, "a misplaced --image must not run");
    assert!(
        stderr.contains("`--image` is an `mvmctl run` flag"),
        "the error must name the flag, stderr: {stderr}"
    );
}

/// Project detection must not outrun the misplaced-image-reference refusal:
/// next to a `package.json`, `mvmctl run node:22 -- index.js` refuses instead
/// of booting the detected node runtime with `node:22` as its command.
#[test]
fn run_refuses_a_misplaced_image_reference_inside_a_detected_project() {
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(cwd.path().join("package.json"), b"{}").unwrap();

    let (ok, stderr) = mvmctl_in(cwd.path(), &["run", "--", "node:22", "index.js"]);
    assert!(!ok, "a misplaced image reference must not run");
    assert!(
        stderr.contains("--image node:22"),
        "the refusal must point at --image, stderr: {stderr}"
    );
    assert!(
        !stderr.contains("detected node"),
        "nothing may be detected before the refusal, stderr: {stderr}"
    );
}

/// The archive flags have to be reachable, not merely declared.
///
/// This repo has shipped an `up::Args` whose flags were never wired to a
/// `Commands` variant, so the surface existed and nothing could invoke it.
/// Asserting `--help` succeeds is what distinguishes a dispatched verb from a
/// struct nobody routes to.
#[test]
fn receipts_export_advertises_the_archive_flags() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["trust", "audit", "receipts", "export", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "receipts export --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in ["--archive", "--full-chain", "--plan-id", "--json"] {
        assert!(help.contains(flag), "help must advertise {flag}:\n{help}");
    }
    // Deliberately absent until chunk embedding lands: a flag whose only
    // behaviour is an error is worse than no flag.
    assert!(
        !help.contains("--with-transcripts"),
        "--with-transcripts must not be advertised while it can only fail:\n{help}"
    );
}

#[test]
fn receipts_verify_is_a_dispatched_verb() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["trust", "audit", "receipts", "verify", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "receipts verify --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.to_lowercase().contains("archive"), "{help}");
}

/// `--json` prints receipts, `--archive` writes a file. Asking for both is a
/// contradiction and clap should refuse it rather than silently picking one.
#[test]
fn receipts_export_refuses_json_and_archive_together() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args([
            "trust",
            "audit",
            "receipts",
            "export",
            "--json",
            "--archive",
            "/tmp/should-not-be-written.mvmev",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "clap must reject --json with --archive"
    );
    assert!(
        !std::path::Path::new("/tmp/should-not-be-written.mvmev").exists(),
        "a refused invocation must not have written anything"
    );
}

#[test]
fn bundle_help_lists_push() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["bundle", "--help"])
        .output()
        .expect("run mvmctl bundle --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["export", "fetch", "install", "push", "gc"] {
        assert!(
            stdout.contains(sub),
            "bundle help must list {sub}:\n{stdout}"
        );
    }
}

#[test]
fn bundle_push_help_lists_positionals_and_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["bundle", "push", "--help"])
        .output()
        .expect("run mvmctl bundle push --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in ["<FILE>", "<REFERENCE>", "--trust-store", "--allow-http"] {
        assert!(
            stdout.contains(needle),
            "push help must list {needle}:\n{stdout}"
        );
    }
}

#[test]
fn bundle_fetch_and_install_help_list_prod_and_registry_sources() {
    for verb in ["fetch", "install"] {
        let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .args(["bundle", verb, "--help"])
            .output()
            .expect("run mvmctl bundle --help");
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("--prod"),
            "{verb} help must list --prod:\n{stdout}"
        );
        assert!(
            stdout.contains("oci:"),
            "{verb} help must name oci://:\n{stdout}"
        );
    }
}

#[test]
fn bundle_push_requires_both_positionals() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["bundle", "push", "./app.mvmpkg"])
        .output()
        .expect("run mvmctl bundle push");
    assert!(!out.status.success(), "a missing reference must be refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("<REFERENCE>"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bundle_fetch_prod_refuses_allow_http() {
    let mvm_home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "bundle",
            "install",
            "--prod",
            "--allow-http",
            "oci://registry.invalid/team/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .expect("run mvmctl bundle install --prod --allow-http");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--prod refuses --allow-http"),
        "stderr: {stderr}"
    );
}

/// `run --prod -- <cmd>` is refused before any pull: the registry host here
/// does not exist, so reaching the network would fail with a different
/// message.
#[test]
fn run_prod_refuses_an_ad_hoc_command_before_pulling() {
    let mvm_home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "run",
            "--image",
            "registry.invalid/team/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--prod",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run mvmctl run --prod -- /bin/true");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refuses an ad-hoc command"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("Omit the command"), "stderr: {stderr}");
    assert!(stderr.contains("declared entrypoint"), "stderr: {stderr}");
}

/// `--prod --profile dev` is refused before any pull.
#[test]
fn run_prod_refuses_the_dev_profile_before_pulling() {
    let mvm_home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "machine",
            "run",
            "--image",
            "registry.invalid/team/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--prod",
            "--profile",
            "dev",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run mvmctl machine run --prod --profile dev");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--profile dev"), "stderr: {stderr}");
}

/// `--prod` with a tag must be refused from the reference alone. The
/// registry host here does not exist, so reaching the network would fail
/// with a different message.
#[test]
fn bundle_fetch_prod_refuses_a_tag_reference() {
    let mvm_home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home.path())
        .env("HOME", mvm_home.path())
        .env("MVM_NO_AUTO_DEV", "1")
        .args([
            "bundle",
            "fetch",
            "--prod",
            "oci://registry.invalid/team/app:v1",
        ])
        .output()
        .expect("run mvmctl bundle fetch --prod");
    assert!(!out.status.success(), "a tag under --prod must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("digest-pinned"), "stderr: {stderr}");
}

/// Run `mvmctl agent-session …` against an isolated home.
fn agent_session(mvm_home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("MVM_HOME", mvm_home)
        .env("HOME", mvm_home)
        .env("MVM_NO_AUTO_DEV", "1")
        .arg("agent-session")
        .args(args)
        .output()
        .expect("run mvmctl agent-session")
}

/// `park` and `resume` advertise the generation fence that makes a retry
/// exact.
#[test]
fn agent_session_park_and_resume_help_list_the_retry_flags() {
    let home = tempfile::tempdir().unwrap();
    for verb in ["park", "resume"] {
        let out = agent_session(home.path(), &[verb, "--help"]);
        assert!(
            out.status.success(),
            "agent-session {verb} --help must exit 0, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let help = String::from_utf8_lossy(&out.stdout);
        assert!(help.contains("--expected-generation"), "{verb}: {help}");
        assert!(help.contains("--json"), "{verb}: {help}");
    }
}

#[test]
fn agent_session_park_refuses_a_non_numeric_expected_generation() {
    let home = tempfile::tempdir().unwrap();
    let out = agent_session(
        home.path(),
        &[
            "park",
            "sess-a",
            "--reason",
            "idle",
            "--expected-generation",
            "one",
        ],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--expected-generation"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A park whose response was lost is retried with the same arguments and is
/// told it already applied, rather than being refused as "not active".
#[test]
fn agent_session_park_retry_is_reported_as_a_replay() {
    let home = tempfile::tempdir().unwrap();
    let open = agent_session(home.path(), &["open", "sess-a"]);
    assert!(
        open.status.success(),
        "{}",
        String::from_utf8_lossy(&open.stderr)
    );
    let park = [
        "park",
        "sess-a",
        "--reason",
        "approval-wait",
        "--expected-generation",
        "1",
        "--json",
    ];
    let replayed = |out: &std::process::Output| -> bool {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        json["replayed"].as_bool().unwrap()
    };
    assert!(!replayed(&agent_session(home.path(), &park)));
    assert!(replayed(&agent_session(home.path(), &park)));

    let changed = agent_session(
        home.path(),
        &[
            "park",
            "sess-a",
            "--reason",
            "idle",
            "--expected-generation",
            "1",
        ],
    );
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr).contains("recorded approval_wait, retried idle"),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
}

#[test]
fn agent_session_renew_help_lists_its_flags() {
    let home = tempfile::tempdir().unwrap();
    let out = agent_session(home.path(), &["renew", "--help"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--for",
        "--expected-deadline",
        "--expected-generation",
        "--json",
    ] {
        assert!(help.contains(flag), "missing {flag}: {help}");
    }
    let park = agent_session(home.path(), &["park", "--help"]);
    assert!(String::from_utf8_lossy(&park.stdout).contains("--retain-for"));
}

/// Park with a deadline, read it back, renew exactly twice, then try to
/// shorten: the real binary replays the retry and refuses the shortening.
#[test]
fn agent_session_renew_extends_replays_and_refuses_to_shorten() {
    let home = tempfile::tempdir().unwrap();
    let ok = |out: std::process::Output| -> serde_json::Value {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
    };
    ok(agent_session(home.path(), &["open", "sess-a"]));
    ok(agent_session(
        home.path(),
        &[
            "park",
            "sess-a",
            "--reason",
            "operator",
            "--retain-for",
            "1h",
        ],
    ));
    let shown = ok(agent_session(home.path(), &["show", "sess-a", "--json"]));
    assert_eq!(shown["retention"]["state"], "alive");
    let deadline = shown["retain_until_unix"].as_u64().unwrap().to_string();

    let renew = [
        "renew",
        "sess-a",
        "--for",
        "5h",
        "--expected-generation",
        "1",
        "--expected-deadline",
        deadline.as_str(),
        "--json",
    ];
    assert_eq!(ok(agent_session(home.path(), &renew))["replayed"], false);
    assert_eq!(ok(agent_session(home.path(), &renew))["replayed"], true);

    let shorten = agent_session(home.path(), &["renew", "sess-a", "--for", "1m"]);
    assert!(!shorten.status.success());
    assert!(
        String::from_utf8_lossy(&shorten.stderr).contains("can only extend"),
        "{}",
        String::from_utf8_lossy(&shorten.stderr)
    );
}

/// `--output` is advertised on `machine run`, and each pre-boot refusal fires
/// before anything is resolved or booted: a profile that allows no host
/// shares, a persistent machine that has no exit to collect at, and a
/// destination that already holds files.
#[test]
fn machine_run_output_is_advertised_and_refused_before_boot() {
    #[allow(deprecated)]
    let help = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "run", "--help"])
        .output()
        .unwrap();
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help.status.success());
    assert!(
        help_text.contains("--output <HOST_DIR:GUEST[:SIZE]>"),
        "help must advertise --output:\n{help_text}"
    );

    let tmp = tempfile::tempdir().unwrap();
    let populated = tmp.path().join("populated");
    std::fs::create_dir(&populated).unwrap();
    std::fs::write(populated.join("keep"), b"mine").unwrap();
    let fresh = format!("{}:/data/out", tmp.path().join("fresh").display());
    let occupied = format!("{}:/data/out", populated.display());

    let run = |extra: &[&str]| {
        #[allow(deprecated)]
        let out = Command::cargo_bin("mvmctl")
            .unwrap()
            .env("HOME", tmp.path())
            .env("MVM_HOME", tmp.path().join("state"))
            .env("MVM_NO_AUTO_DEV", "1")
            .args(["machine", "run", "--image", "alpine"])
            .args(extra)
            .args(["--", "true"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{extra:?} must not run");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    let stderr = run(&["--profile", "restrictive", "--output", &fresh]);
    assert!(
        stderr.contains("does not allow --mount or --output"),
        "restrictive must refuse --output, stderr: {stderr}"
    );
    let stderr = run(&["-d", "--output", &fresh]);
    assert!(
        stderr.contains("has no exit to collect at"),
        "a persistent machine must refuse --output, stderr: {stderr}"
    );
    let stderr = run(&["--output", &occupied]);
    assert!(
        stderr.contains("not an empty directory"),
        "a populated destination must be refused, stderr: {stderr}"
    );
    assert_eq!(std::fs::read(populated.join("keep")).unwrap(), b"mine");
    assert!(!tmp.path().join("fresh").exists());
}

fn isolated_mvmctl(home: &std::path::Path) -> Command {
    #[allow(deprecated)]
    let mut command = Command::cargo_bin("mvmctl").unwrap();
    command
        .env("HOME", home)
        .env("MVM_HOME", home.join("state"))
        .env("MVM_NO_AUTO_DEV", "1");
    command
}

#[test]
fn run_refuses_a_denied_env_variable_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let out = isolated_mvmctl(tmp.path())
        .args([
            "run",
            "--dry-run",
            "--env",
            "LD_PRELOAD=/tmp/hook-value.so",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a loader variable must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("LD_PRELOAD (loader)"), "stderr: {stderr}");
    assert!(stderr.contains("--allow-env NAME"), "stderr: {stderr}");
    assert!(
        !stderr.contains("hook-value"),
        "the value is never echoed: {stderr}"
    );
}

#[test]
fn run_allow_env_readmits_by_exact_name_only() {
    let tmp = tempfile::tempdir().unwrap();
    let out = isolated_mvmctl(tmp.path())
        .args([
            "run",
            "--dry-run",
            "--env",
            "PYTHONPATH=/srv/lib",
            "--allow-env",
            "PYTHONPATH",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "an exact-name re-admission passes: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = isolated_mvmctl(tmp.path())
        .args([
            "run",
            "--dry-run",
            "--env",
            "LD_PRELOAD=/x.so",
            "--allow-env",
            "LD_*",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a pattern never re-admits");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("never a pattern"), "stderr: {stderr}");
}

#[test]
fn allow_env_is_documented_on_run_and_proc_start() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["run", "--help"][..],
        &["machine", "proc", "start", "--help"][..],
    ] {
        let out = isolated_mvmctl(tmp.path()).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("--allow-env <NAME>"), "{args:?}: {stdout}");
    }
}

#[test]
fn machine_prompt_is_listed_and_documents_its_session_and_step_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let machine = isolated_mvmctl(tmp.path())
        .args(["machine", "--help"])
        .output()
        .unwrap();
    assert!(machine.status.success());
    assert!(
        String::from_utf8_lossy(&machine.stdout).contains("prompt"),
        "machine --help does not list prompt"
    );

    let out = isolated_mvmctl(tmp.path())
        .args(["machine", "prompt", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--session <ID>",
        "--idempotency-key <KEY>",
        "--timeout <SECS>",
        "--no-step-checkpoint",
        "[PROMPT]",
    ] {
        assert!(stdout.contains(flag), "{flag} missing: {stdout}");
    }
}

#[test]
fn agent_session_replay_documents_its_checkpoint_fork_and_dry_run_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let out = isolated_mvmctl(tmp.path())
        .args(["agent-session", "replay", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--from <CHECKPOINT>",
        "--as <NAME>",
        "--dry-run",
        "--timeout <SECS>",
    ] {
        assert!(stdout.contains(flag), "{flag} missing: {stdout}");
    }
}

#[test]
fn agent_session_replay_of_an_unknown_session_fails_without_forking() {
    let tmp = tempfile::tempdir().unwrap();
    let out = isolated_mvmctl(tmp.path())
        .args(["agent-session", "replay", "no-such-session", "--dry-run"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no-such-session"), "stderr: {stderr}");
}

#[test]
fn machine_run_help_documents_both_cold_build_flags() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "run", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--no-build") && help.contains("Fail instead of building"),
        "help must offer the fail-fast opt-in:\n{help}"
    );
    assert!(
        help.contains("--build") && help.contains("Skip the first-run notice"),
        "help must say `--build` only skips the notice:\n{help}"
    );
}

#[test]
fn machine_run_rejects_build_with_no_build() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args([
            "machine",
            "run",
            "--image",
            "alpine",
            "--build",
            "--no-build",
        ])
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "stderr: {stderr}");
}

#[test]
fn machine_run_refuses_persistent_environment_before_boot() {
    let tmp = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", tmp.path())
        .env("MVM_HOME", tmp.path().join("state"))
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["machine", "run", "--image", "alpine", "-d", "--env", "K=V"])
        .output()
        .unwrap();

    assert!(!out.status.success(), "persistent environment must not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`machine run --env` is supported only for transient runs"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("declare environment in the image or workload manifest"),
        "stderr must name the supported delivery path: {stderr}"
    );
}

#[test]
fn image_boot_verify_help_lists_every_input() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["image", "boot", "verify", "--help"])
        .output()
        .expect("run mvmctl image boot verify --help");
    assert!(
        out.status.success(),
        "verify help must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--manifest",
        "--bundle",
        "--lock",
        "--artifacts",
        "--artifact",
        "--require-complete",
        "--json",
    ] {
        assert!(help.contains(flag), "help must list {flag}: {help}");
    }
}

#[test]
fn image_boot_verify_requires_every_input() {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["image", "boot", "verify", "--manifest", "m.json"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "missing inputs must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--bundle"), "stderr: {stderr}");
}

/// A manifest the lock does not pin is refused at the digest, before its bytes
/// are parsed or its signature is checked — so this holds in a build without
/// the signature verifier too, and the JSON form still exits nonzero.
#[test]
fn image_boot_verify_refuses_a_manifest_the_lock_does_not_pin() {
    use sha2::Digest as _;

    let tmp = tempfile::tempdir().unwrap();
    let path = |name: &str| tmp.path().join(name);
    std::fs::write(path("image-set.json"), b"{\"not\":\"the pinned bytes\"}").unwrap();
    std::fs::write(path("image-set.json.bundle"), b"{}").unwrap();
    std::fs::create_dir(path("artifacts")).unwrap();
    let lock = format!(
        "schema_version = 1\n\
         repository = \"tinylabscom/mvm\"\n\
         release_tag = \"v0.0.0-smoke\"\n\
         manifest_asset = \"image-set.json\"\n\
         manifest_sha256 = \"{}\"\n\
         \n\
         [signing_identity]\n\
         workflow = \".github/workflows/release.yml\"\n\
         tag_ref = \"refs/tags/v0.0.0-smoke\"\n",
        hex::encode(sha2::Sha256::digest(b"the pinned bytes"))
    );
    std::fs::write(path("images.lock"), lock).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("HOME", tmp.path())
        .env("MVM_HOME", tmp.path().join("state"))
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["image", "boot", "verify", "--json"])
        .arg("--manifest")
        .arg(path("image-set.json"))
        .arg("--bundle")
        .arg(path("image-set.json.bundle"))
        .arg("--lock")
        .arg(path("images.lock"))
        .arg("--artifacts")
        .arg(path("artifacts"))
        .output()
        .unwrap();

    assert!(!out.status.success(), "a refused set must exit nonzero");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json prints the refusal on stdout");
    assert_eq!(report["verified"], false);
    assert_eq!(report["stage"], "manifest-digest");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused at the manifest-digest stage"),
        "stderr: {stderr}"
    );
}

/// `--secret` is shared run surface: both run verbs advertise it.
#[test]
fn run_and_machine_run_help_list_the_secret_flag() {
    for verb in [&["run", "--help"][..], &["machine", "run", "--help"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .args(verb)
            .output()
            .expect("run mvmctl help");
        assert!(
            out.status.success(),
            "{verb:?} must exit 0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--secret"), "{verb:?} help missing --secret");
        assert!(
            text.contains("NAME[:HOST,...]"),
            "{verb:?} help missing the spec shape"
        );
    }
}

/// Endpoint routes are part of both run surfaces, including the persistent
/// `machine run --name` path that records them in `MachineSpec`.
#[test]
fn run_and_machine_run_help_list_the_allow_endpoint_flag() {
    for verb in [&["run", "--help"][..], &["machine", "run", "--help"][..]] {
        let help = mvmctl_help(verb);
        assert!(help.contains("--allow-endpoint"), "{verb:?}: {help}");
        assert!(help.contains("[METHOD ]URL"), "{verb:?}: {help}");
    }
}

#[test]
fn secret_set_help_and_parser_cover_every_injection_mode() {
    let help = mvmctl_help(&["secret", "set", "--help"]);
    assert!(help.contains("--inject"), "secret set help: {help}");

    let home = tempfile::tempdir().unwrap();
    for (name, auth_type, mode) in [
        ("header-key", "bearer", "header"),
        ("query-key", "bearer", "query_param"),
        ("path-key", "bearer", "url_path"),
        ("basic-key", "basic", "basic_auth"),
    ] {
        let stored = isolated_secret_mvmctl(home.path())
            .args([
                "secret",
                "set",
                name,
                "--host",
                "api.example.com",
                "--type",
                auth_type,
                "--inject",
                mode,
                "--value",
                "test-only-value",
            ])
            .output()
            .expect("run mvmctl secret set");
        assert!(
            stored.status.success(),
            "secret set must accept {mode}: {}",
            String::from_utf8_lossy(&stored.stderr)
        );
    }
    let listed = isolated_secret_mvmctl(home.path())
        .args(["secret", "ls"])
        .output()
        .expect("run mvmctl secret ls");
    assert!(listed.status.success());
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.contains("header-key\ttype=bearer"), "{listed}");
    for mode in ["query_param", "url_path", "basic_auth"] {
        assert!(listed.contains(&format!("inject={mode}")), "{listed}");
    }
}

/// An isolated `mvmctl` whose secrets live in the file store, so nothing
/// reaches the operator's keychain.
fn isolated_secret_mvmctl(home: &std::path::Path) -> Command {
    let mut command = isolated_mvmctl(home);
    command.env("MVM_SECRET_STORE_BACKEND", "file");
    command
}

/// A secret the host has never stored refuses the run before anything boots.
#[test]
fn run_with_an_unknown_secret_refuses_before_boot() {
    let home = tempfile::tempdir().unwrap();
    let out = isolated_secret_mvmctl(home.path())
        .args(["run", "--secret", "never-stored", "--", "true"])
        .output()
        .expect("run mvmctl run");
    assert!(!out.status.success(), "an unknown secret must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown secret"), "{stderr}");
    assert!(
        stderr.contains("mvmctl secret set never-stored"),
        "the refusal names the fix: {stderr}"
    );
}

/// A destination the stored binding does not admit refuses before boot: the
/// flag can narrow a binding, never widen it.
#[test]
fn run_with_a_destination_outside_the_binding_refuses_before_boot() {
    let home = tempfile::tempdir().unwrap();
    let stored = isolated_secret_mvmctl(home.path())
        .args([
            "secret",
            "set",
            "anthropic",
            "--provider",
            "anthropic",
            "--value",
            "sk-ant-test-only",
        ])
        .output()
        .expect("run mvmctl secret set");
    assert!(
        stored.status.success(),
        "secret set must succeed: {}",
        String::from_utf8_lossy(&stored.stderr)
    );

    let out = isolated_secret_mvmctl(home.path())
        .args([
            "run",
            "--secret",
            "anthropic:collector.evil.test",
            "--",
            "true",
        ])
        .output()
        .expect("run mvmctl run");
    assert!(!out.status.success(), "a widening destination must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refused before boot"), "{stderr}");
    assert!(stderr.contains("collector.evil.test"), "{stderr}");
    assert!(
        !stderr.contains("sk-ant-test-only"),
        "a refusal never echoes the value: {stderr}"
    );
}

fn mvmctl_help(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(args)
        .output()
        .expect("run mvmctl --help");
    assert!(
        out.status.success(),
        "{args:?} must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The console help states what each escape does to the session, so an
/// operator knows before pressing it whether the shell survives.
#[test]
fn machine_console_help_states_detach_and_terminate_semantics() {
    let help = mvmctl_help(&["machine", "console", "--help"]);
    for needle in [
        "~d   detach: the shell keeps running",
        "~.   end the session",
        "--list",
        "--detach-timeout <SECONDS>",
        "--force",
        "machine detach <name>",
    ] {
        assert!(help.contains(needle), "missing {needle:?} in:\n{help}");
    }
}

/// `attach` is the lifecycle-surface name for the console verb.
#[test]
fn machine_attach_is_an_alias_for_console() {
    let help = mvmctl_help(&["machine", "attach", "--help"]);
    assert!(help.contains("~d   detach"), "{help}");
    assert!(
        help.starts_with("Attach to a development VM's console session"),
        "`attach` must resolve to the console verb:\n{help}"
    );
    let listing = mvmctl_help(&["machine", "--help"]);
    assert!(listing.contains("\n  detach "), "{listing}");
}

#[test]
fn machine_detach_takes_a_vm_name() {
    let help = mvmctl_help(&["machine", "detach", "--help"]);
    assert!(help.contains("session keeps running"), "{help}");
    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .args(["machine", "detach"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a VM name is required");
}

#[test]
fn machine_console_rejects_conflicting_session_flags() {
    for args in [
        &["machine", "console", "dev", "--list", "--force"][..],
        &["machine", "console", "dev", "--command", "id", "--list"],
        &[
            "machine",
            "console",
            "dev",
            "--command",
            "id",
            "--detach-timeout",
            "60",
        ],
        &["machine", "console", "dev", "--detach-timeout", "0"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{args:?} must be refused by the parser"
        );
        assert_eq!(out.status.code(), Some(2), "{args:?} is a usage error");
    }
}

/// `ops mcp stdio` binds the resolved `[tools]` policy as its tool gate: a
/// denied tool is refused before any backend work, an allowed tool passes.
#[test]
fn ops_mcp_enforces_the_project_tool_policy() {
    fn isolated(home: &std::path::Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mvmctl"));
        command
            .env("MVM_HOME", home)
            .env("HOME", home)
            .env("MVM_NO_AUTO_DEV", "1");
        command
    }
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("mvm.toml"),
        "[policy]\ninclude = [\"agent-tools\"]\n",
    )
    .unwrap();
    let groups = home.path().join("config/policy/groups");
    std::fs::create_dir_all(&groups).unwrap();
    std::fs::write(
        groups.join("agent-tools.toml"),
        "[tools]\nallow = [\"mvm.machine.list\"]\ndeny = [\"mvm.machine.stop\"]\n",
    )
    .unwrap();

    let mut child = isolated(home.path())
        .current_dir(project.path())
        .args(["ops", "mcp", "stdio"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mvmctl ops mcp stdio");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    let mut stdout = child.stdout.take().expect("stdout pipe");

    let call = |id: u32, name: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{}}}}}}"#
        )
    };
    use std::io::Write as _;
    writeln!(stdin, "{}", call(1, "mvm.machine.stop")).expect("write denied call");
    writeln!(stdin, "{}", call(2, "mvm.machine.list")).expect("write allowed call");
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":9,"method":"unknown/nope","params":{{}}}}"#
    )
    .expect("write terminator probe");
    stdin.flush().expect("flush frames");

    use std::io::BufRead as _;
    let reader = std::io::BufReader::new(&mut stdout);
    let mut denied_seen = false;
    let mut allowed_seen = false;
    for line in reader.lines() {
        let line = line.expect("read a response line");
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let method = parsed["method"].as_str().unwrap_or("");
        if method == "unknown/nope" || parsed["id"] == 9 {
            break;
        }
        let is_error = parsed["result"]["isError"].as_bool().unwrap_or(false);
        let text = parsed["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        match parsed["id"].as_u64() {
            Some(1) => {
                assert!(is_error, "denied tool must refuse: {line}");
                assert!(text.contains("policy denies"), "{text}");
                denied_seen = true;
            }
            Some(2) => {
                assert!(!is_error, "allowed tool must reach the backend: {line}");
                allowed_seen = true;
            }
            _ => {}
        }
        if denied_seen && allowed_seen {
            break;
        }
    }
    assert!(denied_seen, "the denied call produced no refusal");
    assert!(allowed_seen, "the allowed call produced no result");
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Signed registry packs (PS-06): search / pull / pack registry
// ---------------------------------------------------------------------------

fn mvmctl_isolated(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mvmctl"));
    command
        .env("MVM_HOME", home)
        .env("HOME", home)
        .env("MVM_NO_AUTO_DEV", "1");
    command
}

/// Stage a minimal pack registry on disk: an index and one pack whose
/// manifest/signature/files live at the layout `pull` fetches.
fn stage_pack_registry(root: &std::path::Path) {
    let packs = root.join("packs");
    std::fs::create_dir_all(&packs).unwrap();
    std::fs::write(
        packs.join("index.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "packs": [{
                "namespace": "runtime",
                "name": "python",
                "description": "Python runtime pack",
                "versions": ["1.2.3"],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let pack = packs.join("runtime/python/1.2.3");
    std::fs::create_dir_all(pack.join("files/pack")).unwrap();
    std::fs::write(
        pack.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "reference": "runtime/python@1.2.3",
            "description": "Python runtime pack",
            "files": [{
                "path": "pack/profile.toml",
                "sha256": "0".repeat(64),
                "size": 0,
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(pack.join("manifest.sigstore.json"), b"test bundle").unwrap();
    std::fs::write(
        pack.join("files/pack/profile.toml"),
        b"[tools]\nallow = [\"git\"]\n",
    )
    .unwrap();
}

#[test]
fn pack_registry_verbs_parse_and_show_help() {
    for args in [
        vec!["pull", "--help"],
        vec!["search", "--help"],
        vec!["pack", "registry", "--help"],
        vec!["pack", "registry", "ls", "--help"],
        vec!["pack", "registry", "rm", "--help"],
        vec!["pack", "registry", "update", "--help"],
        vec!["pack", "registry", "revocations", "update", "--help"],
    ] {
        let out = mvmctl_isolated(std::path::Path::new("/tmp"))
            .args(&args)
            .output()
            .unwrap_or_else(|error| panic!("run mvmctl {args:?}: {error}"));
        assert!(
            out.status.success(),
            "mvmctl {args:?} --help must succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = mvmctl_isolated(std::path::Path::new("/tmp"))
        .args(["pack", "registry", "revocations", "update", "--help"])
        .output()
        .expect("revocation help");
    let help = String::from_utf8(out.stdout).expect("UTF-8 help");
    assert!(help.contains("--official"));
}

#[test]
fn pack_info_and_verify_recheck_signed_installed_content() {
    let home = tempfile::tempdir().expect("isolated home");
    let registry = tempfile::tempdir().expect("local registry");
    let pack = registry.path().join("packs/runtime/go/1.0.0");
    std::fs::create_dir_all(pack.join("files/pack")).expect("pack directory");
    std::fs::write(
        registry.path().join("packs/index.json"),
        br#"{"schema_version":1,"packs":[{"namespace":"runtime","name":"go","description":"Go runtime policy","versions":["1.0.0"]}]}"#,
    )
    .expect("registry index");
    std::fs::write(
        pack.join("manifest.json"),
        include_bytes!("../crates/mvm-cli/tests/fixtures/signed-registry-go/manifest.json"),
    )
    .expect("signed manifest");
    std::fs::write(
        pack.join("manifest.sigstore.json"),
        include_bytes!(
            "../crates/mvm-cli/tests/fixtures/signed-registry-go/manifest.sigstore.json"
        ),
    )
    .expect("signature bundle");
    let policy =
        include_bytes!("../crates/mvm-cli/tests/fixtures/signed-registry-go/pack/group.toml");
    std::fs::write(pack.join("files/pack/group.toml"), policy).expect("signed policy");
    let registry_url = format!("file://{}", registry.path().display());

    let pulled = mvmctl_isolated(home.path())
        .env("MVM_PACK_REGISTRY", &registry_url)
        .args(["pull", "runtime/go", "--json"])
        .output()
        .expect("pull signed pack");
    assert!(
        pulled.status.success(),
        "{}",
        String::from_utf8_lossy(&pulled.stderr)
    );
    let pull: serde_json::Value = serde_json::from_slice(&pulled.stdout).expect("pull JSON");
    assert_eq!(pull["reference"], "runtime/go@1.0.0");
    let digest = pull["manifest_sha256"].as_str().expect("manifest digest");

    let info = mvmctl_isolated(home.path())
        .args(["pack", "info", "runtime/go", "--json"])
        .output()
        .expect("inspect installed pack");
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let details: serde_json::Value = serde_json::from_slice(&info.stdout).expect("pack info JSON");
    assert_eq!(details["manifest_sha256"], digest);
    assert_eq!(
        details["signer_identity"],
        mvm_core::registry_pack::LEGACY_PACK_SIGNING_IDENTITY
    );
    assert_eq!(
        details["signer_issuer"],
        mvm_core::registry_pack::OFFICIAL_PACK_SIGNING_ISSUER
    );
    assert_eq!(details["official_status"], "not_established");
    assert_eq!(details["revocation_scope"], "operator_configured_only");
    assert_eq!(
        details["policy_documents"][0]["text"],
        String::from_utf8_lossy(policy).as_ref()
    );

    let verified = mvmctl_isolated(home.path())
        .args(["pack", "verify", "runtime/go@1.0.0"])
        .output()
        .expect("verify installed pack");
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Verified runtime/go@1.0.0"));
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Signer identity:"));
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Official status: not established"));

    let verified_json = mvmctl_isolated(home.path())
        .args(["pack", "verify", "runtime/go@1.0.0", "--json"])
        .output()
        .expect("verify installed pack as JSON");
    assert!(verified_json.status.success());
    let verification: serde_json::Value =
        serde_json::from_slice(&verified_json.stdout).expect("pack verify JSON");
    assert_eq!(verification["manifest_sha256"], digest);
    assert_eq!(
        verification["signer_identity"],
        mvm_core::registry_pack::LEGACY_PACK_SIGNING_IDENTITY
    );
    assert_eq!(verification["official_status"], "not_established");

    let cached_policy = mvm_core::config::mvm_cache_dir_at(home.path())
        .join("registry-packs")
        .join(digest)
        .join("payload/pack/group.toml");
    std::fs::write(&cached_policy, b"tampered").expect("tamper installed policy");
    let refused = mvmctl_isolated(home.path())
        .args(["pack", "info", "runtime/go"])
        .output()
        .expect("inspect tampered pack");
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("Publisher issuer:"));

    let refused_verify = mvmctl_isolated(home.path())
        .args(["pack", "verify", "runtime/go"])
        .output()
        .expect("verify tampered pack");
    assert!(!refused_verify.status.success());
    assert!(!String::from_utf8_lossy(&refused_verify.stdout).contains("Verified runtime/go"));

    std::fs::write(cached_policy, policy).expect("restore signed policy");
    let cached_bundle = mvm_core::config::mvm_cache_dir_at(home.path())
        .join("registry-packs")
        .join(digest)
        .join("manifest.sigstore.json");
    std::fs::write(&cached_bundle, b"invalid signature bundle").expect("tamper installed bundle");
    let refused_signature = mvmctl_isolated(home.path())
        .args(["pack", "verify", "runtime/go"])
        .output()
        .expect("verify invalid signature");
    assert!(!refused_signature.status.success());
    assert!(!String::from_utf8_lossy(&refused_signature.stdout).contains("Signer identity:"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(
            cached_bundle,
            include_bytes!(
                "../crates/mvm-cli/tests/fixtures/signed-registry-go/manifest.sigstore.json"
            ),
        )
        .expect("restore signed bundle");
        let revocation_dir = home.path().join("registry/revocations");
        std::fs::create_dir_all(&revocation_dir).expect("revocation directory");
        std::fs::set_permissions(&revocation_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private revocation directory");
        let trust_path = revocation_dir.join("trust.toml");
        std::fs::write(
            &trust_path,
            "schema_version = 1\nissuer = 'independent release issuer'\naccepted_identities = ['independent release identity']\n",
        )
        .expect("revocation trust");
        std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o600))
            .expect("private revocation trust");
        let refused_missing_feed = mvmctl_isolated(home.path())
            .args(["pack", "verify", "runtime/go"])
            .output()
            .expect("verify without configured revocation feed");
        assert!(!refused_missing_feed.status.success());
        assert!(
            String::from_utf8_lossy(&refused_missing_feed.stderr).contains("revocation"),
            "{}",
            String::from_utf8_lossy(&refused_missing_feed.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&refused_missing_feed.stdout).contains("Signer identity:")
        );
    }
}

#[test]
fn search_reads_a_file_registry_and_marks_installed_packs() {
    let home = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    stage_pack_registry(registry.path());
    let out = mvmctl_isolated(home.path())
        .env(
            "MVM_PACK_REGISTRY",
            format!("file://{}", registry.path().display()),
        )
        .args(["search", "--json"])
        .output()
        .expect("run mvmctl search --json");
    assert!(
        out.status.success(),
        "search must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("search --json emits rows");
    assert_eq!(rows[0]["pack"], "runtime/python");
    assert_eq!(rows[0]["installed"], false);
}

/// The staged bundle is not a Sigstore bundle, so the default build's verifier
/// rejects it. The refusal must come from that check, not from a build with no
/// verifier compiled in: a default build that cannot verify cannot get past
/// the signed image set either.
#[test]
fn pull_refuses_a_pack_whose_signature_does_not_verify_and_installs_nothing() {
    let home = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    stage_pack_registry(registry.path());
    // An empty-but-present trust policy reaches signature verification, so
    // the refusal below comes from the checker, not policy bootstrap.
    let registry_state = home.path().join("registry");
    std::fs::create_dir_all(&registry_state).unwrap();
    std::fs::write(
        registry_state.join("publishers.toml"),
        br#"schema_version = 1

[[publishers]]
namespace = "runtime"
issuer = "https://token.actions.githubusercontent.com"
accepted_identities = ["https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"]
"#,
    )
    .unwrap();
    let out = mvmctl_isolated(home.path())
        .env(
            "MVM_PACK_REGISTRY",
            format!("file://{}", registry.path().display()),
        )
        .args(["pull", "runtime/python"])
        .output()
        .expect("run mvmctl pull");
    assert!(
        !out.status.success(),
        "pull must refuse a pack whose signature does not verify"
    );
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        shown.contains("signature is invalid"),
        "the refusal must come from signature verification: {shown}"
    );
    assert!(
        !shown.contains("manifest-verify feature disabled"),
        "a default build must carry the verifier: {shown}"
    );
    assert!(
        !home.path().join("registry/packs.lock.toml").exists(),
        "no pin may be recorded for an unverified pack"
    );
    assert!(
        !home.path().join("cache/registry-packs").exists(),
        "nothing may be installed for an unverified pack"
    );
}

#[test]
fn pack_registry_ls_starts_empty_and_rm_unpinned_is_a_no_op() {
    let home = tempfile::tempdir().unwrap();
    for argv in [
        ["pack", "ls", "--json"].as_slice(),
        ["pack", "registry", "ls", "--json"].as_slice(),
    ] {
        let out = mvmctl_isolated(home.path())
            .args(argv)
            .output()
            .expect("run pack ls --json");
        assert!(
            out.status.success(),
            "{argv:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rows: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("ls --json emits rows");
        assert!(rows.as_array().expect("rows").is_empty());
    }

    for argv in [
        ["pack", "rm", "runtime/python"].as_slice(),
        ["pack", "registry", "rm", "runtime/python"].as_slice(),
    ] {
        let out = mvmctl_isolated(home.path())
            .args(argv)
            .output()
            .expect("run pack rm");
        assert!(
            out.status.success(),
            "{argv:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(shown.contains("not pinned"), "{shown}");
    }
}

#[test]
fn system_pack_list_preserves_legacy_json_output() {
    let home = tempfile::tempdir().unwrap();
    let run = |command: &[&str]| {
        let output = mvmctl_isolated(home.path())
            .args(command)
            .output()
            .expect("run system pack list");
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("system list JSON")
    };
    assert_eq!(
        run(&["pack", "system", "list", "--json"]),
        run(&["pack", "list", "--json"])
    );
}

#[test]
fn pack_update_dispatches_by_exact_target_shape() {
    let home = tempfile::tempdir().unwrap();
    let missing_registry = format!("file://{}", home.path().join("missing-registry").display());
    let run = |command: &[&str]| {
        mvmctl_isolated(home.path())
            .env("MVM_PACK_REGISTRY", &missing_registry)
            .args(command)
            .output()
            .expect("run pack update")
    };
    let workload = run(&["pack", "update", "runtime/python"]);
    let legacy = run(&["pack", "registry", "update", "runtime/python"]);
    assert!(!workload.status.success());
    assert!(!legacy.status.success());
    assert_eq!(workload.stderr, legacy.stderr);

    let system = run(&["pack", "update", "runtime"]);
    assert!(!system.status.success());
    assert!(
        String::from_utf8_lossy(&system.stderr).contains("not yet fetchable"),
        "{}",
        String::from_utf8_lossy(&system.stderr)
    );
    assert_ne!(system.stderr, workload.stderr);
}

/// `machine run --manifest <app.mvmpkg> -- <cmd>` parses as a bundle-archive
/// launch, and an archive that does not verify is refused at the install step,
/// before the run reaches admission or any backend, with nothing installed.
#[test]
fn machine_run_refuses_an_unverifiable_bundle_archive_before_booting() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("app.mvmpkg");
    std::fs::write(&archive, b"not a signed bundle").unwrap();
    let state = tmp.path().join("state");

    let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .env("HOME", tmp.path())
        .env("MVM_HOME", &state)
        .env("MVM_NO_AUTO_DEV", "1")
        .args(["machine", "run", "--manifest"])
        .arg(&archive)
        .args(["--", "true"])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "an unverifiable archive must not run"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed verification"),
        "the refusal must come from bundle verification: {stderr}"
    );
    let installed = std::fs::read_dir(state.join("bundles"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(installed, 0, "a refused archive installs nothing");
}
