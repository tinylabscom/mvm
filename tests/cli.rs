//! `mvmctl` CLI flag contract tests — fast, no VM boot required.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

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
