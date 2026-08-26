//! Followup H plan-mode end-to-end test (Plan 73).
//!
//! Mirrors the `auto_exec_python_record.rs` pattern: spawns a
//! stand-alone Python script that emits a wire-shape recording to
//! `$MVM_SDK_OUT_PATH`, then drives `mvmctl run --mode plan` over
//! the same script. The recording flows through
//! `mvm_sdk::runtime::compile_recording` to a Workload; the CLI
//! synthesises one `ExecutionPlan` per app and routes each through
//! `mvm_hostd::supervisor::admit_for_run` for a dry-run admission check.
//!
//! What this test asserts (the CLI surface the regression bites):
//!
//! 1. `mvmctl run --mode plan <script>` admits a clean recording
//!    and exits zero. ADMITTED lines hit stdout.
//! 2. `mvmctl run --prod <script>` redirects users to
//!    `mvmctl compile` with a nonzero exit and a clear pointer.
//! 3. `mvmctl run --mode plan` over a non-script path is rejected
//!    with the language-extension hint.
//!
//! The `--dev` alias and `--mode live` happy paths are exercised
//! in `tests/run_live_mode.rs` post-Followup-H-live.
//!
//! Skips when no `python3`/`python` is on PATH.

use std::path::PathBuf;
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

const FAKE_SDK_SCRIPT: &str = r#"
import json, os, sys
out = os.environ.get("MVM_SDK_OUT_PATH")
if not out:
    sys.exit("MVM_SDK_OUT_PATH unset")
recording = {
    "workload_id": "etl-plan-mode",
    "create": {
        "template": "python-3.12",
        "env": {},
        "include": [],
        "tags": {},
        "ttl_seconds": 1800,
    },
    "ops": [
        {"kind": "command_start", "argv": ["python", "run.py"], "env": {}},
    ],
}
with open(out, "w") as f:
    json.dump(recording, f)
"#;

fn python_on_path() -> Option<PathBuf> {
    which::which("python3")
        .ok()
        .or_else(|| which::which("python").ok())
}

/// Build the `mvmctl run --mode plan <script>` invocation against a
/// hermetic `$HOME` so the test never writes into the real user's
/// `~/.mvm/keys/` or `~/.mvm/audit/`. Returns the built `Command`
/// ready for `.output()`.
fn mvmctl_run_plan_cmd(home_dir: &std::path::Path) -> Command {
    // `cargo_bin` is the established pattern across this repo's
    // integration tests; the deprecation warning tracks an upstream
    // assert_cmd transition unrelated to this change.
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl binary");
    cmd.env("HOME", home_dir);
    cmd.env("MVM_HOME", home_dir.join("mvm-state"));
    cmd.env_remove("MVM_SDK_MODE");
    cmd
}

#[test]
fn run_plan_mode_admits_clean_recording_and_exits_zero() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping run_plan_mode_admits_clean_recording: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("hello.py");
    std::fs::write(&script, FAKE_SDK_SCRIPT).unwrap();

    let home = TempDir::new().unwrap();

    let mut cmd = mvmctl_run_plan_cmd(home.path());
    cmd.env("MVM_PYTHON", &python)
        .arg("run")
        .arg("--mode")
        .arg("plan")
        .arg(&script);

    let output = cmd.output().expect("spawn mvmctl run --mode plan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "mvmctl run --mode plan must exit 0 on a clean recording.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("ADMITTED"),
        "expected an ADMITTED line on stdout; got:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("plan_id=") && stdout.contains("signer=host:"),
        "ADMITTED line missing plan_id / signer hints; got:\n{stdout}"
    );
}

#[test]
fn run_prod_alias_redirects_to_mvmctl_build_compile() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("hello.py");
    std::fs::write(&script, "print('noop')\n").unwrap();

    let home = TempDir::new().unwrap();
    let output = mvmctl_run_plan_cmd(home.path())
        .arg("run")
        .arg("--prod")
        .arg(&script)
        .output()
        .expect("spawn mvmctl run --prod");

    assert!(
        !output.status.success(),
        "mvmctl run --prod must fail and redirect"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mvmctl build compile"),
        "--prod must redirect users to `mvmctl build compile` — the verb as it is \
         actually spelled, since a redirect naming a command that does not parse \
         is worse than no redirect; stderr was:\n{stderr}"
    );
}

#[test]
fn run_mode_plan_rejects_non_script_extension() {
    let tmp = TempDir::new().unwrap();
    let not_a_script = tmp.path().join("ir.json");
    std::fs::write(&not_a_script, "{}").unwrap();
    let home = TempDir::new().unwrap();

    let output = mvmctl_run_plan_cmd(home.path())
        .arg("run")
        .arg("--mode")
        .arg("plan")
        .arg(&not_a_script)
        .output()
        .expect("spawn mvmctl run --mode plan ir.json");

    assert!(
        !output.status.success(),
        "plan mode must reject a non-script extension"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".py") || stderr.contains(".ts") || stderr.contains(".js"),
        "expected the language-extension hint in stderr; got:\n{stderr}"
    );
}
