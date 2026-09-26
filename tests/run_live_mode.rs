//! Live-mode end-to-end tests.
//!
//! Two halves:
//!
//! - A user Python script run under `MVM_SDK_MODE=live` drives a `Sandbox`
//!   through the SDK's host-library transport. The script replaces the one C
//!   call (`mvm._hostlib._invoke`) with a recorder, so the test sees exactly
//!   which methods the SDK called, in order, with no library and no microVM.
//! - A real `mvmctl run --mode live <script>` spawns the user script with
//!   `MVM_SDK_MODE=live`, and names the host library beside itself when one
//!   is there. It never hands the script a CLI to run.
//!
//! What the tests assert:
//!
//! 1. A dev machine's `Sandbox` calls `machine.run`, `guest.proc.start`,
//!    `guest.fs.write` and `machine.stop`, and nothing else.
//! 2. Against a prod machine, the SDK raises `SandboxDevOnly` before any
//!    `guest.*` call — security claim 4, enforced client-side as well as by
//!    the guest agent.
//! 3. `mvmctl run --mode live` sets the mode, and sets `MVM_HOSTLIB_PATH`
//!    exactly when the library sits beside the binary.
//!
//! Skips when no `python3`/`python` is on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

/// Installs a recording seam in place of the library call. Each call is
/// appended to the file named by `MVM_TEST_CALL_LOG` as one JSON line, and
/// answered from `REPLIES`. `BUILD_MODE` is substituted per test.
const RECORDER: &str = r#"
import json, os
from mvm import _hostlib

REPLIES = {
    "machine.run": {
        "machine": {"id": "sb-itest-vm", "name": "sb-itest-vm", "status": "running"},
        "plan_id": "plan-itest",
        "build_mode": "BUILD_MODE",
    },
    "guest.proc.start": {"token": "pid-token-itest"},
    "guest.fs.write": {"bytes_written": 5},
    "machine.stop": {},
}

def _record(method, request_json):
    with open(os.environ["MVM_TEST_CALL_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps([method, json.loads(request_json) if request_json else None]) + "\n")
    return 0, json.dumps(REPLIES[method]).encode()

_hostlib._invoke = _record
"#;

const USER_SCRIPT_DEV: &str = r#"
import mvm

sb = mvm.Sandbox.create(image="docker.io/library/python:3.12-slim", workload_id="livehello")
sb.commands.start(["echo", "hi"], env={"MODE": "test"})
sb.files.write("/app/data.bin", b"hello")
sb.kill()
"#;

const USER_SCRIPT_PROD_REJECTED: &str = r#"
import mvm, sys

sb = mvm.Sandbox.create(image="docker.io/library/python:3.12-slim", workload_id="liveprod")
try:
    sb.commands.start(["echo", "hi"])
except mvm.SandboxDevOnly as exc:
    print(f"DEVONLY_REJECTED: {exc}", file=sys.stderr)
    sb.kill()
    sys.exit(0)
else:
    print("UNEXPECTED: commands.start did not raise SandboxDevOnly", file=sys.stderr)
    sys.exit(1)
"#;

fn python_on_path() -> Option<PathBuf> {
    which::which("python3")
        .ok()
        .or_else(|| which::which("python").ok())
}

/// Write `body` behind the recorder for `build_mode`, run it under live mode,
/// and return the recorded `[method, request]` calls.
fn run_recorded(
    python: &Path,
    dir: &Path,
    build_mode: &str,
    body: &str,
) -> (std::process::Output, Vec<serde_json::Value>) {
    let script = dir.join("script.py");
    std::fs::write(
        &script,
        format!("{}{body}", RECORDER.replace("BUILD_MODE", build_mode)),
    )
    .unwrap();
    let log = dir.join("calls.jsonl");
    let output = Command::new(python)
        .env("MVM_SDK_MODE", "live")
        .env("MVM_TEST_CALL_LOG", &log)
        .env_remove("MVM_HOSTLIB_PATH")
        .env(
            "PYTHONPATH",
            std::env::current_dir()
                .unwrap()
                .join("crates/mvm-sdk/sdks/python"),
        )
        .arg(&script)
        .output()
        .expect("spawn user script");
    let calls = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("each recorded call is JSON"))
        .collect();
    (output, calls)
}

fn methods(calls: &[serde_json::Value]) -> Vec<&str> {
    calls
        .iter()
        .map(|call| call[0].as_str().expect("a method name"))
        .collect()
}

#[test]
fn sdk_live_dev_machine_drives_the_host_library() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping sdk_live_dev_machine: no python3/python on PATH");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let (output, calls) = run_recorded(&python, tmp.path(), "dev", USER_SCRIPT_DEV);
    assert!(
        output.status.success(),
        "live-mode user script must exit 0.\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        methods(&calls),
        [
            "machine.run",
            "guest.proc.start",
            "guest.fs.write",
            "machine.stop"
        ]
    );
    assert_eq!(calls[0][1]["image"], "docker.io/library/python:3.12-slim");
    assert_eq!(calls[1][1]["id"], "sb-itest-vm");
    assert_eq!(calls[1][1]["argv"], serde_json::json!(["echo", "hi"]));
    assert_eq!(calls[1][1]["env"], serde_json::json!({"MODE": "test"}));
    assert_eq!(calls[2][1]["path"], "/app/data.bin");
    assert_eq!(calls[3][1]["id"], "sb-itest-vm");
}

#[test]
fn sdk_live_prod_machine_raises_sandbox_dev_only_before_any_guest_call() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping sdk_live_prod_machine: no python3/python on PATH");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let (output, calls) = run_recorded(&python, tmp.path(), "prod", USER_SCRIPT_PROD_REJECTED);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the user script handles SandboxDevOnly itself and exits 0.\n--- stderr ---\n{stderr}"
    );
    assert!(stderr.contains("DEVONLY_REJECTED"), "{stderr}");
    let called = methods(&calls);
    assert!(
        !called.iter().any(|m| m.starts_with("guest.")),
        "a prod machine must refuse DevOnly operations before any guest call; got {called:?}"
    );
    assert_eq!(called, ["machine.run", "machine.stop"]);
}

#[test]
fn run_mode_live_dispatches_to_user_script() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping run_mode_live_dispatches: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noop.py");
    // No-op script — we only assert what `mvmctl run --mode live` hands the
    // script it spawns. The script writes a sentinel file so we can confirm
    // it ran and read what it saw.
    let sentinel = tmp.path().join("ran-under-live.flag");
    std::fs::write(
        &script,
        format!(
            r#"
import os, sys
mode = os.environ.get("MVM_SDK_MODE", "")
library = os.environ.get("MVM_HOSTLIB_PATH", "")
cli = os.environ.get("MVM" + "_CLI_BIN", "")
with open(r"{sentinel}", "w") as f:
    f.write(f"mode={{mode}}\nlibrary={{library}}\ncli_set={{bool(cli)}}")
sys.exit(0)
"#,
            sentinel = sentinel.display(),
        ),
    )
    .unwrap();

    let home = TempDir::new().unwrap();
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl binary");
    cmd.env("HOME", home.path())
        .env_remove("MVM_SDK_MODE")
        .env_remove("MVM_HOSTLIB_PATH")
        .env("MVM_PYTHON", &python)
        .arg("run")
        .arg("--mode")
        .arg("live")
        .arg(&script);
    let beside =
        PathBuf::from(env!("CARGO_BIN_EXE_mvmctl")).with_file_name(if cfg!(target_os = "macos") {
            "libmvm_hostlib.dylib"
        } else {
            "libmvm_hostlib.so"
        });

    let output = cmd.output().expect("spawn mvmctl run --mode live");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "mvmctl run --mode live must exit 0 on a clean script.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    let sentinel_contents =
        std::fs::read_to_string(&sentinel).expect("user script must write the sentinel");
    assert!(
        sentinel_contents.contains("mode=live"),
        "MVM_SDK_MODE must be `live` inside the spawned script; got: {sentinel_contents}"
    );
    assert!(
        sentinel_contents.contains("cli_set=False"),
        "the verb must not hand the script a CLI to run; got: {sentinel_contents}"
    );
    let expected_library = if beside.is_file() {
        beside.display().to_string()
    } else {
        String::new()
    };
    assert!(
        sentinel_contents.contains(&format!("library={expected_library}\n")),
        "MVM_HOSTLIB_PATH must name the library beside mvmctl exactly when one is there \
         (expected {expected_library:?}); got: {sentinel_contents}"
    );
}

#[test]
fn run_dev_alias_dispatches_live_mode() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping run_dev_alias_dispatches: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noop.py");
    let sentinel = tmp.path().join("ran-via-dev-alias.flag");
    std::fs::write(
        &script,
        format!(
            r#"
import os, sys
with open(r"{sentinel}", "w") as f:
    f.write(os.environ.get("MVM_SDK_MODE", "(unset)"))
sys.exit(0)
"#,
            sentinel = sentinel.display(),
        ),
    )
    .unwrap();

    let home = TempDir::new().unwrap();
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl binary");
    cmd.env("HOME", home.path())
        .env_remove("MVM_SDK_MODE")
        .env("MVM_PYTHON", &python)
        .arg("run")
        .arg("--dev")
        .arg(&script);

    let output = cmd.output().expect("spawn mvmctl run --dev");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "mvmctl run --dev must dispatch live mode (post-Followup-H-live). stderr was:\n{stderr}"
    );
    let sentinel_contents =
        std::fs::read_to_string(&sentinel).expect("user script must write the sentinel");
    assert_eq!(sentinel_contents.trim(), "live");
}
