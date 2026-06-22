//! Followup H-live end-to-end test (Plan 73).
//!
//! Mirrors the `run_plan_mode.rs` pattern, but for the live
//! transport. The test stands up:
//!
//! - A fixture `mvmctl` shell script (the "fake mvmctl") that
//!   records each invocation's argv and emits the
//!   `mvmctl machine run --up-json` envelope the SDK expects.
//! - A real `mvmctl run --mode live <script>` invocation that
//!   spawns the user script with `MVM_SDK_MODE=live` +
//!   `MVM_CLI_BIN=<fixture>`.
//! - A user Python script that constructs a `Sandbox` and calls
//!   one `commands.start`.
//!
//! What the test asserts:
//!
//! 1. `mvmctl run --mode live` spawns the user script with the
//!    right env vars (the fixture verifies `MVM_CLI_BIN` was set
//!    by writing the binary path into its own log).
//! 2. The SDK shells `mvmctl machine run --up-json` and parses the envelope.
//! 3. The SDK shells `mvmctl machine proc start` against the dev VM.
//! 4. The SDK shells `mvmctl machine stop` on `Sandbox.__exit__`.
//! 5. Against a prod-template envelope, the SDK raises
//!    `SandboxDevOnly` *before* any `proc start` shell — security
//!    claim 4 enforcement.
//!
//! No real microVM boots. Skips when no `python3`/`python` is on
//! PATH.

use std::path::PathBuf;
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

const USER_SCRIPT_DEV: &str = r#"
import mvm

sb = mvm.Sandbox.create("python-dev", workload_id="livehello")
sb.commands.start(["echo", "hi"], env={"MODE": "test"})
sb.files.write("/app/data.bin", b"hello")
sb.kill()
"#;

const USER_SCRIPT_PROD_REJECTED: &str = r#"
import mvm, sys

sb = mvm.Sandbox.create("python-prod", workload_id="liveprod")
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

/// Write a fixture `mvmctl` shell script that records its argv to a
/// log file and emits the requested envelope on `machine run --up-json`.
fn write_fixture_mvmctl(dir: &std::path::Path, build_mode: &str) -> PathBuf {
    let log = dir.join("fixture-calls.log");
    let stdin_dir = dir.join("fixture-stdin");
    std::fs::create_dir_all(&stdin_dir).unwrap();
    let envelope =
        format!(r#"{{"schema_version": 1, "vm_id": "sb-itest-vm", "build_mode": "{build_mode}"}}"#);

    let script_path = dir.join("fake-mvmctl");
    let script_body = format!(
        r#"#!/usr/bin/env bash
set -u
verb=${{1:-}}
shift || true
echo "$verb $*" >> {log}
if [ "$verb" = "machine" ]; then
  verb=${{1:-}}
  shift || true
fi
case "$verb" in
  run)
    echo '{envelope}'
    exit 0
    ;;
  proc)
    if [ "${{1:-}}" = "start" ]; then
      echo "pid-token-itest"
    fi
    exit 0
    ;;
  fs)
    if [ "${{1:-}}" = "write" ]; then
      cat > {stdin_dir}/fs-write-stdin.bin
    fi
    exit 0
    ;;
  stop)
    exit 0
    ;;
  *)
    echo "fake-mvmctl: unrecognized verb $verb" >&2
    exit 2
    ;;
esac
"#,
        log = log.display(),
        envelope = envelope,
        stdin_dir = stdin_dir.display(),
    );
    std::fs::write(&script_path, script_body).unwrap();
    let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms).unwrap();
    script_path
}

fn read_fixture_log(dir: &std::path::Path) -> Vec<String> {
    let log = dir.join("fixture-calls.log");
    if !log.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Build the `mvmctl run --mode live <script>` invocation. The
/// fixture `mvmctl` shell script lives in `fixture_dir`; we point
/// the SDK at it via `MVM_CLI_BIN` — except that's set by the verb
/// itself, so we instead provide a wrapper script that, when
/// invoked by `mvmctl run --mode live`, hijacks `MVM_CLI_BIN`
/// before reaching the SDK.
///
/// In practice the verb sets `MVM_CLI_BIN=<current_exe>`. To
/// avoid a real `mvmctl machine run` going out and trying to boot a VM,
/// the test overrides `MVM_CLI_BIN` directly via `Command::env`
/// after the verb sets it — that's not possible because the verb
/// is the spawner. So instead the test inlines the env override
/// by running the user script directly with `MVM_SDK_MODE=live`
/// and `MVM_CLI_BIN=<fixture>` — bypassing `mvmctl run --mode
/// live`. A separate test below asserts that the verb itself
/// dispatches; this one asserts the SDK transport.
#[allow(dead_code)]
fn _phantom_doc() {}

#[test]
fn sdk_live_dev_template_shells_to_proc_start() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping sdk_live_dev_template: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("hello.py");
    std::fs::write(&script, USER_SCRIPT_DEV).unwrap();
    let fixture = write_fixture_mvmctl(tmp.path(), "dev");

    // Run the user script directly under MVM_SDK_MODE=live with
    // the fixture mvmctl. This is the inner half of what `mvmctl
    // run --mode live` does — the verb just spawns the script
    // with the same env vars.
    let mut cmd = Command::new(&python);
    cmd.env("MVM_SDK_MODE", "live")
        .env("MVM_CLI_BIN", &fixture)
        .env(
            "PYTHONPATH",
            std::env::current_dir().unwrap().join("sdks/python"),
        )
        .arg(&script);

    let output = cmd.output().expect("spawn user script");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "live-mode user script must exit 0.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    let calls = read_fixture_log(tmp.path());
    // 1: machine run --up-json, 2: machine proc start, 3: machine fs write, 4: machine stop
    assert!(
        calls.len() >= 4,
        "expected >= 4 mvmctl shells (machine run, machine proc start, machine fs write, machine stop); got {calls:?}"
    );
    assert!(
        calls[0].starts_with("machine run -d --up-json"),
        "first shell must be `machine run -d --up-json`, got {:?}",
        calls[0]
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("machine proc start sb-itest-vm")),
        "expected a `machine proc start sb-itest-vm` shell; got {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("machine fs write sb-itest-vm /app/data.bin")),
        "expected a `machine fs write sb-itest-vm /app/data.bin` shell; got {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("machine stop sb-itest-vm")),
        "expected a `machine stop sb-itest-vm` shell; got {calls:?}"
    );
}

#[test]
fn sdk_live_prod_template_raises_sandbox_dev_only_before_proc_start() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping sdk_live_prod_template: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("prod.py");
    std::fs::write(&script, USER_SCRIPT_PROD_REJECTED).unwrap();
    let fixture = write_fixture_mvmctl(tmp.path(), "prod");

    let mut cmd = Command::new(&python);
    cmd.env("MVM_SDK_MODE", "live")
        .env("MVM_CLI_BIN", &fixture)
        .env(
            "PYTHONPATH",
            std::env::current_dir().unwrap().join("sdks/python"),
        )
        .arg(&script);

    let output = cmd.output().expect("spawn prod user script");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "user script handles SandboxDevOnly itself and exits 0.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("DEVONLY_REJECTED"),
        "expected the user script's SandboxDevOnly handler to fire; stderr was:\n{stderr}"
    );

    let calls = read_fixture_log(tmp.path());
    assert!(
        !calls.iter().any(|c| c.starts_with("machine proc")),
        "SDK must NOT have shelled to `mvmctl proc start` against a prod template (security claim 4 client-side enforcement); but the fixture saw: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("machine run -d --up-json")),
        "the `machine run` boot shell must still have fired; got {calls:?}"
    );
}

#[test]
fn run_mode_live_dispatches_to_user_script() {
    let Some(python) = python_on_path() else {
        eprintln!("skipping run_mode_live_dispatches: no python3/python on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noop.py");
    // No-op script — we only assert that mvmctl run --mode live
    // spawns it under MVM_SDK_MODE=live + MVM_CLI_BIN. The script
    // writes a sentinel file so we can confirm it ran.
    let sentinel = tmp.path().join("ran-under-live.flag");
    std::fs::write(
        &script,
        format!(
            r#"
import os, sys
mode = os.environ.get("MVM_SDK_MODE", "")
mvm_bin = os.environ.get("MVM_CLI_BIN", "")
with open(r"{sentinel}", "w") as f:
    f.write(f"mode={{mode}} mvm_bin_set={{bool(mvm_bin)}}")
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
        .arg("--mode")
        .arg("live")
        .arg(&script);

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
        sentinel_contents.contains("mvm_bin_set=True"),
        "MVM_CLI_BIN must be set by the verb; got: {sentinel_contents}"
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
