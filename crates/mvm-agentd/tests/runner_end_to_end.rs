//! End-to-end integration test: spawn the runtime binary against a
//! handcrafted runtime.json + dispatch fragment, pipe stdin, assert
//! stdout/stderr/exit-code.
//!
//! The fragment is a tiny shell script (not a real Python/Node
//! interpreter) so the test runs on any host where `/bin/sh` exists —
//! the runtime itself does not need a real Python interpreter to be
//! exercised here. Real Python/Node dispatch is covered by
//! `just real-mvm-check` against a generated function-runner artifact.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mvm-runner"))
}

fn write_config(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("runtime.json");
    fs::write(
        &path,
        r#"{
            "language": "python",
            "module": "adder",
            "function": "add",
            "format": "json",
            "source_path": "/app"
        }"#,
    )
    .unwrap();
    path
}

/// Replace the runtime's view of `python3` with a sh shim that:
/// - prints the env vars the runtime should have set,
/// - cats stdin to stdout,
/// - exits 0 (or non-zero if the test wants).
fn write_sh_dispatcher(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("dispatch.py");
    fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
    }
    path
}

#[test]
fn happy_path_passes_stdin_and_env_through_to_dispatch() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = write_config(tmp.path());
    let dispatch_dir = tmp.path();
    // Write a fake `dispatch.py` that's actually a shell script.
    // The runtime invokes `python3 dispatch.py`; we override
    // `python3` to `/bin/sh` via the test config below so the file is
    // run by sh.
    write_sh_dispatcher(
        dispatch_dir,
        "#!/bin/sh\n\
         echo \"module=$MVM_MODULE function=$MVM_FUNCTION format=$MVM_FORMAT\"\n\
         cat\n",
    );

    // The runtime hard-codes `python3` as the Python interpreter
    // command. We can't override that without touching the binary
    // itself, so for the integration test we patch the dispatcher
    // *file* to be sh-compatible and override the dispatch_dir env
    // var; then we run the runner under a PATH that points `python3`
    // at `/bin/sh`. We do that with a tiny shim directory.
    let shim_dir = tmp.path().join("bin");
    fs::create_dir(&shim_dir).unwrap();
    let python3_shim = shim_dir.join("python3");
    fs::write(&python3_shim, "#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&python3_shim).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&python3_shim, perms).unwrap();
    }

    let mut child = Command::new(binary_path())
        .env("MVM_RUNTIME_CONFIG", &config_path)
        .env("MVM_RUNTIME_DISPATCH_DIR", dispatch_dir)
        .env(
            "PATH",
            format!(
                "{}:{}",
                shim_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"[2,3]").unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "runtime exited non-zero. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("module=adder"), "stdout: {stdout}");
    assert!(stdout.contains("function=add"), "stdout: {stdout}");
    assert!(stdout.contains("format=json"), "stdout: {stdout}");
    assert!(
        stdout.contains("[2,3]"),
        "stdin not piped through: {stdout}"
    );
}

#[test]
fn missing_runtime_json_emits_config_invalid_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("does-not-exist.json");
    let output = Command::new(binary_path())
        .env("MVM_RUNTIME_CONFIG", &bogus)
        .env("MVM_RUNTIME_DISPATCH_DIR", tmp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"kind\":\"config_invalid\""),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("\"error_id\":"), "stderr: {stderr}");
    // Critical invariant: never log payload bytes or the path that
    // failed. Only the static template message.
    assert!(
        !stderr.contains("does-not-exist"),
        "stderr leaked path: {stderr}"
    );
}

#[test]
fn malformed_runtime_json_emits_config_invalid_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("runtime.json");
    fs::write(&path, br#"{ "runtime": "rust" }"#).unwrap();
    let output = Command::new(binary_path())
        .env("MVM_RUNTIME_CONFIG", &path)
        .env("MVM_RUNTIME_DISPATCH_DIR", tmp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"kind\":\"config_invalid\""),
        "stderr: {stderr}"
    );
}

#[test]
fn child_exit_nonzero_surfaces_child_failed_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = write_config(tmp.path());
    write_sh_dispatcher(tmp.path(), "#!/bin/sh\nexit 7\n");
    let shim_dir = tmp.path().join("bin");
    fs::create_dir(&shim_dir).unwrap();
    let python3_shim = shim_dir.join("python3");
    fs::write(&python3_shim, "#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&python3_shim).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&python3_shim, perms).unwrap();
    }

    let output = Command::new(binary_path())
        .env("MVM_RUNTIME_CONFIG", &config_path)
        .env("MVM_RUNTIME_DISPATCH_DIR", tmp.path())
        .env(
            "PATH",
            format!(
                "{}:{}",
                shim_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"kind\":\"child_failed\""),
        "stderr: {stderr}"
    );
}
