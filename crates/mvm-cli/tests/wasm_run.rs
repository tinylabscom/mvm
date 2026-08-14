//! End-to-end test for `mvmctl machine run --hypervisor wasm`.
//!
//! This exercises the full transient launch path for a wasm32-wasip1 module:
//! manifest parsing, backend selection, launch resolution, and the wasm-specific
//! "no guest agent" run path. It requires the `wasm-backend` feature so that
//! host `wasmtime` is compiled in.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

#[test]
#[cfg(feature = "wasm-backend")]
fn machine_run_wasm_module_prints_and_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mvm_home = tmp.path().to_path_buf();

    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/wasm-hello/fixture/mvm.toml");
    assert!(
        manifest.is_file(),
        "wasm fixture manifest missing: {}",
        manifest.display()
    );

    let mut cmd = Command::cargo_bin("mvmctl").expect("mvmctl binary");
    cmd.arg("machine")
        .arg("run")
        .arg("--hypervisor")
        .arg("wasm")
        .arg("--manifest")
        .arg(&manifest)
        .env("MVM_HOME", &mvm_home);

    let output = cmd.output().expect("spawn mvmctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "wasm run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("hello from wasm"),
        "expected wasm output in stdout: {stdout:?}"
    );
}
