//! End-to-end test for the Phase 7d runtime record-mode pipeline:
//! a `RuntimeRecording` JSON → `compile_recording` lowering →
//! `compile` flake render. Pairs with the unit tests in
//! `src/runtime.rs` — those test the lowering in isolation; this
//! one exercises the full record-mode-to-flake chain so a future
//! refactor doesn't drift between the two stages.

use std::fs;

use mvm_sdk::compile::compile;
use mvm_sdk::runtime::{RuntimeRecording, compile_recording};

fn write_python_file(dir: &std::path::Path, name: &str, body: &str) {
    fs::write(dir.join(name), body).unwrap();
}

#[test]
fn recording_json_round_trips_through_compile_pipeline() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    write_python_file(
        &src_dir,
        "run.py",
        "def main():\n    print('hello from record-mode')\n",
    );

    // Hand-write the recording the way the Python SDK would emit it.
    let recording_json = serde_json::json!({
        "workload_id": "etl",
        "create": {
            "template": "python-3.12",
            "env": {},
            "include": [],
            "tags": {},
            "ttl_seconds": 1800
        },
        "ops": [
            {
                "kind": "files_write",
                "path": "/app/note.txt",
                "bytes_b64": "aGkK"
            },
            {
                "kind": "command_start",
                "argv": ["python", "src/run.py"],
                "env": {}
            }
        ]
    });
    let recording: RuntimeRecording = serde_json::from_value(recording_json).unwrap();

    // Lower into Workload. This is the boundary the CLI's
    // `--from-recording` flag crosses.
    let workload = compile_recording(&recording).expect("lowering succeeds");
    assert_eq!(workload.id, "etl");
    assert_eq!(workload.apps.len(), 1);
    let app = &workload.apps[0];
    // Final CommandStart → entrypoint.
    match &app.entrypoints[0] {
        mvm_sdk::ir::Entrypoint::Command { command, .. } => {
            assert_eq!(command, &vec!["python".to_string(), "src/run.py".into()]);
        }
        other => panic!("expected Command entrypoint, got {other:?}"),
    }
    // FilesWrite → App.files entry (baked at build time, not a shell hook).
    assert!(
        app.hooks.before_start.is_empty(),
        "FilesWrite must not produce a before_start hook"
    );
    assert_eq!(app.files.len(), 1);
    assert_eq!(app.files[0].path, "/app/note.txt");
    {
        use base64::Engine;
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(b"hi\n");
        assert_eq!(
            app.files[0].bytes_b64, expected_b64,
            "bytes_b64 must match base64 of 'hi\\n'"
        );
    }

    // Compile the lowered workload into a flake-bundled directory.
    let out = tmp.path().join("out");
    compile(&workload, &out, tmp.path()).expect("flake compile succeeds");

    // The compile pipeline must emit a flake.nix at least.
    assert!(
        out.join("flake.nix").exists(),
        "flake.nix not emitted at {}",
        out.display()
    );

    // The declarative file must ride into launch.json (the sidecar the
    // generated flake reads at evaluation time) so mkFunctionService can
    // base64-decode it into the rootfs at build time.
    let launch: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("launch.json")).unwrap()).unwrap();
    let files = launch["files"].as_array().expect("launch.files array");
    assert_eq!(files.len(), 1, "launch.files carries the one declared file");
    assert_eq!(files[0]["path"], "/app/note.txt");
    assert_eq!(files[0]["bytes_b64"], "aGkK", "base64 of 'hi\\n'");

    // The flake must thread launch.files into the factory call so the
    // bake actually fires.
    let flake = fs::read_to_string(out.join("flake.nix")).unwrap();
    assert!(
        flake.contains("files = launch.files or [ ]"),
        "flake must pass launch.files into mkFunctionService"
    );
}

#[test]
fn recording_with_no_command_start_fails_lowering() {
    let recording = RuntimeRecording {
        workload_id: "no-cmd".into(),
        create: mvm_sdk::runtime::SandboxCreate {
            template: Some("python-3.12".into()),
            image: None,
            env: Default::default(),
            include: vec![],
            tags: Default::default(),
            ttl_seconds: Some(60),
            resources: None,
            network: None,
        },
        ops: vec![mvm_sdk::runtime::RecordedOp::Kill],
    };
    let err = compile_recording(&recording).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no `Sandbox.commands.start") || msg.contains("entrypoint"),
        "got: {msg}"
    );
}
