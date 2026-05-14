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
        mvm_ir::Entrypoint::Command { command, .. } => {
            assert_eq!(command, &vec!["python".to_string(), "src/run.py".into()]);
        }
        other => panic!("expected Command entrypoint, got {other:?}"),
    }
    // FilesWrite → before_start shell hook.
    assert_eq!(app.hooks.before_start.len(), 1);
    match &app.hooks.before_start[0] {
        mvm_ir::HookCmd::Shell { line } => assert!(
            line.contains("/app/note.txt") && line.contains("base64 -d"),
            "got: {line}"
        ),
        other => panic!("expected Shell hook, got {other:?}"),
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
}

#[test]
fn recording_with_no_command_start_fails_lowering() {
    let recording = RuntimeRecording {
        workload_id: "no-cmd".into(),
        create: mvm_sdk::runtime::SandboxCreate {
            template: "python-3.12".into(),
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
