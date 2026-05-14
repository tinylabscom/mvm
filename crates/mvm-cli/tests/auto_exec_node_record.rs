//! Phase 7f — Node auto-exec end-to-end test.
//!
//! Mirrors `auto_exec_python_record.rs`: spawns a stand-alone JS
//! script that emits a wire-shape recording to
//! `$MVM_SDK_OUT_PATH`, then exercises the same lowering the CLI
//! goes through. Skips when no `node` is on PATH (vitest already
//! covers the SDK-side `flushRecordingToOutPath` independently).
//!
//! The fixture is plain JavaScript so the test doesn't depend on
//! a TypeScript runner being installed on the runner — the `tsx`
//! path is covered by manual smoke until the integration runner
//! provisions one.

use std::process::Command;

use tempfile::TempDir;

const FAKE_SDK_JS: &str = r#"
'use strict';
const fs = require('node:fs');
const out = process.env.MVM_SDK_OUT_PATH;
if (!out) { process.exit(2); }
const recording = {
    workload_id: "etl-test-node",
    create: {
        template: "node-22",
        env: {},
        include: [],
        tags: {},
        ttl_seconds: 1800,
    },
    ops: [
        { kind: "command_start", argv: ["node", "run.js"], env: {} },
    ],
};
fs.writeFileSync(out, JSON.stringify(recording));
"#;

fn node_on_path() -> Option<std::path::PathBuf> {
    which::which("node").ok()
}

#[test]
fn auto_exec_node_script_emits_recording_and_compile_lowers_it() {
    let Some(node) = node_on_path() else {
        eprintln!("skipping auto_exec_node_script: no node on PATH");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("fake-sdk-script.cjs");
    std::fs::write(&script, FAKE_SDK_JS).unwrap();

    let out_recording = tmp.path().join("rec.json");

    let status = Command::new(&node)
        .arg(&script)
        .env("MVM_SDK_MODE", "record")
        .env("MVM_SDK_OUT_PATH", &out_recording)
        .status()
        .expect("spawn node");
    assert!(status.success(), "node exited {status:?}");
    assert!(out_recording.exists(), "recording not written");

    let bytes = std::fs::read(&out_recording).unwrap();
    let recording: mvm_sdk::runtime::RuntimeRecording =
        serde_json::from_slice(&bytes).expect("recording JSON parses");
    let workload =
        mvm_sdk::runtime::compile_recording(&recording).expect("lowering succeeds");

    assert_eq!(workload.id, "etl-test-node");
    let app = &workload.apps[0];
    // node-22 template → nodejs_22 nix package.
    match &app.image {
        mvm_ir::Image::NixPackages { packages } => {
            assert!(
                packages.iter().any(|p| p == "nodejs_22"),
                "expected nodejs_22 package, got {packages:?}"
            );
        }
        other => panic!("expected NixPackages, got {other:?}"),
    }
    match &app.entrypoints[0] {
        mvm_ir::Entrypoint::Command { command, .. } => {
            assert_eq!(command, &vec!["node".to_string(), "run.js".into()]);
        }
        other => panic!("expected Command entrypoint, got {other:?}"),
    }
}

#[test]
fn auto_exec_node_handles_script_that_did_not_emit_recording() {
    let Some(node) = node_on_path() else {
        eprintln!("skipping auto_exec_node_handles_script: no node on PATH");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noop.cjs");
    std::fs::write(&script, "process.exit(0);").unwrap();
    let out_recording = tmp.path().join("rec.json");
    let status = Command::new(&node).arg(&script).status().unwrap();
    assert!(status.success());
    assert!(!out_recording.exists());
}
