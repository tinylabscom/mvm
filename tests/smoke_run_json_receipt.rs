//! Live smoke for `mvmctl run --json --receipt`.
//!
//! The normal unit tests cover the redaction and signature machinery without
//! booting a guest. This smoke exercises the public CLI contract end-to-end:
//! run a command in a transient microVM, emit the redacted JSON summary, write a
//! signed receipt, and assert the two artifacts agree.
//!
//! ## Why this is gated
//!
//! `mvmctl run` boots a microVM and may build the default image. That requires
//! the project builder VM / Linux microVM runtime boundary and is intentionally
//! not portable across every developer host or CI job. `MVM_LIVE_SMOKE=1` is the
//! operator's fence.
//!
//! ## Optional manifest
//!
//! Set `MVM_RUN_SMOKE_MANIFEST=/path/to/mvm.toml` to run against a pre-built
//! smoke manifest. If unset, the command uses the bundled default image path,
//! which is useful for catching JSON-mode stdout contamination in the default
//! image resolver.

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const SMOKE_GATE: &str = "MVM_LIVE_SMOKE";
const MANIFEST_VAR: &str = "MVM_RUN_SMOKE_MANIFEST";
const STDOUT_SECRET: &str = "run-json-stdout-secret";
const STDERR_SECRET: &str = "run-json-stderr-secret";

struct SmokeSandbox {
    home: TempDir,
}

impl SmokeSandbox {
    fn new() -> Self {
        let sandbox = Self {
            home: tempfile::tempdir().expect("tempdir"),
        };
        sandbox.seed_cached_runtime_caches();
        sandbox
    }

    fn path(&self) -> &Path {
        self.home.path()
    }

    fn receipt_path(&self) -> PathBuf {
        self.path().join("run-receipt.json")
    }

    fn mvmctl(&self) -> Command {
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin("mvmctl").expect("cargo_bin mvmctl");
        cmd.env("HOME", self.path())
            .env("MVM_HOME", self.path().join("mvm-home"));
        cmd
    }

    fn scratch_cache(&self) -> PathBuf {
        self.path().join("mvm-home/cache")
    }

    fn seed_cached_runtime_caches(&self) {
        for cache_subdir in ["host-bins", "default-microvm"] {
            let source_root = PathBuf::from(mvm_core::config::mvm_cache_dir()).join(cache_subdir);
            let dest_root = self.scratch_cache().join(cache_subdir);
            sync_tree_if_missing(&source_root, &dest_root)
                .unwrap_or_else(|e| panic!("seed cached {cache_subdir} into scratch cache: {e}"));
        }
    }

    fn persist_cached_runtime_caches(&self) {
        for cache_subdir in ["host-bins", "default-microvm"] {
            let source_root = self.scratch_cache().join(cache_subdir);
            let dest_root = PathBuf::from(mvm_core::config::mvm_cache_dir()).join(cache_subdir);
            sync_tree_if_missing(&source_root, &dest_root).unwrap_or_else(|e| {
                panic!("persist scratch {cache_subdir} back into operator cache: {e}")
            });
        }
    }
}

impl Drop for SmokeSandbox {
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.persist_cached_runtime_caches();
        }));
    }
}

fn sync_tree_if_missing(source_root: &Path, dest_root: &Path) -> std::io::Result<()> {
    if !source_root.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(source_root)? {
        let entry = entry?;
        let source = entry.path();
        let dest = dest_root.join(entry.file_name());
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        copy_tree_if_missing(&source, &dest)?;
    }
    Ok(())
}

fn copy_tree_if_missing(source: &Path, dest: &Path) -> std::io::Result<()> {
    if dest.exists() {
        return Ok(());
    }
    if source.is_dir() {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let child_source = entry.path();
            let child_dest = dest.join(entry.file_name());
            copy_tree_if_missing(&child_source, &child_dest)?;
        }
        return Ok(());
    }
    std::fs::copy(source, dest)?;
    Ok(())
}

fn smoke_enabled() -> bool {
    std::env::var(SMOKE_GATE).as_deref() == Ok("1")
}

#[test]
fn run_json_receipt_smoke_gate_is_documented() {
    assert_eq!(SMOKE_GATE, "MVM_LIVE_SMOKE");
    assert_eq!(MANIFEST_VAR, "MVM_RUN_SMOKE_MANIFEST");
}

#[test]
fn run_json_and_receipt_agree_without_raw_output() {
    if !smoke_enabled() {
        eprintln!(
            "[smoke_run_json_receipt] skipped - set {SMOKE_GATE}=1 to boot a \
             real transient microVM. Optionally set {MANIFEST_VAR}=/path/to/mvm.toml."
        );
        return;
    }

    let sandbox = SmokeSandbox::new();
    let receipt_path = sandbox.receipt_path();
    let receipt_arg = receipt_path.to_string_lossy().into_owned();
    let mut args = vec![
        "run".to_string(),
        "--json".to_string(),
        "--receipt".to_string(),
        receipt_arg.clone(),
        "--timeout".to_string(),
        "30".to_string(),
    ];
    if let Some(manifest) = std::env::var_os(MANIFEST_VAR) {
        args.push("--manifest".to_string());
        args.push(manifest.to_string_lossy().into_owned());
    }
    args.extend([
        "--".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("printf {STDOUT_SECRET}; printf {STDERR_SECRET} >&2"),
    ]);

    let output = sandbox
        .mvmctl()
        .args(&args)
        .output()
        .expect("spawn mvmctl run --json --receipt");
    assert!(
        output.status.success(),
        "mvmctl run --json --receipt failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("json stdout is utf-8");
    let summary: Value =
        serde_json::from_str(&stdout).expect("stdout must contain only the JSON summary");
    let receipt_text = std::fs::read_to_string(&receipt_path).expect("receipt file");
    let receipt: Value = serde_json::from_str(&receipt_text).expect("receipt json");

    assert_eq!(summary["schema_version"], Value::from(1));
    assert_eq!(summary["receipt_path"], Value::from(receipt_arg));
    assert_eq!(summary["invocation"], receipt["payload"]["invocation"]);
    assert_eq!(summary["outcome"], receipt["payload"]["outcome"]);
    assert_eq!(summary["outcome"]["exit_code"], Value::from(0));
    assert_eq!(summary["outcome"]["success"], Value::from(true));

    let combined_artifacts = format!("{stdout}\n{receipt_text}");
    assert!(
        !combined_artifacts.contains(STDOUT_SECRET),
        "JSON summary/receipt must not expose raw guest stdout"
    );
    assert!(
        !combined_artifacts.contains(STDERR_SECRET),
        "JSON summary/receipt must not expose raw guest stderr"
    );
    assert_eq!(
        summary["outcome"]["stdout_bytes"],
        Value::from(STDOUT_SECRET.len())
    );
    assert_eq!(
        summary["outcome"]["stderr_bytes"],
        Value::from(STDERR_SECRET.len())
    );
}
