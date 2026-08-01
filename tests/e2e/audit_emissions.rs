//! E2E coverage for the invariant that every state-changing CLI
//! verb writes one local audit entry. Each test isolates the mvmctl
//! root under a fresh tempdir via `MVM_HOME`, runs the verb, and reads
//! back `<root>/state/log/audit.jsonl` to confirm a JSONL line with
//! the expected `kind` shows up.

use super::harness::mvmctl;
use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

struct IsolatedEnv {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    cache: PathBuf,
}

impl IsolatedEnv {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("mvm-root");
        let cache = root.join("cache");
        Self {
            _tmp: tmp,
            root,
            cache,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = mvmctl();
        cmd.env("HOME", &self.root).env("MVM_HOME", &self.root);
        cmd
    }

    fn audit_log(&self) -> PathBuf {
        self.root.join("state").join("log").join("audit.jsonl")
    }
}

fn read_audit_kinds(path: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(path).expect("audit log should exist");
    raw.lines()
        .map(|line| {
            let v: Value = serde_json::from_str(line).expect("audit line is valid JSON");
            v["kind"].as_str().expect("kind is a string").to_string()
        })
        .collect()
}

#[test]
fn cache_prune_emits_cache_prune_when_dir_missing() {
    let env = IsolatedEnv::new();

    env.cmd().args(["cache", "prune"]).assert().success();

    let kinds = read_audit_kinds(&env.audit_log());
    assert!(
        kinds.iter().any(|k| k == "cache_prune"),
        "expected cache_prune in audit log, got {kinds:?}",
    );
}

#[test]
fn cache_prune_dry_run_does_not_emit() {
    let env = IsolatedEnv::new();
    std::fs::create_dir_all(&env.cache).unwrap();

    env.cmd()
        .args(["cache", "prune", "--dry-run"])
        .assert()
        .success();

    // dry-run is a read-only verb — Plan 37 §6 explicitly excludes it.
    assert!(
        !env.audit_log().exists(),
        "dry-run must not write the audit log"
    );
}

#[test]
fn manifest_prune_orphans_emits_slot_prune() {
    let env = IsolatedEnv::new();

    env.cmd()
        .args(["manifest", "prune", "--orphans", "--json"])
        .assert()
        .success();

    let kinds = read_audit_kinds(&env.audit_log());
    assert!(
        kinds.iter().any(|k| k == "slot_prune"),
        "expected slot_prune in audit log, got {kinds:?}",
    );
}
