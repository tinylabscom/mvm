//! E2E coverage for the Plan 37 §6 invariant: every state-changing CLI
//! verb writes one local audit entry. Each test isolates the mvmctl
//! data/state/cache directories under a fresh tempdir, runs the verb,
//! and reads back `<state>/log/audit.jsonl` to confirm a JSONL line
//! with the expected `kind` shows up.
//!
//! `MVM_DATA_DIR` must be overridden alongside `MVM_STATE_DIR` because
//! `default_audit_log()` honours a legacy `~/.mvm/log/audit.jsonl`
//! when present — without the override, audit lines from a developer's
//! real mvmctl history would shadow the temp dir.

use super::harness::mvmctl;
use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

struct IsolatedEnv {
    _tmp: tempfile::TempDir,
    state: PathBuf,
    data: PathBuf,
    cache: PathBuf,
}

impl IsolatedEnv {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        Self {
            _tmp: tmp,
            state,
            data,
            cache,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = mvmctl();
        cmd.env("MVM_STATE_DIR", &self.state)
            .env("MVM_DATA_DIR", &self.data)
            .env("MVM_CACHE_DIR", &self.cache);
        cmd
    }

    fn audit_log(&self) -> PathBuf {
        self.state.join("log").join("audit.jsonl")
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
