//! `scripts/dev-env.sh` must resolve the dev state root from the worktree it
//! lives in, not from whatever the calling shell happened to export.
//!
//! The variables are exported, so a shell that sourced the script in one
//! worktree carries them into every later child — including a build launched
//! from a different checkout. Two source trees then share one
//! `CARGO_TARGET_DIR`, and because cargo fingerprints embed absolute paths,
//! each alternation recompiles the whole workspace while concurrent builds
//! serialize on that one lock. Nothing reports it; the build is just slow.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Source the script the way the Justfile and AGENTS.md document
/// (`bash -c 'source scripts/dev-env.sh'`) and report what it exported.
///
/// `HOME` is always pinned alongside `MVM_HOME`: a subprocess handed only
/// `MVM_HOME` can still seed from the real `$HOME/.mvm/cache`.
fn source_dev_env(env: &[(&str, &str)], home: &Path) -> HashMap<String, String> {
    let mut command = Command::new("bash");
    command
        .current_dir(repo_root())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .arg("-c")
        .arg(
            "source scripts/dev-env.sh; \
             printf 'MVM_HOME=%s\\nCARGO_TARGET_DIR=%s\\nCARGO_HOME=%s\\n' \
             \"$MVM_HOME\" \"$CARGO_TARGET_DIR\" \"$CARGO_HOME\"",
        );
    for (key, value) in env {
        command.env(key, value);
    }

    let output = command.output().expect("run bash");
    assert!(
        output.status.success(),
        "dev-env.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn expected_state_root() -> PathBuf {
    repo_root().join(".mvm-test")
}

#[test]
fn resolves_all_three_vars_from_the_worktree_when_the_env_is_clean() {
    let home = tempfile::tempdir().expect("tempdir");
    let vars = source_dev_env(&[], home.path());
    let root = expected_state_root();

    assert_eq!(vars["MVM_HOME"], root.to_string_lossy());
    assert_eq!(
        vars["CARGO_TARGET_DIR"],
        root.join("target").to_string_lossy()
    );
    assert_eq!(vars["CARGO_HOME"], root.join("cargo").to_string_lossy());
}

#[test]
fn reclaims_state_inherited_from_another_worktree() {
    let home = tempfile::tempdir().expect("tempdir");
    let foreign = tempfile::tempdir().expect("tempdir");
    let foreign_root = foreign.path().join("other-worktree/.mvm-test");

    let vars = source_dev_env(
        &[
            ("MVM_HOME", &foreign_root.to_string_lossy()),
            (
                "CARGO_TARGET_DIR",
                &foreign_root.join("target").to_string_lossy(),
            ),
            ("CARGO_HOME", &foreign_root.join("cargo").to_string_lossy()),
        ],
        home.path(),
    );
    let root = expected_state_root();

    // Every one of the three is reclaimed, not just the one that hurts most.
    assert_eq!(vars["MVM_HOME"], root.to_string_lossy());
    assert_eq!(
        vars["CARGO_TARGET_DIR"],
        root.join("target").to_string_lossy()
    );
    assert_eq!(vars["CARGO_HOME"], root.join("cargo").to_string_lossy());
}

#[test]
fn honours_an_override_that_points_inside_this_worktree() {
    let home = tempfile::tempdir().expect("tempdir");
    let local = repo_root().join("custom-target");

    let vars = source_dev_env(
        &[("CARGO_TARGET_DIR", &local.to_string_lossy())],
        home.path(),
    );

    assert_eq!(vars["CARGO_TARGET_DIR"], local.to_string_lossy());
}

#[test]
fn keep_inherited_opts_out_of_reclaiming() {
    let home = tempfile::tempdir().expect("tempdir");
    let foreign = tempfile::tempdir().expect("tempdir");
    let foreign_target = foreign.path().join("other-worktree/.mvm-test/target");

    let vars = source_dev_env(
        &[
            ("CARGO_TARGET_DIR", &foreign_target.to_string_lossy()),
            ("MVM_DEV_ENV_KEEP_INHERITED", "1"),
        ],
        home.path(),
    );

    assert_eq!(vars["CARGO_TARGET_DIR"], foreign_target.to_string_lossy());
}
