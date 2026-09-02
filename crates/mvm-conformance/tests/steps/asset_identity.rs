//! Step definitions for the content-addressed asset-identity scenarios.
//!
//! The scenarios drive `mvmctl trust audit asset id` — the offline half of
//! the asset-identity claim. The digest it prints must equal what admission
//! records for the same path, so the expected values here are computed with
//! the same primitives the host path uses: raw SHA-256 for a file (an
//! external oracle), and `mvm_fs::hash::hash_source` for a directory tree.

use std::path::PathBuf;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;
use sha2::Digest as _;

use super::cli::mvmctl_command;
use crate::world::CliWorld;

fn fixture_dir(world: &mut CliWorld) -> &tempfile::TempDir {
    world
        .asset_fixture_dir
        .get_or_insert_with(|| tempfile::tempdir().expect("create asset fixture dir"))
}

fn asset_path(world: &mut CliWorld, name: &str) -> PathBuf {
    fixture_dir(world).path().join(name)
}

fn run_stdout(world: &mut CliWorld) -> Vec<u8> {
    world
        .last_run
        .as_ref()
        .expect("a run step must precede this assertion")
        .stdout
        .clone()
}

#[given(expr = "a file asset {string} containing {string}")]
fn file_asset(world: &mut CliWorld, name: String, content: String) {
    let path = asset_path(world, &name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create asset fixture parent dirs");
    }
    std::fs::write(&path, content.as_bytes()).expect("write file asset");
}

#[given(expr = "a directory asset {string} with file {string} containing {string}")]
fn directory_asset(world: &mut CliWorld, dir: String, file: String, content: String) {
    let path = asset_path(world, &dir).join(file);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create directory asset parents");
    }
    std::fs::write(&path, content.as_bytes()).expect("write directory asset file");
}

#[when(expr = "I compute the asset identity of {string}")]
fn compute_asset_identity(world: &mut CliWorld, name: String) {
    let path = asset_path(world, &name);
    let home = world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step");
    let output = mvmctl_command()
        .args([
            "trust",
            "audit",
            "asset",
            "id",
            path.to_str()
                .expect("asset fixture path must be valid UTF-8"),
        ])
        .isolated_home(home.path())
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[then(expr = "the output is the sha256 of file asset {string}")]
fn output_is_sha256_of_file(world: &mut CliWorld, name: String) {
    let path = asset_path(world, &name);
    let bytes = std::fs::read(&path).expect("read file asset");
    let digest = hex::encode(sha2::Sha256::digest(&bytes));
    let stdout = String::from_utf8(run_stdout(world)).expect("asset identity output must be UTF-8");
    assert_eq!(
        stdout.trim(),
        digest,
        "asset identity must be the file's raw sha256"
    );
}

#[then(expr = "the output is the canonical tree hash of directory asset {string}")]
fn output_is_tree_hash(world: &mut CliWorld, name: String) {
    let path = asset_path(world, &name);
    let digest = mvm_fs::hash::hash_source(&path).expect("hash directory asset");
    let stdout = String::from_utf8(run_stdout(world)).expect("asset identity output must be UTF-8");
    assert_eq!(
        stdout.trim(),
        digest,
        "asset identity must be the canonical tree manifest hash"
    );
}
