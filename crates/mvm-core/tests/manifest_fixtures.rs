//! Integration tests for the `mvm.toml` parser using on-disk fixtures.
//!
//! The fixture corpus lives at `<workspace-root>/tests/fixtures/manifests/`.
//! Valid fixtures must parse and validate; invalid fixtures must fail with
//! an error message that mentions the offending concept.

use std::path::{Path, PathBuf};

use mvm_core::manifest::Manifest;

/// Resolve the workspace fixture directory from the crate manifest dir.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/manifests")
        .canonicalize()
        .expect("fixture directory exists")
}

fn fixture(subdir: &str, name: &str) -> PathBuf {
    fixtures_dir().join(subdir).join(name)
}

fn parse(path: &Path) -> Result<Manifest, String> {
    Manifest::read_file(path).map_err(|e| format!("{e:#}"))
}

#[test]
fn minimal_valid_manifest_parses() {
    let m = parse(&fixture("valid", "minimal.toml")).expect("minimal.toml should parse");
    assert_eq!(m.flake_ref(), ".");
    assert_eq!(m.profile, "default");
    assert_eq!(m.cpus, 2);
    assert_eq!(m.mem, "1024M");
    assert!(!m.is_image_source());
}

#[test]
fn image_backed_manifest_parses() {
    let m = parse(&fixture("valid", "image-backed.toml")).expect("image-backed.toml should parse");
    assert!(m.is_image_source());
    assert_eq!(m.image.as_deref(), Some("alpine:3.20"));
    assert_eq!(m.cpus, 2);
    assert!(m.net);
    assert_eq!(m.network.allow_hosts, vec!["api.example.com:443"]);
    assert_eq!(m.dev.volumes, vec!["./src:/work/src:ro"]);
    assert_eq!(m.dev.init, vec!["echo ready"]);
}

#[test]
fn network_section_parses() {
    let m = parse(&fixture("valid", "with-network.toml")).expect("with-network.toml should parse");
    assert!(!m.is_image_source());
    assert!(m.net);
    assert_eq!(m.network.allow_hosts, vec!["pypi.org:443", "example.com"]);
}

#[test]
fn invalid_both_sources_rejected() {
    let err =
        parse(&fixture("invalid", "both-sources.toml")).expect_err("both sources should fail");
    assert!(
        err.contains("mutually exclusive"),
        "error should mention mutual exclusivity: {err}"
    );
}

#[test]
fn invalid_unknown_key_rejected() {
    let err = parse(&fixture("invalid", "unknown-key.toml")).expect_err("unknown key should fail");
    assert!(
        err.contains("netwrok") || err.contains("unknown"),
        "error should mention the unknown key: {err}"
    );
}

#[test]
fn invalid_bad_volume_mode_rejected() {
    let err = parse(&fixture("invalid", "bad-volume-mode.toml"))
        .expect_err("bad volume mode should fail");
    assert!(
        err.contains("volume mode") || err.contains("ro"),
        "error should mention volume mode: {err}"
    );
}

#[test]
fn invalid_schema_too_new_rejected() {
    let err =
        parse(&fixture("invalid", "schema-too-new.toml")).expect_err("too-new schema should fail");
    assert!(
        err.contains("schema_version") && err.contains("upgrade mvmctl"),
        "error should mention schema version: {err}"
    );
}

#[test]
fn invalid_empty_image_rejected() {
    let err = parse(&fixture("invalid", "empty-image.toml")).expect_err("empty image should fail");
    assert!(
        err.contains("image") && err.contains("empty"),
        "error should mention empty image: {err}"
    );
}

#[test]
fn invalid_zero_cpus_rejected() {
    let err = parse(&fixture("invalid", "zero-cpus.toml")).expect_err("zero cpus should fail");
    assert!(
        err.contains("cpus") && err.contains(">= 1"),
        "error should mention cpus >= 1: {err}"
    );
}

/// Enumerate the fixture directories and ensure every file is covered by a
/// named test above. This fails if someone adds a fixture but forgets to
/// assert its outcome.
#[test]
fn all_fixtures_are_accounted_for() {
    let valid_dir = fixtures_dir().join("valid");
    let invalid_dir = fixtures_dir().join("invalid");

    let mut valid: Vec<_> = std::fs::read_dir(&valid_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    let mut invalid: Vec<_> = std::fs::read_dir(&invalid_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    valid.sort();
    invalid.sort();

    assert_eq!(
        valid,
        vec!["image-backed.toml", "minimal.toml", "with-network.toml"]
    );
    assert_eq!(
        invalid,
        vec![
            "bad-volume-mode.toml",
            "both-sources.toml",
            "empty-image.toml",
            "schema-too-new.toml",
            "unknown-key.toml",
            "zero-cpus.toml",
        ]
    );
}
