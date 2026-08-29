//! The default build carries no Linux host-binary payload. These assert that
//! it *says so* rather than quietly behaving as if it had one.
//!
//! Gating `embedded_binaries.rs` on the feature without this file would leave
//! the default configuration — the one nearly every `cargo test` run uses —
//! asserting nothing at all about the embedded set.
#![cfg(not(feature = "embed-host-bins"))]

use mvm_cli::host_binaries::embedded::EMBEDDED;
use mvm_cli::host_binaries::extract::{ensure_boot_host_binaries, ensure_extracted};

#[test]
fn the_default_build_embeds_nothing() {
    assert!(
        EMBEDDED.is_empty(),
        "a build without `embed-host-bins` must carry no payload, found {} entries",
        EMBEDDED.len()
    );
}

/// The refusal has to name the command that fixes it. An empty extract dir
/// would otherwise surface later as a missing file and read as a corrupted
/// cache rather than as a build that was never asked to embed anything.
#[test]
fn extraction_refuses_and_names_the_rebuild_command() {
    let tmp = tempfile::TempDir::new().unwrap();
    let err = ensure_extracted(tmp.path()).unwrap_err().to_string();
    assert!(err.contains("embed-host-bins"), "{err}");
    assert!(err.contains("just embed"), "{err}");
}

#[test]
fn boot_binary_extraction_refuses_too() {
    let tmp = tempfile::TempDir::new().unwrap();
    let err = match ensure_boot_host_binaries(tmp.path()) {
        Ok(_) => panic!("an unembedded build must not produce boot host binaries"),
        Err(err) => err.to_string(),
    };
    assert!(err.contains("embed-host-bins"), "{err}");
}

/// Refusing before any filesystem work matters: a half-populated cache
/// directory is what the next run would take as a valid extraction.
#[test]
fn refusal_leaves_no_cache_directory_behind() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("host-bins");
    assert!(ensure_extracted(&root).is_err());
    assert!(!root.exists(), "refusal must not create {}", root.display());
}
