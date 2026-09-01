//! A build without `embed-host-bins` never cross-compiles the Linux host
//! binaries. What it *ships* is whatever the content store could prove belongs
//! to this tree: nothing on a cold machine, the restored set once a `just
//! embed` has published one.
//!
//! Both states have a contract and this file asserts both, in one test rather
//! than two that skip past each other — the empty arm must refuse and say so,
//! the restored arm must be complete. Gating `embedded_binaries.rs` on the
//! feature without this would leave the default configuration — the one nearly
//! every `cargo test` run uses — asserting nothing at all about the payload.
#![cfg(not(feature = "embed-host-bins"))]

use mvm_cli::host_binaries::embedded::EMBEDDED;
use mvm_cli::host_binaries::extract::{ensure_boot_host_binaries, ensure_extracted};
use mvm_cli::host_binaries::manifest::{BOOTSTRAP_SUPPORT_BINARIES, HOST_BINARIES, SEED_BINARIES};

/// Every binary `build.rs` embeds, whichever arm produced the table.
fn expected_payload_len() -> usize {
    HOST_BINARIES.len() + SEED_BINARIES.len() + BOOTSTRAP_SUPPORT_BINARIES.len()
}

#[test]
fn the_default_build_ships_only_a_payload_the_store_could_prove() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("host-bins");

    match ensure_extracted(&root) {
        // Cold: nothing proven, so nothing shipped. The refusal has to name the
        // command that fixes it, and refuse before any filesystem work — a
        // half-populated cache directory is what the next run would take as a
        // valid extraction.
        Err(err) => {
            let err = err.to_string();
            assert!(
                EMBEDDED.is_empty(),
                "extraction refused while carrying {} entries",
                EMBEDDED.len()
            );
            assert!(err.contains("embed-host-bins"), "{err}");
            assert!(err.contains("just embed"), "{err}");
            assert!(!root.exists(), "refusal must not create {}", root.display());
        }
        // Warm: restored from the content store. A restore is all-or-nothing,
        // because extraction verifies the table as a unit and a builder VM
        // missing one binary fails later and elsewhere.
        Ok(dir) => {
            assert_eq!(
                EMBEDDED.len(),
                expected_payload_len(),
                "a restored payload must be the whole manifest, not a subset"
            );
            for bin in EMBEDDED {
                assert!(
                    dir.join(bin.name).is_file(),
                    "{} missing from the extraction",
                    bin.name
                );
            }
        }
    }
}

#[test]
fn boot_binary_extraction_agrees_with_the_table() {
    let tmp = tempfile::TempDir::new().unwrap();
    match ensure_boot_host_binaries(tmp.path()) {
        Ok(boot) => {
            assert!(
                !EMBEDDED.is_empty(),
                "boot binaries produced from an empty table"
            );
            assert!(!boot.stage0_init.is_empty(), "stage0-init must have bytes");
        }
        Err(err) => {
            let err = err.to_string();
            assert!(EMBEDDED.is_empty(), "refused while carrying a payload");
            assert!(err.contains("embed-host-bins"), "{err}");
        }
    }
}
