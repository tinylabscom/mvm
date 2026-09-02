//! Properties of the embedded Linux host-binary payload. Only present when
//! `embed-host-bins` is on; `unembedded_host_binaries.rs` covers the default
//! build, so neither configuration is left asserting nothing.
#![cfg(feature = "embed-host-bins")]

use mvm_cli::host_binaries::embedded::EMBEDDED;
use mvm_cli::host_binaries::manifest::{BOOTSTRAP_SUPPORT_BINARIES, HOST_BINARIES, SEED_BINARIES};
use sha2::{Digest, Sha256};

#[test]
fn embedded_set_is_only_builder_bootstrap_payloads() {
    let mut expected: Vec<&str> = HOST_BINARIES.iter().map(|binary| binary.name).collect();
    expected.extend(SEED_BINARIES.iter().copied());
    expected.extend(BOOTSTRAP_SUPPORT_BINARIES.iter().map(|binary| binary.name));
    expected.sort_unstable();

    let mut actual: Vec<&str> = EMBEDDED.iter().map(|binary| binary.name).collect();
    actual.sort_unstable();

    assert_eq!(
        actual, expected,
        "workload guest binaries belong to the initramfs/runtime artifacts, not mvmctl"
    );
}

#[test]
fn each_embedded_binary_starts_with_elf_magic() {
    for bin in EMBEDDED.iter() {
        if bin.bytes.is_empty() {
            continue;
        }
        assert!(
            bin.bytes.len() > 1024,
            "{}: non-stub payload is implausibly small",
            bin.name
        );
        assert_eq!(
            &bin.bytes[..4],
            &[0x7F, b'E', b'L', b'F'],
            "{}: non-stub payload is not an ELF binary",
            bin.name
        );
    }
}

#[test]
fn embedded_sha256_matches_payload() {
    for bin in EMBEDDED.iter() {
        let mut h = Sha256::new();
        h.update(bin.bytes);
        let actual = hex::encode(h.finalize());
        assert_eq!(actual, bin.sha256_hex, "{}: embedded hash drift", bin.name);
    }
}
