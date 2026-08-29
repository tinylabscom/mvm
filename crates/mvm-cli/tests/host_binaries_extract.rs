//! Properties of the embedded Linux host-binary payload. Only present when
//! `embed-host-bins` is on; `unembedded_host_binaries.rs` covers the default
//! build, so neither configuration is left asserting nothing.
#![cfg(feature = "embed-host-bins")]

use mvm_cli::host_binaries::extract::ensure_extracted;
use sha2::Digest as _;
use std::os::unix::fs::PermissionsExt;

#[test]
fn ensure_extracted_writes_all_binaries_with_matching_sha() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = ensure_extracted(tmp.path()).expect("extract");

    use mvm_cli::host_binaries::embedded::EMBEDDED;
    for bin in EMBEDDED.iter() {
        let p = dir.join(bin.name);
        assert!(p.exists(), "missing {}", bin.name);
        let bytes = std::fs::read(&p).unwrap();
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, &bytes);
        let actual = hex::encode(sha2::Digest::finalize(h));
        assert_eq!(actual, bin.sha256_hex, "{}: SHA drift", bin.name);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "{}: wrong mode", bin.name);
    }
}

#[test]
fn ensure_extracted_is_idempotent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir1 = ensure_extracted(tmp.path()).unwrap();
    let dir2 = ensure_extracted(tmp.path()).unwrap();
    assert_eq!(dir1, dir2);
}

#[test]
fn embedded_binaries_are_real_for_vm_boot() {
    let tmp = tempfile::TempDir::new().unwrap();
    let boot = mvm_cli::host_binaries::extract::ensure_boot_host_binaries(tmp.path())
        .expect("boot host binaries extract");
    assert!(!boot.stage0_init.is_empty(), "stage0-init must be embedded");
    assert!(boot.dir.join("stage0-init").is_file());
}
