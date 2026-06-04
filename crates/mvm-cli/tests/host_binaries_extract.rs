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

// The boot guard must reject a stub build (MVM_SKIP_EMBED_BINARIES=1) and
// admit a real one. The expected verdict is whatever this binary was
// compiled with, so the test is valid in both modes.
#[test]
fn ensure_extracted_for_boot_matches_build_mode() {
    use mvm_cli::host_binaries::embedded::EMBEDDED;
    use mvm_cli::host_binaries::extract::ensure_extracted_for_boot;

    let tmp = tempfile::TempDir::new().unwrap();
    let res = ensure_extracted_for_boot(tmp.path());
    let is_stub_build = EMBEDDED.iter().any(|b| b.bytes.is_empty());
    if is_stub_build {
        assert!(res.is_err(), "stub build must be refused for VM boot");
    } else {
        assert!(res.is_ok(), "real build must extract for VM boot");
    }
}
