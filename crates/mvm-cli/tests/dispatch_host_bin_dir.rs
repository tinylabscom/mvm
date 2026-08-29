//! Only present when `embed-host-bins` is on: with the feature off there is no
//! payload to populate the dir with, and `ensure_extracted` refuses by design —
//! `unembedded_host_binaries.rs` asserts that refusal.
#![cfg(feature = "embed-host-bins")]

/// Integration test: ensure_extracted populates the host-bin dir that
/// dispatch wires into BuilderMounts.host_bin_dir before launching the
/// builder VM.
#[test]
fn dispatch_populates_host_bin_dir_before_builder_call() {
    use mvm_cli::host_binaries::extract::ensure_extracted;
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = ensure_extracted(tmp.path()).unwrap();
    assert!(dir.join("mvm-host-vm-init").exists());
    assert!(dir.join("mvm-egress-proxy").exists());
}
