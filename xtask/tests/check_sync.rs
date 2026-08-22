use std::process::Command;

#[test]
fn xtask_check_sync_passes_on_main() {
    // Cargo builds package binaries before integration tests and exposes their
    // exact paths here. Reusing that binary avoids a nested workspace build
    // racing the parent test run's doctest compilation.
    let status = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("check-mvm-host-binaries-sync")
        .status()
        .expect("spawn the Cargo-built xtask binary");
    assert!(
        status.success(),
        "xtask reported a sync drift between Rust manifest and Nix attrset"
    );
}
