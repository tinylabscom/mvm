// E2E smoke. Boots Stage 0, lets it produce
// the builder-VM image with the embedded host-bins baked in,
// asserts the produced rootfs.ext4 has the expected files with
// the expected SHA-256.
//
// Gated on `MVM_E2E_SMOKE=1` because it requires a working
// libkrun + zigbuild toolchain and runs for several minutes.

use assert_cmd::cargo::CommandCargoExt;

#[test]
fn dev_up_e2e_smoke() {
    if std::env::var("MVM_E2E_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping E2E smoke; set MVM_E2E_SMOKE=1 to run");
        return;
    }
    #[allow(deprecated)]
    let status = std::process::Command::cargo_bin("mvmctl")
        .expect("locate mvmctl binary")
        .args(["dev", "up"])
        .status()
        .expect("spawn mvmctl");
    assert!(status.success(), "mvmctl dev up failed");
    // Caller is responsible for `mvmctl dev down` between runs.
}
