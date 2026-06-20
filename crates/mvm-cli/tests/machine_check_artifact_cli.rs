//! `mvmctl machine check-artifact` round-trip: pack a dev `.mvm` for this
//! host's arch, then verify + preview its admission. Read-only — no boot.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

#[test]
fn check_artifact_reports_verified_runnable_and_admission_preview() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work = tmp.path();
    let data = work.join("data");
    let kernel = work.join("vmlinux");
    let rootfs = work.join("rootfs.ext4");
    let cmdline = work.join("cmdline.txt");
    std::fs::write(&kernel, b"kernel bytes").unwrap();
    std::fs::write(&rootfs, b"rootfs bytes").unwrap();
    std::fs::write(&cmdline, b"console=hvc0").unwrap();
    let artifact = work.join("out.mvm");

    // Pack for THIS host's arch so the arch-gate reports runnable everywhere
    // (CI is x86_64, dev boxes aarch64). `std::env::consts::ARCH` matches
    // mvm's GuestArch strings ("aarch64" / "x86_64").
    let host_arch = std::env::consts::ARCH;

    #[allow(deprecated)]
    let pack = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_DATA_DIR", &data)
        .args([
            "artifact",
            "pack",
            "--kernel",
            kernel.to_str().unwrap(),
            "--rootfs",
            rootfs.to_str().unwrap(),
            "--cmdline",
            cmdline.to_str().unwrap(),
            "--target-arch",
            host_arch,
            "--profile",
            "dev",
            "--allows-egress",
            "--allows-volumes",
            "--out",
            artifact.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        pack.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&pack.stderr)
    );

    #[allow(deprecated)]
    let check = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_DATA_DIR", &data)
        .args([
            "machine",
            "check-artifact",
            artifact.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "check-artifact failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(
        stdout.contains("\"runnable_here\": true"),
        "expected runnable_here=true, got: {stdout}"
    );
    // The artifact declares egress + volumes; the preview reflects the
    // declared posture (proving it flows through admission_for).
    assert!(
        stdout.contains("\"egress\": \"allowed\""),
        "expected egress=allowed for an egress-declaring artifact, got: {stdout}"
    );
    assert!(
        stdout.contains("\"volumes\": true"),
        "expected volumes=true for a volume-declaring artifact, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("\"target_arch\": \"{host_arch}\"")),
        "expected target_arch={host_arch}, got: {stdout}"
    );
}
