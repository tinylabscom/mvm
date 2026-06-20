//! Round-trip test for `mvmctl artifact extract`: pack a dev artifact,
//! extract it, and assert the verified payload lands on disk under the
//! requested output directory.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

#[test]
fn artifact_extract_round_trips_a_packed_dev_artifact() {
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
    let dest = work.join("extracted");

    // Pack a dev artifact, signed by the host signer materialized under
    // the temp MVM_DATA_DIR.
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
            "aarch64",
            "--profile",
            "dev",
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

    // Extract verifies against the same signer's public key (the default)
    // before writing any payload bytes.
    #[allow(deprecated)]
    let extract = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("MVM_DATA_DIR", &data)
        .args([
            "artifact",
            "extract",
            artifact.to_str().unwrap(),
            "--out",
            dest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "extract failed: {}",
        String::from_utf8_lossy(&extract.stderr)
    );

    assert_eq!(
        std::fs::read(dest.join("kernel/vmlinux")).unwrap(),
        b"kernel bytes"
    );
    assert_eq!(
        std::fs::read(dest.join("rootfs/rootfs.ext4")).unwrap(),
        b"rootfs bytes"
    );
    assert_eq!(
        std::fs::read(dest.join("cmdline.txt")).unwrap(),
        b"console=hvc0"
    );
}
