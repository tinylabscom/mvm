//! Live end-to-end smoke for `mvmctl run --image <oci>`.
//!
//! Disabled by default. Set `MVM_OCI_IMAGE_RUNNER_SMOKE=1` on a host with
//! a working workload backend (Vz on macOS 26+, libkrun on macOS 13-25,
//! Firecracker on Linux/KVM), the matching supervisor/drainer helper
//! binaries built into the workspace `target/`, a populated builder-VM
//! image cache, and network access to the registry.
//!
//! Unlike a unit test, this drives the REAL CLI path so it exercises the
//! whole chain that only fails on a live boot:
//!
//! 1. OCI pull + hardened unpack,
//! 2. mvm-runtime injection (agent + netinit + `/init` + `/mvm/runtime`),
//! 3. ext4 materialize in the builder VM,
//! 4. the `admit_overlay_aware` admission gate (the injected rootfs must
//!    pass it — an un-injected OCI rootfs is refused),
//! 5. boot on the workload backend,
//! 6. a real in-guest agent round-trip: the agent runs the trailing
//!    command over vsock and streams its stdout back.
//!
//! The marker echoed by the in-guest command proves the command actually
//! ran inside the guest, not on the host.

#![cfg(unix)]

use std::process::Command;

const ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_SMOKE";
const IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_REF";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";

#[test]
fn run_image_boots_and_round_trips_the_agent() {
    if std::env::var(ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_smoke] skipped - set {ENABLE_VAR}=1 on a host with a workload \
             backend + builder-VM cache to pull an OCI image, inject the mvm runtime, boot it, \
             and round-trip the guest agent"
        );
        return;
    }

    let image_ref = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let marker = format!("oci-smoke-marker-{}", std::process::id());
    let mvmctl = env!("CARGO_BIN_EXE_mvmctl");

    // Put the workspace target dir on PATH so the run path finds the
    // freshly-built supervisor/drainer helper binaries.
    let target_dir = std::path::Path::new(mvmctl)
        .parent()
        .expect("mvmctl binary has a parent dir")
        .to_path_buf();
    let path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{path}", target_dir.display());

    let output = Command::new(mvmctl)
        .env("PATH", path)
        .args(["run", "--image", &image_ref, "--", "/bin/echo", &marker])
        .output()
        .expect("spawn mvmctl run --image");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "mvmctl run --image exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains(&marker) || stderr.contains(&marker),
        "guest did not echo the marker {marker:?} - the agent round-trip did not run.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
