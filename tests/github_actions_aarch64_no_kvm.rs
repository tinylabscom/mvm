//! Regression checks for the aarch64 no-KVM smoke's binary build contract.
//!
//! The smoke lives in `ci-full.yml` (nightly / manual dispatch), not in the
//! merge queue, because a cold QEMU TCG build can take hours and blocks the
//! queue. The contract it exercises is still worth pinning: source binary
//! preservation, release-helper separation, and the vsock/device setup.

use std::fs;

const EXPECTED_RELEASE_HELPER_BUILD: &str =
    "cargo build --release -p mvmctl --features user,release-artifact-bootstrap,release-channel";
const EXPECTED_SOURCE_BUILD: &str = "cargo build --release -p mvmctl --features user";
const COPY_SOURCE_BINARY: &str = "cp target/release/mvmctl /tmp/mvmctl-source-under-test";
const LIBRARY_ONLY_BUILD: &str =
    "cargo build --release -p mvm-cli --features release-artifact-bootstrap";
const REQUIRED_VIRTIOFS_PACKAGE: &str = "virtiofsd";
const REQUIRED_VIRTIO_ROM_PACKAGE: &str = "ipxe-qemu";
const REQUIRED_CI_VSOCK_OWNERSHIP: &str = "sudo chown \"$(id -u):$(id -g)\" /dev/vhost-vsock";
const REQUIRED_LOCAL_VSOCK_DEVICE: &str = "--device /dev/vhost-vsock:/dev/vhost-vsock";
const REQUIRED_BUILDER_DOWNLOAD: &str =
    "./target/release/mvmctl --builder qemu __builder-vm-bootstrap -v";
const REQUIRED_BOOTSTRAP: &str =
    "/tmp/mvmctl-source-under-test --builder qemu bootstrap --production -v";
const FIRST_MACHINE_RUN: &str = "/tmp/mvmctl-source-under-test machine run";
const REQUIRED_BAKED_ENTRYPOINT: &str = "--entrypoint";
const FORBIDDEN_ENTRYPOINT_OVERRIDE: &str = "-- /bin/true";

#[test]
fn aarch64_no_kvm_smokes_build_the_mvmctl_binary_they_execute() {
    let ci_workflow = fs::read_to_string(".github/workflows/ci.yml").expect("read CI workflow");
    assert!(
        !ci_workflow.contains("aarch64-no-kvm-smoke:"),
        "the merge-queue CI workflow must not define the aarch64 no-KVM smoke job"
    );

    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    let job = workflow
        .split("  aarch64-no-kvm-smoke:\n")
        .nth(1)
        .expect("extended CI workflow must define the aarch64 no-KVM smoke job");
    let script = fs::read_to_string("scripts/local-aarch64-no-kvm-smoke.sh")
        .expect("read local aarch64 no-KVM smoke script");

    for (source, contents) in [
        ("extended CI workflow", job),
        ("local smoke script", script.as_str()),
    ] {
        assert!(
            contents.contains(EXPECTED_SOURCE_BUILD),
            "{source} must build the root mvmctl package in source-channel mode"
        );
        assert!(
            contents.contains(COPY_SOURCE_BINARY),
            "{source} must preserve the exact source-channel binary used by the smoke"
        );
        assert!(
            contents.contains(EXPECTED_RELEASE_HELPER_BUILD),
            "{source} must build the release-only published-builder download helper"
        );
        assert!(
            !contents.contains(LIBRARY_ONLY_BUILD),
            "{source} must not build only the mvm-cli library"
        );
        assert!(
            contents.contains(REQUIRED_BAKED_ENTRYPOINT),
            "{source} must exercise the exit_code image's baked entrypoint"
        );
        assert!(
            !contents.contains(FORBIDDEN_ENTRYPOINT_OVERRIDE),
            "{source} must not replace the exit_code image's baked command with /bin/true"
        );
        assert!(
            contents.contains(REQUIRED_VIRTIOFS_PACKAGE),
            "{source} must install virtiofsd before the builder VM shares the checkout"
        );
        assert!(
            contents.contains(REQUIRED_VIRTIO_ROM_PACKAGE),
            "{source} must install the QEMU virtio ROM before booting the builder VM"
        );
        let source_build = contents
            .find(EXPECTED_SOURCE_BUILD)
            .expect("source build must be present");
        let preserve_source = contents
            .find(COPY_SOURCE_BINARY)
            .expect("source binary copy must be present");
        let release_helper_build = contents
            .find(EXPECTED_RELEASE_HELPER_BUILD)
            .expect("release helper build must be present");
        let builder_download = contents
            .find(REQUIRED_BUILDER_DOWNLOAD)
            .unwrap_or_else(|| panic!("{source} must download the published builder VM"));
        let bootstrap = contents
            .find(REQUIRED_BOOTSTRAP)
            .unwrap_or_else(|| panic!("{source} must bootstrap source-matched launch artifacts"));
        let machine_run = contents
            .find(FIRST_MACHINE_RUN)
            .unwrap_or_else(|| panic!("{source} must execute the first machine run"));
        assert!(
            source_build < preserve_source
                && preserve_source < release_helper_build
                && release_helper_build < builder_download
                && builder_download < bootstrap
                && bootstrap < machine_run,
            "{source} must preserve the source binary, download only the builder VM with the release helper, then bootstrap before launch"
        );
    }

    assert!(
        job.contains(REQUIRED_CI_VSOCK_OWNERSHIP),
        "extended CI workflow must let the unprivileged QEMU process open /dev/vhost-vsock"
    );
    assert!(
        script.contains(REQUIRED_LOCAL_VSOCK_DEVICE),
        "local smoke container must receive the host vhost-vsock device"
    );
}
