//! Regression checks for the hosted no-KVM and local aarch64 smoke contracts.
//!
//! The hosted smoke lives in `ci-full.yml` (nightly / manual dispatch), not in
//! the merge queue, because a cold QEMU TCG build can take hours and blocks the
//! queue. Hosted runners have terminated long TCG builds on both architectures,
//! so hosted CI prepares the bundle with KVM and explicitly denies KVM for the
//! install-and-boot witness. The local Apple Silicon script retains the full
//! aarch64 no-KVM lifecycle witness.

use std::fs;

const EXPECTED_RELEASE_HELPER_BUILD: &str =
    "cargo build --release -p mvmctl --features user,release-artifact-bootstrap,release-channel";
const EXPECTED_SOURCE_BUILD: &str = "cargo build --release -p mvmctl --features user";
const COPY_SOURCE_BINARY: &str = "cp target/release/mvmctl /tmp/mvmctl-source-under-test";
const LIBRARY_ONLY_BUILD: &str =
    "cargo build --release -p mvm-cli --features release-artifact-bootstrap";
const REQUIRED_VIRTIOFS_PACKAGE: &str = "virtiofsd";
const REQUIRED_VIRTIO_ROM_PACKAGE: &str = "ipxe-qemu";
const REQUIRED_CI_VSOCK_OWNERSHIP: &str = "sudo chown \"$USER\" /dev/vhost-vsock";
const REQUIRED_KVM_DENIAL: &str = "sudo chmod 000 /dev/kvm";
const REQUIRED_KVM_ACCESS: &str = "sudo chmod 666 /dev/kvm";
const REQUIRED_LOCAL_VSOCK_DEVICE: &str = "--device /dev/vhost-vsock:/dev/vhost-vsock";
const FORBIDDEN_LOCAL_KVM_DEVICE: &str = "--device /dev/kvm:/dev/kvm";
const REQUIRED_BUILDER_DOWNLOAD: &str =
    "/tmp/mvmctl-release-helper --builder qemu __builder-vm-bootstrap -v";
const REQUIRED_BOOTSTRAP: &str =
    "/tmp/mvmctl-source-under-test --builder qemu bootstrap --production -v";
const REQUIRED_QEMU_BUILD: &str =
    "/tmp/mvmctl-source-under-test --builder qemu machine build --flake examples/exit_code";
const REQUIRED_STREAMED_BUILD_LOG: &str = "2>&1 | tee /tmp/mvmctl-build.log";
const FORBIDDEN_SILENT_BUILD_LOG: &str = "> /tmp/mvmctl-build.log 2>&1";
const FIRST_MACHINE_RUN: &str = "/tmp/mvmctl-source-under-test machine run";
const REQUIRED_BAKED_ENTRYPOINT: &str = "--entrypoint";
const FORBIDDEN_ENTRYPOINT_OVERRIDE: &str = "-- /bin/true";
const BINARY_ARTIFACT: &str = "no-kvm-binaries";
const BOOTSTRAP_ARTIFACT: &str = "no-kvm-bootstrap-cache";
const BUNDLE_ARTIFACT: &str = "no-kvm-bundle";

#[test]
fn no_kvm_smokes_use_source_binary_and_bound_hosted_tcg_to_boot() {
    let ci_workflow = fs::read_to_string(".github/workflows/ci.yml").expect("read CI workflow");
    assert!(
        !ci_workflow.contains("no-kvm-smoke:"),
        "the merge-queue CI workflow must not define the no-KVM smoke job"
    );

    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read extended CI workflow");
    let prepare = workflow
        .split("  no-kvm-prepare:\n")
        .nth(1)
        .and_then(|rest| rest.split("  no-kvm-bootstrap:\n").next())
        .expect("extended CI workflow must define the no-KVM prepare job");
    let bootstrap_job = workflow
        .split("  no-kvm-bootstrap:\n")
        .nth(1)
        .and_then(|rest| rest.split("  no-kvm-build:\n").next())
        .expect("extended CI workflow must define the no-KVM bootstrap job");
    let build_job = workflow
        .split("  no-kvm-build:\n")
        .nth(1)
        .and_then(|rest| rest.split("  no-kvm-smoke:\n").next())
        .expect("extended CI workflow must define the no-KVM build job");
    let smoke_job = workflow
        .split("  no-kvm-smoke:\n")
        .nth(1)
        .expect("extended CI workflow must define the no-KVM smoke job");
    let workflow_path = format!("{prepare}{bootstrap_job}{build_job}{smoke_job}");
    let script = fs::read_to_string("scripts/local-aarch64-no-kvm-smoke.sh")
        .expect("read local aarch64 no-KVM smoke script");

    for (source, contents) in [
        ("extended CI workflow", workflow_path.as_str()),
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

    for job in [bootstrap_job, build_job, smoke_job] {
        assert!(
            job.contains(REQUIRED_CI_VSOCK_OWNERSHIP),
            "every live job must let the unprivileged QEMU process open /dev/vhost-vsock"
        );
        assert!(
            job.contains("runs-on: ubuntu-24.04")
                && !job.contains("runs-on: ubuntu-24.04-arm")
                && job.contains("qemu-system-x86"),
            "hosted no-KVM live jobs must use the stable x86_64 runner and matching QEMU"
        );
    }
    for job in [bootstrap_job, smoke_job] {
        assert!(
            job.contains(REQUIRED_KVM_DENIAL),
            "the hosted unaccelerated stages must deny KVM before making a TCG claim"
        );
    }
    assert!(
        build_job.contains(REQUIRED_KVM_ACCESS) && !build_job.contains(REQUIRED_KVM_DENIAL),
        "bounded hosted bundle preparation must use KVM and make no TCG-build claim"
    );
    assert!(
        build_job.contains(REQUIRED_STREAMED_BUILD_LOG)
            && !build_job.contains(FORBIDDEN_SILENT_BUILD_LOG),
        "the hosted workload build must stream progress while retaining its diagnostic log"
    );
    assert!(
        prepare.contains("runs-on: ubuntu-24.04") && !prepare.contains("runs-on: ubuntu-24.04-arm"),
        "the exact hosted smoke binaries must be compiled for the x86_64 runner that executes them"
    );
    assert!(
        prepare.contains("uses: actions/upload-artifact@v7")
            && prepare.contains(&format!("name: {BINARY_ARTIFACT}")),
        "the prepare job must publish the exact source and release-helper binaries"
    );
    assert!(
        bootstrap_job.contains("needs: no-kvm-prepare")
            && bootstrap_job.contains(&format!("name: {BINARY_ARTIFACT}"))
            && bootstrap_job.contains("uses: actions/upload-artifact@v7")
            && bootstrap_job.contains(&format!("name: {BOOTSTRAP_ARTIFACT}")),
        "bootstrap must use exact binaries and publish reusable launch artifacts"
    );
    assert!(
        build_job.contains("needs: no-kvm-bootstrap")
            && build_job.contains(&format!("name: {BINARY_ARTIFACT}"))
            && build_job.contains(&format!("name: {BOOTSTRAP_ARTIFACT}"))
            && build_job.contains(REQUIRED_QEMU_BUILD)
            && build_job.contains("uses: actions/upload-artifact@v7")
            && build_job.contains(&format!("name: {BUNDLE_ARTIFACT}")),
        "the KVM build runner must restore bootstrap state and publish the sealed bundle"
    );
    assert!(
        smoke_job.contains("needs: no-kvm-build")
            && smoke_job.contains(&format!("name: {BOOTSTRAP_ARTIFACT}"))
            && smoke_job.contains(&format!("name: {BUNDLE_ARTIFACT}"))
            && smoke_job.contains("bundle install /tmp/no-kvm-bundle/exit-code-x86_64.mvmpkg")
            && smoke_job.contains("machine run"),
        "the smoke runner must install and boot the bundle in its own runner window"
    );
    for job in [bootstrap_job, build_job, smoke_job] {
        assert!(
            !job.contains(EXPECTED_SOURCE_BUILD) && !job.contains(EXPECTED_RELEASE_HELPER_BUILD),
            "live jobs must not spend their short lifetime recompiling mvmctl"
        );
    }
    let install_rust = bootstrap_job
        .find("name: Install Rust toolchain")
        .expect("the bootstrap runner must install Rust for guest-runtime bootstrap");
    let install_zigbuild = bootstrap_job
        .find("uses: ./.github/actions/install-zigbuild")
        .expect("the bootstrap runner must install cargo-zigbuild");
    let bootstrap = bootstrap_job
        .find("Bootstrap source-matched launch artifacts")
        .expect("the bootstrap runner must bootstrap source-matched launch artifacts");
    assert!(
        install_rust < install_zigbuild && install_zigbuild < bootstrap,
        "the live runner must install the guest cross-toolchain before bootstrap"
    );
    assert!(
        script.contains(REQUIRED_LOCAL_VSOCK_DEVICE),
        "local smoke container must receive the host vhost-vsock device"
    );
    assert!(
        !script.contains(FORBIDDEN_LOCAL_KVM_DEVICE)
            && script.contains("--flake examples/exit_code")
            && script.contains("--builder qemu")
            && script.contains("--hypervisor qemu"),
        "the local Apple Silicon witness must retain the full unaccelerated build lifecycle"
    );
}
