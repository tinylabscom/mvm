//! Pin the release workflow's asset names to the Rust constructors that fetch
//! them.
//!
//! The published filename and the downloader's expected filename are decided in
//! two files that nothing otherwise couples: `.github/workflows/release.yml`
//! writes the asset, and a `*ArtifactNames::for_arch` constructor builds the URL
//! an installed `mvmctl` requests. A rename on either side type-checks, tests
//! green, and then every end-user download 404s on the next release — the one
//! place we cannot iterate quickly. These tests are the coupling.
//!
//! The workflow never spells an arch out; it interpolates one. Since
//! `for_arch` is pure string formatting, feeding it the workflow's own
//! interpolation tokens yields exactly the template the YAML must contain — so
//! renaming the prefix or the extension on the Rust side turns these red
//! without the test restating either name itself.

use std::fs;
use std::path::Path;

/// How the release workflow spells the arch inside a `run:` block…
const SHELL_ARCH_TOKEN: &str = "${ARCH}";
/// …and inside a step's `with:` block.
const MATRIX_ARCH_TOKEN: &str = "${{ matrix.arch }}";

fn release_workflow() -> String {
    let path = Path::new(".github/workflows/release.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn assert_publishes(workflow: &str, asset: &str) {
    assert!(
        workflow.contains(asset),
        "release.yml must publish {asset:?} — the downloader requests exactly this name"
    );
}

#[test]
fn release_publishes_every_sdk_sidecar_asset_the_downloader_requests() {
    let workflow = release_workflow();
    for token in [SHELL_ARCH_TOKEN, MATRIX_ARCH_TOKEN] {
        let names = mvmctl::build::sdk_sidecar::SdkSidecarArtifactNames::for_arch(token);
        assert_publishes(&workflow, &names.archive);
        assert_publishes(&workflow, &names.archive_checksum);
    }
}

#[test]
fn release_publishes_every_runtime_overlay_asset_the_downloader_requests() {
    let workflow = release_workflow();
    for token in [SHELL_ARCH_TOKEN, MATRIX_ARCH_TOKEN] {
        let names = mvmctl::build::runtime_overlay::RuntimeOverlayArtifactNames::for_arch(token);
        assert_publishes(&workflow, &names.archive);
        assert_publishes(&workflow, &names.archive_checksum);
    }
}

/// Publishing the asset is not enough — the release job has to attach it. A job
/// whose artifacts upload but are never listed in `gh release create` leaves
/// the downloader with a 404 exactly as a rename would.
#[test]
fn the_release_job_attaches_the_sdk_sidecar_assets() {
    let workflow = release_workflow();
    assert!(
        workflow.contains("  sdk-sidecar-image:"),
        "release.yml must define the sdk-sidecar-image job"
    );
    assert!(
        workflow.contains("sdk-sidecar-image, default-microvm]"),
        "the release job must declare the sdk-sidecar-image job in its needs"
    );
    for pattern in [
        "artifacts/sdk-sidecar-*.tar.gz",
        "artifacts/sdk-sidecar-*.tar.gz.sha256",
    ] {
        assert!(
            workflow.contains(pattern),
            "the release job's asset list must include {pattern:?}"
        );
    }
}

/// The downloader fetches `<asset>.bundle`; the release has to attach it under
/// exactly that name or every download refuses as unsigned.
#[test]
fn release_attaches_the_signature_bundle_the_verifier_fetches() {
    let workflow = release_workflow();
    let sidecar = mvmctl::build::sdk_sidecar::SdkSidecarArtifactNames::for_arch("*");
    let overlay = mvmctl::build::runtime_overlay::RuntimeOverlayArtifactNames::for_arch("*");
    for asset in [sidecar.archive, overlay.archive] {
        let bundle = mvmctl::build::release_signature::bundle_asset_name(&asset);
        assert!(
            workflow.contains(&format!("artifacts/{bundle}")),
            "the release job's asset list must attach {bundle:?}"
        );
    }
}

/// Every signed blob in the release uses the one bundle format this project
/// ships: `--new-bundle-format`.
///
/// The in-binary Rust sigstore stack parses only that shape, and
/// `cosign verify-blob --bundle` documents it as the preferred input — so a
/// single format serves both consumers and there is no legacy fallback to keep
/// in step. A bare `--bundle` left behind would sign an artifact the in-binary
/// verifier cannot read, and nothing surfaces that until a real release ships.
#[test]
fn every_signed_release_blob_uses_the_one_bundle_format() {
    let workflow = release_workflow();
    let mut checked = 0usize;
    for (offset, _) in workflow.match_indices("cosign sign-blob") {
        // The invocation is a line-continued shell command; its flags run up to
        // the first line that is not a continuation.
        let invocation: String = workflow[offset..]
            .lines()
            .take_while(|line| line.trim_end().ends_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            invocation.contains("--new-bundle-format"),
            "every `cosign sign-blob` must use --new-bundle-format; found one without it:\n{invocation}"
        );
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected to find the release's signing invocations, found {checked}"
    );
}

/// The release must consume its own artifacts through the production download
/// ladder *before* publishing them.
///
/// That ladder is fail-closed at every rung, so an artifact this pipeline builds
/// slightly wrong does not degrade — it strands every download. The self-check
/// is the only thing that turns that into a failed release instead of a shipped
/// one, and it has to run after signing and before `gh release create`.
#[test]
fn the_release_consumes_its_own_artifacts_before_publishing_them() {
    let workflow = release_workflow();
    let verify = workflow
        .find("- name: Verify the published artifacts survive the consumer path")
        .expect("release.yml must consume its artifacts before publishing them");
    // Matched on a stable prefix: the step's name grows as blobs join the loop,
    // and the ordering property this asserts does not depend on that wording.
    let sign = workflow
        .find("- name: Sign release tarballs")
        .expect("release.yml must sign the tarballs");
    let publish = workflow
        .find("- name: Create GitHub Release")
        .expect("release.yml must create the release");
    assert!(
        sign < verify && verify < publish,
        "the consumer check must run after signing and before publishing"
    );
    assert!(
        workflow.contains("--example download-release-artifact"),
        "the check must drive the real downloader, not a restatement of it"
    );
}

/// Both published architectures must be built, or a whole platform's users get
/// the fail-closed refusal this artifact exists to prevent.
#[test]
fn the_sdk_sidecar_job_builds_both_published_arches() {
    let workflow = release_workflow();
    let job = workflow
        .split("  sdk-sidecar-image:")
        .nth(1)
        .expect("release.yml must define the sdk-sidecar-image job");
    let job = job
        .split("\n  # ")
        .next()
        .expect("the job block is non-empty");
    for arch in ["aarch64", "x86_64"] {
        assert!(
            job.contains(&format!("arch: {arch}")),
            "the sdk-sidecar-image matrix must build {arch}"
        );
    }
}

fn kernel_build_workflow() -> String {
    let path = Path::new(".github/workflows/kernel-build.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// Every published checksum manifest must be signed, and its bundle published.
///
/// A manifest is what each downloader anchors on: it hashes the artifact and
/// compares against the manifest, so an unsigned one lets whoever can swap an
/// artifact swap its recorded digest too and the comparison still passes. The
/// image blobs (kernel, rootfs, verity sidecar) are not tarballs and carry no
/// signature of their own, so the manifest is their only anchor.
///
/// Dropping a manifest from the signing loop, or signing it and forgetting to
/// attach the bundle, both fail the same way: the download still succeeds, still
/// "verifies", and nothing surfaces it until a real release ships. Hence a gate.
#[test]
fn every_published_checksum_manifest_is_signed_and_its_bundle_attached() {
    let workflow = release_workflow();
    let sign_step = workflow
        .split("- name: Sign release tarballs")
        .nth(1)
        .expect("release.yml must have a signing step");
    let sign_loop = sign_step
        .split("done")
        .next()
        .expect("the signing loop is non-empty");
    let assets = workflow
        .split("assets=(")
        .nth(1)
        .expect("release.yml must list release assets")
        .split(')')
        .next()
        .expect("the asset list is non-empty");

    for manifest in [
        "artifacts/checksums-sha256.txt",
        "artifacts/builder-vm-*-checksums-sha256.txt",
        "artifacts/default-microvm-*-checksums-sha256.txt",
    ] {
        assert!(
            sign_loop.contains(manifest),
            "{manifest} must be cosign-signed; every artifact digest below it inherits its trust"
        );
        assert!(
            assets.contains(&format!("{manifest}.bundle")),
            "{manifest}.bundle must be attached to the release, or the verifier 404s"
        );
    }

    // The kernel manifest ships from its own workflow and is just as load-bearing.
    let kernel = kernel_build_workflow();
    let manifest = "kernel-${ARCH}-checksums-sha256.txt";
    assert!(
        kernel.contains(&format!("--bundle \"{manifest}.bundle\"")),
        "kernel-build.yml must cosign-sign {manifest}"
    );
    assert!(
        kernel.contains(&format!("\"{manifest}.bundle\" \\")),
        "kernel-build.yml must upload {manifest}.bundle beside the manifest"
    );
}

/// The staged image must be booted, and booted *before* it is uploaded.
///
/// Every other gate in the `default-microvm` job is a checksum, a signature, or
/// a byte-level read, and none of them can answer the only question asked of a
/// boot image: does it boot. A release shipped for five weeks whose guest
/// panicked before userspace while every checksum verified clean.
///
/// The ordering is the whole value. These are steps in one job, so a failed
/// boot aborts before the upload — but only while it stays above it. Reorder
/// the two and the gate silently becomes a post-mortem on an artifact the world
/// already has.
#[test]
fn the_staged_microvm_image_is_booted_before_it_is_uploaded() {
    let workflow = release_workflow();
    let job = workflow
        .split("  default-microvm:")
        .nth(1)
        .expect("release.yml must define the default-microvm job");
    let job = job
        .split("\n  # ")
        .next()
        .expect("the job block is non-empty");

    let boot = job
        .find("- name: Boot the staged image before it becomes a release asset")
        .expect("the default-microvm job must boot the image it is about to publish");
    let upload = job
        .find("- name: Upload default microVM image artifacts")
        .expect("the default-microvm job must upload its artifacts");
    assert!(
        boot < upload,
        "the boot gate must run before the upload, or it cannot refuse the publish"
    );

    // It must boot the staged bytes. Booting a published asset would be the
    // `boot-latency` lane's job and would prove nothing about this release.
    // Scoped to the boot step alone — the span up to the upload also covers the
    // SBOM and pack-manifest steps, which legitimately name release URLs.
    let rest = &job[boot..upload];
    let step_end = rest[1..]
        .find("\n      - name:")
        .map_or(rest.len(), |offset| offset + 1);
    let step = &rest[..step_end];
    assert!(
        step.contains("MVM_RUNTIME_BOOT_ROOTFS: staging/"),
        "the boot gate must boot the staged rootfs, not a published one"
    );
    assert!(
        !step.contains("releases/download"),
        "the boot gate must not fetch a published artifact"
    );
}
