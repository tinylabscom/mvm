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
