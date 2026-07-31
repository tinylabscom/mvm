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

/// The image tarballs must be signed with `--new-bundle-format`. The in-binary
/// Rust verifier parses only that shape; a legacy `--bundle` here fails to
/// parse on every download, and nothing would catch it until a real release
/// shipped. The binary tarballs must NOT move — those are read by the cosign
/// CLI (`install.sh`, `mvmctl update`), which wants the legacy shape.
#[test]
fn image_tarballs_are_signed_in_the_format_the_in_binary_verifier_parses() {
    let workflow = release_workflow();
    let step = workflow
        .split("- name: Sign release tarballs and SBOM")
        .nth(1)
        .expect("release.yml must define the tarball signing step");
    let step = step
        .split("\n      - name:")
        .next()
        .expect("the signing step is non-empty");

    let image_sign = step
        .split("for tarball in artifacts/runtime-overlay-*.tar.gz artifacts/sdk-sidecar-*.tar.gz")
        .nth(1)
        .expect("the image tarballs must be signed by their own loop")
        .split("done")
        .next()
        .expect("the image signing loop is non-empty");
    assert!(
        image_sign.contains("--new-bundle-format"),
        "image tarballs must be signed with --new-bundle-format: {image_sign}"
    );

    // The generic loop produces the cosign-CLI-consumed bundles, so it must
    // skip the image tarballs rather than double-signing them legacy.
    let generic_sign = step
        .split("for tarball in artifacts/*.tar.gz")
        .nth(1)
        .expect("the binary tarballs keep their own loop")
        .split("done")
        .next()
        .expect("the generic signing loop is non-empty");
    assert!(
        generic_sign.contains("runtime-overlay-*|sdk-sidecar-*"),
        "the legacy-format loop must skip the image tarballs: {generic_sign}"
    );
    assert!(
        !generic_sign.contains("--new-bundle-format"),
        "the cosign-CLI-consumed bundles must stay on the legacy format"
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
