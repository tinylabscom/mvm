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

use sha2::{Digest, Sha256};

/// How the release workflow spells the arch inside a `run:` block…
const SHELL_ARCH_TOKEN: &str = "${ARCH}";
/// …and inside a step's `with:` block.
const MATRIX_ARCH_TOKEN: &str = "${{ matrix.arch }}";

fn release_workflow() -> String {
    let path = Path::new(".github/workflows/release.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// The boot image train's workflow. The four image jobs live here, not in
/// `release.yml`: images ship on their own `boot-image/vN` counter so a rootfs
/// fix does not need a CLI release.
fn boot_image_workflow() -> String {
    let path = Path::new(".github/workflows/release-boot-image.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn justfile() -> String {
    fs::read_to_string("Justfile").expect("Justfile must be readable")
}

fn ci_workflow() -> String {
    let path = Path::new(".github/workflows/ci.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn pages_workflow() -> String {
    let path = Path::new(".github/workflows/pages.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn verify_checksum_manifest(directory: &Path) {
    let manifest_path = directory.join("SHA256SUMS");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
    for line in manifest.lines() {
        let (expected, name) = line.split_once("  ").unwrap_or_else(|| {
            panic!(
                "malformed checksum line in {}: {line}",
                manifest_path.display()
            )
        });
        let artifact_path = directory.join(name);
        let bytes = fs::read(&artifact_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", artifact_path.display()));
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            expected,
            "{} does not match its published checksum",
            artifact_path.display()
        );
    }
}

#[test]
fn public_cve_corpus_is_integrity_checked_and_non_certifying() {
    let root = Path::new("public/public/security/cve-corpus");
    verify_checksum_manifest(root);

    for cve in ["CVE-2021-21315", "CVE-2025-55182"] {
        let directory = root.join(cve);
        verify_checksum_manifest(&directory);
        let page = fs::read_to_string(directory.join("index.html")).expect("read CVE page");
        assert!(page.contains("Tier 2 was not attempted"));
        assert!(page.contains("Containment is not proven"));
    }

    let guide = fs::read_to_string("public/src/content/docs/security/cve-demonstrations.md")
        .expect("read CVE demonstration guide");
    assert!(guide.contains("/security/cve-corpus/"));
    assert!(guide.contains("non-certifying"));
}

fn assert_publishes(workflow: &str, asset: &str) {
    assert!(
        workflow.contains(asset),
        "the image workflow must publish {asset:?} — the downloader requests exactly this name"
    );
}

#[test]
fn release_publishes_every_sdk_sidecar_asset_the_downloader_requests() {
    let workflow = boot_image_workflow();
    for arch in ["aarch64", "x86_64"] {
        for libc in [
            mvmctl::build::guest_libc::GuestLibc::Glibc,
            mvmctl::build::guest_libc::GuestLibc::Musl,
        ] {
            let names = mvmctl::build::sdk_sidecar::SdkSidecarArtifactNames::for_target(arch, libc);
            assert_publishes(&workflow, &names.archive);
            assert_publishes(&workflow, &names.archive_checksum);
        }
    }
}

#[test]
fn release_publishes_every_runtime_overlay_asset_the_downloader_requests() {
    let workflow = boot_image_workflow();
    for token in [SHELL_ARCH_TOKEN, MATRIX_ARCH_TOKEN] {
        let names = mvmctl::build::runtime_overlay::RuntimeOverlayArtifactNames::for_arch(token);
        assert_publishes(&workflow, &names.archive);
        assert_publishes(&workflow, &names.archive_checksum);
    }
}

#[test]
fn runtime_overlay_release_carries_every_oci_guest_runtime_binary() {
    let workflow = boot_image_workflow();
    let runtime_flake = fs::read_to_string("nix/images/runtime-overlay/flake.nix")
        .expect("runtime-overlay flake must be readable");
    let guest_package = fs::read_to_string("nix/packages/mvm-guest-agent.nix")
        .expect("guest-agent package must be readable");

    for name in mvmctl::build::guest_agent_build::OCI_GUEST_RUNTIME_BINARY_NAMES {
        assert!(
            workflow.contains(name),
            "release-boot-image.yml must put {name} in the published runtime archive"
        );
        assert!(
            runtime_flake.contains(name),
            "runtime-overlay flake must stage {name} for release packaging"
        );
        if name != "mvm-egress-client" {
            assert!(
                guest_package.contains(name),
                "mvm-guest-agent.nix must build {name} before the overlay flake stages it"
            );
        }
    }
}

/// Publishing the asset is not enough — the release job has to attach it. A job
/// whose artifacts upload but are never listed in `gh release create` leaves
/// the downloader with a 404 exactly as a rename would.
#[test]
fn the_release_job_attaches_the_sdk_sidecar_assets() {
    let boot_image = boot_image_workflow();
    assert!(
        boot_image.contains("  sdk-sidecar-image:"),
        "release-boot-image.yml must define the sdk-sidecar-image job"
    );
    let publish_needs = job_block(&boot_image, "publish-boot-image")
        .lines()
        .find(|line| line.trim_start().starts_with("needs:"))
        .expect("the boot image publish job must declare its dependencies");
    assert!(
        publish_needs.contains("sdk-sidecar-image"),
        "the boot image publish job must declare the sdk-sidecar-image job in its needs"
    );
    // Both releases attach it for now: the download side still composes its URL
    // from the CLI version, so dropping it from the `vN` release would 404 every
    // fresh install before the boot image tag is ever consulted.
    for workflow in [&boot_image, &release_workflow()] {
        for pattern in [
            "artifacts/sdk-sidecar-*-glibc.tar.gz",
            "artifacts/sdk-sidecar-*-glibc.tar.gz.sha256",
            "artifacts/sdk-sidecar-*-musl.tar.gz",
            "artifacts/sdk-sidecar-*-musl.tar.gz.sha256",
        ] {
            assert!(
                workflow.contains(pattern),
                "the publishing job's asset list must include {pattern:?}"
            );
        }
    }
}

/// The downloader fetches `<asset>.bundle`; the release has to attach it under
/// exactly that name or every download refuses as unsigned.
#[test]
fn release_attaches_the_signature_bundle_the_verifier_fetches() {
    let workflow = release_workflow();
    let overlay = mvmctl::build::runtime_overlay::RuntimeOverlayArtifactNames::for_arch("*");
    let mut assets = vec![overlay.archive];
    for libc in [
        mvmctl::build::guest_libc::GuestLibc::Glibc,
        mvmctl::build::guest_libc::GuestLibc::Musl,
    ] {
        assets.push(
            mvmctl::build::sdk_sidecar::SdkSidecarArtifactNames::for_target("*", libc).archive,
        );
    }
    for asset in assets {
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
    let workflow = format!("{}\n{}", release_workflow(), boot_image_workflow());
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

/// Build provenance must cover the artifacts the release signs directly, and be
/// recorded before the release is published.
///
/// The signature and the attestation answer different questions — who published
/// this, versus what went into it — but they have to cover the same subject set.
/// If the signing loop grows a tarball the attest step never sees, a downstream
/// consumer that requires provenance starts rejecting an artifact this pipeline
/// considers fully released, and nothing here would say so.
#[test]
fn the_release_attests_build_provenance_for_the_signed_tarballs() {
    let workflow = release_workflow();

    assert!(
        workflow.contains("attestations: write"),
        "the release workflow must grant `attestations: write`; \
         actions/attest-build-provenance records nothing without it"
    );

    let attest = workflow
        .find("actions/attest-build-provenance")
        .expect("the release job must attest build provenance");

    let step: String = workflow[attest..]
        .lines()
        .take(4)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        step.contains("subject-path: artifacts/*.tar.gz"),
        "provenance must cover the same tarballs the signing loop signs directly, found:\n{step}"
    );

    let publish = workflow
        .find("gh release create")
        .expect("the release job must publish the tag");
    assert!(
        attest < publish,
        "provenance must be attested before `gh release create`, not after"
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
fn the_sdk_sidecar_job_builds_every_published_arch_and_libc() {
    let workflow = boot_image_workflow();
    let job = workflow
        .split("  sdk-sidecar-image:")
        .nth(1)
        .expect("release-boot-image.yml must define the sdk-sidecar-image job");
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
    for libc in ["glibc", "musl"] {
        assert!(
            job.contains(&format!("libc: {libc}")),
            "the sdk-sidecar-image matrix must build {libc}"
        );
    }
    for package in ["sdk-sidecar-image", "sdk-sidecar-image-musl"] {
        assert!(
            job.contains(&format!("package: {package}")),
            "the sdk-sidecar-image matrix must build {package}"
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
    let workflow = boot_image_workflow();
    let job = workflow
        .split("  default-microvm:")
        .nth(1)
        .expect("release-boot-image.yml must define the default-microvm job");
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

/// A plain boot proves the release image reaches userspace, but it does not
/// exercise the initramfs or dm-verity sidecars. The pre-publish gate must run
/// the exact same staged image a second time with the complete sealed triple.
#[test]
fn the_staged_microvm_boot_gate_covers_plain_and_sealed_boots() {
    let workflow = boot_image_workflow();
    let job = workflow
        .split("  default-microvm:")
        .nth(1)
        .expect("release-boot-image.yml must define the default-microvm job");
    let boot = job
        .find("- name: Boot the staged image before it becomes a release asset")
        .expect("the default-microvm job must define its boot gate");
    let rest = &job[boot..];
    let step_end = rest[1..]
        .find("\n      - name:")
        .map_or(rest.len(), |offset| offset + 1);
    let step = &rest[..step_end];

    assert_eq!(
        step.matches("prebuilt_runtime_image_boots_within_budget")
            .count(),
        2,
        "the gate must boot once plainly and once through the sealed path"
    );
    for variable in [
        "MVM_RUNTIME_BOOT_INITRD=",
        "MVM_RUNTIME_BOOT_ROOTFS_VERITY=",
        "MVM_RUNTIME_BOOT_ROOTFS_ROOTHASH=",
    ] {
        assert!(
            step.contains(variable),
            "the sealed boot invocation must set {variable}"
        );
    }
    assert!(
        step.contains("MVM_RUNTIME_BOOT_INITRD=\"$HOME/.mvm/cache/initramfs/initramfs.cpio.gz\""),
        "the staged universal initramfs must use the production cache path so activation runs"
    );
}

/// The four jobs that build a boot image. They move as a set: splitting them
/// across two release trains would mean a `boot-image/vN` release that is
/// missing a piece the same tag is supposed to carry.
const IMAGE_JOBS: [&str; 4] = [
    "builder-vm-image",
    "runtime-overlay-image",
    "sdk-sidecar-image",
    "default-microvm",
];

/// Slice one job's block out of a workflow — from its key to the next line at
/// job indentation.
///
/// A comment sitting between two jobs documents the one below it, so this
/// over-reads a trailing comment at worst. It never truncates a job's own
/// steps, which is the direction that would make an assertion pass by looking
/// at nothing.
fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
    let key = format!("\n  {job}:\n");
    let start = workflow
        .find(&key)
        .unwrap_or_else(|| panic!("no job named {job:?} in this workflow"))
        + key.len();
    let rest = &workflow[start..];
    let mut end = rest.len();
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        if let Some(tail) = line.strip_prefix("  ")
            && !tail.starts_with([' ', '#', '\n'])
        {
            end = offset;
            break;
        }
        offset += line.len();
    }
    &rest[..end]
}

/// The tag patterns a workflow's `push` trigger fires on.
fn push_tag_patterns(workflow: &str) -> Vec<String> {
    let tags = workflow
        .split("    tags:\n")
        .nth(1)
        .expect("the workflow must have a push tag trigger");
    tags.lines()
        .map_while(|line| line.strip_prefix("      - "))
        .map(|pattern| pattern.trim().trim_matches('"').to_string())
        .collect()
}

/// The image jobs belong to the boot image train, and to it alone.
///
/// A copy left behind in `release.yml` would not fail anything — it would
/// quietly rebuild the same image on the CLI's schedule, which is the coupling
/// the split exists to remove, and publish a second set of bytes under a
/// second identity.
#[test]
fn the_image_jobs_live_in_the_boot_image_workflow_and_nowhere_else() {
    let release = release_workflow();
    let boot_image = boot_image_workflow();
    for job in IMAGE_JOBS {
        assert!(
            boot_image.contains(&format!("\n  {job}:\n")),
            "release-boot-image.yml must define the {job} job"
        );
        assert!(
            !release.contains(&format!("\n  {job}:\n")),
            "{job} moved to release-boot-image.yml; release.yml must not define it too"
        );
        assert!(
            !release.contains(&format!("needs.{job}.")),
            "release.yml refers to {job}, which is now a job in another workflow — \
             a cross-workflow `needs` edge is a hard error at parse time"
        );
    }
    let release_needs = release
        .split("\n  release:\n")
        .nth(1)
        .and_then(|job| {
            job.lines()
                .find(|line| line.trim_start().starts_with("needs:"))
        })
        .expect("release.yml must define the release job with a needs list");
    for job in IMAGE_JOBS {
        assert!(
            !release_needs.contains(job),
            "the release job still needs {job}, which no longer exists in this workflow"
        );
    }
}

/// Neither train can fire the other.
///
/// GitHub tag globs anchor at the start and do not cross `/`, so the two
/// patterns are disjoint — but that is a claim about someone else's matcher,
/// so what is asserted here is the thing we control: the patterns themselves,
/// and that each train's example tag fails the other's literal prefix. If the
/// matching rule ever changed, disjoint prefixes would still keep them apart.
#[test]
fn the_two_release_trains_cannot_fire_each_other() {
    assert_eq!(
        push_tag_patterns(&release_workflow()),
        vec!["v*".to_string()],
        "release.yml must fire on the CLI version tag and nothing else"
    );
    assert_eq!(
        push_tag_patterns(&boot_image_workflow()),
        vec!["boot-image/v*".to_string()],
        "release-boot-image.yml must fire on the boot image tag and nothing else"
    );

    let cli_tag = "v0.18.0";
    let boot_tag = mvmctl::core::config::DEFAULT_BOOT_IMAGE_TAG;
    let prefix = |pattern: &str| pattern.split('*').next().unwrap_or_default().to_string();
    assert!(
        !boot_tag.starts_with(&prefix("v*")),
        "{boot_tag} must not match the CLI train's pattern"
    );
    assert!(
        !cli_tag.starts_with(&prefix("boot-image/v*")),
        "{cli_tag} must not match the boot image train's pattern"
    );
}

/// Publishing an image tag from a topic branch would disclose code that has
/// not passed the repository's merge gates. Keep the image release helper on
/// the same merged-main boundary as the CLI release helper.
#[test]
fn boot_image_release_recipe_tags_the_fetched_main_commit() {
    let justfile = justfile();
    let recipe = justfile
        .split("release-image VERSION:")
        .nth(1)
        .expect("Justfile must define release-image")
        .split("\n# ── Documentation")
        .next()
        .expect("release-image recipe must end before documentation recipes");

    assert!(
        recipe.contains("git fetch origin main"),
        "release-image must refresh origin/main before choosing the release commit"
    );
    assert!(
        recipe.contains("git tag \"$TAG\" origin/main"),
        "release-image must tag merged origin/main, never the caller's current HEAD"
    );
    assert!(
        !recipe.contains("git tag \"$TAG\"\n"),
        "release-image must not implicitly tag the caller's current HEAD"
    );
}

#[test]
fn boot_image_release_recipe_refuses_an_existing_tag() {
    let justfile = justfile();
    let recipe = justfile
        .split("release-image VERSION:")
        .nth(1)
        .expect("Justfile must define release-image")
        .split("\n# ── Documentation")
        .next()
        .expect("release-image recipe must end before documentation recipes");

    assert!(
        recipe.contains("git rev-parse --verify \"refs/tags/$TAG\""),
        "release-image must refuse a tag that already exists after fetching tags"
    );
}

/// The protected environment survives the move, and it is the boot image
/// train's own.
///
/// It is what constrains which ref can mint a keyless signing identity. Losing
/// it does not fail the job: the signing step is `continue-on-error: true`, so
/// a broken identity means the pack quietly stops shipping and everything else
/// looks green. Nothing else would notice.
///
/// Naming the *wrong* environment fails far louder but just as opaquely. This
/// workflow fires on `boot-image/v*` and asked for `release-signing`, whose
/// policy admits `v*` and nothing else — GitHub tag globs anchor at the start
/// and do not cross `/`. Every gated job was refused one second in, with no
/// steps run and nothing in the log to read.
#[test]
fn the_moved_jobs_keep_the_boot_image_signing_environment() {
    let boot_image = boot_image_workflow();
    // The two jobs that cosign-sign a pack manifest inside the job itself.
    for job in ["builder-vm-image", "default-microvm"] {
        let block = job_block(&boot_image, job);
        assert!(
            block.contains("cosign sign-blob"),
            "{job} is listed here because it signs; if it no longer does, move it \
             out of this list rather than dropping the assertion"
        );
        assert!(
            block.contains("    environment: boot-image-signing\n"),
            "{job} must keep `environment: boot-image-signing`, or its keyless \
             signing identity silently stops being mintable. It must be that \
             environment and not `release-signing`: this workflow's tags are \
             `boot-image/v*`, which a `v*` policy refuses outright"
        );
    }
    // The publish job signs the checksum manifests every downloader anchors on.
    assert!(
        job_block(&boot_image, "publish-boot-image")
            .contains("    environment: boot-image-signing\n"),
        "the boot image publish job signs, so it needs the same environment"
    );
    assert!(
        boot_image.contains("id-token: write"),
        "keyless OIDC signing needs id-token: write at the workflow level"
    );
    assert!(
        boot_image.contains("contents: write"),
        "creating a release and uploading assets needs contents: write"
    );
}

#[test]
fn pages_workflow_installs_every_wasm_target_used_by_the_demo() {
    let workflow = pages_workflow();
    assert!(
        workflow.contains("targets: wasm32-unknown-unknown, wasm32-wasip1"),
        "pages.yml must install both the browser and guest WASM targets"
    );
}

#[test]
fn release_lookups_pass_the_filter_directly_to_gh_jq() {
    for (name, workflow) in [
        ("pages.yml", pages_workflow()),
        ("release.yml", release_workflow()),
    ] {
        assert!(
            workflow.contains("--json tagName --jq '"),
            "{name} must pass its semantic-version filter directly to gh --jq"
        );
        assert!(
            !workflow.contains("--json tagName --jq -r"),
            "{name} must pass the filter directly to gh --jq; -r is a standalone jq flag"
        );
    }
}

#[test]
fn pages_deployment_uses_the_checked_in_wrangler_config() {
    let workflow = pages_workflow();
    let account_job = job_block(&workflow, "cloudflare-account");
    let package = fs::read_to_string("public/package.json").expect("read site package manifest");
    let config = fs::read_to_string("public/wrangler.toml").expect("read Wrangler config");

    assert!(
        workflow.contains("cloudflare-account:")
            && account_job.contains("runs-on: ubuntu-latest")
            && workflow.contains("needs: cloudflare-account")
            && workflow.contains("command: pages deployment list --project-name=mvm")
            && !workflow.contains("pages project create"),
        "the Pages workflow must verify the configured account and project before building"
    );
    assert!(
        workflow.contains("uses: pnpm/action-setup@v6"),
        "the Pages workflow must use the Node 24-compatible pnpm setup action"
    );
    assert!(
        workflow.contains("workingDirectory: public")
            && workflow.contains("command: pages deploy --branch=main"),
        "the Pages action must deploy from public/ so Wrangler reads the checked-in config"
    );
    assert!(
        config.contains("name = \"mvm\"") && config.contains("pages_build_output_dir = \"./dist\""),
        "Wrangler must target the existing mvm project and Astro output"
    );
    // Wrangler refuses a Pages config carrying `account_id` outright --
    // "Configuration file for Pages projects does not support account_id" --
    // so the deploy fails after a successful build, at the last step. The
    // account is supplied by the workflow from `secrets.CLOUDFLARE_ACCOUNT_ID`,
    // which is where it belongs: it is deployment identity, not site config,
    // and checking it in pins one account into a file every fork inherits.
    assert!(
        !config.contains("account_id"),
        "a Pages wrangler config must not carry account_id; the workflow passes \
         accountId from secrets"
    );
    assert!(
        package.contains("\"wrangler\": \"^4.127.0\"")
            && package.contains("\"check:deploy-assets\":")
            && package.contains(
                "\"deploy\": \"pnpm build && pnpm check:deploy-assets && wrangler pages deploy --branch=main\""
            ),
        "the site must pin Wrangler and validate assets in its production deploy command"
    );
}

#[test]
fn pages_deployment_refuses_an_incomplete_weblinux_bundle() {
    let workflow = pages_workflow();
    let validator = fs::read_to_string("public/scripts/check-weblinux-deploy-assets.mjs")
        .expect("read WebLinux deployment validator");

    assert!(
        workflow.contains("node public/scripts/check-weblinux-deploy-assets.mjs public/dist"),
        "Pages must run the shared WebLinux bundle validator before publishing"
    );

    for asset in [
        "demo/weblinux/demo.js",
        "demo/weblinux/worker.js",
        "demo/weblinux/qemu-system-x86_64.js",
        "demo/weblinux/qemu-system-x86_64.wasm.gz",
        "demo/weblinux/pack/kernel.img",
        "demo/weblinux/pack/rootfs.bin",
    ] {
        assert!(
            validator.contains(asset),
            "the shared deployment validator must require {asset}"
        );
    }
}

#[test]
fn qemu_wasm_site_pack_is_built_once_on_the_boot_image_train() {
    let boot_image = boot_image_workflow();
    let pages = pages_workflow();
    let publish_needs = job_block(&boot_image, "publish-boot-image")
        .lines()
        .find(|line| line.trim_start().starts_with("needs:"))
        .expect("the boot image publish job must declare its dependencies");

    assert!(
        boot_image.contains("\n  qemu-wasm-site-pack:\n"),
        "release-boot-image.yml must build the browser QEMU pack on the boot-image tag"
    );
    assert!(
        boot_image.contains("nix build ./nix#qemu-wasm-smoke-pack"),
        "the boot-image workflow must build the QEMU-WASM pack from the tagged tree"
    );
    assert!(
        publish_needs.contains("qemu-wasm-site-pack"),
        "the boot-image release must wait for the QEMU-WASM pack before publishing"
    );
    for asset in [
        "qemu-wasm-smoke-pack.tar.gz",
        "qemu-wasm-smoke-pack.tar.gz.sha256",
        "qemu-wasm-smoke-pack.tar.gz.sha256.bundle",
    ] {
        assert!(
            boot_image.contains(asset),
            "the boot-image release must publish {asset} for site deployments"
        );
        assert!(
            pages.contains(asset),
            "pages.yml must download and verify {asset} instead of rebuilding QEMU"
        );
    }
    assert!(
        !pages.contains("nix build ./nix#qemu-wasm-smoke-pack"),
        "site deployment must not rebuild the tagged QEMU-WASM pack"
    );
    assert!(
        !pages.contains("nix-installer-action"),
        "site deployment no longer needs Nix once the QEMU-WASM pack is released"
    );
    assert!(
        pages.contains("cosign verify-blob")
            && pages.contains("release-boot-image.yml@refs/tags/boot-image/v.*")
            && pages.contains("sha256sum -c qemu-wasm-smoke-pack.tar.gz.sha256"),
        "site deployment must verify the tag-built pack's release identity"
    );
    assert!(
        pages.contains("gh release view \"${CANDIDATE}\"")
            && pages.contains("HAS_SITE_PACK")
            && pages.contains("| sort_by(.v) | reverse | .[].tag"),
        "site deployment must select the newest semantic release that actually carries the pack"
    );
    assert!(
        pages.contains("./web/weblinux-demo/build.sh qemu-wasm-smoke-pack"),
        "site deployment must stage the verified pack with the current demo shell"
    );
}

#[test]
fn weblinux_qemu_module_is_staged_below_the_pages_file_limit() {
    let build =
        fs::read_to_string("web/weblinux-demo/build.sh").expect("read WebLinux build script");
    let worker = fs::read_to_string("web/weblinux-demo/worker.js").expect("read WebLinux worker");

    assert!(
        build.contains("gzip -9 -n \"$DEST_DIR/qemu-system-x86_64.wasm\""),
        "the oversized QEMU-WASM module must be compressed while staging"
    );
    assert!(
        worker.contains("qemu-system-x86_64.wasm.gz")
            && worker.contains("new DecompressionStream(\"gzip\")")
            && worker.contains("self.Module.wasmBinary = await loadCompressedWasm()"),
        "the worker must explicitly decompress the staged module before Emscripten starts"
    );
}

/// The compiled-in boot image tag must name the release the workflow creates.
///
/// The tag is spliced straight into a download URL, so a drift between the two
/// is not a type error or a failed test anywhere else — it is a 404 on a fresh
/// install's first boot, which is the worst place to discover it.
#[test]
fn the_boot_image_tag_composes_the_url_the_workflow_uploads_to() {
    let tag = mvmctl::core::config::DEFAULT_BOOT_IMAGE_TAG;
    let workflow = boot_image_workflow();

    // The tag the workflow publishes under is its own ref name, so a tag push
    // that fires this workflow is exactly the release the URL below resolves.
    assert!(
        push_tag_patterns(&workflow)
            .iter()
            .any(|pattern| tag.starts_with(pattern.trim_end_matches('*'))),
        "{tag} would not fire release-boot-image.yml, so no release by that name \
         is ever created"
    );
    assert!(
        workflow.contains("TAG_NAME: ${{ github.ref_name }}")
            && workflow.contains("gh release create \"${TAG_NAME}\""),
        "the publish job must create the release under the pushed tag verbatim"
    );

    for asset in [
        "default-microvm-vmlinux-x86_64",
        "default-microvm-rootfs-x86_64.ext4",
        "default-microvm-x86_64-checksums-sha256.txt",
    ] {
        let url = format!("https://github.com/tinylabscom/mvm/releases/download/{tag}/{asset}");
        assert!(
            url.contains("/releases/download/boot-image/v"),
            "the composed URL must sit under the boot image tag: {url}"
        );
        let staged = asset.replace("x86_64", "${ARCH}");
        assert!(
            workflow.contains(&staged),
            "the workflow must stage {staged:?}, or {url} 404s"
        );
    }
}

/// A release candidate must not be published as GitHub's "Latest" release.
///
/// `mvmctl update` resolves `/repos/<repo>/releases/latest` to decide what
/// version to move a user to. `gh release create` marks a release latest unless
/// told otherwise, so without an explicit `--prerelease` a `v0.18.0-rc.1` tag
/// silently becomes the upgrade target for every stable installation — the one
/// class of user who did not opt into a prerelease.
///
/// The guard is asserted rather than a bare flag, because always passing
/// `--prerelease` would break every stable release instead.
#[test]
fn a_prerelease_tag_is_not_published_as_the_latest_release() {
    let workflow = release_workflow();

    assert!(
        workflow.contains("prerelease=(--prerelease)"),
        "release.yml must be able to publish a release as a prerelease, or an \
         rc tag becomes the upgrade target for every stable install"
    );
    assert!(
        workflow.contains(r#"if [[ "${TAG_NAME#v}" == *-* ]]; then"#),
        "the prerelease flag must be gated on the tag carrying a semver \
         prerelease segment, so a stable tag still publishes as latest"
    );

    let create = workflow
        .find("gh release create \"${TAG_NAME}\"")
        .expect("release.yml must create the release under the pushed tag");
    let guard = workflow
        .find("prerelease=(--prerelease)")
        .expect("checked above");
    assert!(
        guard < create,
        "the prerelease decision must be made before the release is created"
    );
    assert!(
        workflow[create..].contains(r#""${prerelease[@]}""#),
        "`gh release create` must expand the prerelease array, or deciding it \
         changes nothing about what gets published"
    );
}

#[test]
fn the_ci_boot_witness_pins_the_compiled_boot_image_tag() {
    let tag = mvmctl::core::config::DEFAULT_BOOT_IMAGE_TAG;
    assert!(
        ci_workflow().contains(&format!("IMAGE_TAG: {tag}")),
        "the merge-queue boot witness must validate the compiled default boot image tag {tag}"
    );
}

#[test]
fn the_cross_compile_installers_share_a_cortex_flag_compatible_zigbuild() {
    let workspace = fs::read_to_string("Cargo.toml").expect("read workspace manifest");
    let version = workspace
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("cargo-zigbuild = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .expect("workspace cargo-zigbuild pin");
    let parts = version
        .split('.')
        .map(|part| part.parse::<u32>().expect("numeric cargo-zigbuild version"))
        .collect::<Vec<_>>();
    assert!(
        parts.as_slice() >= &[0, 23, 0],
        "cargo-zigbuild {version} forwards Rust's AArch64 cortex workaround to Zig, which rejects it"
    );

    for path in [
        ".github/actions/install-zigbuild/action.yml",
        "scripts/local-aarch64-no-kvm-smoke.sh",
    ] {
        let installer = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
        assert!(
            installer.contains(&format!("cargo-zigbuild --version {version}")),
            "{path} must install the workspace cargo-zigbuild pin {version}"
        );
    }
}

/// A CLI release with no boot image assets must not publish.
///
/// The image train and the CLI train are now separate, so it is possible to cut
/// a `vN` release when no `boot-image/v*` release exists. The result is not a
/// degraded release, it is a broken one: `download_default_microvm_image`
/// resolves its assets off the CLI release, so every fresh install 404s on
/// first boot. Warning past that ships the failure and discovers it later,
/// which is the exact pattern this gate family exists to end.
#[test]
fn a_release_with_no_boot_image_assets_refuses_to_publish() {
    let workflow = release_workflow();
    let step = workflow
        .split("- name: Attach the boot image release assets to this release")
        .nth(1)
        .expect("release.yml must attach boot image assets");
    let step = step
        .split("\n      - name:")
        .next()
        .expect("the step body is non-empty");

    assert!(
        step.contains("::error::"),
        "a missing boot image release must be an error, not a warning:\n{step}"
    );
    assert!(
        step.contains("exit 1"),
        "a missing boot image release must fail the publish:\n{step}"
    );
    assert!(
        !step.contains("::warning::") && !step.contains("exit 0"),
        "the missing-boot-image path must not warn-and-continue:\n{step}"
    );
}

/// The boot gate must carry the toolchain its own test needs.
///
/// The gate runs `cargo test`, which builds mvmctl, whose `build.rs`
/// cross-compiles the embedded host binaries as static musl and requires the
/// pinned zig. The first real image release failed here: the gate aborted
/// before starting a guest, which reads in the log as "the image does not
/// boot" and is nothing of the kind. A gate that cannot run is worse than no
/// gate, because it blocks a release for a reason that has nothing to do with
/// the artifact.
#[test]
fn the_boot_gate_installs_the_toolchain_its_test_needs() {
    let workflow = boot_image_workflow();
    let job = workflow
        .split("  default-microvm:")
        .nth(1)
        .expect("the boot image workflow must define default-microvm");
    let boot = job
        .find("- name: Boot the staged image before it becomes a release asset")
        .expect("the job must boot the staged image");

    // The toolchain has to be installed *before* the boot step, not merely
    // present somewhere in the file.
    let before = &job[..boot];
    assert!(
        before.contains("./.github/actions/install-zigbuild"),
        "the boot gate must install the pinned zig before it runs cargo test; \
         without it the gate fails before reaching a guest"
    );
}

/// Every workflow that can mint an identity a shipped binary trusts must be
/// gated on a protected environment, so the ref allowed to produce a valid
/// signature is constrained by that environment's tag policy rather than by
/// whoever can trigger the workflow.
///
/// This is not theoretical. `release-boot-image.yml` asked for an environment
/// scoped to `v*` while firing on `boot-image/v*`; the mismatch blocked every
/// gated job one second in, with no steps and nothing in the log to read. And
/// `release.yml` — which mints the one identity `RELEASE_IDENTITY_TEMPLATES`
/// names, the identity every installed mvmctl verifies against — declared no
/// environment at all.
///
/// The environments' tag policies live in repository settings and cannot be
/// asserted from here. What is assertable, and what regressed, is that the
/// declaration exists at all.
#[test]
fn workflows_minting_trusted_identities_are_gated_on_an_environment() {
    for (path, expected_env) in [
        (".github/workflows/release.yml", "release-signing"),
        (
            ".github/workflows/release-boot-image.yml",
            "boot-image-signing",
        ),
        (".github/workflows/revocations.yml", "revocations-signing"),
    ] {
        let body = fs::read_to_string(Path::new(path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        assert!(
            body.contains(&format!("environment: {expected_env}")),
            "{path} mints an identity in mvm_core::release_trust, so it must \
             declare `environment: {expected_env}`. Without it any ref that can \
             trigger the workflow can mint a signature the shipped verifier \
             accepts."
        );
    }
}

/// The two signing environments are deliberately distinct. Sharing one would
/// let a boot image signature validate a CLI tarball and the reverse, which is
/// the exact confusion `BOOT_IMAGE_IDENTITY_TEMPLATES` is kept separate from
/// `RELEASE_IDENTITY_TEMPLATES` to prevent.
#[test]
fn the_two_release_trains_do_not_share_a_signing_environment() {
    let cli = fs::read_to_string(Path::new(".github/workflows/release.yml"))
        .expect("release.yml must be readable");
    let boot = fs::read_to_string(Path::new(".github/workflows/release-boot-image.yml"))
        .expect("release-boot-image.yml must be readable");
    assert!(
        !cli.contains("environment: boot-image-signing"),
        "the CLI train must not sign under the boot image train's environment"
    );
    assert!(
        !boot.contains("environment: release-signing"),
        "the boot image train must not sign under the CLI train's environment; \
         its tags are boot-image/v*, which a v*-scoped policy refuses outright"
    );
}

/// The initramfs is what `mvm-verity-init` runs as PID 1 to set up dm-verity
/// and mount the runtime overlay before `switch_root`. Without it a published
/// prod image cannot be sealed-booted from its own release assets — and nothing
/// published it, so `download_initramfs` had never once succeeded.
///
/// Pinned against the Rust constructor rather than against a literal, because
/// the failure this prevents is a rename on one side only, which produces a 404
/// at install time and nothing at build time.
#[test]
fn release_publishes_every_initramfs_asset_the_downloader_requests() {
    let workflow = release_workflow();
    for token in [SHELL_ARCH_TOKEN, MATRIX_ARCH_TOKEN] {
        let names = mvmctl::build::initramfs::InitramfsArtifactNames::for_arch(token);
        assert_publishes(&workflow, &names.archive);
        assert_publishes(&workflow, &names.archive_checksum);
    }
}

/// Publishing is not attaching. A job whose artifacts upload but never appear
/// in `gh release create` leaves the downloader with the same 404 a rename
/// would, and the release still reports success.
#[test]
fn the_release_job_builds_and_attaches_the_initramfs() {
    let workflow = release_workflow();
    assert!(
        workflow.contains("  initramfs-image:"),
        "release.yml must define the initramfs-image job"
    );
    assert!(
        workflow.contains("needs: [bdd, e2e-docs, build, initramfs-image]"),
        "the release job must wait for initramfs-image, or it publishes without it"
    );
    let release = job_block(&workflow, "release");
    assert!(
        release.contains("needs.initramfs-image.result == 'success'"),
        "the release job must fail closed when the initramfs build fails"
    );
    for pattern in [
        "artifacts/initramfs-*.tar.gz",
        "artifacts/initramfs-*.tar.gz.sha256",
    ] {
        assert!(
            workflow.contains(pattern),
            "the release job's asset list must include {pattern:?}"
        );
    }
    // Both arches, or an install on the other one 404s exactly as before.
    let block = job_block(&workflow, "initramfs-image");
    for arch in ["aarch64", "x86_64"] {
        assert!(
            block.contains(&format!("arch: {arch}")),
            "the initramfs-image matrix must build {arch}"
        );
    }
}

/// Every member `extract_initramfs_archive` requires must actually be put in
/// the tarball. Four come from the derivation and the fifth is generated at
/// packaging; leaving any out fails at install time with
/// `missing required archive member`, on a host that cannot debug it.
#[test]
fn the_initramfs_tarball_carries_every_member_the_extractor_requires() {
    let workflow = release_workflow();
    let block = job_block(&workflow, "initramfs-image");
    for member in [
        mvm_fs::initramfs::INITRAMFS_IMAGE_FILE,
        mvm_fs::initramfs::INITRAMFS_HASH_FILE,
        mvm_fs::initramfs::INITRAMFS_SIZE_FILE,
        mvm_fs::initramfs::VERSION_FILE,
        mvm_fs::initramfs::CHECKSUM_MANIFEST_FILE,
    ] {
        assert!(
            block.contains(member),
            "the initramfs tarball must carry {member:?}, which the extractor requires"
        );
    }
}
