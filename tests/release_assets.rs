//! Pin the CLI release workflow to what the shipped binary expects of it.
//!
//! A release is the binary archives, one signed checksum manifest over them and
//! a signed SBOM. Boot images are not part of it: they are members of the
//! signed image set `crates/mvm-core/images.lock` pins, published by
//! mvm-images. These tests keep the release publishing exactly that, gated the
//! way the installer and `mvmctl update` need it gated.

use std::fs;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

fn release_workflow() -> String {
    let path = Path::new(".github/workflows/release.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// The first-run lanes `release.yml` calls after publishing a tag, and a
/// maintainer dispatches against a candidate before tagging.
fn first_run_smoke_workflow() -> String {
    let path = Path::new(".github/workflows/first-run-smoke.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn just_module(name: &str) -> String {
    let path = format!("just/{name}/mod.just");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

/// The publish path must be reachable without pushing a tag.
///
/// Every release defect found while cutting v0.18.0-rc.1 lived in the publish
/// job, and the publish job used to be unreachable except by a tag push: the
/// dry run stopped after `build`. So each attempt surfaced exactly one defect,
/// at roughly two and a half hours per discovery, four times over — a missing
/// cross-compile target, an incomplete boot image, a transient 403, and a
/// duplicate asset name that 422'd *after* the release had been created.
///
/// A dry run reaches `gh release create` against a throwaway draft, so those
/// same failures surface in minutes. The draft is deleted afterwards, and
/// `always()` on the cleanup matters: a create that succeeds and then fails
/// uploading leaves a draft behind, which is exactly the case that produced the
/// 422.
///
/// What a dry run cannot prove is asserted here too, by requiring the signing
/// and downstream-trigger steps to stay tag-only: their keyless identity pins
/// `refs/tags/*`, which a dispatch cannot mint. Pretending otherwise would make
/// a green dry run mean more than it does.
#[test]
fn a_dry_run_reaches_the_publish_step_without_a_tag() {
    let workflow = release_workflow();

    let create = workflow
        .find("gh release create \"${publish_tag}\"")
        .expect("the publish step must create the release under a computed tag");

    assert!(
        workflow.contains("publish_tag=\"dry-run-${GITHUB_RUN_ID}\""),
        "a dry run must publish under a scratch tag, never the real one"
    );
    assert!(
        workflow.contains("draft=(--draft)"),
        "a dry run must publish a draft — a draft is not listed and is not \
         resolved by /releases/latest, so `mvmctl update` cannot see it"
    );

    let cleanup = workflow
        .find("name: Delete the dry-run draft release")
        .expect("a dry run must delete the draft it created");
    assert!(
        create < cleanup,
        "the draft must be deleted after it is created, not before"
    );
    assert!(
        workflow[cleanup..].starts_with("name: Delete the dry-run draft release")
            && workflow[cleanup..cleanup + 400].contains("always()"),
        "cleanup must run even when the publish failed, or a create that fails \
         part-way through its uploads leaves the draft behind"
    );

    // A dry run runs from a branch, so anything minting or verifying a keyless
    // signature pinned to `refs/tags/*` has to stay on the tag path.
    for step in [
        "Sign release tarballs, checksum manifests, and SBOM",
        "Attest build provenance for the release tarballs (release-provenance)",
        "Trigger crates.io publish workflow",
    ] {
        let at = workflow
            .find(step)
            .unwrap_or_else(|| panic!("{step} must exist"));
        let window = &workflow[at..(at + 300).min(workflow.len())];
        assert!(
            window.contains("github.event_name == 'push'"),
            "{step} must be gated to tag pushes: a dry run cannot mint a \
             refs/tags identity, and must not publish or trigger anything real"
        );
    }
}

/// The release must not carry a signing step for per-variant image manifests.
///
/// Nothing writes a `*-image-*.manifest.json`, and nothing reads one: the
/// per-variant verifier was retired in favour of image sets. A step signing that
/// glob always took its empty branch and reported success, which reads like a
/// signature the release does not make. Image sets are signed where they are
/// published, not here.
#[test]
fn the_release_does_not_sign_image_manifests_nothing_produces() {
    let workflow = release_workflow();
    assert!(
        !workflow.contains("-image-*.manifest.json"),
        "release.yml signs or publishes `*-image-*.manifest.json`, which no job \
         produces; a step over that glob always succeeds having signed nothing"
    );
}

/// The published asset list must not name the same file twice.
///
/// A catch-all such as `artifacts/*.tar.gz` matches every tarball, including
/// any a narrower entry beside it also names. Passing a duplicate to `gh release create` makes GitHub accept the first upload and
/// reject the second with `ReleaseAsset.name already exists` — HTTP 422,
/// arriving *after* the release has been created, so the run goes red having
/// published a half-populated release.
///
/// This is checked as an overlap between the glob patterns rather than as the
/// presence of the `sort -u` that fixes it, so removing the overlap a different
/// way keeps the test honest, and re-introducing an overlapping catch-all
/// without deduplicating fails it.
#[test]
fn the_release_asset_list_cannot_upload_one_file_twice() {
    let workflow = release_workflow();

    let start = workflow
        .find("assets=(")
        .expect("the publish step must build an assets array");
    let len = workflow[start..]
        .find("\n          )")
        .expect("the assets array must be closed");
    let body = &workflow[start..start + len];

    let patterns: Vec<&str> = body
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(
        patterns.len() > 5,
        "parsed {} asset patterns — the parse broke, and a test that checks \
         nothing passes forever",
        patterns.len()
    );

    // A catch-all `dir/*.suffix` subsumes any `dir/prefix-*.suffix` beside it:
    // both expand over the same directory and end in the same suffix.
    let mut overlaps = Vec::new();
    for broad in &patterns {
        let Some((dir, suffix)) = broad.split_once("/*") else {
            continue;
        };
        for narrow in &patterns {
            if narrow == broad {
                continue;
            }
            if narrow.starts_with(&format!("{dir}/")) && narrow.ends_with(suffix) {
                overlaps.push(format!("{broad} also matches {narrow}"));
            }
        }
    }

    if !overlaps.is_empty() {
        assert!(
            workflow.contains(r#"mapfile -t assets < <(printf '%s\n' "${assets[@]}" | sort -u)"#),
            "the asset list has overlapping globs and is not deduplicated, so \
             `gh release create` uploads a file twice and GitHub refuses the \
             second with a 422 after creating the release:\n  {}",
            overlaps.join("\n  ")
        );

        let dedupe = workflow.find("| sort -u)").expect("checked above");
        // The invocation, not the phrase: `gh release create` also appears in
        // the comment above the array, which precedes the dedupe and would make
        // this ordering check fail against correct code.
        let create = workflow
            .find("gh release create \"${publish_tag}\"")
            .expect("the publish step must create the release under a computed tag");
        assert!(
            dedupe < create,
            "the list must be deduplicated before the release is created"
        );
    }
}

/// The release prep must test the tree it pushes, not the tree before it.
///
/// `just release::pr` runs the workspace suite and *then* calls `release::_prep`,
/// which is where the version actually changes. So the suite green-lights the
/// pre-bump tree while the bumped tree — the one that becomes the release — was
/// never run.
///
/// That is not hypothetical: a version parser that could not read a
/// pre-release suffix reached CI on v0.18.0-rc.1 because no published version
/// had ever carried one, making the defect unreachable until the bump.
#[test]
fn the_release_prep_runs_the_suite_after_the_version_is_bumped() {
    let justfile = just_module("release");
    let prep = justfile
        .find("_prep VERSION:")
        .expect("the shared release prep recipe must exist");
    let body = &justfile[prep..];

    let bump = body
        .find("version = \\\"$V\\\"")
        .expect("_release-prep must rewrite the workspace version");
    let suite = body
        .find("cargo nextest run --workspace")
        .expect("_release-prep must run the workspace suite against the bumped tree");
    let commit = body
        .find(r#"git commit -m "release: v$V""#)
        .expect("_release-prep must commit the bump");

    assert!(
        bump < suite,
        "the suite must run after the version is rewritten, or it witnesses the \
         tree as it was before the release"
    );
    assert!(
        suite < commit,
        "the suite must gate the commit, or a failing bumped tree is still pushed"
    );
}

/// A version bump invalidates every detached fuzz lockfile, so the bump has to
/// fix them.
///
/// The cargo-fuzz crates are separate workspaces pinning the internal `mvm-*`
/// crates by version, and `ci.yml` checks them with `cargo check --locked`. The
/// step sits behind a change-detector and `check-all` cannot see detached
/// lockfiles, so nothing on the PR evaluates them — v0.18.0-rc.1 was 13-green
/// on its PR and was evicted from the merge queue three times.
#[test]
fn the_release_prep_refreshes_the_detached_fuzz_lockfiles() {
    let justfile = just_module("release");
    let prep = justfile
        .find("_prep VERSION:")
        .expect("the shared release prep recipe must exist");
    let body = &justfile[prep..];

    assert!(
        body.contains("crates/*/fuzz*/Cargo.toml"),
        "_release-prep must walk the fuzz manifests, or their locks keep naming \
         the previous version and the merge queue rejects the release"
    );
    assert!(
        body.contains("crates/deps/*/fuzz*/Cargo.toml"),
        "the fuzz crate under crates/deps must be refreshed too — ci.yml globs \
         both paths, so covering one leaves the gate red"
    );

    let refresh = body
        .find("cargo metadata --manifest-path")
        .expect("_release-prep must re-resolve each fuzz lock");
    let commit = body
        .find(r#"git commit -m "release: v$V""#)
        .expect("_release-prep must commit the bump");
    assert!(
        refresh < commit,
        "the locks must be refreshed before the commit, or the release PR \
         carries the stale ones"
    );
}

/// Every cross-compiled release target must have its std installed by the
/// toolchain this repo actually pins.
///
/// `release.yml` passes `targets:` to `dtolnay/rust-toolchain`, which installs
/// them for *the action's* toolchain. `rust-toolchain.toml` then overrides
/// which toolchain cargo uses, and the override does not inherit those targets.
/// A target listed only in the workflow therefore has no `core`/`std` at build
/// time, and the build fails with E0463.
///
/// It failed exactly once and only in the worst place: no PR lane builds
/// `aarch64-unknown-linux-gnu`, so the first evidence was a tagged release
/// pipeline going red. That is what this test replaces.
///
/// A target that is its runner's native triple is exempt — its std ships with
/// the toolchain, and listing every host triple here would make each
/// contributor install std for platforms they never build.
#[test]
fn every_cross_compiled_release_target_is_pinned_by_the_toolchain_file() {
    let workflow = release_workflow();
    let toolchain_file =
        fs::read_to_string("rust-toolchain.toml").expect("rust-toolchain.toml must be readable");

    // Only the `targets = [...]` array counts. Searching the whole file would
    // match the comment above that array, which names the very target it
    // explains — the first draft of this test passed with the target removed,
    // for exactly that reason.
    let targets_start = toolchain_file
        .find("targets = [")
        .expect("rust-toolchain.toml must declare a targets array");
    let targets_len = toolchain_file[targets_start..]
        .find(']')
        .expect("the targets array must be closed");
    let toolchain = &toolchain_file[targets_start..targets_start + targets_len];

    // Runner image -> the triple its rustc is native to.
    let native = [
        ("macos-latest", "aarch64-apple-darwin"),
        ("ubuntu-latest", "x86_64-unknown-linux-gnu"),
        ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
    ];

    // The build matrix entries. `target` is the stable release-asset contract;
    // `build_target` is the Rust ABI that actually goes into that archive.
    let mut pairs = Vec::new();
    let lines: Vec<&str> = workflow.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(target) = line.trim().strip_prefix("- target: ") else {
            continue;
        };
        let build_target = lines[i + 1..]
            .iter()
            .take(6)
            .find_map(|l| l.trim().strip_prefix("build_target: "))
            .unwrap_or_else(|| panic!("matrix entry {target} names no build target"));
        let os = lines[i + 1..]
            .iter()
            .take(6)
            .find_map(|l| l.trim().strip_prefix("os: "))
            .unwrap_or_else(|| panic!("matrix entry {target} names no runner"));
        pairs.push((build_target.trim().to_string(), os.trim().to_string()));
    }

    assert!(
        !pairs.is_empty(),
        "no build matrix entries found — the parse broke, and a test that \
         checks nothing passes forever"
    );

    for (target, os) in &pairs {
        let is_native = native
            .iter()
            .any(|(runner, triple)| runner == os && triple == target);
        if is_native {
            continue;
        }
        assert!(
            toolchain.contains(target),
            "{target} is cross-compiled on {os} but rust-toolchain.toml does not \
             pin it, so the pinned toolchain has no std for it and the release \
             build fails with `can't find crate for core`"
        );
    }
}

/// Linux release payloads must be static musl binaries, while their published
/// archive names stay on the historical `*-unknown-linux-gnu` contract so an
/// older installed mvmctl can still discover and download its update.
#[test]
fn linux_release_assets_keep_their_names_but_build_musl_payloads() {
    let workflow = release_workflow();

    for (asset_target, build_target) in [
        ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"),
        ("aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"),
    ] {
        let entry = format!("- target: {asset_target}\n            build_target: {build_target}");
        assert!(
            workflow.contains(&entry),
            "release asset {asset_target} must be built from {build_target}"
        );
    }

    assert!(
        workflow.contains("cargo zigbuild --profile release-min --target \"${BUILD_TARGET}\""),
        "Linux musl release binaries must use cargo-zigbuild"
    );
    assert!(
        workflow.contains("ARCHIVE_NAME=\"mvmctl-${TARGET}\""),
        "the public archive name must remain based on the compatibility target"
    );
    assert!(
        workflow.contains("target/${BUILD_TARGET}/release-min/${BIN_NAME}"),
        "packaging must copy the binary from the musl build target"
    );
    assert!(
        workflow.contains("name: Verify Linux release payloads are statically linked")
            && workflow.contains("if: endsWith(matrix.build_target, '-unknown-linux-musl')")
            && workflow.contains("description=\"$(file --brief \"${binary}\")\"")
            && workflow.contains("*\"statically linked\"*"),
        "the release must fail closed if mvmctl or an embedded Linux helper regains a glibc dependency"
    );
}

fn ci_workflow() -> String {
    let path = Path::new(".github/workflows/ci.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn website_deploy_workflow() -> String {
    let path = Path::new(".github/workflows/workers.yml");
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn website_workflow() -> String {
    let path = Path::new(".github/workflows/website.yml");
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
        checked >= 1,
        "expected to find the release's signing invocation, found {checked}"
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

/// The combined checksum manifest must be signed, and its bundle published.
///
/// It is what the installer and `mvmctl update` anchor on: they hash the
/// archive and compare against the manifest, so an unsigned one lets whoever
/// can swap an archive swap its recorded digest too and the comparison still
/// passes.
///
/// Dropping the manifest from the signing loop, or signing it and forgetting to
/// attach the bundle, both fail the same way: the download still succeeds, still
/// "verifies", and nothing surfaces it until a real release ships. Hence a gate.
#[test]
fn the_combined_checksum_manifest_is_signed_and_its_bundle_attached() {
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

    let manifest = "artifacts/checksums-sha256.txt";
    assert!(
        sign_loop.contains(manifest),
        "{manifest} must be cosign-signed; every archive digest in it inherits its trust"
    );
    assert!(
        assets.contains(&format!("{manifest}.bundle")),
        "{manifest}.bundle must be attached to the release, or the verifier 404s"
    );
}

/// The CLI release carries no image. Images are built and signed in
/// mvm-images, and every consumer verifies them against the signed root the
/// lock pins; a CLI release that rebuilt, mirrored or re-signed one would be a
/// second producer under a second identity, which is what moving images out
/// of this repository ended.
#[test]
fn the_cli_release_carries_no_image() {
    let workflow = release_workflow();
    for image_asset in [
        "nix/images",
        "artifacts/runtime-overlay",
        "artifacts/sdk-sidecar",
        "artifacts/initramfs",
        "artifacts/builder-vm",
        "artifacts/default-microvm",
        "vmlinux",
        "pack-manifest.json",
        "release-boot-image",
        "kernel-build.yml",
    ] {
        assert!(
            !workflow.contains(image_asset),
            "release.yml names {image_asset:?}; images ship from mvm-images, not from a CLI release"
        );
    }
}

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

/// The CLI release fires on its own version tag and nothing else — in
/// particular not on the image-set tag the lock pins, which names a release in
/// another repository.
///
/// GitHub tag globs anchor at the start and do not cross `/`, but that is a
/// claim about someone else's matcher, so what is asserted here is the thing we
/// control: the pattern itself, and that the image-set tag fails its literal
/// prefix.
#[test]
fn the_cli_release_fires_on_its_own_tag_alone() {
    assert_eq!(
        push_tag_patterns(&release_workflow()),
        vec!["v*".to_string()],
        "release.yml must fire on the CLI version tag and nothing else"
    );

    let image_tag = mvmctl::core::config::default_boot_image_tag();
    let prefix = |pattern: &str| pattern.split('*').next().unwrap_or_default().to_string();
    assert!(
        !image_tag.starts_with(&prefix("v*")),
        "{image_tag} must not match the CLI train's pattern"
    );
}

#[test]
fn workers_workflow_installs_every_wasm_target_used_by_the_demo() {
    let workflow = website_deploy_workflow();
    assert!(
        workflow.contains("targets: wasm32-unknown-unknown, wasm32-wasip1"),
        "workers.yml must install both the browser and guest WASM targets"
    );
}

#[test]
fn workers_deploys_website_updates_merged_to_main() {
    let workflow = website_deploy_workflow();
    assert!(
        workflow.contains("  push:\n    branches:\n      - main\n"),
        "workers.yml must deploy website changes after they merge to main"
    );
    for path in [
        "public/**",
        "web/mvm-demo/**",
        "web/mvm-demo-guest/**",
        ".github/workflows/workers.yml",
    ] {
        assert!(
            workflow.contains(&format!("      - \"{path}\"")),
            "workers.yml must deploy main-branch updates to {path}"
        );
    }
}

#[test]
fn workers_bakes_a_trusted_archive_hash_for_every_installer_target() {
    let workflow = website_deploy_workflow();
    let installer = fs::read_to_string("install.sh").expect("read install.sh");
    let pin = fs::read_to_string("scripts/pin-installer-default.sh").expect("read the pin script");

    assert!(
        workflow.contains(
            r#"run: sh scripts/pin-installer-default.sh "${INSTALL_VERSION}" install.sh"#
        ) && workflow.contains("sigstore/cosign-installer"),
        "the stable-site deployment must bake the installer through the pin script, with cosign available to it"
    );
    assert!(
        pin.contains("--pattern 'checksums-sha256.txt*'")
            && pin.contains("checksums-sha256.txt.bundle")
            && pin.contains("cosign verify-blob")
            && pin.contains("release.yml@refs/tags/$TAG"),
        "the pin must authenticate the published release's checksum manifest under the exact release-workflow tag identity"
    );

    for (target, variable) in [
        (
            "aarch64-apple-darwin",
            "DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN",
        ),
        (
            "x86_64-unknown-linux-gnu",
            "DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU",
        ),
        (
            "aarch64-unknown-linux-gnu",
            "DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU",
        ),
    ] {
        assert!(
            installer.contains(&format!("{variable}=\"")),
            "install.sh must carry the {target} trust-anchor sentinel"
        );
        assert!(
            pin.contains(&format!("{target}:{variable}")),
            "the pin script must bake the {target} archive hash into {variable}"
        );
    }
}

#[test]
fn promoted_prebuilt_pin_pr_dispatches_ci_for_its_branch() {
    let workflow = release_workflow();
    let job = workflow
        .split("  propose-prebuilt-pin:\n")
        .nth(1)
        .expect("release workflow must propose a prebuilt pin");

    assert!(job.contains("gh pr create --base main --head \"$branch\""));
    assert!(job.contains("      actions: write"));
    assert!(
        job.contains("gh workflow run ci.yml --ref \"$branch\""),
        "a PR opened by the workflow token needs an explicit CI dispatch"
    );
}

/// The installer's offline fallback has one writer.
///
/// `release::_prep` used to set `DEFAULT_VERSION` to the version it was
/// preparing — a tag that did not exist yet — while leaving the previous
/// release's archive hashes beside it, so a fresh install falling back to it
/// either found no release or refused the archive as a hash mismatch. The pin
/// script writes the version and its hashes together, from a promoted
/// release's signed manifest, and nothing else touches those lines.
#[test]
fn the_installer_default_is_written_only_by_the_pin_script() {
    let justfile = just_module("release");
    let prep = justfile
        .find("_prep VERSION:")
        .expect("the shared release prep recipe must exist");
    let body = &justfile[prep..];
    let body = &body[..body.find("\ntag VERSION:").unwrap_or(body.len())];
    assert!(
        body.contains("./scripts/pin-installer-default.sh --newest install.sh"),
        "the release PR must pin the newest promoted release, not the one it prepares"
    );

    // A `sed` naming the pinned variables is a writer unless it only prints
    // (`sed -n ... /p`), which is how the compat lanes read the default.
    let writes_the_pin = |text: &str| {
        text.lines().any(|line| {
            line.contains("sed")
                && !line.contains("sed -n")
                && (line.contains("DEFAULT_VERSION") || line.contains("DEFAULT_ARCHIVE_SHA256"))
        })
    };
    let mut files = vec![
        Path::new("Justfile").to_path_buf(),
        Path::new("just/release/mod.just").to_path_buf(),
    ];
    for dir in [".github/workflows", "scripts", "scripts/installer-compat"] {
        files.extend(
            fs::read_dir(dir)
                .expect("read dir")
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file()),
        );
    }
    let writers: Vec<String> = files
        .iter()
        .filter(|path| !path.ends_with("pin-installer-default.sh"))
        .filter(|path| writes_the_pin(&fs::read_to_string(path).unwrap_or_default()))
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        writers.is_empty(),
        "only scripts/pin-installer-default.sh may rewrite the installer default, found: {writers:?}"
    );
}

#[test]
fn installer_pins_a_legacy_bootstrap_verifier_for_every_target() {
    let installer = fs::read_to_string("install.sh").expect("read install.sh");

    assert!(
        installer.contains("COSIGN_VERSION=\"v3.1.3\""),
        "the temporary verifier version must be explicit and reviewable"
    );
    for variable in [
        "COSIGN_SHA256_AARCH64_APPLE_DARWIN",
        "COSIGN_SHA256_X86_64_UNKNOWN_LINUX_GNU",
        "COSIGN_SHA256_AARCH64_UNKNOWN_LINUX_GNU",
    ] {
        let prefix = format!("{variable}=\"");
        let value = installer
            .lines()
            .find_map(|line| line.strip_prefix(&prefix)?.strip_suffix('"'))
            .unwrap_or_else(|| panic!("install.sh has no {variable}"));
        assert_eq!(value.len(), 64, "{variable} must be a SHA-256");
        assert!(
            value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{variable} must contain only hexadecimal digits"
        );
    }
}

#[test]
fn website_validation_covers_demo_guest_and_deploy_workflow_changes() {
    let workflow = website_workflow();
    for path in ["web/mvm-demo-guest/**", ".github/workflows/workers.yml"] {
        assert!(
            workflow.contains(&format!("      - \"{path}\"")),
            "website.yml must validate pull requests that update {path}"
        );
    }
}

/// `gh` has no `-r` flag. Passing one consumes `--jq`'s value, demoting the
/// real expression to a positional argument, and gh rejects the whole
/// invocation with `unknown command "<the entire jq program>"`.
#[test]
fn release_lookups_pass_the_filter_directly_to_gh_jq() {
    let mut workflows = Vec::new();
    for entry in fs::read_dir(".github/workflows").expect("read the workflows directory") {
        let path = entry.expect("read a workflow entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            workflows.push((name, fs::read_to_string(&path).expect("read a workflow")));
        }
    }
    let jq_lookups = workflows
        .iter()
        .filter(|(_, workflow)| workflow.contains("--jq"))
        .collect::<Vec<_>>();
    assert!(
        !jq_lookups.is_empty(),
        "the fixture must include at least one gh --jq lookup"
    );

    for (name, workflow) in jq_lookups {
        assert!(
            workflow.contains("--jq '"),
            "{name} must pass its filter expression directly to gh --jq"
        );
        assert!(
            !workflow.contains("--jq -r"),
            "{name} must pass the filter directly to gh --jq; -r is a standalone jq flag"
        );
    }
}

/// The deployed WebLinux pack must come from the tag `images.lock` pins, not
/// from whichever image release happens to be newest when the job runs.
#[test]
fn the_website_deployment_takes_its_runtime_pack_from_the_locked_tag() {
    let workflow = website_deploy_workflow();
    let downloader = fs::read_to_string("scripts/download-qemu-wasm-smoke-pack.sh")
        .expect("read WebLinux downloader");
    assert!(
        workflow.contains("download-qemu-wasm-smoke-pack.sh")
            && downloader.contains(r#"LOCKED_TAG="$("$SCRIPT_DIR/locked-image-tag.sh")""#),
        "workers.yml must delegate to a downloader that reads the image-set tag from images.lock"
    );
    assert!(
        !workflow.contains("gh release list"),
        "enumerating published releases and taking the highest is a `latest` \
         selection, which makes what the site deploys a property of whoever \
         published last"
    );
}

#[test]
fn workers_deployment_uses_the_checked_in_wrangler_config() {
    let workflow = website_deploy_workflow();
    let account_job = job_block(&workflow, "cloudflare-account");
    let package = fs::read_to_string("public/package.json").expect("read site package manifest");
    let config = fs::read_to_string("public/wrangler.toml").expect("read Wrangler config");

    assert!(
        workflow.contains("cloudflare-account:")
            && account_job.contains("runs-on: ubuntu-latest")
            && workflow.contains("needs: cloudflare-account")
            && account_job.contains("command: whoami"),
        "the Workers workflow must verify its Cloudflare credentials before building"
    );
    assert!(
        workflow.contains("uses: pnpm/action-setup@v6"),
        "the Workers workflow must use the Node 24-compatible pnpm setup action"
    );
    assert!(
        workflow.contains("workingDirectory: public")
            && workflow.contains("command: deploy")
            && !workflow.contains("command: pages "),
        "the Workers action must deploy from public/ so Wrangler reads the checked-in config"
    );
    assert!(
        config.contains("name = \"mvm\"")
            && config.contains("[assets]")
            && config.contains("directory = \"./dist\"")
            && config.contains("not_found_handling = \"404-page\"")
            && !config.contains("pages_build_output_dir"),
        "Wrangler must deploy the Astro output as mvm Worker static assets"
    );
    assert!(
        !config.contains("account_id"),
        "deployment identity must come from the workflow secret, not site config"
    );
    assert!(
        package.contains("\"wrangler\": \"^4.127.0\"")
            && package.contains("\"check:deploy-assets\":")
            && package.contains(
                "\"deploy\": \"pnpm build && pnpm check:deploy-assets && wrangler deploy\""
            )
            && package.contains(
                "\"deploy:preview\": \"pnpm build && pnpm check:deploy-assets && wrangler versions upload\""
            )
            && package.contains(
                "\"preview:cloudflare\": \"pnpm build && pnpm check:deploy-assets && wrangler dev\""
            ),
        "the site must pin Wrangler and validate assets in its Worker deploy and preview commands"
    );
}

#[test]
fn workers_deployment_refuses_an_incomplete_weblinux_bundle() {
    let workflow = website_deploy_workflow();
    let validator = fs::read_to_string("public/scripts/check-weblinux-deploy-assets.mjs")
        .expect("read WebLinux deployment validator");

    assert!(
        workflow.contains("node public/scripts/check-weblinux-deploy-assets.mjs public/dist"),
        "Workers must run the shared WebLinux bundle validator before publishing"
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

/// Site deployment fetches the browser QEMU pack the image set publishes; it
/// never rebuilds it.
#[test]
fn qemu_wasm_site_pack_is_fetched_from_the_image_set_not_rebuilt() {
    let workers = website_deploy_workflow();
    let downloader = fs::read_to_string("scripts/download-qemu-wasm-smoke-pack.sh")
        .expect("read WebLinux downloader");

    let asset = "qemu-wasm-smoke-pack.tar.gz";
    assert!(
        downloader.contains(asset),
        "the Workers downloader must acquire and verify {asset} instead of rebuilding QEMU"
    );
    assert!(
        !workers.contains("nix build ./nix#qemu-wasm-smoke-pack"),
        "site deployment must not rebuild the published QEMU-WASM pack"
    );
    assert!(
        !workers.contains("nix-installer-action"),
        "site deployment does not need Nix once the QEMU-WASM pack is published"
    );
    assert!(
        downloader.contains("cosign verify-blob")
            && downloader.contains("image_set workflow")
            && downloader.contains("image_set tag_ref")
            && downloader.contains("sha256sum -c expected.txt"),
        "site deployment must verify the locked root identity and member digest"
    );
    assert!(
        workers.contains("download-qemu-wasm-smoke-pack.sh") && downloader.contains("LOCKED_TAG"),
        "site deployment must take the pack from the release images.lock pins"
    );
    assert!(
        workers.contains("./web/weblinux-demo/build.sh qemu-wasm-smoke-pack"),
        "site deployment must stage the verified pack with the current demo shell"
    );
}

#[test]
fn qemu_wasm_local_tools_use_the_published_pack_and_maintained_harness() {
    let recipes = just_module("site");
    let downloader = fs::read_to_string("scripts/download-qemu-wasm-smoke-pack.sh")
        .expect("read QEMU-WASM pack downloader");
    let harness = fs::read_to_string("scripts/run-qemu-wasm-smoke-chromium.py")
        .expect("read maintained QEMU-WASM Chromium harness");

    for retired in [
        "scripts/build-qemu-wasm-smoke-pack.sh",
        "scripts/run-qemu-wasm-demo-chromium.py",
        "scripts/run-qemu-wasm-smoke-suite.py",
    ] {
        assert!(
            !Path::new(retired).exists(),
            "retired QEMU-WASM tool must stay deleted: {retired}"
        );
    }
    assert!(
        !recipes.contains("qemu-wasm-pack *ARGS:"),
        "the site module must not offer the retired Lima-backed build recipe"
    );
    assert!(
        recipes.contains("qemu-pack *ARGS:")
            && downloader.contains("locked-image-tag.sh")
            && downloader.contains("qemu-wasm-smoke-pack.tar.gz"),
        "local QEMU-WASM setup must use the tree-pinned published pack"
    );
    assert!(
        !downloader.contains("NOT currently published")
            && !downloader.contains("build-qemu-wasm-smoke-pack.sh"),
        "the downloader must not direct users back to the retired build path"
    );
    assert!(
        harness.contains("serve-qemu-wasm-smoke-pack.py")
            && Path::new("scripts/serve-qemu-wasm-smoke-pack.py").is_file(),
        "the maintained Chromium harness must use its checked-in server"
    );
}

#[test]
fn weblinux_qemu_module_is_staged_below_the_cloudflare_asset_file_limit() {
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
    let tag = mvmctl::core::config::default_boot_image_tag();
    let lock = mvmctl::core::image_set::image_train_lock();
    assert_eq!(tag, lock.image_set.release_tag.as_str());
    assert_eq!(lock.repository.as_str(), "tinylabscom/mvm-images");
    let url = lock.manifest_url();
    assert!(
        url.contains("/tinylabscom/mvm-images/releases/download/image-set/v"),
        "the composed URL must sit under the external image-set release: {url}"
    );
}

/// No tag is published as GitHub's "Latest" release by the step that creates
/// it.
///
/// `mvmctl update` resolves `/repos/<repo>/releases/latest` and install.sh
/// installs the newest non-prerelease, so a release published as a full one
/// reaches every user who did not ask for anything newer. A release candidate
/// must never; a stable tag must not until a fresh install of it has booted a
/// microVM. `gh release create` marks a release latest unless told otherwise,
/// so the create step passes `--prerelease` for every tag, and only
/// `promote-release` undoes it.
#[test]
fn every_tag_is_published_as_a_prerelease_until_it_is_promoted() {
    let workflow = release_workflow();
    let release = job_block(&workflow, "release");

    let create = release
        .find("gh release create \"${publish_tag}\"")
        .expect("release.yml must create the release under a computed tag");
    assert!(
        release.contains("publish_tag=\"${TAG_NAME}\""),
        "the computed tag must default to the pushed tag, or a real release \
         publishes under something other than the tag that triggered it"
    );
    let staged = release
        .find("          prerelease=(--prerelease)\n")
        .expect("every tag must be staged as a prerelease, unconditionally");
    assert!(
        staged < create,
        "the prerelease decision must be made before the release is created"
    );
    assert!(
        !release[..create].contains("prerelease=()\n          if [[ \"${TAG_NAME#v}\""),
        "a stable tag must not be exempted from staging: it would reach every \
         user before its first-run smoke ran"
    );
    assert!(
        release[create..].contains(r#""${prerelease[@]}""#),
        "`gh release create` must expand the prerelease array, or deciding it \
         changes nothing about what gets published"
    );
    assert!(
        !release.contains("--latest") && !release.contains("workers.yml"),
        "the release job must neither mark a release latest nor publish the \
         installer default; only promote-release may"
    );
}

/// A fresh install of the published tag must boot a microVM on each backend
/// before the tag is promoted.
///
/// `verify-release` proves the asset set is complete and signed, and nothing
/// before this proved a user could run it: v0.17.0 is a published, signed
/// release whose first `machine run` cannot start a microVM on a fresh host.
#[test]
fn a_stable_tag_is_promoted_only_after_a_fresh_install_boots() {
    let workflow = release_workflow();

    let gate = job_block(&workflow, "first-run-smoke");
    assert!(
        gate.contains("    needs: [verify-release]\n"),
        "the smoke must wait for verify-release, which waits for the kernels a \
         first run downloads"
    );
    assert!(
        gate.contains("github.event_name == 'push' && needs.verify-release.result == 'success'"),
        "the smoke runs for a pushed tag whose asset set verified"
    );
    assert!(
        gate.contains("    uses: ./.github/workflows/first-run-smoke.yml\n")
            && gate.contains("      tag: ${{ github.ref_name }}\n"),
        "the release must run the shared first-run lanes against exactly the \
         tag being released"
    );

    let lanes = first_run_smoke_workflow();
    let lanes_on = lanes
        .split("\npermissions:")
        .next()
        .expect("first-run-smoke.yml has an `on:` block");
    assert!(
        lanes_on.contains("  workflow_call:\n")
            && lanes_on.contains("  workflow_dispatch:\n")
            && lanes_on.matches("      tag:\n").count() == 2
            && lanes_on.matches("        required: true\n").count() == 2,
        "the lanes must be callable by the release and dispatchable against a \
         published candidate, each with a required tag"
    );
    let smoke = job_block(&lanes, "first-run-smoke");
    assert!(
        smoke.contains(r#"run: sh scripts/smoke-fresh-install.sh "${TAG_NAME}""#)
            && smoke.contains("TAG_NAME: ${{ inputs.tag }}"),
        "the smoke must install exactly the tag it was given"
    );
    let e2e = fs::read_to_string(".github/workflows/e2e-docs.yml").expect("e2e-docs workflow");
    let macos_runner = "runs-on: [self-hosted, macOS, ARM64, m1]";
    assert!(
        e2e.contains(macos_runner),
        "e2e-docs.yml no longer names the Apple Silicon runner this test expects"
    );
    assert!(
        smoke.contains("runner: [self-hosted, macOS, ARM64, m1]"),
        "the macOS lane must run on the self-hosted runner that boots guests — \
         no hosted macOS runner can"
    );
    assert!(
        smoke.contains("runner: ubuntu-latest") && smoke.contains("sudo chmod 666 /dev/kvm"),
        "the Linux lane must boot through KVM on a hosted runner"
    );
    assert!(
        smoke.contains("fail-fast: false"),
        "one backend's failure must not hide the other's transcript"
    );
    let upload = smoke
        .find("uses: actions/upload-artifact@")
        .expect("the smoke must upload its transcript");
    assert!(
        smoke[..upload].contains("if: always()"),
        "the transcript matters most when the smoke fails"
    );

    let promote = job_block(&workflow, "promote-release");
    assert!(
        promote.contains("    needs: [first-run-smoke]\n")
            && promote.contains("needs.first-run-smoke.result == 'success'"),
        "promotion must require every first-run lane to pass"
    );
    assert!(
        promote.contains("if [[ \"${TAG_NAME#v}\" == *-* ]]; then"),
        "a release candidate must stay a prerelease after its smoke passes"
    );
    let edit = promote
        .find("gh release edit \"${TAG_NAME}\"")
        .expect("promotion must edit the pushed tag's release");
    assert!(
        promote[edit..].contains("--prerelease=false --latest"),
        "promotion must make the tag a full release and GitHub's latest"
    );
    let dispatch = promote
        .find("gh workflow run workers.yml")
        .expect("promotion must publish the installer default");
    assert!(
        edit < dispatch && promote[dispatch..].contains("-f install_version=\"${TAG_NAME}\""),
        "the site must bake the tag only after it is promoted: its baking \
         script refuses a prerelease"
    );
}

/// The Linux archive is booted, egress included, before anything is
/// published.
///
/// Every other pre-publish lane builds mvmctl and its host binaries from the
/// tree against the runner's glibc. The release ships static musl binaries, and
/// v0.22.0's network endpoint made a syscall under musl that its seccomp filter
/// did not allow, so every run that granted egress failed on the shipped
/// release while every lane was green. Only a lane that boots the archive the
/// build uploaded, and grants egress, reaches that endpoint.
#[test]
fn the_release_publishes_only_an_archive_whose_first_run_egress_passed() {
    let workflow = release_workflow();

    let gate = job_block(&workflow, "release-archive-smoke");
    assert!(
        gate.contains("    needs: [build]\n")
            && gate.contains("    uses: ./.github/workflows/release-archive-smoke.yml\n"),
        "the archive smoke must run the shared lane on what `build` uploaded"
    );
    assert!(
        gate.contains("tag: ${{ github.event_name == 'push' && github.ref_name || '' }}"),
        "a tag's archive must report the tag's version; a dry run has none to check"
    );
    let release = job_block(&workflow, "release");
    assert!(
        release.contains("needs.release-archive-smoke.result == 'success'"),
        "publication must require the archive smoke to pass"
    );
    let build = job_block(&workflow, "build");
    assert!(
        build.contains("- target: x86_64-unknown-linux-gnu\n            build_target: x86_64-unknown-linux-musl\n")
            && build.contains("name: mvmctl-${{ matrix.target }}"),
        "the smoke downloads the x86_64 Linux archive by the name the build uploads it under"
    );

    let path = Path::new(".github/workflows/release-archive-smoke.yml");
    let lane = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let lane_on = lane
        .split("\npermissions:")
        .next()
        .expect("release-archive-smoke.yml has an `on:` block");
    assert!(
        lane_on.contains("  workflow_call:\n") && lane_on.contains("  workflow_dispatch:\n"),
        "the lane must be callable by the release and dispatchable against an earlier run"
    );
    let smoke = job_block(&lane, "release-archive-smoke");
    assert!(
        smoke.contains("runs-on: ubuntu-latest") && smoke.contains("sudo chmod 666 /dev/kvm"),
        "the archive must boot through KVM on a hosted runner"
    );
    assert_eq!(
        smoke
            .matches("name: mvmctl-x86_64-unknown-linux-gnu\n")
            .count(),
        2,
        "both download paths must fetch the x86_64 Linux archive"
    );
    assert!(
        smoke.contains("sha256sum --check mvmctl-x86_64-unknown-linux-gnu.tar.gz.sha256"),
        "the archive must be the one the build recorded a checksum for"
    );
    assert!(
        smoke.contains(
            "MVM_SMOKE_ARCHIVE: ${{ runner.temp }}/release-archive/mvmctl-x86_64-unknown-linux-gnu.tar.gz"
        ) && smoke.contains(r#"run: sh scripts/smoke-fresh-install.sh ${TAG_NAME:+"$TAG_NAME"}"#),
        "the lane must run the fresh-install smoke on the downloaded archive"
    );
    let upload = smoke
        .find("uses: actions/upload-artifact@")
        .expect("the lane must upload its transcript");
    assert!(
        smoke[..upload].contains("if: always()"),
        "the transcript matters most when the smoke fails"
    );

    let script = fs::read_to_string("scripts/smoke-fresh-install.sh").expect("smoke script");
    assert!(
        script
            .contains(r#"mvmctl machine run --image "$EGRESS_IMAGE" --allow-host "$EGRESS_HOST""#),
        "the smoke must boot a workload granted egress, or the endpoint never starts"
    );
}

/// The merge-queue boot witness must validate the bytes a fresh install
/// requests. It reads the pin rather than carrying a copy, so what is asserted
/// here is the read: a literal would be a second place to advance by hand, and
/// advancing only one of two makes CI validate an image users never receive.
#[test]
fn the_ci_boot_witness_resolves_the_locked_boot_image_tag() {
    let workflow = ci_workflow();
    let resolve = workflow
        .find(r#"echo "IMAGE_TAG=$(./scripts/locked-image-tag.sh)""#)
        .expect("the boot witness must resolve IMAGE_TAG from images.lock");
    let fetch = workflow
        .find("- name: Fetch and verify the pinned bootable image")
        .expect("the boot witness must fetch the pinned image");
    assert!(
        resolve < fetch,
        "IMAGE_TAG must be resolved before the step that splices it into a \
         download URL, or the fetch runs against an empty tag"
    );
    assert!(
        !workflow.contains(&format!(
            "IMAGE_TAG: {}",
            mvmctl::core::config::default_boot_image_tag()
        )),
        "the tag must be read from images.lock, not copied into the workflow"
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

    let action_path = ".github/actions/install-zigbuild/action.yml";
    let action = fs::read_to_string(action_path).expect("read install-zigbuild action");
    assert!(
        action.contains(&format!("VERSION={version}")),
        "{action_path} must install the workspace cargo-zigbuild pin {version}"
    );

    let script_path = "scripts/local-aarch64-no-kvm-smoke.sh";
    let script = fs::read_to_string(script_path).expect("read local aarch64 smoke script");
    assert!(
        script.contains(&format!("cargo-zigbuild --version {version}")),
        "{script_path} must install the workspace cargo-zigbuild pin {version}"
    );
}

/// Every workflow that can mint an identity a shipped binary trusts must be
/// gated on a protected environment, so the ref allowed to produce a valid
/// signature is constrained by that environment's tag policy rather than by
/// whoever can trigger the workflow.
///
/// This is not theoretical. `release.yml` — which mints the one identity
/// `RELEASE_IDENTITY_TEMPLATES` names, the identity every installed mvmctl
/// verifies against — once declared no environment at all.
///
/// The environments' tag policies live in repository settings and cannot be
/// asserted from here. What is assertable, and what regressed, is that the
/// declaration exists at all.
#[test]
fn workflows_minting_trusted_identities_are_gated_on_an_environment() {
    for (path, expected_env) in [
        (".github/workflows/release.yml", "release-signing"),
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

#[test]
fn image_pin_updates_open_evidence_bearing_prs_without_merging_them() {
    let workflow = fs::read_to_string(".github/workflows/update-image-pin.yml")
        .expect("image pin workflow must be readable");
    for evidence in [
        "root manifest SHA-256",
        "producer source commit",
        "compatibility",
        "keyless signature",
    ] {
        assert!(
            workflow.contains(evidence),
            "pin update PR body must record {evidence}"
        );
    }
    assert!(workflow.contains("gh pr create"), "workflow must open a PR");
    assert!(
        !workflow.contains("gh pr merge")
            && !workflow.contains("--auto")
            && !workflow.contains("enablePullRequestAutoMerge"),
        "pin update workflow must never merge or enable auto-merge"
    );
}

/// The lock rewrite is the xtask that re-parses what it wrote. An inline
/// rewrite once named sections the lock does not have and failed every run
/// before proposing anything, which is invisible until the weekly schedule
/// fires.
#[test]
fn image_pin_updates_rewrite_the_lock_through_the_checked_parser() {
    let workflow = fs::read_to_string(".github/workflows/update-image-pin.yml")
        .expect("image pin workflow must be readable");
    assert!(
        workflow.contains("xtask -- repin-image-lock candidate/image-set.json"),
        "the pin update must rewrite images.lock through xtask repin-image-lock"
    );
    assert!(
        !workflow.contains("python3"),
        "the pin update must not carry a second, untested lock writer"
    );
}

#[test]
fn image_contract_reader_agrees_with_the_checked_lock() {
    let output = Command::new("./scripts/locked-image-tag.sh")
        .args(["compatibility", "builder_cache_contract"])
        .output()
        .expect("run image-lock reader");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).expect("reader prints UTF-8");
    let expected = mvmctl::core::image_set::image_train_lock()
        .compatibility
        .builder_cache_contract;
    assert_eq!(printed.trim(), expected.to_string());

    let wrong_section = Command::new("./scripts/locked-image-tag.sh")
        .args(["image_set", "builder_cache_contract"])
        .output()
        .expect("run image-lock reader with the wrong section");
    assert!(!wrong_section.status.success());
}

#[test]
fn remote_image_contract_checks_follow_the_locked_version() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("ci workflow");
    let downloader = fs::read_to_string("scripts/download-qemu-wasm-smoke-pack.sh")
        .expect("WebLinux downloader");
    let pin_update =
        fs::read_to_string(".github/workflows/update-image-pin.yml").expect("image pin workflow");
    assert!(ci.contains("locked-image-tag.sh compatibility builder_cache_contract"));
    assert!(ci.contains(".compatibility.builder_cache_contract == $contract"));
    assert!(downloader.contains("locked-image-tag.sh\" compatibility builder_cache_contract"));
    assert!(downloader.contains(".compatibility.builder_cache_contract == $contract"));
    assert!(pin_update.contains(".compatibility.builder_cache_contract == 5"));
}

#[test]
fn remote_image_consumers_resolve_the_publisher_from_the_single_lock() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("ci workflow");
    let workers = fs::read_to_string(".github/workflows/workers.yml").expect("workers workflow");
    let downloader = fs::read_to_string("scripts/download-qemu-wasm-smoke-pack.sh")
        .expect("WebLinux downloader");
    assert!(
        ci.contains("locked-image-tag.sh image_set repository")
            && ci.contains("locked-image-tag.sh image_set manifest_sha256")
            && ci.contains("check")
    );
    assert!(workers.contains("download-qemu-wasm-smoke-pack.sh"));
    for field in [
        "image_set repository",
        "image_set manifest_asset",
        "image_set manifest_sha256",
        "image_set workflow",
        "image_set tag_ref",
    ] {
        assert!(
            downloader.contains(field),
            "WebLinux downloader must resolve {field} from images.lock"
        );
    }
}

/// Only a CLI release may become GitHub's "Latest".
///
/// `mvmctl update` follows that marker, and `gh release create` sets it on
/// every non-prerelease it creates unless told otherwise — so the boot image
/// train took it (`boot-image/v0.1.5` was "Latest" while the newest CLI release
/// was v0.17.0), and an update would have gone looking for an mvmctl archive
/// on a release that has none. Images now ship from mvm-images, so the one
/// other release this repository creates is the revocations channel.
#[test]
fn only_a_cli_release_can_become_the_latest_release() {
    let revocations =
        fs::read_to_string(".github/workflows/revocations.yml").expect("revocations workflow");
    let create = revocations
        .find("gh release create revocations")
        .expect("the revocations channel creates its release");
    assert!(
        revocations[create..create + 200].contains("--latest=false"),
        "the revocations release must never be marked latest"
    );
}

/// Pull requests compile `mvmctl` with the exact feature set the release
/// builds it with.
///
/// v0.18.0-rc.2's tag died at compile time in its macOS documented-surface
/// lane: an item gated for one release feature and used under another built in
/// every partial combination CI checked, and only the full set broke. The step
/// reads the set out of release.yml, so it cannot drift from what ships.
#[test]
fn pull_requests_compile_mvmctl_with_the_release_feature_set() {
    let release = release_workflow();
    let features: Vec<&str> = release
        .lines()
        .find_map(|line| line.strip_prefix("  MVMCTL_RELEASE_FEATURES: "))
        .expect("release.yml must declare MVMCTL_RELEASE_FEATURES as a workflow env line")
        .trim()
        .split(',')
        .collect();
    assert!(
        features.contains(&"embed-host-bins") && features.contains(&"release-artifact-bootstrap"),
        "the parsed set no longer looks like the release's: {features:?}"
    );

    let ci = ci_workflow();
    let lane = job_block(&ci, "lint-features-embed");
    assert!(
        lane.contains(
            "features=\"$(sed -n 's/^  MVMCTL_RELEASE_FEATURES: *//p' .github/workflows/release.yml)\""
        ),
        "the CI step must read the feature set from release.yml, not carry a copy"
    );
    assert!(
        lane.contains(r#"cargo check --locked -p mvmctl --bins --features "$features""#),
        "the CI step must compile the mvmctl binary with that set"
    );
    assert!(
        lane.contains("uses: ./.github/actions/install-zigbuild"),
        "`embed-host-bins` cross-compiles the host payload, which needs the pinned zig"
    );
    let aggregate = job_block(&ci, "test");
    assert!(
        aggregate.contains("lint-features-embed"),
        "the lane must feed the required Test aggregate"
    );
}

/// `just e2e::smoke-fresh-install` runs the same script the release gate runs, so a
/// maintainer can reproduce a red first-run lane locally.
#[test]
fn the_fresh_install_smoke_recipe_runs_the_release_gate_script() {
    assert!(
        just_module("e2e").contains(
            "smoke-fresh-install VERSION=\"\":\n    ./scripts/smoke-fresh-install.sh {{ VERSION }}\n"
        ),
        "the recipe must run the release gate's script with an optional version"
    );
}
