//! Source-level contract for the installer bootstrap trust path. The release
//! archive integration tests exercise the actual shell behavior; these steps
//! keep the user-visible fail-closed sequence in the BDD inventory.

use cucumber::{given, then, when};

use crate::steps::cli::workspace_root;
use crate::world::CliWorld;

fn installer() -> String {
    std::fs::read_to_string(workspace_root().join("install.sh")).expect("read install.sh")
}

#[given("a fresh host with neither mvmctl nor cosign")]
fn fresh_host(_world: &mut CliWorld) {}

#[when("the installer selects a verifier for the baked release")]
fn select_verifier(_world: &mut CliWorld) {}

#[then("the archive trust anchor is checked before its mvmctl executes")]
fn fresh_install_trust_precedes_verifier_execution(_world: &mut CliWorld) {
    let script = installer();
    let compare = script
        .find("trusted archive SHA-256 mismatch")
        .expect("installer must compare the downloaded archive with its trust anchor");
    let extract = script
        .find("could not extract the authenticated bootstrap verifier")
        .expect("installer must extract only an authenticated bootstrap verifier");
    let fallback = script
        .find("COSIGN=\"$(bootstrap_cosign)\"")
        .expect("a legacy archive must fall back to a pinned signature verifier");

    assert!(
        compare < extract && extract < fallback,
        "archive authentication must precede verifier probing and fallback"
    );
}

#[then("the tag-pinned signature bundle is mandatory")]
fn fresh_install_requires_tag_pinned_bundle(_world: &mut CliWorld) {
    let script = installer();
    assert!(
        script.contains("no signature bundle published for $ARCHIVE")
            && script.contains("--tag \"$VERSION\""),
        "the bootstrap verifier must require the release bundle under the selected tag"
    );
}

#[then("there is no unsigned fresh-install fallback")]
fn fresh_install_has_no_unsigned_fallback(_world: &mut CliWorld) {
    let script = installer();
    assert!(
        !script.contains("skipping signature verification")
            && script.contains("fresh install requires a trusted archive SHA-256")
            && script.contains("trusted cosign SHA-256 mismatch"),
        "a host without a verifier must authenticate one or refuse the install"
    );
}

#[then("a legacy archive uses a hash-pinned temporary verifier")]
fn legacy_install_uses_pinned_temporary_verifier(_world: &mut CliWorld) {
    let script = installer();
    assert!(
        script.contains("COSIGN_VERSION=\"v")
            && script.contains("COSIGN_SHA256_AARCH64_APPLE_DARWIN=\"")
            && script.contains("COSIGN_SHA256_X86_64_UNKNOWN_LINUX_GNU=\"")
            && script.contains("COSIGN_SHA256_AARCH64_UNKNOWN_LINUX_GNU=\"")
            && script.contains("COSIGN=\"$(bootstrap_cosign)\""),
        "legacy releases must use one versioned, target-hash-pinned verifier"
    );
}
