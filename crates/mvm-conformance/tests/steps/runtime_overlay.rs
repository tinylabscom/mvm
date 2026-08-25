//! Steps for the runtime-overlay integrity contract: the overlay disk that
//! carries guest-runtime binaries must be hash-verified before a microVM can
//! attach it, and a tampered artifact must fail closed.

use std::path::Path;

use cucumber::{given, then, when};
use mvm_build::runtime_overlay::{InstallOptions, install_overlay_into_cache};
use mvm_fs::ext4::Node;
use mvm_fs::overlay::{RuntimeOverlayResolver, read_overlay_artifact_from_dir};

use crate::world::CliWorld;

/// A valid-looking dm-verity root hash for the fake overlay. The resolver only
/// checks formatting (64 lowercase hex chars), not cryptographic correctness.
const FAKE_ROOTHASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Build a minimal runtime-overlay artifact in `source_dir` that satisfies the
/// resolver's payload check: an ext4 image carrying every required guest path,
/// plus the verity sidecar, roothash, and VERSION sidecars.
fn build_minimal_runtime_overlay(source_dir: &Path) -> mvm_fs::overlay::RuntimeOverlayArtifact {
    std::fs::create_dir_all(source_dir).expect("create overlay source dir");

    // Taken from the resolver's own list rather than restated: a fixture that
    // claims to carry "every required guest path" and then names them itself is
    // one an added path silently makes wrong, and it fails as an unrelated
    // integrity error rather than as a stale fixture.
    let nodes: Vec<Node> = mvm_fs::overlay::REQUIRED_OVERLAY_GUEST_PATHS
        .iter()
        .map(|path| Node::File {
            path: path.to_string(),
            mode: 0o644,
            data: b"bdd-runtime-overlay-stub".to_vec(),
            xattrs: Vec::new(),
        })
        .collect();

    let ext4_bytes = mvm_fs::ext4::build_image(nodes).expect("build minimal overlay ext4");
    std::fs::write(source_dir.join("overlay.ext4"), ext4_bytes).expect("write overlay.ext4");
    std::fs::write(source_dir.join("overlay.verity"), b"verity-sidecar")
        .expect("write overlay.verity");
    std::fs::write(
        source_dir.join("overlay.roothash"),
        format!("{FAKE_ROOTHASH}\n"),
    )
    .expect("write overlay.roothash");
    std::fs::write(
        source_dir.join("VERSION"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .expect("write VERSION");

    let arch = std::env::consts::ARCH;
    read_overlay_artifact_from_dir(source_dir, arch).expect("read overlay artifact from source dir")
}

#[given("an isolated mvm home with a verified runtime overlay in the cache")]
fn isolated_home_with_verified_overlay(world: &mut CliWorld) {
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let source = home.path().join("overlay-source");
    let artifact = build_minimal_runtime_overlay(&source);
    let cache_root = home.path().join("cache");
    install_overlay_into_cache(&artifact, &cache_root, &InstallOptions { overwrite: true })
        .expect("install runtime overlay into isolated cache");
    world.isolated_home = Some(home);
}

#[when("a byte in the cached runtime overlay ext4 is flipped")]
fn flip_cached_overlay_byte(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a Given step must isolate the mvm home");
    let layout = mvm_fs::overlay::RuntimeOverlayLayout::under(
        &home.path().join("cache"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
    );
    let mut bytes = std::fs::read(&layout.overlay_ext4).expect("read cached overlay.ext4");
    if bytes.is_empty() {
        bytes.push(0u8);
    }
    bytes[0] = bytes[0].wrapping_add(1);
    std::fs::write(&layout.overlay_ext4, bytes).expect("write flipped overlay.ext4");
}

#[when("the runtime overlay is resolved for the current arch")]
fn resolve_runtime_overlay(world: &mut CliWorld) {
    let home = world
        .isolated_home
        .as_ref()
        .expect("a Given step must isolate the mvm home");
    let resolver = RuntimeOverlayResolver::new(
        home.path().join("cache"),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    world.runtime_overlay_result = Some(
        resolver
            .resolve(std::env::consts::ARCH)
            .map_err(|error| error.to_string()),
    );
}

#[then("the runtime overlay resolves successfully")]
fn runtime_overlay_resolves(world: &mut CliWorld) {
    let outcome = world
        .runtime_overlay_result
        .as_ref()
        .expect("a When step must resolve the overlay first");
    assert!(
        outcome.is_ok(),
        "expected the runtime overlay to resolve, but got: {outcome:?}"
    );
}

#[then("the runtime overlay resolution fails with an integrity error")]
fn runtime_overlay_refused_integrity(world: &mut CliWorld) {
    let err = world
        .runtime_overlay_result
        .as_ref()
        .expect("a When step must resolve the overlay first")
        .as_ref()
        .expect_err("tampered overlay must fail resolution");
    assert!(
        err.contains("integrity") || err.contains("checksum") || err.contains("sha256"),
        "expected an integrity refusal, got: {err}"
    );
}
