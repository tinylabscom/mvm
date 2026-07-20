//! Linux-gated integration test for the runtime-overlay build
//! orchestrator against the flake at `nix/images/runtime-overlay/`.
//!
//! Gates on:
//!
//! 1. `#[cfg(target_os = "linux")]` — `nix build` runs Linux-only
//!    and per CLAUDE.md "Host Nix is never used by mvmctl,"
//!    macOS contributors don't have it anyway.
//! 2. `which::which("nix")` — skips cleanly when the contributor
//!    has no `nix` on `$PATH`. CI lanes that exercise the
//!    builder-vm flake already have `nix` installed via the
//!    same `nixpkgs/nixos-25.11` channel.
//!
//! These tests build the real artifact and then run the resolver
//! over the produced files. End-to-end: the producer (flake) and
//! consumer (resolver) agree on the cache layout. If they disagree
//! on file names or VERSION content this test fires before
//! contributors hit it at boot.

#![cfg(target_os = "linux")]

use mvm_build::runtime_overlay::{OverlayBuildSpec, build_overlay_with_nix};
use mvm_core::arch::GuestArch;
use mvm_fs::overlay::RuntimeOverlayResolver;
use std::path::Path;
use tempfile::TempDir;

fn skip_if_no_nix() -> bool {
    if which::which("nix").is_err() {
        eprintln!(
            "mvm runtime-overlay build integration test skipped: \
             nix not on $PATH (install Nix to run this test)"
        );
        return true;
    }
    false
}

/// Path to the workspace root from inside an integration test
/// crate. `CARGO_MANIFEST_DIR` resolves to
/// `<workspace>/crates/mvm-build` for this crate; the workspace
/// is two levels up.
fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn host_arch_or_skip_known() -> Option<GuestArch> {
    // The flake builds for both aarch64 and x86_64 Linux. The
    // host's arch is whichever this binary was compiled for —
    // and on Linux that matches one of the two flake systems.
    if cfg!(target_arch = "aarch64") {
        Some(GuestArch::Aarch64)
    } else if cfg!(target_arch = "x86_64") {
        Some(GuestArch::X86_64)
    } else {
        eprintln!("runtime-overlay build test skipped: host arch is neither aarch64 nor x86_64");
        None
    }
}

#[test]
fn build_produces_resolver_compatible_artifact() {
    if skip_if_no_nix() {
        return;
    }
    let Some(arch) = host_arch_or_skip_known() else {
        return;
    };

    let workspace = workspace_root();
    let out_dir = TempDir::new().expect("tempdir");
    let result_link = out_dir.path().join("result");
    let spec = OverlayBuildSpec::new(workspace.clone(), arch, result_link.clone());

    let artifact = build_overlay_with_nix(&spec).expect("nix build runtime-overlay");
    assert_eq!(artifact.arch, arch.to_string());
    assert!(artifact.overlay_ext4.exists());
    assert!(artifact.sidecar.exists());
    assert!(artifact.roothash_file.exists());
    assert_eq!(artifact.roothash.len(), 64);
    assert!(
        artifact
            .roothash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    // The resolver expects a cache layout of
    // `<cache>/runtime-overlay/<version>/<arch>/{overlay.ext4,
    // overlay.verity, overlay.roothash, VERSION}`. Stage the
    // nix-built files into that layout and run the resolver to
    // prove producer + consumer agree end-to-end.
    let cache = TempDir::new().expect("cache tempdir");
    let staged = cache
        .path()
        .join("runtime-overlay")
        .join(&artifact.version)
        .join(arch.to_string());
    std::fs::create_dir_all(&staged).unwrap();
    copy_file(&artifact.overlay_ext4, &staged.join("overlay.ext4"));
    copy_file(&artifact.sidecar, &staged.join("overlay.verity"));
    copy_file(&artifact.roothash_file, &staged.join("overlay.roothash"));
    // VERSION file is at the artifact_dir level (next to the
    // ext4), not duplicated from `roothash_file.parent()`. The
    // flake produces it as `$out/VERSION` so the resolver sees
    // it in the same dir.
    copy_file(&result_link.join("VERSION"), &staged.join("VERSION"));

    let resolver =
        RuntimeOverlayResolver::new(cache.path().to_path_buf(), artifact.version.clone());
    let resolved = resolver
        .resolve(&arch.to_string())
        .expect("resolver must accept the freshly-built artifact");
    assert_eq!(resolved.version, artifact.version);
    assert_eq!(resolved.roothash, artifact.roothash);
    assert_eq!(resolved.arch, artifact.arch);
}

#[test]
fn build_produces_verity_sidecar_matching_overlay_block_geometry() {
    if skip_if_no_nix() {
        return;
    }
    let Some(arch) = host_arch_or_skip_known() else {
        return;
    };

    let workspace = workspace_root();
    let out_dir = TempDir::new().expect("tempdir");
    let result_link = out_dir.path().join("result");
    let spec = OverlayBuildSpec::new(workspace, arch, result_link);

    let artifact = build_overlay_with_nix(&spec).expect("nix build runtime-overlay");
    let overlay_bytes = std::fs::read(&artifact.overlay_ext4).expect("read overlay.ext4");
    let sidecar_bytes = std::fs::read(&artifact.sidecar).expect("read overlay.verity");
    let data_blocks = overlay_bytes.len() as u64 / 4096;
    let expected_sidecar_blocks = verity_tree_block_count(data_blocks, 4096);

    assert_eq!(
        sidecar_bytes.len() as u64,
        expected_sidecar_blocks * 4096,
        "overlay.verity must encode exactly the dm-verity hash tree for the 4 KiB-block overlay ext4"
    );
}

#[test]
fn build_is_byte_deterministic_for_same_workspace() {
    // The per-version cache hinges on byte-identical builds against
    // the same workspace producing the same roothash. Run the build
    // twice and compare overlay.ext4 bytes + roothash.
    if skip_if_no_nix() {
        return;
    }
    let Some(arch) = host_arch_or_skip_known() else {
        return;
    };

    let workspace = workspace_root();

    let first = TempDir::new().unwrap();
    let first_link = first.path().join("result-1");
    let first_spec = OverlayBuildSpec::new(workspace.clone(), arch, first_link.clone());
    let first_artifact = build_overlay_with_nix(&first_spec).expect("first build succeeds");

    let second = TempDir::new().unwrap();
    let second_link = second.path().join("result-2");
    let second_spec = OverlayBuildSpec::new(workspace.clone(), arch, second_link.clone());
    let second_artifact = build_overlay_with_nix(&second_spec).expect("second build succeeds");

    assert_eq!(
        first_artifact.roothash, second_artifact.roothash,
        "byte-deterministic invariant: two builds of the same \
         workspace must produce the same roothash"
    );
    let bytes_a = std::fs::read(&first_artifact.overlay_ext4).unwrap();
    let bytes_b = std::fs::read(&second_artifact.overlay_ext4).unwrap();
    assert_eq!(
        bytes_a.len(),
        bytes_b.len(),
        "overlay.ext4 must have the same size across builds"
    );
    assert_eq!(
        bytes_a, bytes_b,
        "byte-deterministic invariant: overlay.ext4 must be \
         byte-identical across builds (ADR-018 verity cache)"
    );
}

fn copy_file(src: &Path, dst: &Path) {
    let bytes = std::fs::read(src).unwrap_or_else(|e| {
        panic!("read {src:?}: {e}");
    });
    std::fs::write(dst, bytes).unwrap_or_else(|e| {
        panic!("write {dst:?}: {e}");
    });
}

fn verity_tree_block_count(data_blocks: u64, hash_block_size: u64) -> u64 {
    let digest_size = 32u64;
    let hashes_per_block = hash_block_size / digest_size;
    let mut level_hashes = data_blocks.max(1);
    let mut total_blocks = 0u64;
    loop {
        let level_blocks = level_hashes.div_ceil(hashes_per_block).max(1);
        total_blocks += level_blocks;
        if level_blocks == 1 {
            return total_blocks;
        }
        level_hashes = level_blocks;
    }
}
