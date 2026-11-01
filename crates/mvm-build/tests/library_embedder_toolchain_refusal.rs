//! A process that declared itself a library embedder never runs the Rust
//! toolchain or `curl` for guest-runtime preparation. This file is its own
//! test binary because the declaration cannot be taken back.

use mvm_build::guest_agent_build::{
    GuestAgentBuildError, GuestAgentBuildSpec, build_guest_binaries,
};
use mvm_build::runtime_overlay::{RuntimeOverlayError, fetch_cli_release_archive};
use mvm_core::arch::GuestArch;

#[test]
fn an_embedder_is_refused_every_guest_runtime_spawn() {
    mvm_vmm::host::aux_bin::declare_library_embedder();
    let scratch = tempfile::tempdir().expect("tempdir");

    let spec = GuestAgentBuildSpec::new(
        scratch.path().join("ws"),
        GuestArch::host(),
        scratch.path().join("target"),
    );
    let err = build_guest_binaries(&spec).expect_err("an embedder must not build");
    assert!(
        matches!(err, GuestAgentBuildError::CliSpawnRefused(_)),
        "{err}"
    );
    assert!(err.to_string().contains("mvmctl bootstrap"), "{err}");
    assert!(
        !scratch.path().join("target").exists(),
        "a refusal must not even take the build lock"
    );

    let dest = scratch.path().join("archive");
    let err = fetch_cli_release_archive("http://127.0.0.1:9/none", "0.0.0", "a.tar.gz", &dest)
        .expect_err("an embedder must not download");
    assert!(
        matches!(err, RuntimeOverlayError::CliSpawnRefused(_)),
        "{err}"
    );
}
