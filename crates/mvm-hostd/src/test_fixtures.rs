//! Fixtures shared by this crate's tests.

use std::path::Path;

use mvm_core::util::test_env::TestEnv;

/// Point `MVM_HOME` and `HOME` at a fresh scratch directory for as long as the
/// returned guard lives.
///
/// Any test whose code path resolves a path through `mvm_core::config` —
/// host config, the keys directory, VM or mock-VM state — needs this, even
/// when it never sets anything itself. `cargo test` runs a crate's tests as
/// threads of one process, so an unguarded test reads whichever home another
/// test has pointed the process at: one configured to refuse admission, or
/// one that is deleted halfway through. Holding the guard also serializes it
/// against every other test that changes the environment.
///
/// Bind both halves and keep them to the end of the test.
pub(crate) fn isolated_mvm_home() -> (TestEnv, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    (env, home)
}

/// Install the runtime overlay a cold boot requires into `<mvm_home>/cache`.
///
/// The fixture goes through the shared overlay reader and cache installer, so
/// the resolver verifies the same ext4 payload, checksums, version, and
/// sidecars as production.
pub(crate) fn install_runtime_overlay(mvm_home: &Path) {
    use mvm_build::runtime_overlay::{InstallOptions, install_overlay_into_cache};
    use mvm_fs::ext4::{Node, Owner};
    use mvm_fs::overlay::{REQUIRED_OVERLAY_GUEST_PATHS, read_overlay_artifact_from_dir};

    let source = mvm_home.join("runtime-overlay-source");
    std::fs::create_dir_all(&source).expect("create runtime overlay source");
    let nodes = REQUIRED_OVERLAY_GUEST_PATHS
        .iter()
        .map(|path| Node::File {
            path: path.to_string(),
            mode: 0o755,
            data: b"session-resume-runtime-stub".to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        })
        .collect();
    let ext4 = mvm_fs::ext4::build_image(nodes, &Default::default())
        .expect("build runtime overlay fixture");
    std::fs::write(source.join("overlay.ext4"), ext4).expect("write overlay ext4");
    std::fs::write(source.join("overlay.verity"), b"verity-sidecar")
        .expect("write overlay verity sidecar");
    std::fs::write(
        source.join("overlay.roothash"),
        format!("{}\n", "ab".repeat(32)),
    )
    .expect("write overlay root hash");
    std::fs::write(
        source.join("VERSION"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .expect("write overlay version");

    let artifact = read_overlay_artifact_from_dir(&source, std::env::consts::ARCH)
        .expect("read runtime overlay fixture");
    install_overlay_into_cache(
        &artifact,
        &mvm_home.join("cache"),
        &InstallOptions { overwrite: true },
    )
    .expect("install runtime overlay fixture");
}
