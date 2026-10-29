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
    let cache = mvm_home.join("cache");
    let workspace = mvm_build::image_source::guest_runtime_source_checkout()
        .expect("source-channel test checkout");
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
        &cache, &workspace, version, arch,
    )
    .expect("complete source-runtime fixture");
    mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache, version, arch, &runtime,
    )
    .expect("assemble fixture overlay");
    mvm_build::initramfs::build_initramfs_from_guest_runtime(
        &cache.join("initramfs"),
        version,
        arch,
        &runtime,
    )
    .expect("assemble fixture initramfs");
}
