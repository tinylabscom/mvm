//! Shared test scaffolding for the volume service test modules.

use std::path::Path;

use super::dto::CreateBlockVolumeRequest;
use super::service::{LocalVolumeService, VolumeService};

/// Isolated `MVM_HOME` for one volume test. Holds the process-wide env lock
/// (via `TestEnv`) so parallel tests never see each other's catalogs.
pub(crate) struct TestVolumeHome {
    _env: mvm_core::util::test_env::TestEnv,
    root: tempfile::TempDir,
}

impl TestVolumeHome {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        // Isolate the test MVM_HOME and HOME so tests can't reach the developer
        // cache. Also opt-in to a fast test mode that keeps volume images small
        // on CI so the test-suite stays quick while preserving metadata values
        // the tests assert (capacity_mib).
        env.isolate_mvm_home(root.path());
        // Fast-test opt-in: when present tests create smaller actual image files
        // (kept conservative at 4 MiB) while keeping the recorded capacity_mib
        // unchanged. This keeps mkfs / encryption work cheap in CI and local
        // runs that use the test scaffolding. The value is read by the
        // create_mvm_managed implementation and by mkfs when the global env var
        // is present for a cargo test run.
        // Set a test-wide fast flag; concrete min-bytes may be provided by
        // the environment to compare slow/fast runs. Only set the explicit
        // min-bytes default when the external environment has not supplied one.
        env.set("MVM_TEST_FAST", "1");
        if std::env::var_os("MVM_TEST_VOLUMES_MIN_BYTES").is_none() {
            env.set("MVM_TEST_VOLUMES_MIN_BYTES", "4194304");
        }
        Self { _env: env, root }
    }

    pub(crate) fn path(&self) -> &Path {
        self.root.path()
    }

    /// Create a locked managed block volume of `capacity_mib` MiB.
    pub(crate) fn create_block(&self, name: &str, capacity_mib: u32) {
        let request = CreateBlockVolumeRequest::builder(name)
            .expect("volume name")
            .capacity_mib(capacity_mib)
            .build()
            .expect("create request");
        LocalVolumeService::new()
            .create_block_volume(&request)
            .expect("create block volume");
    }
}
