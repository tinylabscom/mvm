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
        env.set("MVM_HOME", root.path());
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
