//! Shared test scaffolding for the volume service test modules.

use std::path::Path;

use super::dto::CreateBlockVolumeRequest;
use super::service::{LocalVolumeService, VolumeService, probe_from_fn};

/// A service whose storage probe reports every path as verified encrypted.
/// Confined to disposable test homes; it never runs host tools.
pub(crate) fn service() -> LocalVolumeService {
    LocalVolumeService::with_host_encryption_probe(probe_from_fn(|_| Ok(())))
}

/// A service whose storage probe refuses every path, standing in for a host
/// whose volume storage is not verified encrypted.
pub(crate) fn unverified_service() -> LocalVolumeService {
    LocalVolumeService::with_host_encryption_probe(probe_from_fn(|path| {
        anyhow::bail!("synthetic: {} has no dm-crypt mapping", path.display())
    }))
}

/// Isolated `MVM_HOME` for one volume test. Holds the process-wide env lock
/// (via `TestEnv`) so parallel tests never see each other's catalogs.
pub(crate) struct TestVolumeHome {
    env: mvm_core::util::test_env::TestEnv,
    root: tempfile::TempDir,
}

impl TestVolumeHome {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", root.path());
        // Hermetic: an override in the developer's shell must not leak into
        // tests that assert a refusal.
        env.remove(mvm_core::host_storage_encryption::ALLOW_UNVERIFIED_STORAGE_ENV);
        Self { env, root }
    }

    /// Turn on the development override for unverified volume storage.
    pub(crate) fn allow_unverified_storage(&mut self) {
        self.env.set(
            mvm_core::host_storage_encryption::ALLOW_UNVERIFIED_STORAGE_ENV,
            "1",
        );
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
        service()
            .create_block_volume(&request)
            .expect("create block volume");
    }
}
