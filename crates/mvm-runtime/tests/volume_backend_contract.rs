use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use mvm_core::volume::{VolumeEntry, VolumePath};
use mvm_runtime::storage::volume::{LocalBackend, VolumeBackend, VolumeFuture, contract};

struct ExternalBackend {
    inner: LocalBackend,
}

impl VolumeBackend for ExternalBackend {
    fn kind(&self) -> &'static str {
        "external-contract-test"
    }

    fn put<'a>(&'a self, key: &'a VolumePath, data: Bytes) -> VolumeFuture<'a, ()> {
        self.inner.put(key, data)
    }

    fn get<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, Bytes> {
        self.inner.get(key)
    }

    fn list<'a>(&'a self, prefix: &'a VolumePath) -> VolumeFuture<'a, Vec<VolumeEntry>> {
        self.inner.list(prefix)
    }

    fn delete<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, ()> {
        self.inner.delete(key)
    }

    fn stat<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, VolumeEntry> {
        self.inner.stat(key)
    }

    fn rename<'a>(&'a self, from: &'a VolumePath, to: &'a VolumePath) -> VolumeFuture<'a, ()> {
        self.inner.rename(from, to)
    }

    fn health_check(&self) -> VolumeFuture<'_, ()> {
        self.inner.health_check()
    }

    fn local_export_path(&self) -> Option<&Path> {
        self.inner.local_export_path()
    }
}

#[tokio::test]
async fn external_trait_object_passes_the_canonical_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let inner = LocalBackend::new(tmp.path().to_path_buf()).await.unwrap();
    let backend: Arc<dyn VolumeBackend> = Arc::new(ExternalBackend { inner });

    contract::assert_backend_contract(backend.as_ref()).await;
}
