use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use mvm_core::volume::{VolumeEntry, VolumeError, VolumePath};
use mvm_runtime::storage::volume::{LocalBackend, VolumeBackend, contract};

struct ExternalBackend {
    inner: LocalBackend,
}

#[async_trait]
impl VolumeBackend for ExternalBackend {
    fn kind(&self) -> &'static str {
        "external-contract-test"
    }

    async fn put(&self, key: &VolumePath, data: Bytes) -> Result<(), VolumeError> {
        self.inner.put(key, data).await
    }

    async fn get(&self, key: &VolumePath) -> Result<Bytes, VolumeError> {
        self.inner.get(key).await
    }

    async fn list(&self, prefix: &VolumePath) -> Result<Vec<VolumeEntry>, VolumeError> {
        self.inner.list(prefix).await
    }

    async fn delete(&self, key: &VolumePath) -> Result<(), VolumeError> {
        self.inner.delete(key).await
    }

    async fn stat(&self, key: &VolumePath) -> Result<VolumeEntry, VolumeError> {
        self.inner.stat(key).await
    }

    async fn rename(&self, from: &VolumePath, to: &VolumePath) -> Result<(), VolumeError> {
        self.inner.rename(from, to).await
    }

    async fn health_check(&self) -> Result<(), VolumeError> {
        self.inner.health_check().await
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
