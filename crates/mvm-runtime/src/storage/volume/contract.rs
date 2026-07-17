//! Generic [`VolumeBackend`] contract test fixture.
//!
//! Every backend impl — [`crate::storage::volume::LocalBackend`], mvmd-side
//! `ObjectStoreBackend`, mvmd-side `EncryptedBackend<B>` — must pass
//! [`assert_backend_contract`] for the same set of operations.
//!
//! Re-export so mvmd can pull this in directly via the `mvmctl` facade.

use bytes::Bytes;

use mvm_core::volume::{VolumeError, VolumePath};

use crate::storage::volume::backend::VolumeBackend;

/// Run the full trait contract against `backend`. Panics on the first
/// violation, with a message identifying the failed assertion.
///
/// The fixture assumes `backend` is empty when called and does not
/// clean up after itself — callers should construct a fresh backend
/// per invocation.
pub async fn assert_backend_contract<B: VolumeBackend>(backend: &B) {
    health_check_passes(backend).await;
    put_get_round_trip(backend).await;
    overwrite_replaces_content(backend).await;
    get_missing_returns_not_found(backend).await;
    delete_then_get_is_not_found(backend).await;
    delete_missing_is_not_found(backend).await;
    rename_round_trip(backend).await;
    rename_to_existing_is_already_exists(backend).await;
    stat_returns_metadata(backend).await;
    list_returns_entries(backend).await;
}

fn key(s: &str) -> VolumePath {
    VolumePath::new(s).expect("valid test key")
}

async fn health_check_passes<B: VolumeBackend>(b: &B) {
    b.health_check()
        .await
        .expect("contract: health_check must pass on a fresh backend");
}

async fn put_get_round_trip<B: VolumeBackend>(b: &B) {
    let k = key("contract/put-get/file.txt");
    b.put(&k, Bytes::from_static(b"hello"))
        .await
        .expect("contract: put must succeed");
    let bytes = b
        .get(&k)
        .await
        .expect("contract: get after put must succeed");
    assert_eq!(
        &bytes[..],
        b"hello",
        "contract: get must return exactly the bytes from put"
    );
    b.delete(&k).await.expect("contract: cleanup delete");
}

async fn overwrite_replaces_content<B: VolumeBackend>(b: &B) {
    let k = key("contract/overwrite/file.txt");
    b.put(&k, Bytes::from_static(b"v1"))
        .await
        .expect("contract: backend op");
    b.put(&k, Bytes::from_static(b"v2-longer"))
        .await
        .expect("contract: backend op");
    let bytes = b.get(&k).await.expect("contract: backend op");
    assert_eq!(
        &bytes[..],
        b"v2-longer",
        "contract: second put must overwrite first"
    );
    b.delete(&k).await.expect("contract: backend op");
}

async fn get_missing_returns_not_found<B: VolumeBackend>(b: &B) {
    let k = key("contract/missing/never-existed");
    match b.get(&k).await {
        Err(VolumeError::NotFound(_)) => {}
        Ok(_) => panic!("contract: get on missing key must fail"),
        Err(e) => panic!("contract: get on missing key must return NotFound, got: {e}"),
    }
}

async fn delete_then_get_is_not_found<B: VolumeBackend>(b: &B) {
    let k = key("contract/delete-get/doomed");
    b.put(&k, Bytes::from_static(b"x"))
        .await
        .expect("contract: backend op");
    b.delete(&k).await.expect("contract: backend op");
    match b.get(&k).await {
        Err(VolumeError::NotFound(_)) => {}
        Ok(_) => panic!("contract: get after delete must fail"),
        Err(e) => panic!("contract: get after delete must return NotFound, got: {e}"),
    }
}

async fn delete_missing_is_not_found<B: VolumeBackend>(b: &B) {
    let k = key("contract/delete-missing/never-existed");
    match b.delete(&k).await {
        Err(VolumeError::NotFound(_)) => {}
        Ok(_) => panic!("contract: delete on missing key must fail"),
        Err(e) => panic!("contract: delete on missing key must return NotFound, got: {e}"),
    }
}

async fn rename_round_trip<B: VolumeBackend>(b: &B) {
    let from = key("contract/rename/src");
    let to = key("contract/rename/dst");
    b.put(&from, Bytes::from_static(b"data"))
        .await
        .expect("contract: backend op");
    b.rename(&from, &to).await.expect("contract: rename");
    match b.get(&from).await {
        Err(VolumeError::NotFound(_)) => {}
        _ => panic!("contract: source must be NotFound after rename"),
    }
    let bytes = b.get(&to).await.expect("contract: backend op");
    assert_eq!(
        &bytes[..],
        b"data",
        "contract: rename must preserve content"
    );
    b.delete(&to).await.expect("contract: backend op");
}

async fn rename_to_existing_is_already_exists<B: VolumeBackend>(b: &B) {
    let from = key("contract/rename-conflict/src");
    let to = key("contract/rename-conflict/dst");
    b.put(&from, Bytes::from_static(b"a"))
        .await
        .expect("contract: backend op");
    b.put(&to, Bytes::from_static(b"b"))
        .await
        .expect("contract: backend op");
    match b.rename(&from, &to).await {
        Err(VolumeError::AlreadyExists(_)) => {}
        Ok(_) => panic!("contract: rename onto existing key must fail"),
        Err(e) => panic!("contract: rename onto existing key must be AlreadyExists, got: {e}"),
    }
    b.delete(&from).await.expect("contract: backend op");
    b.delete(&to).await.expect("contract: backend op");
}

async fn stat_returns_metadata<B: VolumeBackend>(b: &B) {
    let k = key("contract/stat/file.txt");
    b.put(&k, Bytes::from_static(b"twelve bytes"))
        .await
        .expect("contract: put");
    let entry = b.stat(&k).await.expect("contract: stat after put");
    assert_eq!(entry.size, 12, "contract: stat size must match put length");
    assert!(!entry.is_dir, "contract: stat on file must report not-dir");
    b.delete(&k).await.expect("contract: backend op");
}

async fn list_returns_entries<B: VolumeBackend>(b: &B) {
    let a = key("contract/list/a.txt");
    let bb = key("contract/list/b.txt");
    let nested = key("contract/list/sub/c.txt");
    b.put(&a, Bytes::from_static(b"a"))
        .await
        .expect("contract: backend op");
    b.put(&bb, Bytes::from_static(b"bb"))
        .await
        .expect("contract: backend op");
    b.put(&nested, Bytes::from_static(b"ccc"))
        .await
        .expect("contract: backend op");

    let entries = b.list(&key("contract/list")).await.expect("contract: list");
    let mut names: Vec<String> = entries.iter().map(|e| e.path.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "contract/list/a.txt".to_string(),
            "contract/list/b.txt".to_string(),
            "contract/list/sub".to_string(),
        ],
        "contract: list must return direct children"
    );

    b.delete(&a).await.expect("contract: backend op");
    b.delete(&bb).await.expect("contract: backend op");
    b.delete(&nested).await.expect("contract: backend op");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::volume::LocalBackend;

    #[tokio::test]
    async fn local_backend_passes_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(tmp.path().to_path_buf())
            .await
            .expect("contract: backend op");
        assert_backend_contract(&backend).await;
    }
}
