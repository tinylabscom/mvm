//! Canonical host-directory backend.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use chrono::Utc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::{VolumeBackend, VolumeEntry, VolumeError, VolumeFuture, VolumePath};

/// Host-directory-backed canonical volume backend.
pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Create the root when absent and verify it is a directory.
    pub async fn new(root: PathBuf) -> Result<Self, VolumeError> {
        fs::create_dir_all(&root).await.map_err(VolumeError::Io)?;
        let root = fs::canonicalize(&root).await.map_err(VolumeError::Io)?;
        let metadata = fs::metadata(&root).await.map_err(VolumeError::Io)?;
        if !metadata.is_dir() {
            return Err(VolumeError::Other(
                "local backend root is not a directory".into(),
            ));
        }
        Ok(Self { root })
    }

    fn resolve(&self, key: &VolumePath) -> Result<PathBuf, VolumeError> {
        let resolved = self.root.join(key.as_str());
        if !resolved.starts_with(&self.root) {
            return Err(VolumeError::InvalidPath(
                "resolved volume path escapes its root".into(),
            ));
        }
        Ok(resolved)
    }

    async fn assert_in_root(&self, path: &Path) -> Result<(), VolumeError> {
        let canonical = fs::canonicalize(path).await.map_err(VolumeError::Io)?;
        if !canonical.starts_with(&self.root) {
            return Err(VolumeError::InvalidPath(
                "volume path resolves outside its root".into(),
            ));
        }
        Ok(())
    }
}

impl VolumeBackend for LocalBackend {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn put<'a>(&'a self, key: &'a VolumePath, data: Bytes) -> VolumeFuture<'a, ()> {
        Box::pin(async move {
            let target = self.resolve(key)?;
            let parent = target.parent().ok_or_else(|| {
                VolumeError::InvalidPath("volume path has no parent directory".into())
            })?;
            fs::create_dir_all(parent).await.map_err(VolumeError::Io)?;
            self.assert_in_root(parent).await?;
            let temporary = parent.join(format!(
                ".mvm-tmp-{}-{}",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await
                .map_err(VolumeError::Io)?;
            if let Err(error) = file.write_all(&data).await {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(VolumeError::Io(error));
            }
            if let Err(error) = file.sync_all().await {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(VolumeError::Io(error));
            }
            drop(file);
            if let Err(error) = fs::rename(&temporary, &target).await {
                let _ = fs::remove_file(&temporary).await;
                return Err(VolumeError::Io(error));
            }
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, Bytes> {
        Box::pin(async move {
            let target = self.resolve(key)?;
            match fs::read(&target).await {
                Ok(bytes) => {
                    self.assert_in_root(&target).await?;
                    Ok(Bytes::from(bytes))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Err(VolumeError::NotFound(key.clone()))
                }
                Err(error) => Err(VolumeError::Io(error)),
            }
        })
    }

    fn list<'a>(&'a self, prefix: &'a VolumePath) -> VolumeFuture<'a, Vec<VolumeEntry>> {
        Box::pin(async move {
            let target = self.resolve(prefix)?;
            let metadata = match fs::metadata(&target).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VolumeError::NotFound(prefix.clone()));
                }
                Err(error) => return Err(VolumeError::Io(error)),
            };
            if !metadata.is_dir() {
                return Err(VolumeError::Other("list target is not a directory".into()));
            }
            self.assert_in_root(&target).await?;
            let mut entries = Vec::new();
            let mut directory = fs::read_dir(&target).await.map_err(VolumeError::Io)?;
            while let Some(entry) = directory.next_entry().await.map_err(VolumeError::Io)? {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".mvm-tmp-") {
                    continue;
                }
                let path = VolumePath::new(format!(
                    "{}/{}",
                    prefix.as_str().trim_end_matches('/'),
                    name
                ))
                .map_err(|_| VolumeError::InvalidPath("invalid local volume entry".into()))?;
                let metadata = entry.metadata().await.map_err(VolumeError::Io)?;
                entries.push(VolumeEntry {
                    path,
                    size: metadata.len(),
                    is_dir: metadata.is_dir(),
                    etag: None,
                });
            }
            Ok(entries)
        })
    }

    fn delete<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, ()> {
        Box::pin(async move {
            let target = self.resolve(key)?;
            let metadata = match fs::metadata(&target).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VolumeError::NotFound(key.clone()));
                }
                Err(error) => return Err(VolumeError::Io(error)),
            };
            self.assert_in_root(&target).await?;
            if metadata.is_dir() {
                fs::remove_dir_all(target).await.map_err(VolumeError::Io)
            } else {
                fs::remove_file(target).await.map_err(VolumeError::Io)
            }
        })
    }

    fn stat<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, VolumeEntry> {
        Box::pin(async move {
            let target = self.resolve(key)?;
            let metadata = match fs::metadata(&target).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VolumeError::NotFound(key.clone()));
                }
                Err(error) => return Err(VolumeError::Io(error)),
            };
            self.assert_in_root(&target).await?;
            Ok(VolumeEntry {
                path: key.clone(),
                size: metadata.len(),
                is_dir: metadata.is_dir(),
                etag: None,
            })
        })
    }

    fn rename<'a>(&'a self, from: &'a VolumePath, to: &'a VolumePath) -> VolumeFuture<'a, ()> {
        Box::pin(async move {
            let source = self.resolve(from)?;
            let destination = self.resolve(to)?;
            match fs::metadata(&source).await {
                Ok(_) => self.assert_in_root(&source).await?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VolumeError::NotFound(from.clone()));
                }
                Err(error) => return Err(VolumeError::Io(error)),
            }
            match fs::metadata(&destination).await {
                Ok(_) => return Err(VolumeError::AlreadyExists(to.clone())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(VolumeError::Io(error)),
            }
            let parent = destination.parent().ok_or_else(|| {
                VolumeError::InvalidPath("rename destination has no parent".into())
            })?;
            fs::create_dir_all(parent).await.map_err(VolumeError::Io)?;
            self.assert_in_root(parent).await?;
            fs::rename(source, destination)
                .await
                .map_err(VolumeError::Io)
        })
    }

    fn health_check(&self) -> VolumeFuture<'_, ()> {
        Box::pin(async move {
            let metadata = fs::metadata(&self.root).await.map_err(VolumeError::Io)?;
            if !metadata.is_dir() {
                return Err(VolumeError::Other(
                    "local backend root is not a directory".into(),
                ));
            }
            Ok(())
        })
    }

    fn local_export_path(&self) -> Option<&Path> {
        Some(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::super::contract::assert_backend_contract;
    use super::*;

    #[tokio::test]
    async fn passes_canonical_contract() {
        let directory = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(directory.path().to_path_buf())
            .await
            .unwrap();
        assert_backend_contract(&backend).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let backend = LocalBackend::new(root.path().to_path_buf()).await.unwrap();
        let error = backend
            .put(
                &VolumePath::new("escape/file").unwrap(),
                Bytes::from_static(b"x"),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, VolumeError::InvalidPath(_)));
    }

    #[tokio::test]
    async fn direct_child_listing_skips_abandoned_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".mvm-tmp-stale"), b"partial").unwrap();
        let backend = LocalBackend::new(directory.path().to_path_buf())
            .await
            .unwrap();
        backend
            .put(
                &VolumePath::new("real.txt").unwrap(),
                Bytes::from_static(b"complete"),
            )
            .await
            .unwrap();
        backend
            .put(
                &VolumePath::new("nested/file.txt").unwrap(),
                Bytes::from_static(b"nested"),
            )
            .await
            .unwrap();

        let mut entries = backend.list(&VolumePath::new(".").unwrap()).await.unwrap();
        entries.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
        let paths: Vec<_> = entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry.is_dir))
            .collect();
        assert_eq!(paths, vec![("./nested", true), ("./real.txt", false)]);
    }
}
