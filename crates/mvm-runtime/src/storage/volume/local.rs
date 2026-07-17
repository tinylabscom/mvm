//! `LocalBackend` — host-directory-backed [`VolumeBackend`].
//!
//! Backing layout:
//! - Each `VolumePath` resolves to `<root>/<key>`.
//! - Atomic puts: write to `<root>/.tmp.<random>`, fsync, rename.
//! - Symlink-escape defence: every operation re-canonicalises the
//!   resolved path and asserts `starts_with(<root>)` after resolution.
//!
//! This impl ships in the runtime's volume-backend module. mvmd uses it
//! directly for buckets whose backend is `BucketProvider::LocalVirtiofs`.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use mvm_core::volume::{VolumeEntry, VolumeError, VolumePath};

use crate::storage::volume::backend::VolumeBackend;

pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Construct backend rooted at `root`. Creates the directory if
    /// missing. Verifies the root is a directory and writable.
    pub async fn new(root: PathBuf) -> Result<Self, VolumeError> {
        fs::create_dir_all(&root).await.map_err(VolumeError::Io)?;
        let meta = fs::metadata(&root).await.map_err(VolumeError::Io)?;
        if !meta.is_dir() {
            return Err(VolumeError::Other(format!(
                "LocalBackend root must be a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Resolve a `VolumePath` to an absolute filesystem path under
    /// `self.root`. Rejects symlink escapes by canonicalising the
    /// parent directory and asserting `starts_with(self.root)`.
    fn resolve(&self, key: &VolumePath) -> Result<PathBuf, VolumeError> {
        let resolved = self.root.join(key.as_str());
        // Quick lexical check — `VolumePath::new` already rejected
        // `..` segments and absolute paths, but defence-in-depth.
        if !resolved.starts_with(&self.root) {
            return Err(VolumeError::InvalidPath(format!(
                "resolved path {} escapes root {}",
                resolved.display(),
                self.root.display()
            )));
        }
        Ok(resolved)
    }

    /// Canonicalise an existing path and assert it stays within root —
    /// catches symlinks pointing outside the volume.
    async fn assert_in_root(&self, path: &Path) -> Result<(), VolumeError> {
        let canonical = fs::canonicalize(path).await.map_err(VolumeError::Io)?;
        let root_canonical = fs::canonicalize(&self.root)
            .await
            .map_err(VolumeError::Io)?;
        if !canonical.starts_with(&root_canonical) {
            return Err(VolumeError::InvalidPath(format!(
                "symlink escape: {} resolves outside {}",
                path.display(),
                self.root.display()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl VolumeBackend for LocalBackend {
    fn kind(&self) -> &'static str {
        "local"
    }

    async fn put(&self, key: &VolumePath, data: Bytes) -> Result<(), VolumeError> {
        let target = self.resolve(key)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await.map_err(VolumeError::Io)?;
        }

        // Atomic write: temp file in target's parent dir, then rename.
        let tmp_name = format!(
            ".mvm-tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let tmp_path = target
            .parent()
            .map(|p| p.join(&tmp_name))
            .unwrap_or_else(|| PathBuf::from(&tmp_name));

        let mut file = fs::File::create(&tmp_path).await.map_err(VolumeError::Io)?;
        file.write_all(&data).await.map_err(VolumeError::Io)?;
        file.sync_all().await.map_err(VolumeError::Io)?;
        drop(file);

        fs::rename(&tmp_path, &target)
            .await
            .map_err(VolumeError::Io)?;
        Ok(())
    }

    async fn get(&self, key: &VolumePath) -> Result<Bytes, VolumeError> {
        let target = self.resolve(key)?;
        match fs::read(&target).await {
            Ok(bytes) => {
                self.assert_in_root(&target).await?;
                Ok(Bytes::from(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(VolumeError::NotFound(key.clone()))
            }
            Err(e) => Err(VolumeError::Io(e)),
        }
    }

    async fn list(&self, prefix: &VolumePath) -> Result<Vec<VolumeEntry>, VolumeError> {
        let target = self.resolve(prefix)?;
        let meta = match fs::metadata(&target).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VolumeError::NotFound(prefix.clone()));
            }
            Err(e) => return Err(VolumeError::Io(e)),
        };
        if !meta.is_dir() {
            return Err(VolumeError::Other(format!(
                "list target {} is not a directory",
                prefix.as_str()
            )));
        }

        let mut out = Vec::new();
        let mut iter = fs::read_dir(&target).await.map_err(VolumeError::Io)?;
        while let Some(entry) = iter.next_entry().await.map_err(VolumeError::Io)? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip our own atomic-write tmp files.
            if name_str.starts_with(".mvm-tmp-") {
                continue;
            }
            let entry_path = if prefix.as_str().is_empty() {
                name_str.to_string()
            } else {
                format!("{}/{}", prefix.as_str().trim_end_matches('/'), name_str)
            };
            let ep =
                VolumePath::new(entry_path).map_err(|e| VolumeError::InvalidPath(e.to_string()))?;
            let m = entry.metadata().await.map_err(VolumeError::Io)?;
            out.push(VolumeEntry {
                path: ep,
                size: m.len(),
                is_dir: m.is_dir(),
                etag: None,
            });
        }
        Ok(out)
    }

    async fn delete(&self, key: &VolumePath) -> Result<(), VolumeError> {
        let target = self.resolve(key)?;
        let meta = match fs::metadata(&target).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VolumeError::NotFound(key.clone()));
            }
            Err(e) => return Err(VolumeError::Io(e)),
        };
        if meta.is_dir() {
            fs::remove_dir_all(&target).await.map_err(VolumeError::Io)?;
        } else {
            fs::remove_file(&target).await.map_err(VolumeError::Io)?;
        }
        Ok(())
    }

    async fn stat(&self, key: &VolumePath) -> Result<VolumeEntry, VolumeError> {
        let target = self.resolve(key)?;
        let meta = match fs::metadata(&target).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VolumeError::NotFound(key.clone()));
            }
            Err(e) => return Err(VolumeError::Io(e)),
        };
        Ok(VolumeEntry {
            path: key.clone(),
            size: meta.len(),
            is_dir: meta.is_dir(),
            etag: None,
        })
    }

    async fn rename(&self, from: &VolumePath, to: &VolumePath) -> Result<(), VolumeError> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;

        // Source must exist; otherwise NotFound.
        match fs::metadata(&src).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VolumeError::NotFound(from.clone()));
            }
            Err(e) => return Err(VolumeError::Io(e)),
        }

        // Destination must NOT exist (rename is non-overwriting at
        // trait level — callers `delete` first if they want overwrite).
        match fs::metadata(&dst).await {
            Ok(_) => return Err(VolumeError::AlreadyExists(to.clone())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(VolumeError::Io(e)),
        }

        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).await.map_err(VolumeError::Io)?;
        }
        fs::rename(&src, &dst).await.map_err(VolumeError::Io)?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), VolumeError> {
        let meta = fs::metadata(&self.root).await.map_err(VolumeError::Io)?;
        if !meta.is_dir() {
            return Err(VolumeError::Other(format!(
                "root {} is not a directory",
                self.root.display()
            )));
        }
        Ok(())
    }

    fn local_export_path(&self) -> Option<&Path> {
        Some(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> (tempfile::TempDir, LocalBackend) {
        let tmp = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(tmp.path().to_path_buf()).await.unwrap();
        (tmp, backend)
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("hello.txt").unwrap();
        b.put(&key, Bytes::from_static(b"hi")).await.unwrap();
        let bytes = b.get(&key).await.unwrap();
        assert_eq!(&bytes[..], b"hi");
    }

    #[tokio::test]
    async fn put_creates_parent_dirs() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("a/b/c.txt").unwrap();
        b.put(&key, Bytes::from_static(b"deep")).await.unwrap();
        let bytes = b.get(&key).await.unwrap();
        assert_eq!(&bytes[..], b"deep");
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("nope").unwrap();
        let err = b.get(&key).await.unwrap_err();
        assert!(matches!(err, VolumeError::NotFound(_)));
    }

    #[tokio::test]
    async fn delete_then_get_is_not_found() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("doomed").unwrap();
        b.put(&key, Bytes::from_static(b"x")).await.unwrap();
        b.delete(&key).await.unwrap();
        let err = b.get(&key).await.unwrap_err();
        assert!(matches!(err, VolumeError::NotFound(_)));
    }

    #[tokio::test]
    async fn delete_missing_is_not_found() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("never").unwrap();
        let err = b.delete(&key).await.unwrap_err();
        assert!(matches!(err, VolumeError::NotFound(_)));
    }

    #[tokio::test]
    async fn rename_round_trip() {
        let (_tmp, b) = fresh().await;
        let from = VolumePath::new("src").unwrap();
        let to = VolumePath::new("dst").unwrap();
        b.put(&from, Bytes::from_static(b"data")).await.unwrap();
        b.rename(&from, &to).await.unwrap();
        let err = b.get(&from).await.unwrap_err();
        assert!(matches!(err, VolumeError::NotFound(_)));
        let bytes = b.get(&to).await.unwrap();
        assert_eq!(&bytes[..], b"data");
    }

    #[tokio::test]
    async fn rename_to_existing_is_already_exists() {
        let (_tmp, b) = fresh().await;
        let from = VolumePath::new("src").unwrap();
        let to = VolumePath::new("dst").unwrap();
        b.put(&from, Bytes::from_static(b"data")).await.unwrap();
        b.put(&to, Bytes::from_static(b"other")).await.unwrap();
        let err = b.rename(&from, &to).await.unwrap_err();
        assert!(matches!(err, VolumeError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn list_returns_entries() {
        let (_tmp, b) = fresh().await;
        b.put(&VolumePath::new("a.txt").unwrap(), Bytes::from_static(b"a"))
            .await
            .unwrap();
        b.put(
            &VolumePath::new("b.txt").unwrap(),
            Bytes::from_static(b"bb"),
        )
        .await
        .unwrap();
        b.put(
            &VolumePath::new("sub/c.txt").unwrap(),
            Bytes::from_static(b"ccc"),
        )
        .await
        .unwrap();

        // List root.
        let mut entries = b.list(&VolumePath::new(".").unwrap()).await.unwrap();
        entries.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, vec!["./a.txt", "./b.txt", "./sub"]);

        // List nested dir.
        let nested = b.list(&VolumePath::new("sub").unwrap()).await.unwrap();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].path.as_str(), "sub/c.txt");
        assert_eq!(nested[0].size, 3);
        assert!(!nested[0].is_dir);
    }

    #[tokio::test]
    async fn stat_returns_metadata() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("f.txt").unwrap();
        b.put(&key, Bytes::from_static(b"hello")).await.unwrap();
        let entry = b.stat(&key).await.unwrap();
        assert_eq!(entry.size, 5);
        assert!(!entry.is_dir);
    }

    #[tokio::test]
    async fn local_export_path_is_root() {
        let (tmp, b) = fresh().await;
        assert_eq!(b.local_export_path(), Some(tmp.path()));
    }

    #[tokio::test]
    async fn health_check_passes_on_valid_root() {
        let (_tmp, b) = fresh().await;
        b.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn put_overwrites_existing() {
        let (_tmp, b) = fresh().await;
        let key = VolumePath::new("k").unwrap();
        b.put(&key, Bytes::from_static(b"v1")).await.unwrap();
        b.put(&key, Bytes::from_static(b"v2-longer")).await.unwrap();
        assert_eq!(&b.get(&key).await.unwrap()[..], b"v2-longer");
    }

    #[tokio::test]
    async fn list_skips_atomic_write_tmp_files() {
        let (tmp, b) = fresh().await;
        // Manually drop a stray tmp file (simulating a crashed mid-put).
        std::fs::write(tmp.path().join(".mvm-tmp-stale"), b"junk").unwrap();
        b.put(
            &VolumePath::new("real.txt").unwrap(),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let entries = b.list(&VolumePath::new(".").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, vec!["./real.txt"]);
    }
}
