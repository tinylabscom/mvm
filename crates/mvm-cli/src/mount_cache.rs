//! Content-addressed ext4 images for host-directory mounts.
//!
//! Persistent `--host` registrations and transient `--mount` launches share
//! this one cache. Source identity covers the filesystem semantics the ext4
//! writer emits; cache identity also covers its format version and volume
//! label. Cache objects are immutable and verified on every lookup. A writable
//! consumer receives a private copy-on-write clone and never the cache object.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_SCHEMA_VERSION: u32 = 1;
const CACHE_DIR_NAME: &str = "mount-images";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountFingerprint {
    source: PathBuf,
    source_sha256: String,
    cache_key: String,
    volume_label: String,
}

impl MountFingerprint {
    pub(crate) fn source(&self) -> &Path {
        &self.source
    }

    pub(crate) fn cache_key(&self) -> &str {
        &self.cache_key
    }
}

#[derive(Debug)]
pub(crate) struct CachedMountImage {
    path: PathBuf,
    fingerprint: MountFingerprint,
}

impl CachedMountImage {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn fingerprint(&self) -> &MountFingerprint {
        &self.fingerprint
    }

    /// Produce a private writable image without ever granting write access to
    /// the shared cache object. Reflink is the ordinary fast path; a
    /// sparse-aware copy preserves correctness on filesystems without CoW.
    pub(crate) fn writable_copy(&self, target: &Path) -> Result<PathBuf> {
        let parent = target
            .parent()
            .with_context(|| format!("writable mount image has no parent: {}", target.display()))?;
        mvm_core::config::create_private_dir(parent)
            .with_context(|| format!("creating writable mount image dir {}", parent.display()))?;
        let staging = tempfile::Builder::new()
            .prefix(".mount-copy-")
            .tempdir_in(parent)
            .with_context(|| format!("creating mount image staging dir in {}", parent.display()))?;
        let staged_image = staging.path().join("image.ext4");
        mvm_fs::clone::reflink_or_copy(&self.path, &staged_image).with_context(|| {
            format!(
                "cloning cached mount image {} to {}",
                self.path.display(),
                target.display()
            )
        })?;
        set_private_writable(&staged_image)?;
        std::fs::rename(&staged_image, target).with_context(|| {
            format!(
                "publishing writable mount image {} from cache",
                target.display()
            )
        })?;
        Ok(target.to_path_buf())
    }
}

pub(crate) enum MountCacheLookup {
    Hit(CachedMountImage),
    Miss(MountCacheMiss),
}

impl MountCacheLookup {
    pub(crate) fn is_miss(&self) -> bool {
        matches!(self, Self::Miss(_))
    }

    pub(crate) fn resolve(self) -> Result<CachedMountImage> {
        match self {
            Self::Hit(image) => Ok(image),
            Self::Miss(miss) => miss.materialize(),
        }
    }
}

pub(crate) struct MountCacheMiss {
    cache: MountImageCache,
    fingerprint: MountFingerprint,
    _lock: mvm_core::atomic_io::FileLock,
}

impl MountCacheMiss {
    fn materialize(self) -> Result<CachedMountImage> {
        let staging = tempfile::Builder::new()
            .prefix(".mount-image-")
            .tempdir_in(&self.cache.root)
            .with_context(|| {
                format!(
                    "creating mount cache staging dir in {}",
                    self.cache.root.display()
                )
            })?;
        let staged_image = staging.path().join("image.ext4");
        let nodes = mvm_fs::rootfs::collect_nodes(&self.fingerprint.source, mount_walk_options())
            .with_context(|| {
            format!(
                "collecting mount source {} for materialization",
                self.fingerprint.source.display()
            )
        })?;
        let after = mvm_fs::rootfs::fingerprint_ext4_nodes(&nodes)
            .context("fingerprinting the collected mount nodes")?;
        if after != self.fingerprint.source_sha256 {
            bail!(
                "mount source {} changed while it was being snapshotted; retry the launch",
                self.fingerprint.source.display()
            );
        }
        let build = mvm_fs::ext4::BuildOptions::default()
            .with_volume_name(self.fingerprint.volume_label.as_bytes());
        mvm_fs::rootfs::materialize_ext4_nodes_pure(nodes, &staged_image, &build).with_context(
            || {
                format!(
                    "materializing mount source {} into an ext4 image",
                    self.fingerprint.source.display()
                )
            },
        )?;

        let image_sha256 = mvm_core::crypto::image_verify::sha256_file(&staged_image)
            .with_context(|| format!("hashing staged mount image {}", staged_image.display()))?;
        let image_bytes = std::fs::metadata(&staged_image)
            .with_context(|| format!("stat staged mount image {}", staged_image.display()))?
            .len();
        let image_path = self.cache.image_path(&self.fingerprint.cache_key);
        set_cache_read_only(&staged_image)?;
        std::fs::rename(&staged_image, &image_path)
            .with_context(|| format!("publishing cached mount image {}", image_path.display()))?;
        let manifest = MountCacheManifest {
            schema_version: CACHE_SCHEMA_VERSION,
            cache_key: self.fingerprint.cache_key.clone(),
            source_sha256: self.fingerprint.source_sha256.clone(),
            materializer_format_version: mvm_fs::rootfs::EXT4_MATERIALIZER_FORMAT_VERSION,
            volume_label: self.fingerprint.volume_label.clone(),
            image_sha256,
            image_bytes,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .context("serializing cached mount image manifest")?;
        mvm_core::atomic_io::atomic_write(
            &self.cache.manifest_path(&self.fingerprint.cache_key),
            &manifest_bytes,
        )
        .context("publishing cached mount image manifest")?;
        Ok(CachedMountImage {
            path: image_path,
            fingerprint: self.fingerprint,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MountImageCache {
    root: PathBuf,
}

impl MountImageCache {
    pub(crate) fn new() -> Result<Self> {
        let root = PathBuf::from(mvm_core::config::mvm_cache_dir()).join(CACHE_DIR_NAME);
        #[cfg(test)]
        {
            Self::at_verified(root, |_| Ok(()))
        }
        #[cfg(not(test))]
        {
            Self::at_verified(
                root,
                crate::doctor::require_local_volume_host_path_encrypted,
            )
        }
    }

    fn at_verified(
        root: PathBuf,
        verify_encrypted: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Self> {
        let cache = Self::at(root);
        let root = cache.ensure_private_root()?;
        verify_encrypted(root).context("mount image cache is not on encrypted backing storage")?;
        Ok(cache)
    }

    fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn ensure_private_root(&self) -> Result<&Path> {
        mvm_core::config::create_private_dir(&self.root)
            .with_context(|| format!("creating mount image cache {}", self.root.display()))?;
        Ok(&self.root)
    }

    pub(crate) fn fingerprint(
        &self,
        source: &Path,
        volume_label: &str,
    ) -> Result<MountFingerprint> {
        let source = std::fs::canonicalize(source).with_context(|| {
            format!(
                "mount source directory does not exist: {}",
                source.display()
            )
        })?;
        if !source.is_dir() {
            bail!("mount source is not a directory: {}", source.display());
        }
        let source_sha256 = fingerprint_source(&source)?;
        let cache_key = cache_key(&source_sha256, volume_label);
        Ok(MountFingerprint {
            source,
            source_sha256,
            cache_key,
            volume_label: volume_label.to_string(),
        })
    }

    pub(crate) fn lookup(&self, fingerprint: MountFingerprint) -> Result<MountCacheLookup> {
        self.ensure_private_root()?;
        let image_path = self.image_path(&fingerprint.cache_key);
        let lock = mvm_core::atomic_io::FileLock::acquire(&image_path)
            .context("locking cached mount image")?;
        if self.cache_entry_is_valid(&fingerprint)? {
            return Ok(MountCacheLookup::Hit(CachedMountImage {
                path: image_path,
                fingerprint,
            }));
        }
        Ok(MountCacheLookup::Miss(MountCacheMiss {
            cache: self.clone(),
            fingerprint,
            _lock: lock,
        }))
    }

    fn cache_entry_is_valid(&self, fingerprint: &MountFingerprint) -> Result<bool> {
        let manifest_path = self.manifest_path(&fingerprint.cache_key);
        let image_path = self.image_path(&fingerprint.cache_key);
        if !manifest_path.is_file() || !is_regular_file(&image_path) {
            return Ok(false);
        }
        let raw = match std::fs::read(&manifest_path) {
            Ok(raw) => raw,
            Err(error) => {
                tracing::warn!(cache_key = %fingerprint.cache_key, %error, "cached mount manifest is unreadable; rebuilding");
                return Ok(false);
            }
        };
        let manifest: MountCacheManifest = match serde_json::from_slice(&raw) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(cache_key = %fingerprint.cache_key, %error, "cached mount manifest is invalid; rebuilding");
                return Ok(false);
            }
        };
        if !manifest.matches(fingerprint) {
            return Ok(false);
        }
        let metadata = std::fs::metadata(&image_path)
            .with_context(|| format!("stat cached mount image {}", image_path.display()))?;
        if metadata.len() != manifest.image_bytes {
            return Ok(false);
        }
        let actual = mvm_core::crypto::image_verify::sha256_file(&image_path)
            .with_context(|| format!("verifying cached mount image {}", image_path.display()))?;
        Ok(actual == manifest.image_sha256)
    }

    fn image_path(&self, cache_key: &str) -> PathBuf {
        self.root.join(format!("{cache_key}.ext4"))
    }

    fn manifest_path(&self, cache_key: &str) -> PathBuf {
        self.root.join(format!("{cache_key}.json"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountCacheManifest {
    schema_version: u32,
    cache_key: String,
    source_sha256: String,
    materializer_format_version: u32,
    volume_label: String,
    image_sha256: String,
    image_bytes: u64,
}

impl MountCacheManifest {
    fn matches(&self, fingerprint: &MountFingerprint) -> bool {
        self.schema_version == CACHE_SCHEMA_VERSION
            && self.cache_key == fingerprint.cache_key
            && self.source_sha256 == fingerprint.source_sha256
            && self.materializer_format_version == mvm_fs::rootfs::EXT4_MATERIALIZER_FORMAT_VERSION
            && self.volume_label == fingerprint.volume_label
            && self.image_sha256.len() == 64
            && self
                .image_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }
}

fn mount_walk_options() -> mvm_fs::rootfs::WalkOptions {
    mvm_fs::rootfs::WalkOptions::new(mvm_fs::rootfs::UnsupportedNodePolicy::Reject)
        .with_vanished_node_policy(mvm_fs::rootfs::VanishedNodePolicy::Skip)
        .with_file_content_policy(mvm_fs::rootfs::FileContentPolicy::DeferToEmitVerified)
}

fn fingerprint_source(source: &Path) -> Result<String> {
    mvm_fs::rootfs::fingerprint_ext4_source(source, mount_walk_options())
        .with_context(|| format!("fingerprinting mount source {}", source.display()))
}

fn cache_key(source_sha256: &str, volume_label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm.mount-image-cache.v1\0");
    hasher.update(mvm_fs::rootfs::EXT4_MATERIALIZER_FORMAT_VERSION.to_be_bytes());
    fold_cache_key_field(&mut hasher, source_sha256.as_bytes());
    fold_cache_key_field(&mut hasher, volume_label.as_bytes());
    hex::encode(hasher.finalize())
}

fn fold_cache_key_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(unix)]
fn set_cache_read_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        .with_context(|| format!("making cached mount image read-only: {}", path.display()))
}

#[cfg(not(unix))]
fn set_cache_read_only(path: &Path) -> Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("making writable mount image private: {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_writable(path: &Path) -> Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    fn source(root: &Path, bytes: &[u8]) -> PathBuf {
        let path = root.join("source");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("marker"), bytes).unwrap();
        path
    }

    #[test]
    fn unchanged_content_hits_one_verified_cache_object() {
        let scratch = tempfile::tempdir().unwrap();
        let cache = MountImageCache::at(scratch.path().join("cache"));
        let source = source(scratch.path(), b"same");
        let first = cache.fingerprint(&source, "mvmmnt0").unwrap();
        let key = first.cache_key().to_string();
        assert!(cache.lookup(first).unwrap().is_miss());
        let image = cache
            .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(image.fingerprint().cache_key(), key);

        let second = cache
            .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
            .unwrap();
        assert!(!second.is_miss());
        assert_eq!(second.resolve().unwrap().path(), image.path());
    }

    #[test]
    fn changed_bytes_with_equal_mtime_select_a_new_cache_object() {
        let scratch = tempfile::tempdir().unwrap();
        let cache = MountImageCache::at(scratch.path().join("cache"));
        let source = source(scratch.path(), b"before");
        let marker = source.join("marker");
        let original_mtime = std::fs::metadata(&marker).unwrap().modified().unwrap();
        let before = cache.fingerprint(&source, "mvmmnt0").unwrap();

        std::fs::write(&marker, b"after!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        let after = cache.fingerprint(&source, "mvmmnt0").unwrap();
        assert_ne!(before.cache_key(), after.cache_key());
    }

    #[test]
    fn a_source_change_after_lookup_refuses_to_publish_under_the_old_key() {
        let scratch = tempfile::tempdir().unwrap();
        let cache_root = scratch.path().join("cache");
        let cache = MountImageCache::at(cache_root.clone());
        let source = source(scratch.path(), b"before");
        let lookup = cache
            .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
            .unwrap();
        std::fs::write(source.join("marker"), b"after").unwrap();

        let error = lookup.resolve().unwrap_err();
        assert!(format!("{error:#}").contains("changed while it was being snapshotted"));
        assert_eq!(
            std::fs::read_dir(&cache_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    matches!(
                        entry.path().extension().and_then(|value| value.to_str()),
                        Some("ext4" | "json")
                    )
                })
                .count(),
            0
        );
    }

    #[test]
    fn a_tampered_cache_image_is_a_miss_and_is_rebuilt() {
        let scratch = tempfile::tempdir().unwrap();
        let cache = MountImageCache::at(scratch.path().join("cache"));
        let source = source(scratch.path(), b"trusted");
        let image = cache
            .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
            .unwrap()
            .resolve()
            .unwrap();
        set_private_writable(image.path()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(image.path())
            .unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(b"tampered").unwrap();
        file.sync_all().unwrap();

        let lookup = cache
            .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
            .unwrap();
        assert!(lookup.is_miss());
        lookup.resolve().unwrap();
        assert!(
            !cache
                .lookup(cache.fingerprint(&source, "mvmmnt0").unwrap())
                .unwrap()
                .is_miss()
        );
    }

    #[test]
    fn a_writable_copy_cannot_mutate_the_shared_cache_object() {
        let scratch = tempfile::tempdir().unwrap();
        let cache = MountImageCache::at(scratch.path().join("cache"));
        let source = source(scratch.path(), b"source");
        let cached = cache
            .lookup(cache.fingerprint(&source, "mvmvolwork").unwrap())
            .unwrap()
            .resolve()
            .unwrap();
        let cached_digest = mvm_core::crypto::image_verify::sha256_file(cached.path()).unwrap();
        let private = cached
            .writable_copy(&scratch.path().join("private.ext4"))
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(private)
            .unwrap();
        file.seek(SeekFrom::Start(8192)).unwrap();
        file.write_all(b"guest mutation").unwrap();
        file.sync_all().unwrap();

        assert_eq!(
            mvm_core::crypto::image_verify::sha256_file(cached.path()).unwrap(),
            cached_digest
        );
    }

    #[test]
    fn cache_identity_includes_the_ext4_volume_label() {
        let scratch = tempfile::tempdir().unwrap();
        let cache = MountImageCache::at(scratch.path().join("cache"));
        let source = source(scratch.path(), b"same");
        assert_ne!(
            cache.fingerprint(&source, "first").unwrap().cache_key(),
            cache.fingerprint(&source, "second").unwrap().cache_key()
        );
    }

    #[test]
    fn mount_cache_uses_verified_deferred_file_contents() {
        let scratch = tempfile::tempdir().unwrap();
        let source = source(scratch.path(), &[0x5a; 64 * 1024]);
        let nodes = mvm_fs::rootfs::collect_nodes(&source, mount_walk_options()).unwrap();
        assert!(nodes.iter().any(|node| matches!(
            node,
            mvm_fs::ext4::Node::FileFromHost {
                expected_sha256: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn cache_initialization_refuses_unencrypted_backing_before_writing_bytes() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("cache");
        let error = MountImageCache::at_verified(root.clone(), |path| {
            assert!(path.is_dir());
            anyhow::bail!("unencrypted test backing")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("unencrypted test backing"));
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }
}
