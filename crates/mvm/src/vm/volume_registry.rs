//! Per-VM volume mount registry — plan 45 §D5 (Path C; renamed from
//! the prior `share_registry` without behavioural change).
//!
//! Tracks which virtio-fs volumes are currently attached to a VM
//! so `mvmctl volume ls` / `rm` operate on a stable list rather
//! than guessing at host-side state. Persisted at
//! `~/.mvm/instances/<vm>/volume_mounts.json` (mode 0600, atomic
//! writes).
//!
//! The host-side `virtiofsd` process and Firecracker
//! virtio-device-attach plumbing live elsewhere — this registry
//! is the catalog the orchestrator hands to those tools and
//! reads back from on subsequent calls.
//!
use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::domain::volume::WrappedKey;
use serde::{Deserialize, Serialize};

/// Maximum number of volume mounts per VM. Defends against
/// `mvmctl volume mount` being looped without bound and the
/// agent's virtio-fs tag namespace exhausting (the kernel limits
/// per-VM devices already, but we cap earlier so callers see a
/// clear error rather than virtio-fs's opaque ENOMEM).
pub const MAX_VOLUME_MOUNTS_PER_VM: usize = 16;

/// Per-host managed local volume catalog path:
/// `~/.mvm/volumes/registry.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalVolumeCatalog {
    #[serde(default)]
    pub volumes: BTreeMap<String, LocalVolumeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalVolumeEntry {
    pub volume_name: String,
    pub host_path: String,
    pub encrypted: bool,
    #[serde(default)]
    pub encryption: LocalVolumeEncryption,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LocalVolumeEncryption {
    /// Compatibility shape for ad-hoc / pre-existing managed
    /// directories whose at-rest encryption comes from the host
    /// filesystem or block device.
    #[default]
    HostBacked,
    /// MVM owns the encryption lifecycle: `ciphertext_path` is the
    /// encrypted archive at rest, `host_path` is only populated while
    /// the volume is explicitly unlocked for a microVM mount.
    MvmManaged(MvmManagedVolumeEncryption),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MvmManagedVolumeEncryption {
    pub state: LocalVolumeState,
    pub ciphertext_path: String,
    pub wrapped_key: WrappedKey,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalVolumeState {
    Locked,
    Unlocked,
}

impl LocalVolumeCatalog {
    pub fn path() -> PathBuf {
        PathBuf::from(mvm_core::config::mvm_data_dir())
            .join("volumes")
            .join("registry.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let parsed: Self =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        Ok(parsed)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent of {}", path.display()))?;
        }
        let json = serde_json::to_vec_pretty(self).context("serialize LocalVolumeCatalog")?;
        mvm_core::util::atomic_io::atomic_write(&path, &json)
            .with_context(|| format!("atomic_write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
        }
        Ok(())
    }

    pub fn add(&mut self, entry: LocalVolumeEntry) -> Result<()> {
        if self.volumes.contains_key(&entry.volume_name) {
            anyhow::bail!("local volume {:?} already exists", entry.volume_name);
        }
        if !entry.encrypted {
            anyhow::bail!("local volume {:?} must be encrypted", entry.volume_name);
        }
        if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
            && enc.ciphertext_path.is_empty()
        {
            anyhow::bail!(
                "mvm-managed local volume {:?} must record ciphertext_path",
                entry.volume_name
            );
        }
        self.volumes.insert(entry.volume_name.clone(), entry);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&LocalVolumeEntry> {
        self.volumes.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut LocalVolumeEntry> {
        self.volumes.get_mut(name)
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, LocalVolumeEntry> {
        self.volumes.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.volumes.is_empty()
    }
}

/// One attached virtio-fs volume mount.
///
/// `volume_name` is the logical identity (also used as the
/// virtio-fs tag the kernel sees, so the agent's `MountVolume`
/// validation applies). `host_path` is the absolute host-side
/// directory exposed via virtio-fs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeMountEntry {
    /// Logical volume identifier — used as the virtio-fs tag and
    /// as the future foreign key into the per-host volume
    /// catalog.
    pub volume_name: String,
    /// Absolute host-side directory exposed via virtio-fs.
    pub host_path: String,
    /// Mount point inside the guest. Validated via
    /// `mvm_core::crypto::policy::MountPathPolicy` before reaching
    /// the registry.
    pub guest_path: String,
    /// `true` when the volume is exposed read-only.
    pub read_only: bool,
    /// RFC 3339 timestamp of attach.
    pub attached_at: String,
}

/// Persistent volume-mount catalog for one VM. Map keyed by
/// `guest_path` so a second `mvmctl volume mount` against the
/// same mount point is rejected at this layer rather than
/// tripping over virtio-fs's tag-conflict shape inside the
/// guest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeMountRegistry {
    #[serde(default)]
    pub mounts: BTreeMap<String, VolumeMountEntry>,
}

impl VolumeMountRegistry {
    /// Disk path of the catalog for `vm_name`.
    pub fn path_for(vm_name: &str) -> PathBuf {
        PathBuf::from(mvm_core::config::mvm_data_dir())
            .join("instances")
            .join(vm_name)
            .join("volume_mounts.json")
    }

    /// Load from disk; returns an empty registry when the file is
    /// missing (matches the VmNameRegistry forgiving shape).
    pub fn load(vm_name: &str) -> Result<Self> {
        let path = Self::path_for(vm_name);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let parsed: Self =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        Ok(parsed)
    }

    /// Save atomically, mode 0600.
    pub fn save(&self, vm_name: &str) -> Result<()> {
        let path = Self::path_for(vm_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent of {}", path.display()))?;
        }
        let json = serde_json::to_vec_pretty(self).context("serialize VolumeMountRegistry")?;
        mvm_core::util::atomic_io::atomic_write(&path, &json)
            .with_context(|| format!("atomic_write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
        }
        Ok(())
    }

    /// Insert a new volume mount. Returns `Err` when:
    /// - `guest_path` is already attached to this VM
    /// - the per-VM mount cap would be exceeded
    pub fn add(&mut self, entry: VolumeMountEntry) -> Result<()> {
        if self.mounts.contains_key(&entry.guest_path) {
            anyhow::bail!(
                "VM already has a volume mount at {:?}; remove it first",
                entry.guest_path
            );
        }
        if self.mounts.len() >= MAX_VOLUME_MOUNTS_PER_VM {
            anyhow::bail!(
                "VM already has the maximum {MAX_VOLUME_MOUNTS_PER_VM} volume mounts; \
                 remove one before adding another"
            );
        }
        self.mounts.insert(entry.guest_path.clone(), entry);
        Ok(())
    }

    /// Remove the mount at `guest_path`. Returns the dropped
    /// entry when one was present.
    pub fn remove(&mut self, guest_path: &str) -> Option<VolumeMountEntry> {
        self.mounts.remove(guest_path)
    }

    /// Iterator over the catalog in deterministic (BTree) order.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, VolumeMountEntry> {
        self.mounts.iter()
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let g = super::super::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var("MVM_DATA_DIR").ok();
            unsafe {
                std::env::set_var("MVM_DATA_DIR", tmp.path());
            }
            DataDirGuard {
                _guard: g,
                prev,
                _tmp: tmp,
            }
        }
    }

    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
            }
        }
    }

    fn make_entry(guest: &str, vol: &str) -> VolumeMountEntry {
        VolumeMountEntry {
            volume_name: vol.to_string(),
            host_path: format!("/host/{vol}"),
            guest_path: guest.to_string(),
            read_only: false,
            attached_at: "2026-05-05T00:00:00Z".to_string(),
        }
    }

    fn make_local_entry(name: &str) -> LocalVolumeEntry {
        LocalVolumeEntry {
            volume_name: name.to_string(),
            host_path: format!("/encrypted/{name}"),
            encrypted: true,
            encryption: LocalVolumeEncryption::HostBacked,
            created_at: "2026-05-05T00:00:00Z".to_string(),
        }
    }

    fn make_mvm_managed_entry(name: &str, state: LocalVolumeState) -> LocalVolumeEntry {
        LocalVolumeEntry {
            volume_name: name.to_string(),
            host_path: format!("/plain/{name}"),
            encrypted: true,
            encryption: LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state,
                ciphertext_path: format!("/cipher/{name}.mvve"),
                wrapped_key: WrappedKey {
                    master_key_version: 1,
                    wrapped: vec![1, 2, 3],
                    algorithm: mvm_core::domain::volume::WrapAlgorithm::Aes256Gcm,
                    bound: None,
                },
            }),
            created_at: "2026-05-05T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn empty_registry_is_empty() {
        let r = VolumeMountRegistry::default();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn add_and_remove_roundtrip() {
        let mut r = VolumeMountRegistry::default();
        r.add(make_entry("/data/foo", "data-vol")).unwrap();
        assert_eq!(r.len(), 1);
        let dropped = r.remove("/data/foo").unwrap();
        assert_eq!(dropped.volume_name, "data-vol");
        assert!(r.is_empty());
    }

    #[test]
    fn add_rejects_duplicate_guest_path() {
        let mut r = VolumeMountRegistry::default();
        r.add(make_entry("/data/foo", "vol-a")).unwrap();
        let err = r.add(make_entry("/data/foo", "vol-b")).unwrap_err();
        assert!(err.to_string().contains("already has a volume mount"));
    }

    #[test]
    fn add_caps_count() {
        let mut r = VolumeMountRegistry::default();
        for i in 0..MAX_VOLUME_MOUNTS_PER_VM {
            r.add(make_entry(&format!("/data/{i}"), &format!("vol-{i}")))
                .unwrap();
        }
        let err = r.add(make_entry("/data/over", "vol-over")).unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let _g = DataDirGuard::new();
        let mut r = VolumeMountRegistry::default();
        r.add(make_entry("/data/foo", "data-vol")).unwrap();
        r.save("vm-1").unwrap();
        let loaded = VolumeMountRegistry::load("vm-1").unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    fn load_missing_returns_empty() {
        let _g = DataDirGuard::new();
        let r = VolumeMountRegistry::load("never-saved").unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _g = DataDirGuard::new();
        let r = VolumeMountRegistry::default();
        r.save("perm-test").unwrap();
        let mode = std::fs::metadata(VolumeMountRegistry::path_for("perm-test"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn local_volume_catalog_save_load_roundtrip() {
        let _g = DataDirGuard::new();
        let mut c = LocalVolumeCatalog::default();
        c.add(make_local_entry("work")).unwrap();
        c.save().unwrap();
        let loaded = LocalVolumeCatalog::load().unwrap();
        assert_eq!(loaded, c);
        assert_eq!(loaded.get("work").unwrap().host_path, "/encrypted/work");
    }

    #[test]
    fn local_volume_catalog_rejects_duplicates() {
        let mut c = LocalVolumeCatalog::default();
        c.add(make_local_entry("work")).unwrap();
        let err = c.add(make_local_entry("work")).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn local_volume_catalog_rejects_unencrypted_entry() {
        let mut c = LocalVolumeCatalog::default();
        let mut e = make_local_entry("work");
        e.encrypted = false;
        let err = c.add(e).unwrap_err();
        assert!(err.to_string().contains("must be encrypted"));
    }

    #[test]
    fn local_volume_catalog_mvm_managed_roundtrip() {
        let _g = DataDirGuard::new();
        let mut c = LocalVolumeCatalog::default();
        c.add(make_mvm_managed_entry("work", LocalVolumeState::Locked))
            .unwrap();
        c.save().unwrap();
        let loaded = LocalVolumeCatalog::load().unwrap();
        let entry = loaded.get("work").unwrap();
        match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.state, LocalVolumeState::Locked);
                assert_eq!(enc.ciphertext_path, "/cipher/work.mvve");
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed volume"),
        }
    }

    #[test]
    fn local_volume_catalog_defaults_missing_encryption_to_host_backed() {
        let _g = DataDirGuard::new();
        let path = LocalVolumeCatalog::path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"volumes":{"work":{"volume_name":"work","host_path":"/encrypted/work","encrypted":true,"created_at":"2026-05-05T00:00:00Z"}}}"#,
        )
        .unwrap();
        let loaded = LocalVolumeCatalog::load().unwrap();
        assert!(matches!(
            loaded.get("work").unwrap().encryption,
            LocalVolumeEncryption::HostBacked
        ));
    }

    #[test]
    fn unknown_field_in_persisted_json_is_rejected() {
        let _g = DataDirGuard::new();
        let path = VolumeMountRegistry::path_for("schema-test");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"mounts":{},"smuggled":1}"#).unwrap();
        let err = VolumeMountRegistry::load("schema-test").unwrap_err();
        assert!(
            err.to_string().contains("unknown field")
                || err
                    .source()
                    .map(|s| s.to_string().contains("unknown field"))
                    .unwrap_or(false),
            "expected unknown-field rejection, got: {err}"
        );
    }
}
