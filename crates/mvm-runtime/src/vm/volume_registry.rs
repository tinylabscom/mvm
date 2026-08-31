//! Per-VM volume mount registry.
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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::crypto::policy::validate_mount_path;
use mvm_core::domain::volume::{GuestPath, VolumeName, WrappedKey};
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
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
    /// Local artifact shape presented to the VM after unlock. Absent in a
    /// catalog written before the field existed, and defaulted rather than
    /// version-bumped — a new optional field is `#[serde(default)]`, not a
    /// schema migration.
    #[serde(default)]
    pub kind: LocalVolumeKind,
    #[serde(default)]
    pub encryption: LocalVolumeEncryption,
    pub created_at: String,
}

/// Materialized shape of a managed local volume.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LocalVolumeKind {
    /// Legacy host directory exposed only by backends with directory sharing.
    #[default]
    Directory,
    /// Portable ext4 image attached as a virtio block device.
    BlockImage { size_mib: u32 },
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
    Unlocking,
    Unlocked,
    Locking,
    Publishing,
    Restoring,
}

impl LocalVolumeCatalog {
    pub fn path() -> PathBuf {
        PathBuf::from(mvm_core::config::mvm_home())
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
        for (name, entry) in &parsed.volumes {
            if name != &entry.volume_name {
                bail!(
                    "local volume catalog key {:?} does not match entry identity {:?}",
                    name,
                    entry.volume_name
                );
            }
            validate_local_volume_entry(entry)?;
        }
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
        validate_local_volume_entry(&entry)?;
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

fn validate_local_volume_entry(entry: &LocalVolumeEntry) -> Result<()> {
    if !entry.encrypted {
        bail!("local volume {:?} must be encrypted", entry.volume_name);
    }
    if matches!(entry.kind, LocalVolumeKind::BlockImage { size_mib: 0 }) {
        bail!(
            "block volume {:?} must have non-zero capacity",
            entry.volume_name
        );
    }
    if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
        && enc.ciphertext_path.is_empty()
    {
        bail!(
            "mvm-managed local volume {:?} must record ciphertext_path",
            entry.volume_name
        );
    }
    Ok(())
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
    /// Artifact shape captured when the registration is created. Legacy
    /// persisted mounts decode as directories.
    #[serde(default)]
    pub kind: LocalVolumeKind,
    /// RFC 3339 timestamp of attach.
    pub attached_at: String,
    /// How the host path is anchored. Older registry entries did not carry
    /// this field; those decode as [`VolumeMountSource::Legacy`] and are
    /// resolved through the catalog when a matching managed volume exists.
    #[serde(default)]
    pub source: VolumeMountSource,
}

/// Persistent origin of a registered local volume path.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeMountSource {
    /// Compatibility value for registry entries written before source typing.
    #[default]
    Legacy,
    /// The path must continue to match an encrypted local-catalog entry.
    ManagedCatalog,
    /// The path is operator-supplied and host encryption must be rechecked by
    /// the CLI immediately before launch.
    AdHocHost,
}

/// Security-relevant source classification after launch-time resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedVolumeSource {
    /// MVM-managed encrypted archive, explicitly unlocked for this launch.
    MvmManaged,
    /// Catalog entry relying on encrypted host storage.
    HostBackedCatalog,
    /// Operator-supplied host directory relying on encrypted host storage.
    AdHocHost,
}

/// Validated, canonical attachment handed from the persisted registry to the
/// admitted VM launch path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVolumeAttachment {
    pub volume_name: VolumeName,
    pub host_path: PathBuf,
    pub guest_path: GuestPath,
    pub read_only: bool,
    pub kind: LocalVolumeKind,
    pub source: ResolvedVolumeSource,
}

impl ResolvedVolumeAttachment {
    /// Convert into the single backend-agnostic VM attachment carrier.
    pub fn as_vm_volume(&self) -> VmVolume {
        let (size, kind) = match &self.kind {
            LocalVolumeKind::Directory => (String::new(), VmVolumeKind::DirShare),
            LocalVolumeKind::BlockImage { size_mib } => {
                (format!("{size_mib}M"), VmVolumeKind::Disk)
            }
        };
        VmVolume {
            materialized_image: None,
            host: self.host_path.display().to_string(),
            guest: self.guest_path.as_str().to_string(),
            size,
            read_only: self.read_only,
            kind,
            // This bit means in-guest block encryption. Managed local volumes
            // are encrypted by the host lifecycle instead.
            encrypted: false,
        }
    }
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
        PathBuf::from(mvm_core::config::mvm_home())
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

    /// Resolve every persisted entry into a canonical launch attachment.
    ///
    /// Resolution revalidates identities, mount policy, catalog state, and the
    /// live filesystem immediately before the launch path constructs its
    /// signed share grants. Managed paths must still match their catalog entry,
    /// and MVM-managed archives must be explicitly unlocked.
    pub fn resolve_for_launch(
        &self,
        catalog: &LocalVolumeCatalog,
    ) -> Result<Vec<ResolvedVolumeAttachment>> {
        self.mounts
            .values()
            .map(|entry| resolve_mount_entry(entry, catalog))
            .collect()
    }
}

fn resolve_mount_entry(
    entry: &VolumeMountEntry,
    catalog: &LocalVolumeCatalog,
) -> Result<ResolvedVolumeAttachment> {
    let volume_name = VolumeName::new(entry.volume_name.clone())
        .with_context(|| format!("invalid registered volume name {:?}", entry.volume_name))?;
    let canonical_guest = validate_mount_path(&entry.guest_path)
        .with_context(|| format!("registered guest path {:?} rejected", entry.guest_path))?;
    let guest_path = GuestPath::new(canonical_guest)
        .with_context(|| format!("invalid registered guest path {:?}", entry.guest_path))?;

    let effective_source = match entry.source {
        VolumeMountSource::Legacy if catalog.get(volume_name.as_str()).is_some() => {
            VolumeMountSource::ManagedCatalog
        }
        VolumeMountSource::Legacy => VolumeMountSource::AdHocHost,
        source => source,
    };
    let (resolved_source, kind) = match effective_source {
        VolumeMountSource::ManagedCatalog => resolve_managed_source(entry, catalog, &volume_name)?,
        VolumeMountSource::AdHocHost => {
            (ResolvedVolumeSource::AdHocHost, LocalVolumeKind::Directory)
        }
        VolumeMountSource::Legacy => bail!("legacy volume source was not normalized"),
    };

    let registered_path = Path::new(&entry.host_path);
    if !registered_path.is_absolute() {
        bail!(
            "registered host path for volume {:?} must be absolute: {}",
            volume_name,
            registered_path.display()
        );
    }
    let host_path = std::fs::canonicalize(registered_path).with_context(|| {
        format!(
            "registered host path for volume {:?} does not exist: {}",
            volume_name,
            registered_path.display()
        )
    })?;
    match &kind {
        LocalVolumeKind::Directory if !host_path.is_dir() => bail!(
            "registered directory volume {:?} is not a directory: {}",
            volume_name,
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } if !host_path.is_file() => bail!(
            "registered block volume {:?} is not a file: {}",
            volume_name,
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } => {
            ext4_view::Ext4::load_from_path(&host_path).with_context(|| {
                format!(
                    "registered block volume {:?} is not a valid ext4 image: {}",
                    volume_name,
                    host_path.display()
                )
            })?;
        }
        LocalVolumeKind::Directory => {}
    }

    Ok(ResolvedVolumeAttachment {
        volume_name,
        host_path,
        guest_path,
        read_only: entry.read_only,
        kind,
        source: resolved_source,
    })
}

fn resolve_managed_source(
    entry: &VolumeMountEntry,
    catalog: &LocalVolumeCatalog,
    volume_name: &VolumeName,
) -> Result<(ResolvedVolumeSource, LocalVolumeKind)> {
    let managed = catalog.get(volume_name.as_str()).with_context(|| {
        format!(
            "managed volume {:?} is missing from the local catalog",
            volume_name
        )
    })?;
    if managed.volume_name != volume_name.as_str() {
        bail!(
            "managed volume catalog identity changed for {:?}: found {:?}",
            volume_name,
            managed.volume_name
        );
    }
    if !managed.encrypted {
        bail!("managed volume {:?} is not marked encrypted", volume_name);
    }
    if Path::new(&managed.host_path) != Path::new(&entry.host_path) {
        bail!(
            "managed volume {:?} host path changed after registration: {} -> {}",
            volume_name,
            entry.host_path,
            managed.host_path
        );
    }
    if managed.kind != entry.kind {
        bail!(
            "managed volume {:?} artifact kind changed after registration",
            volume_name
        );
    }
    match &managed.encryption {
        LocalVolumeEncryption::HostBacked => Ok((
            ResolvedVolumeSource::HostBackedCatalog,
            managed.kind.clone(),
        )),
        LocalVolumeEncryption::MvmManaged(encryption) => {
            if encryption.state != LocalVolumeState::Unlocked {
                bail!(
                    "managed volume {:?} is locked; unlock it before launching the VM",
                    volume_name
                );
            }
            Ok((ResolvedVolumeSource::MvmManaged, managed.kind.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        _env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let g = super::super::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.set("MVM_HOME", tmp.path());
            DataDirGuard {
                _guard: g,
                _env: env,
                _tmp: tmp,
            }
        }
    }

    fn make_entry(guest: &str, vol: &str) -> VolumeMountEntry {
        VolumeMountEntry {
            volume_name: vol.to_string(),
            host_path: format!("/host/{vol}"),
            guest_path: guest.to_string(),
            read_only: false,
            kind: LocalVolumeKind::Directory,
            attached_at: "2026-05-05T00:00:00Z".to_string(),
            source: VolumeMountSource::ManagedCatalog,
        }
    }

    fn make_local_entry(name: &str) -> LocalVolumeEntry {
        LocalVolumeEntry {
            volume_name: name.to_string(),
            host_path: format!("/encrypted/{name}"),
            encrypted: true,
            kind: LocalVolumeKind::Directory,
            encryption: LocalVolumeEncryption::HostBacked,
            created_at: "2026-05-05T00:00:00Z".to_string(),
        }
    }

    fn make_mvm_managed_entry(name: &str, state: LocalVolumeState) -> LocalVolumeEntry {
        LocalVolumeEntry {
            volume_name: name.to_string(),
            host_path: format!("/plain/{name}"),
            encrypted: true,
            kind: LocalVolumeKind::Directory,
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
    fn local_volume_catalog_rejects_zero_capacity_block_entry() {
        let mut catalog = LocalVolumeCatalog::default();
        let mut entry = make_local_entry("work");
        entry.kind = LocalVolumeKind::BlockImage { size_mib: 0 };
        let err = catalog.add(entry).unwrap_err();
        assert!(err.to_string().contains("non-zero capacity"));
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
        assert_eq!(loaded.get("work").unwrap().kind, LocalVolumeKind::Directory);
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

    #[test]
    fn legacy_mount_entry_defaults_to_legacy_source() {
        let entry: VolumeMountEntry = serde_json::from_str(
            r#"{"volume_name":"work","host_path":"/host/work","guest_path":"/data/work","read_only":true,"attached_at":"2026-05-05T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(entry.source, VolumeMountSource::Legacy);
    }

    #[test]
    fn managed_unlocked_mount_resolves_to_typed_vm_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("plain");
        std::fs::create_dir(&host).unwrap();
        let mut catalog = LocalVolumeCatalog::default();
        let mut local = make_mvm_managed_entry("work", LocalVolumeState::Unlocked);
        local.host_path = host.display().to_string();
        catalog.add(local).unwrap();
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([(
                "/data/work".to_string(),
                VolumeMountEntry {
                    volume_name: "work".to_string(),
                    host_path: host.display().to_string(),
                    guest_path: "/data/work".to_string(),
                    read_only: true,
                    kind: LocalVolumeKind::Directory,
                    attached_at: "2026-05-05T00:00:00Z".to_string(),
                    source: VolumeMountSource::ManagedCatalog,
                },
            )]),
        };

        let resolved = registry.resolve_for_launch(&catalog).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].volume_name.as_str(), "work");
        assert_eq!(resolved[0].guest_path.as_str(), "/data/work");
        assert_eq!(resolved[0].host_path, host.canonicalize().unwrap());
        assert_eq!(resolved[0].source, ResolvedVolumeSource::MvmManaged);
        let vm_volume = resolved[0].as_vm_volume();
        assert_eq!(
            vm_volume.host,
            host.canonicalize().unwrap().display().to_string()
        );
        assert_eq!(vm_volume.guest, "/data/work");
        assert!(vm_volume.read_only);
        assert!(matches!(
            vm_volume.kind,
            mvm_core::vm_backend::VmVolumeKind::DirShare
        ));
        assert!(!vm_volume.encrypted);
    }

    #[test]
    fn managed_block_mount_resolves_to_portable_disk_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("work.ext4");
        let mut image = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&host)
            .unwrap();
        image.set_len(16 * 1024 * 1024).unwrap();
        mvm_fs::ext4::mkfs::format_empty_ext4(&mut image, 16 * 1024 * 1024).unwrap();
        image.sync_all().unwrap();

        let mut catalog = LocalVolumeCatalog::default();
        let mut local = make_mvm_managed_entry("work", LocalVolumeState::Unlocked);
        local.host_path = host.display().to_string();
        local.kind = LocalVolumeKind::BlockImage { size_mib: 16 };
        catalog.add(local).unwrap();
        let mut entry = make_entry("/data/work", "work");
        entry.host_path = host.display().to_string();
        entry.kind = LocalVolumeKind::BlockImage { size_mib: 16 };
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/data/work".to_string(), entry)]),
        };

        let resolved = registry.resolve_for_launch(&catalog).unwrap();
        let vm_volume = resolved[0].as_vm_volume();
        assert_eq!(
            vm_volume.host,
            host.canonicalize().unwrap().display().to_string()
        );
        assert_eq!(vm_volume.guest, "/data/work");
        assert_eq!(vm_volume.size, "16M");
        assert!(matches!(vm_volume.kind, VmVolumeKind::Disk));
    }

    #[test]
    fn managed_locked_mount_is_refused_before_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("plain");
        std::fs::create_dir(&host).unwrap();
        let mut catalog = LocalVolumeCatalog::default();
        let mut local = make_mvm_managed_entry("work", LocalVolumeState::Locked);
        local.host_path = host.display().to_string();
        catalog.add(local).unwrap();
        let mut entry = make_entry("/data/work", "work");
        entry.host_path = host.display().to_string();
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/data/work".to_string(), entry)]),
        };

        let err = registry.resolve_for_launch(&catalog).unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[test]
    fn managed_mount_refuses_a_changed_catalog_path() {
        let tmp = tempfile::tempdir().unwrap();
        let registered = tmp.path().join("registered");
        let catalog_path = tmp.path().join("catalog");
        std::fs::create_dir(&registered).unwrap();
        std::fs::create_dir(&catalog_path).unwrap();
        let mut catalog = LocalVolumeCatalog::default();
        let mut local = make_mvm_managed_entry("work", LocalVolumeState::Unlocked);
        local.host_path = catalog_path.display().to_string();
        catalog.add(local).unwrap();
        let mut entry = make_entry("/data/work", "work");
        entry.host_path = registered.display().to_string();
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/data/work".to_string(), entry)]),
        };

        let err = registry.resolve_for_launch(&catalog).unwrap_err();
        assert!(err.to_string().contains("changed"));
    }

    #[test]
    fn ad_hoc_mount_resolves_without_catalog_but_remains_distinguishable() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("adhoc");
        std::fs::create_dir(&host).unwrap();
        let mut entry = make_entry("/work/input", "input");
        entry.host_path = host.display().to_string();
        entry.source = VolumeMountSource::AdHocHost;
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/work/input".to_string(), entry)]),
        };

        let resolved = registry
            .resolve_for_launch(&LocalVolumeCatalog::default())
            .unwrap();
        assert_eq!(resolved[0].source, ResolvedVolumeSource::AdHocHost);
    }

    #[test]
    fn mount_resolution_revalidates_guest_policy_and_host_existence() {
        let mut traversal = make_entry("/data/../etc", "work");
        traversal.source = VolumeMountSource::AdHocHost;
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/data/../etc".to_string(), traversal)]),
        };
        assert!(
            registry
                .resolve_for_launch(&LocalVolumeCatalog::default())
                .unwrap_err()
                .to_string()
                .contains("guest path")
        );

        let mut missing = make_entry("/data/work", "work");
        missing.source = VolumeMountSource::AdHocHost;
        let registry = VolumeMountRegistry {
            mounts: BTreeMap::from([("/data/work".to_string(), missing)]),
        };
        assert!(
            registry
                .resolve_for_launch(&LocalVolumeCatalog::default())
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
    }
}
