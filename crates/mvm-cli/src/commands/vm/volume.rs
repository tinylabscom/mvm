//! `mvmctl volume` — encrypted local block-volume lifecycle and VM attachment.
//!
//! This command owns two registries:
//! - managed local encrypted volumes in `~/.mvm/volumes/registry.json`
//! - per-VM mounts in `~/.mvm/instances/<vm>/volume_mounts.json`
//!
//! Registrations are resolved immediately before launch, included in the same
//! admitted volume set handed to the VMM and guest activation payload, and
//! rejected before boot when their encrypted state or local artifact changes.
//!
//! MVM-managed block volumes are authenticated ciphertext while locked and are
//! materialized only for their explicit lifecycle. Host-backed and ad-hoc
//! directory mounts remain accepted only when the exact host path is itself on
//! encrypted storage (macOS encrypted APFS/FileVault or Linux dm-crypt/LUKS).
//!
//! ## `--remote` mode (mvmd proxy)
//!
//! `--remote` routes operations through mvmd's REST API rather than
//! executing locally. v1 stub only — the actual `mvmctl::mvmd_client`
//! module ships in a follow-up once the mvmd-side bucket
//! reconciliation lands. Today `--remote` returns a clear "not yet
//! implemented" error.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::crypto::key_rotation;
use mvm_core::crypto::policy::validate_mount_path;
use mvm_core::crypto::rotation_policy;
use mvm_core::domain::volume::{MasterKeyState, OrgId, WrapAlgorithm, WrappedKey};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::volume_registry::{
    LocalVolumeCatalog, LocalVolumeEncryption, LocalVolumeEntry, LocalVolumeKind, LocalVolumeState,
    MvmManagedVolumeEncryption, ResolvedVolumeSource, VolumeMountEntry, VolumeMountRegistry,
    VolumeMountSource,
};
use rand::RngCore;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Cli;
use super::shared::clap_vm_name;

mod snapshot;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: VolumeCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum VolumeCmd {
    /// Create a managed encrypted local volume.
    Create {
        /// Logical volume name.
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        volume: String,
        /// Root directory under which encrypted volume state
        /// will be created. Defaults to ~/.mvm/volumes/local.
        #[arg(long)]
        root: Option<String>,
        /// Use the previous host-backed encryption gate instead of
        /// an mvm-managed encrypted archive.
        #[arg(long)]
        host_backed: bool,
        /// Capacity of a new portable ext4 block volume.
        #[arg(long, default_value = "1G")]
        size: String,
    },
    /// Decrypt a managed volume into its private local attachment artifact.
    Unlock { volume: String },
    /// Seal a managed volume and remove its plaintext attachment artifact.
    Lock { volume: String },
    /// List managed local volumes.
    Catalog {
        #[arg(long)]
        json: bool,
    },
    /// Create an immutable encrypted snapshot of a locked managed volume.
    Snapshot { volume: String, snapshot: String },
    /// Restore a locked managed volume from an immutable local snapshot.
    Restore { volume: String, snapshot: String },
    /// Mount a virtio-fs volume into a VM.
    ///
    /// Operations against provider-backed (S3 / Hetzner / R2 / GCS /
    /// Azure) volumes route through mvmd via `--remote`. v1 mvm-side
    /// `mount` handles only local volumes (host directory exposed via
    /// virtio-fs).
    Mount {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Logical volume name.
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        #[arg(long)]
        volume: String,
        /// Absolute host directory exposed via virtio-fs. Advanced
        /// path: omitted for managed volumes created with
        /// `mvmctl volume create`.
        #[arg(long)]
        host: Option<String>,
        /// Mount point inside the VM (must be under /mnt, /data,
        /// or /work; never under /etc, /usr, /lib, /proc, /nix,
        /// etc.)
        #[arg(long)]
        guest: String,
        /// Mount the volume read-write (default: read-only).
        #[arg(long)]
        rw: bool,
        /// Route through mvmd REST instead of writing the local
        /// registry. Stub in v1.
        #[arg(long)]
        remote: bool,
    },
    /// List registered volume mounts for a VM.
    Ls {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        #[arg(long)]
        json: bool,
        /// Route through mvmd REST instead of reading the local
        /// registry. Stub in v1.
        #[arg(long)]
        remote: bool,
    },
    /// Unmount a registered volume.
    Unmount {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Guest mount path to detach.
        guest_path: String,
        /// Route through mvmd REST instead of editing the local
        /// registry. Stub in v1.
        #[arg(long)]
        remote: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        VolumeCmd::Create {
            volume,
            root,
            host_backed,
            size,
        } => create(&volume, root.as_deref(), host_backed, &size),
        VolumeCmd::Unlock { volume } => unlock(&volume),
        VolumeCmd::Lock { volume } => lock(&volume),
        VolumeCmd::Catalog { json } => catalog(json),
        VolumeCmd::Snapshot { volume, snapshot } => snapshot::create(&volume, &snapshot),
        VolumeCmd::Restore { volume, snapshot } => snapshot::restore(&volume, &snapshot),
        VolumeCmd::Mount {
            name,
            volume,
            host,
            guest,
            rw,
            remote,
        } => {
            if remote {
                return remote_stub("volume mount");
            }
            mount(&name, &volume, host.as_deref(), &guest, rw)
        }
        VolumeCmd::Ls { name, json, remote } => {
            if remote {
                return remote_stub("volume ls");
            }
            ls(&name, json)
        }
        VolumeCmd::Unmount {
            name,
            guest_path,
            remote,
        } => {
            if remote {
                return remote_stub("volume unmount");
            }
            unmount(&name, &guest_path)
        }
    }
}

fn default_managed_volume_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("local")
}

fn default_mvm_volume_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("mvm-managed")
}

fn local_master_key_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("master-keys")
        .join("local")
}

fn acquire_volume_lifecycle_lock() -> Result<mvm_core::util::atomic_io::FileLock> {
    mvm_core::util::atomic_io::FileLock::try_acquire(&LocalVolumeCatalog::path())?
        .context("another local volume lifecycle operation is already in progress")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalVolumeLeaseCatalog {
    #[serde(default)]
    leases: BTreeMap<String, LocalVolumeLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalVolumeLease {
    vm_name: String,
    volume_name: String,
    read_only: bool,
    acquired_at: String,
}

impl LocalVolumeLeaseCatalog {
    fn path() -> PathBuf {
        PathBuf::from(mvm_core::config::mvm_home())
            .join("volumes")
            .join("attachments.json")
    }

    fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading volume leases {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing volume leases {}", path.display()))
    }

    fn save(&self) -> Result<()> {
        let path = Self::path();
        let bytes = serde_json::to_vec_pretty(self).context("serializing volume leases")?;
        mvm_core::util::atomic_io::atomic_write(&path, &bytes)
            .with_context(|| format!("saving volume leases {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        Ok(())
    }
}

fn local_volume_lease_key(host_path: &Path) -> Result<String> {
    let canonical = if host_path.exists() {
        fs::canonicalize(host_path)
            .with_context(|| format!("canonicalizing leased volume {}", host_path.display()))?
    } else {
        let parent = host_path
            .parent()
            .with_context(|| format!("leased volume has no parent: {}", host_path.display()))?;
        let file_name = host_path
            .file_name()
            .with_context(|| format!("leased volume has no file name: {}", host_path.display()))?;
        fs::canonicalize(parent)
            .with_context(|| format!("canonicalizing leased volume parent {}", parent.display()))?
            .join(file_name)
    };
    let mut hash = Sha256::new();
    hash.update(canonical.as_os_str().as_encoded_bytes());
    Ok(hex::encode(hash.finalize()))
}

#[derive(Debug)]
struct LocalVolumeLeaseGuard {
    vm_name: String,
    keys: Vec<String>,
    committed: bool,
}

impl LocalVolumeLeaseGuard {
    fn acquire(vm_name: &str, volumes: &[mvm_runtime::image::RuntimeVolume]) -> Result<Self> {
        let mut catalog = LocalVolumeLeaseCatalog::load()?;
        let mut requested = Vec::new();
        for volume in volumes
            .iter()
            .filter(|volume| matches!(volume.kind, mvm_core::vm_backend::VmVolumeKind::Disk))
        {
            let key = local_volume_lease_key(Path::new(&volume.host))?;
            if let Some(existing) = catalog.leases.get(&key) {
                bail!(
                    "block volume for guest path {:?} is already attached to VM {:?}; detach or \
                     stop that VM before attaching another writer or reader",
                    volume.guest,
                    existing.vm_name
                );
            }
            if requested.iter().any(|existing: &String| existing == &key) {
                bail!(
                    "block volume host artifact {:?} is attached more than once in this launch",
                    volume.host
                );
            }
            catalog.leases.insert(
                key.clone(),
                LocalVolumeLease {
                    vm_name: vm_name.to_string(),
                    volume_name: volume.guest.clone(),
                    read_only: volume.read_only,
                    acquired_at: mvm_core::util::time::utc_now(),
                },
            );
            requested.push(key);
        }
        if !requested.is_empty() {
            catalog.save()?;
        }
        Ok(Self {
            vm_name: vm_name.to_string(),
            keys: requested,
            committed: false,
        })
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    fn release(&self) -> Result<()> {
        if self.keys.is_empty() {
            return Ok(());
        }
        let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
        let mut catalog = LocalVolumeLeaseCatalog::load()?;
        for key in &self.keys {
            if catalog
                .leases
                .get(key)
                .is_some_and(|lease| lease.vm_name == self.vm_name)
            {
                catalog.leases.remove(key);
            }
        }
        catalog.save()
    }
}

impl Drop for LocalVolumeLeaseGuard {
    fn drop(&mut self) {
        if !self.committed
            && let Err(error) = self.release()
        {
            tracing::error!(
                vm = %self.vm_name,
                error = %error,
                "failed to roll back local volume attachment leases"
            );
        }
    }
}

pub(in crate::commands) fn release_volume_leases_for_vm(vm_name: &str) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    let mut catalog = LocalVolumeLeaseCatalog::load()?;
    let before = catalog.leases.len();
    catalog.leases.retain(|_, lease| lease.vm_name != vm_name);
    if catalog.leases.len() != before {
        catalog.save()?;
    }
    Ok(())
}

fn ensure_volume_not_attached(entry: &LocalVolumeEntry, operation: &str) -> Result<()> {
    let key = local_volume_lease_key(Path::new(&entry.host_path))?;
    if let Some(lease) = LocalVolumeLeaseCatalog::load()?.leases.get(&key) {
        bail!(
            "cannot {operation} volume {:?}: it is attached to VM {:?}",
            entry.volume_name,
            lease.vm_name
        );
    }
    Ok(())
}

fn unlock_staging_path(host_path: &Path) -> PathBuf {
    host_path.with_extension("unlocking")
}

fn lock_staging_path(ciphertext_path: &Path) -> PathBuf {
    ciphertext_path.with_extension("locking")
}

fn validate_materialized_volume(entry: &LocalVolumeEntry) -> Result<()> {
    let host_path = Path::new(&entry.host_path);
    match &entry.kind {
        LocalVolumeKind::Directory if host_path.is_dir() => Ok(()),
        LocalVolumeKind::Directory => bail!(
            "materialized directory volume {:?} is missing: {}",
            entry.volume_name,
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } if !host_path.is_file() => bail!(
            "materialized block volume {:?} is missing: {}",
            entry.volume_name,
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } => ext4_view::Ext4::load_from_path(host_path)
            .map(|_| ())
            .with_context(|| {
                format!(
                    "materialized block volume {:?} is not ext4: {}",
                    entry.volume_name,
                    host_path.display()
                )
            }),
    }
}

fn remove_materialized_volume(entry: &LocalVolumeEntry) -> Result<()> {
    let host_path = Path::new(&entry.host_path);
    if !host_path.exists() {
        return Ok(());
    }
    match &entry.kind {
        LocalVolumeKind::Directory => fs::remove_dir_all(host_path)
            .with_context(|| format!("removing directory volume {}", host_path.display())),
        LocalVolumeKind::BlockImage { .. } => fs::remove_file(host_path)
            .with_context(|| format!("removing block volume {}", host_path.display())),
    }
}

fn set_local_volume_state(
    catalog: &mut LocalVolumeCatalog,
    volume_name: &str,
    state: LocalVolumeState,
) -> Result<()> {
    let entry = catalog
        .get_mut(volume_name)
        .with_context(|| format!("local volume {volume_name:?} disappeared during recovery"))?;
    let LocalVolumeEncryption::MvmManaged(encryption) = &mut entry.encryption else {
        bail!("local volume {volume_name:?} changed encryption mode during recovery");
    };
    encryption.state = state;
    Ok(())
}

fn recover_local_volume_catalog() -> Result<LocalVolumeCatalog> {
    let mut catalog = LocalVolumeCatalog::load()?;
    let names = catalog.volumes.keys().cloned().collect::<Vec<_>>();
    let mut changed = false;

    for name in names {
        let entry = catalog
            .get(&name)
            .with_context(|| format!("local volume {name:?} disappeared during recovery"))?
            .clone();
        let LocalVolumeEncryption::MvmManaged(encryption) = &entry.encryption else {
            continue;
        };
        match encryption.state {
            LocalVolumeState::Locked | LocalVolumeState::Unlocked => {}
            LocalVolumeState::Unlocking => {
                let staging = unlock_staging_path(Path::new(&entry.host_path));
                let archive_staging =
                    Path::new(&entry.host_path).with_extension("unlocking-archive");
                if validate_materialized_volume(&entry).is_ok() {
                    set_local_volume_state(&mut catalog, &name, LocalVolumeState::Unlocked)?;
                } else {
                    remove_materialized_volume(&entry)?;
                    if staging.is_dir() {
                        fs::remove_dir_all(&staging).with_context(|| {
                            format!("removing interrupted unlock dir {}", staging.display())
                        })?;
                    } else if staging.exists() {
                        fs::remove_file(&staging).with_context(|| {
                            format!("removing interrupted unlock file {}", staging.display())
                        })?;
                    }
                    if archive_staging.exists() {
                        fs::remove_file(&archive_staging).with_context(|| {
                            format!(
                                "removing interrupted unlock archive {}",
                                archive_staging.display()
                            )
                        })?;
                    }
                    set_local_volume_state(&mut catalog, &name, LocalVolumeState::Locked)?;
                }
                changed = true;
            }
            LocalVolumeState::Locking => {
                let staging = lock_staging_path(Path::new(&encryption.ciphertext_path));
                if staging.exists() {
                    fs::remove_file(&staging).with_context(|| {
                        format!("removing interrupted seal {}", staging.display())
                    })?;
                }
                validate_materialized_volume(&entry)
                    .with_context(|| format!("recovering interrupted seal for volume {name:?}"))?;
                set_local_volume_state(&mut catalog, &name, LocalVolumeState::Unlocked)?;
                changed = true;
            }
            LocalVolumeState::Publishing => {
                let ciphertext = PathBuf::from(&encryption.ciphertext_path);
                let staging = lock_staging_path(&ciphertext);
                if staging.exists() {
                    fs::rename(&staging, &ciphertext).with_context(|| {
                        format!(
                            "publishing recovered sealed volume {} -> {}",
                            staging.display(),
                            ciphertext.display()
                        )
                    })?;
                }
                let actual = ciphertext_content_hash(&ciphertext)?;
                if !encryption.wrapped_key.binding_matches_content(&actual) {
                    bail!(
                        "recovering volume {name:?} refused: published ciphertext binding mismatch"
                    );
                }
                set_local_volume_state(&mut catalog, &name, LocalVolumeState::Locked)?;
                remove_materialized_volume(&entry)?;
                changed = true;
            }
            LocalVolumeState::Restoring => {
                let ciphertext = PathBuf::from(&encryption.ciphertext_path);
                let staging = ciphertext.with_extension("restoring");
                if staging.exists() {
                    fs::rename(&staging, &ciphertext).with_context(|| {
                        format!(
                            "publishing recovered restored volume {} -> {}",
                            staging.display(),
                            ciphertext.display()
                        )
                    })?;
                }
                let actual = ciphertext_content_hash(&ciphertext)?;
                if !encryption.wrapped_key.binding_matches_content(&actual) {
                    bail!(
                        "recovering volume {name:?} refused: restored ciphertext binding mismatch"
                    );
                }
                set_local_volume_state(&mut catalog, &name, LocalVolumeState::Locked)?;
                changed = true;
            }
        }
    }
    if changed {
        catalog.save()?;
    }
    Ok(catalog)
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))?;
    Ok(())
}

fn remote_stub(op: &str) -> Result<()> {
    bail!("{op} --remote not yet implemented. Use the local volume registry for now.")
}

fn validate_volume_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        bail!(
            "volume name length {} outside [1, 32] (used as virtio-fs tag)",
            name.len()
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("volume name {name:?} must be lowercase alphanumeric + hyphens");
    }
    if name.starts_with('-') {
        bail!("volume name {name:?} must not start with a hyphen");
    }
    Ok(())
}

fn create(volume_name: &str, root: Option<&str>, host_backed: bool, size: &str) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    recover_local_volume_catalog()?;
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    if host_backed {
        return create_host_backed(volume_name, root);
    }
    create_mvm_managed(volume_name, root, size)
}

fn create_host_backed(volume_name: &str, root: Option<&str>) -> Result<()> {
    let root = match root {
        Some(root) => std::path::PathBuf::from(root),
        None => default_managed_volume_root(),
    };
    if !root.is_absolute() {
        bail!(
            "managed volume root must be absolute, got {}",
            root.display()
        );
    }
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating managed volume root {}", root.display()))?;
    crate::doctor::require_local_volume_host_path_encrypted(&root)?;

    let host_path = root.join(volume_name);
    if host_path.exists() && !host_path.is_dir() {
        bail!(
            "managed volume path {} exists but is not a directory",
            host_path.display()
        );
    }
    std::fs::create_dir_all(&host_path)
        .with_context(|| format!("creating managed volume {}", host_path.display()))?;
    crate::doctor::require_local_volume_host_path_encrypted(&host_path)?;

    let mut catalog = LocalVolumeCatalog::load()?;
    catalog.add(LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        kind: LocalVolumeKind::Directory,
        encryption: LocalVolumeEncryption::HostBacked,
        created_at: mvm_core::util::time::utc_now(),
    })?;
    catalog.save()?;
    println!(
        "created encrypted local volume {volume_name:?} at {}",
        host_path.display()
    );
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} host={} encrypted=true",
        host_path.display()
    );
    Ok(())
}

fn create_mvm_managed(volume_name: &str, root: Option<&str>, size: &str) -> Result<()> {
    let root = match root {
        Some(root) => PathBuf::from(root),
        None => default_mvm_volume_root(),
    };
    if !root.is_absolute() {
        bail!(
            "managed volume root must be absolute, got {}",
            root.display()
        );
    }
    ensure_private_dir(&root)?;
    let ciphertext_dir = root.join("encrypted");
    let plaintext_dir = root.join("unlocked");
    ensure_private_dir(&ciphertext_dir)?;
    ensure_private_dir(&plaintext_dir)?;

    let ciphertext_path = ciphertext_dir.join(format!("{volume_name}.mvve"));
    let host_path = plaintext_dir.join(format!("{volume_name}.ext4"));
    if ciphertext_path.exists() || host_path.exists() {
        bail!(
            "managed volume {volume_name:?} already has on-disk state under {}",
            root.display()
        );
    }

    let size_mib = mvm_core::util::parse_human_size(size)
        .with_context(|| format!("invalid volume size {size:?}"))?;
    if size_mib == 0 {
        bail!("volume size must be greater than zero");
    }
    let size_bytes = u64::from(size_mib)
        .checked_mul(1024 * 1024)
        .context("volume size overflow")?;

    let (mut wrapped_key, dek) = generate_wrapped_volume_key()?;
    let mut scratch = tempfile::NamedTempFile::new_in(&root)
        .context("creating empty block-volume scratch file")?;
    scratch
        .as_file_mut()
        .set_len(size_bytes)
        .context("sizing empty block-volume image")?;
    mvm_fs::ext4::mkfs::format_empty_ext4(scratch.as_file_mut(), size_bytes)
        .context("formatting empty block-volume image as ext4")?;
    scratch
        .as_file()
        .sync_all()
        .context("syncing empty block-volume image")?;
    write_encrypted_volume_file(scratch.path(), &ciphertext_path, dek.expose_secret())?;
    // Bind the DEK to the ciphertext archive it now protects.
    wrapped_key.rebind_content(ciphertext_content_hash(&ciphertext_path)?);

    let mut catalog = LocalVolumeCatalog::load()?;
    catalog.add(LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        kind: LocalVolumeKind::BlockImage { size_mib },
        encryption: LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
            state: LocalVolumeState::Locked,
            ciphertext_path: ciphertext_path.to_string_lossy().into_owned(),
            wrapped_key,
        }),
        created_at: mvm_core::util::time::utc_now(),
    })?;
    catalog.save()?;
    println!(
        "created locked mvm-managed encrypted volume {volume_name:?} at {}",
        ciphertext_path.display()
    );
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} ciphertext={} state=locked",
        ciphertext_path.display()
    );
    Ok(())
}

/// Opportunistically roll the local master KEK when it is past its
/// 90-day lifetime, re-wrapping the catalog's mvm-managed volume
/// keys onto the new KEK. Invoked whenever a managed volume key is minted —
/// the closest thing to a periodic "on use" trigger the local CLI has.
///
/// Cheap and non-destructive: re-wrapping leaves the underlying DEK (and
/// the on-disk ciphertext) untouched, so an existing volume keeps
/// decrypting. Best-effort scope — only keys already at the current active
/// version are swept (a single re-wrap can't span mixed versions); a volume
/// wrapped under an older legacy KEK keeps unlocking via its recorded
/// version and the retained legacy key file. The age check itself lives in
/// `rotation_policy` and is fully unit-tested there.
fn maybe_rotate_local_master_key() -> Result<()> {
    let active_dir = local_master_key_dir();
    let manifest = key_rotation::load_manifest(&active_dir)?;
    let Some(active_version) = manifest
        .entries
        .iter()
        .find(|e| e.state == MasterKeyState::Active)
        .map(|e| e.version)
    else {
        return Ok(()); // nothing minted yet — the first key isn't a rotation
    };

    let mut catalog = LocalVolumeCatalog::load()?;
    let mut names: Vec<String> = Vec::new();
    let mut sweep: Vec<WrappedKey> = Vec::new();
    for (name, entry) in catalog.volumes.iter() {
        if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
            && enc.wrapped_key.master_key_version == active_version
        {
            names.push(name.clone());
            sweep.push(enc.wrapped_key.clone());
        }
    }

    let org = OrgId::new("local").context("constructing local org id")?;
    let decision = rotation_policy::rotate_if_due(
        &active_dir,
        &org,
        &mut sweep,
        rotation_policy::default_interval(),
        chrono::Utc::now(),
    )?;

    if let rotation_policy::RotationDecision::Rotated {
        from_version,
        to_version,
        migrated,
    } = decision
    {
        for (name, rewrapped) in names.into_iter().zip(sweep) {
            if let Some(LocalVolumeEntry {
                encryption: LocalVolumeEncryption::MvmManaged(enc),
                ..
            }) = catalog.volumes.get_mut(&name)
            {
                enc.wrapped_key = rewrapped;
            }
        }
        catalog.save()?;
        eprintln!(
            "rotated local master KEK v{from_version} → v{to_version}; \
             re-wrapped {migrated} volume key(s)"
        );
    }
    Ok(())
}

fn generate_wrapped_volume_key() -> Result<(WrappedKey, secrecy::SecretBox<Vec<u8>>)> {
    // Roll the KEK first if it's past its lifetime, then mint under the
    // (possibly fresh) active version.
    maybe_rotate_local_master_key()?;
    let active_dir = local_master_key_dir();
    let manifest = key_rotation::load_manifest(&active_dir)?;
    let version = if manifest.latest_version() == 0 {
        let org_id = OrgId::new("local").context("constructing local org id")?;
        key_rotation::rotate_master_key(&active_dir, &org_id)?.version
    } else {
        manifest.latest_version()
    };
    let master = key_rotation::load_master_key(&active_dir, version)?;
    let mut dek = vec![0u8; mvm_core::crypto::snapshot_encryption::KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut dek);
    let wrapped = mvm_core::crypto::snapshot_crypto::encrypt(&dek, master.expose_secret())
        .context("wrapping volume data key")?;
    Ok((
        WrappedKey {
            master_key_version: version,
            wrapped,
            algorithm: WrapAlgorithm::Aes256Gcm,
            // Bound to the ciphertext archive once it exists (the caller sets
            // this via `rebind_content` after writing the archive).
            bound: None,
        },
        secrecy::SecretBox::new(Box::new(dek)),
    ))
}

/// sha256-hex of a ciphertext archive — the per-volume content-hash a DEK
/// binds to.
fn ciphertext_content_hash(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing ciphertext archive {}", path.display()))
}

fn unwrap_volume_key(entry: &LocalVolumeEntry) -> Result<secrecy::SecretBox<Vec<u8>>> {
    let enc = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => enc,
        LocalVolumeEncryption::HostBacked => {
            bail!(
                "volume {:?} is host-backed, not mvm-managed",
                entry.volume_name
            )
        }
    };
    // Admit gate: refuse a DEK presented against a different ciphertext
    // than it was bound to (a swapped archive). Unbound keys pass. Runs
    // before the master is even loaded.
    let actual = ciphertext_content_hash(Path::new(&enc.ciphertext_path))?;
    if !enc.wrapped_key.binding_matches_content(&actual) {
        bail!(
            "volume {:?} DEK binding mismatch: ciphertext content_hash does not \
             match the artifact this key was bound to; refusing to unwrap",
            entry.volume_name
        );
    }
    let master =
        key_rotation::load_master_key(&local_master_key_dir(), enc.wrapped_key.master_key_version)
            .with_context(|| format!("loading master key for volume {:?}", entry.volume_name))?;
    let dek = match enc.wrapped_key.algorithm {
        WrapAlgorithm::Aes256Gcm => mvm_core::crypto::snapshot_crypto::decrypt(
            &enc.wrapped_key.wrapped,
            master.expose_secret(),
        )
        .with_context(|| format!("unwrapping data key for volume {:?}", entry.volume_name))?,
        WrapAlgorithm::AesKwp => {
            bail!("AES-KWP wrapped local volume keys are not supported by mvmctl")
        }
    };
    if dek.len() != mvm_core::crypto::snapshot_encryption::KEY_SIZE {
        bail!(
            "unwrapped data key for volume {:?} is {} bytes, expected {}",
            entry.volume_name,
            dek.len(),
            mvm_core::crypto::snapshot_encryption::KEY_SIZE
        );
    }
    Ok(secrecy::SecretBox::new(Box::new(dek)))
}

fn write_plain_archive(src_dir: &Path, archive_path: &Path) -> Result<()> {
    let archive = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(archive_path)
        .with_context(|| format!("creating archive {}", archive_path.display()))?;
    let mut builder = tar::Builder::new(archive);
    builder
        .append_dir_all(".", src_dir)
        .with_context(|| format!("archiving {}", src_dir.display()))?;
    builder.finish().context("finishing volume archive")?;
    Ok(())
}

fn write_encrypted_volume_archive(
    src_dir: &Path,
    ciphertext_path: &Path,
    dek: &[u8],
) -> Result<()> {
    if let Some(parent) = ciphertext_path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = ciphertext_path.with_extension(format!("{}.plain.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        write_plain_archive(src_dir, &tmp)?;
        mvm_core::crypto::snapshot_encryption::encrypt_file_in_place(&tmp, dek)
            .context("encrypting volume archive")?;
        fs::rename(&tmp, ciphertext_path).with_context(|| {
            format!(
                "renaming encrypted archive {} -> {}",
                tmp.display(),
                ciphertext_path.display()
            )
        })?;
        fs::set_permissions(ciphertext_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", ciphertext_path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_encrypted_volume_file(src_file: &Path, ciphertext_path: &Path, dek: &[u8]) -> Result<()> {
    if let Some(parent) = ciphertext_path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = ciphertext_path.with_extension(format!("{}.plain.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        fs::copy(src_file, &tmp).with_context(|| {
            format!(
                "copying block volume {} -> {}",
                src_file.display(),
                tmp.display()
            )
        })?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        mvm_core::crypto::snapshot_encryption::encrypt_file_in_place(&tmp, dek)
            .context("encrypting block volume")?;
        fs::rename(&tmp, ciphertext_path).with_context(|| {
            format!(
                "renaming encrypted block volume {} -> {}",
                tmp.display(),
                ciphertext_path.display()
            )
        })?;
        fs::set_permissions(ciphertext_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", ciphertext_path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn decrypt_volume_archive_to_dir(
    ciphertext_path: &Path,
    dest_dir: &Path,
    dek: &[u8],
) -> Result<()> {
    if dest_dir.exists() {
        bail!(
            "plaintext volume directory {} already exists",
            dest_dir.display()
        );
    }
    let staging = unlock_staging_path(dest_dir);
    let tmp = dest_dir.with_extension("unlocking-archive");
    let result = (|| -> Result<()> {
        fs::create_dir(&staging)
            .with_context(|| format!("creating unlock staging dir {}", staging.display()))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", staging.display()))?;
        fs::copy(ciphertext_path, &tmp).with_context(|| {
            format!(
                "copy encrypted archive {} -> {}",
                ciphertext_path.display(),
                tmp.display()
            )
        })?;
        mvm_core::crypto::snapshot_encryption::decrypt_file_in_place(&tmp, dek)
            .context("decrypting volume archive")?;
        let file = File::open(&tmp).with_context(|| format!("opening {}", tmp.display()))?;
        let mut archive = tar::Archive::new(file);
        archive
            .unpack(&staging)
            .with_context(|| format!("unpacking volume into {}", staging.display()))?;
        fs::rename(&staging, dest_dir).with_context(|| {
            format!(
                "publishing unlocked directory {} -> {}",
                staging.display(),
                dest_dir.display()
            )
        })?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn decrypt_volume_file(ciphertext_path: &Path, dest_file: &Path, dek: &[u8]) -> Result<()> {
    if dest_file.exists() {
        bail!(
            "plaintext block volume {} already exists",
            dest_file.display()
        );
    }
    let parent = dest_file
        .parent()
        .with_context(|| format!("block volume path has no parent: {}", dest_file.display()))?;
    ensure_private_dir(parent)?;
    let tmp = unlock_staging_path(dest_file);
    let result = (|| -> Result<()> {
        fs::copy(ciphertext_path, &tmp).with_context(|| {
            format!(
                "copying encrypted block volume {} -> {}",
                ciphertext_path.display(),
                tmp.display()
            )
        })?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        mvm_core::crypto::snapshot_encryption::decrypt_file_in_place(&tmp, dek)
            .context("decrypting block volume")?;
        ext4_view::Ext4::load_from_path(&tmp)
            .with_context(|| format!("decrypted block volume {} is not ext4", tmp.display()))?;
        File::open(&tmp)
            .with_context(|| format!("opening {} for sync", tmp.display()))?
            .sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        fs::rename(&tmp, dest_file).with_context(|| {
            format!(
                "publishing decrypted block volume {} -> {}",
                tmp.display(),
                dest_file.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn unlock(volume_name: &str) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let mut catalog = recover_local_volume_catalog()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    let dek = unwrap_volume_key(&entry)?;
    let ciphertext_path = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => {
            if enc.state == LocalVolumeState::Unlocked {
                bail!("volume {volume_name:?} is already unlocked");
            }
            PathBuf::from(&enc.ciphertext_path)
        }
        LocalVolumeEncryption::HostBacked => {
            bail!("volume {volume_name:?} is host-backed and does not need unlock")
        }
    };
    set_local_volume_state(&mut catalog, volume_name, LocalVolumeState::Unlocking)?;
    catalog.save()?;
    match &entry.kind {
        LocalVolumeKind::Directory => decrypt_volume_archive_to_dir(
            &ciphertext_path,
            Path::new(&entry.host_path),
            dek.expose_secret(),
        )?,
        LocalVolumeKind::BlockImage { .. } => decrypt_volume_file(
            &ciphertext_path,
            Path::new(&entry.host_path),
            dek.expose_secret(),
        )?,
    }
    set_local_volume_state(&mut catalog, volume_name, LocalVolumeState::Unlocked)?;
    let host_path = catalog
        .get(volume_name)
        .with_context(|| format!("volume {volume_name:?} disappeared after unlock"))?
        .host_path
        .clone();
    catalog.save()?;
    println!(
        "unlocked volume {volume_name:?} at {}",
        Path::new(&host_path).display()
    );
    mvm_core::audit_emit!(VolumeOpen, "volume={volume_name} state=unlocked");
    Ok(())
}

fn lock(volume_name: &str) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let mut catalog = recover_local_volume_catalog()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    ensure_volume_not_attached(&entry, "lock")?;
    let dek = unwrap_volume_key(&entry)?;
    let ciphertext_path = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => {
            if enc.state == LocalVolumeState::Locked {
                bail!("volume {volume_name:?} is already locked");
            }
            PathBuf::from(&enc.ciphertext_path)
        }
        LocalVolumeEncryption::HostBacked => {
            bail!("volume {volume_name:?} is host-backed and cannot be sealed by mvmctl")
        }
    };
    let host_path = PathBuf::from(&entry.host_path);
    match &entry.kind {
        LocalVolumeKind::Directory if !host_path.is_dir() => bail!(
            "plaintext volume directory {} is missing; cannot lock",
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } if !host_path.is_file() => bail!(
            "plaintext block volume {} is missing; cannot lock",
            host_path.display()
        ),
        LocalVolumeKind::BlockImage { .. } => {
            ext4_view::Ext4::load_from_path(&host_path).with_context(|| {
                format!(
                    "plaintext block volume {} is not a valid ext4 image",
                    host_path.display()
                )
            })?;
        }
        LocalVolumeKind::Directory => {}
    }
    set_local_volume_state(&mut catalog, volume_name, LocalVolumeState::Locking)?;
    catalog.save()?;
    let tmp_ciphertext = lock_staging_path(&ciphertext_path);
    match &entry.kind {
        LocalVolumeKind::Directory => {
            write_encrypted_volume_archive(&host_path, &tmp_ciphertext, dek.expose_secret())?
        }
        LocalVolumeKind::BlockImage { .. } => {
            write_encrypted_volume_file(&host_path, &tmp_ciphertext, dek.expose_secret())?
        }
    }
    let new_hash = ciphertext_content_hash(&tmp_ciphertext)?;
    let catalog_entry = catalog
        .get_mut(volume_name)
        .with_context(|| format!("volume {volume_name:?} disappeared while sealing"))?;
    let LocalVolumeEncryption::MvmManaged(encryption) = &mut catalog_entry.encryption else {
        bail!("volume {volume_name:?} changed encryption mode while sealing");
    };
    encryption.wrapped_key.rebind_content(new_hash);
    encryption.state = LocalVolumeState::Publishing;
    catalog.save()?;
    fs::rename(&tmp_ciphertext, &ciphertext_path).with_context(|| {
        format!(
            "replacing encrypted archive {} -> {}",
            tmp_ciphertext.display(),
            ciphertext_path.display()
        )
    })?;
    set_local_volume_state(&mut catalog, volume_name, LocalVolumeState::Locked)?;
    catalog.save()?;
    remove_materialized_volume(&entry)?;
    println!("locked volume {volume_name:?}");
    mvm_core::audit_emit!(VolumeLock, "volume={volume_name} state=locked");
    Ok(())
}

fn catalog(json: bool) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    let catalog = recover_local_volume_catalog()?;
    if json {
        let rows: Vec<&LocalVolumeEntry> = catalog.iter().map(|(_, v)| v).collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if catalog.is_empty() {
        println!("(no managed local volumes)");
        return Ok(());
    }
    println!(
        "{:<22} {:<10} {:<12} {:<12} HOST",
        "VOLUME", "ENCRYPTED", "STATE", "KIND"
    );
    for (_, e) in catalog.iter() {
        let state = match &e.encryption {
            LocalVolumeEncryption::HostBacked => "host-backed",
            LocalVolumeEncryption::MvmManaged(enc) => match enc.state {
                LocalVolumeState::Locked => "locked",
                LocalVolumeState::Unlocking => "unlocking",
                LocalVolumeState::Unlocked => "unlocked",
                LocalVolumeState::Locking => "locking",
                LocalVolumeState::Publishing => "publishing",
                LocalVolumeState::Restoring => "restoring",
            },
        };
        let kind = match &e.kind {
            LocalVolumeKind::Directory => "directory".to_string(),
            LocalVolumeKind::BlockImage { size_mib } => format!("block-{size_mib}M"),
        };
        println!(
            "{:<22} {:<10} {:<12} {:<12} {}",
            e.volume_name, e.encrypted, state, kind, e.host_path
        );
    }
    Ok(())
}

fn resolve_mount_host(volume_name: &str, host: Option<&str>) -> Result<(String, LocalVolumeKind)> {
    if let Some(host) = host {
        return Ok((host.to_string(), LocalVolumeKind::Directory));
    }
    let catalog = LocalVolumeCatalog::load()?;
    let entry = catalog.get(volume_name).with_context(|| {
        format!(
            "no managed local volume named {volume_name:?}; run `mvmctl volume create \
             {volume_name}` or pass --host <encrypted-dir>"
        )
    })?;
    if !entry.encrypted {
        bail!("managed local volume {volume_name:?} is not marked encrypted");
    }
    if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
        && enc.state != LocalVolumeState::Unlocked
    {
        bail!(
            "managed local volume {volume_name:?} is locked; run `mvmctl volume unlock \
             {volume_name}` before mounting"
        );
    }
    Ok((entry.host_path.clone(), entry.kind.clone()))
}

fn mount(
    vm_name: &str,
    volume_name: &str,
    host: Option<&str>,
    guest: &str,
    rw: bool,
) -> Result<()> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    recover_local_volume_catalog()?;
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let ad_hoc_host = host.is_some();
    let (host, kind) = resolve_mount_host(volume_name, host)?;

    // Host path must be absolute and exist on disk; otherwise
    // virtiofsd would fail later with a confusing message.
    if !std::path::Path::new(&host).is_absolute() {
        bail!("--host path must be absolute, got {:?}", host);
    }
    match &kind {
        LocalVolumeKind::Directory if !std::path::Path::new(&host).is_dir() => {
            bail!("--host path {:?} is not an existing directory", host)
        }
        LocalVolumeKind::BlockImage { .. } if !std::path::Path::new(&host).is_file() => {
            bail!("managed block volume {:?} is not an existing file", host)
        }
        LocalVolumeKind::BlockImage { .. } => {
            ext4_view::Ext4::load_from_path(&host)
                .with_context(|| format!("managed block volume {host:?} is not ext4"))?;
        }
        LocalVolumeKind::Directory => {}
    }
    if ad_hoc_host {
        crate::doctor::require_local_volume_host_path_encrypted(std::path::Path::new(&host))?;
    }

    // Validate the guest-side path against the mount policy
    // before we touch the registry — same check the agent runs.
    let canonical_guest = validate_mount_path(guest)
        .with_context(|| format!("guest path {:?} rejected by policy", guest))?;

    let mut registry = VolumeMountRegistry::load(vm_name)?;
    registry.add(VolumeMountEntry {
        volume_name: volume_name.to_string(),
        host_path: host.clone(),
        guest_path: canonical_guest.clone(),
        read_only: !rw,
        kind,
        attached_at: mvm_core::util::time::utc_now(),
        source: if ad_hoc_host {
            VolumeMountSource::AdHocHost
        } else {
            VolumeMountSource::ManagedCatalog
        },
    })?;
    registry.save(vm_name)?;

    println!(
        "{vm_name}: registered volume {volume_name:?} → {canonical_guest} (host={host}, ro={})",
        !rw
    );
    mvm_core::audit_emit!(VmVolumeAdd, vm: vm_name, "volume={volume_name} host={host} guest={canonical_guest} ro={}" ,
        !rw
    );
    Ok(())
}

/// Merge persisted local registrations into the volume list used to construct
/// both signed admission grants and the backend launch configuration.
#[derive(Debug)]
pub(super) struct PreparedLaunchVolumes {
    pub(super) volumes: Vec<mvm_runtime::image::RuntimeVolume>,
    lease_guard: LocalVolumeLeaseGuard,
}

impl PreparedLaunchVolumes {
    pub(super) fn commit(&mut self) {
        self.lease_guard.commit();
    }
}

pub(super) fn merge_registered_volumes_for_launch(
    vm_name: &str,
    explicit: &[mvm_runtime::image::RuntimeVolume],
) -> Result<PreparedLaunchVolumes> {
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {vm_name:?}"))?;
    let registry = VolumeMountRegistry::load(vm_name)?;
    if registry.is_empty() {
        let volumes = explicit.to_vec();
        let lease_guard = LocalVolumeLeaseGuard::acquire(vm_name, &volumes)?;
        return Ok(PreparedLaunchVolumes {
            volumes,
            lease_guard,
        });
    }
    let catalog = recover_local_volume_catalog()?;
    let resolved = registry.resolve_for_launch(&catalog)?;

    let mut guest_paths = explicit
        .iter()
        .map(|volume| volume.guest.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut volumes = explicit.to_vec();
    volumes.reserve(resolved.len());
    for attachment in resolved {
        let guest = attachment.guest_path.as_str().to_string();
        if !guest_paths.insert(guest.clone()) {
            bail!("duplicate guest mount path {guest:?} between explicit and registered volumes");
        }
        if matches!(
            attachment.source,
            ResolvedVolumeSource::HostBackedCatalog | ResolvedVolumeSource::AdHocHost
        ) {
            crate::doctor::require_local_volume_host_path_encrypted(&attachment.host_path)
                .with_context(|| {
                    format!(
                        "registered volume {:?} no longer has encrypted host backing",
                        attachment.volume_name
                    )
                })?;
        }
        let vm_volume = attachment.as_vm_volume();
        volumes.push(mvm_runtime::image::RuntimeVolume::from(&vm_volume));
    }
    let lease_guard = LocalVolumeLeaseGuard::acquire(vm_name, &volumes)?;
    Ok(PreparedLaunchVolumes {
        volumes,
        lease_guard,
    })
}

fn ls(vm_name: &str, json: bool) -> Result<()> {
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    let registry = VolumeMountRegistry::load(vm_name)?;
    if json {
        let rows: Vec<&VolumeMountEntry> = registry.iter().map(|(_, v)| v).collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if registry.is_empty() {
        println!("(no volume mounts)");
        return Ok(());
    }
    println!(
        "{:<22} {:<22} {:<14} {:<4} HOST",
        "GUEST", "VOLUME", "ATTACHED", "RO"
    );
    for (_, e) in registry.iter() {
        println!(
            "{:<22} {:<22} {:<14} {:<4} {}",
            e.guest_path,
            e.volume_name,
            &e.attached_at[..e.attached_at.len().min(14)],
            if e.read_only { "yes" } else { "no" },
            e.host_path,
        );
    }
    Ok(())
}

fn unmount(vm_name: &str, guest_path: &str) -> Result<()> {
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    let mut registry = VolumeMountRegistry::load(vm_name)?;
    let dropped = registry
        .remove(guest_path)
        .with_context(|| format!("VM {:?} has no volume mount at {:?}", vm_name, guest_path))?;
    registry.save(vm_name)?;
    println!(
        "{vm_name}: unmounted volume {} from {} (host={})",
        dropped.volume_name, dropped.guest_path, dropped.host_path
    );
    mvm_core::audit_emit!(VmVolumeRemove, vm: vm_name, "volume={} guest={}" ,
        dropped.volume_name, dropped.guest_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    struct DataDirGuard {
        _env: mvm_core::util::test_env::TestEnv,
        tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            let tmp = tempfile::tempdir().expect("tempdir");
            env.set("MVM_HOME", tmp.path());
            Self { _env: env, tmp }
        }

        fn path(&self) -> &Path {
            self.tmp.path()
        }
    }

    #[test]
    fn mvm_managed_volume_create_unlock_lock_roundtrip() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();

        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.state, LocalVolumeState::Locked);
                PathBuf::from(&enc.ciphertext_path)
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        assert!(ciphertext.is_file());

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(Path::new(&entry.host_path).is_file());
        assert_eq!(entry.kind, LocalVolumeKind::BlockImage { size_mib: 16 });
        assert!(matches!(
            &entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Unlocked,
                ..
            })
        ));

        let mut image = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&entry.host_path)
            .unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[0x7a]).unwrap();
        image.sync_all().unwrap();
        lock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        assert!(matches!(
            &entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Locked,
                ..
            })
        ));

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        let mut image = File::open(&entry.host_path).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut marker = [0u8; 1];
        image.read_exact(&mut marker).unwrap();
        assert_eq!(marker, [0x7a]);
    }

    #[test]
    fn registered_managed_mount_is_consumed_by_launch_resolution() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", true).unwrap();

        let prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert_eq!(prepared.volumes[0].guest, "/data/work");
        assert!(!prepared.volumes[0].read_only);
        assert!(matches!(
            prepared.volumes[0].kind,
            mvm_core::vm_backend::VmVolumeKind::Disk
        ));
        assert!(Path::new(&prepared.volumes[0].host).is_file());
    }

    #[test]
    fn block_attachment_lease_is_exclusive_and_released_on_stop() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", true).unwrap();
        mount("vm-2", "work", None, "/data/work", true).unwrap();

        let prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        drop(prepared);
        assert!(merge_registered_volumes_for_launch("vm-2", &[]).is_ok());

        let mut prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        prepared.commit();
        drop(prepared);
        let lock_error = lock("work").unwrap_err();
        assert!(lock_error.to_string().contains("attached to VM \"vm-1\""));
        let error = match merge_registered_volumes_for_launch("vm-2", &[]) {
            Ok(_) => panic!("second VM must not acquire an active block lease"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("already attached to VM \"vm-1\"")
        );

        release_volume_leases_for_vm("vm-1").unwrap();
        assert!(merge_registered_volumes_for_launch("vm-2", &[]).is_ok());
    }

    #[test]
    fn launch_resolution_refuses_volume_locked_after_registration() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", false).unwrap();
        lock("work").unwrap();

        let err = merge_registered_volumes_for_launch("vm-1", &[]).unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[test]
    fn launch_resolution_refuses_explicit_guest_path_collision() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", false).unwrap();
        let explicit = mvm_runtime::image::RuntimeVolume {
            host: "/explicit.ext4".to_string(),
            guest: "/data/work".to_string(),
            size: "1G".to_string(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        };

        let err = merge_registered_volumes_for_launch("vm-1", &[explicit]).unwrap_err();
        assert!(err.to_string().contains("duplicate guest mount path"));
    }

    #[test]
    fn mvm_managed_mount_refuses_locked_volume() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        let err = mount("vm-1", "work", None, "/mnt/work", false).unwrap_err();
        assert!(err.to_string().contains("is locked"), "got: {err}");
    }

    #[test]
    fn mvm_managed_unlock_rejects_tampered_ciphertext() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => PathBuf::from(&enc.ciphertext_path),
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        let mut bytes = fs::read(&ciphertext).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&ciphertext, bytes).unwrap();
        let err = unlock("work").unwrap_err();
        // The DEK binding catches a flipped byte at admit (the ciphertext
        // hash no longer matches the bound artifact), before the archive is
        // even decrypted. Either gate is a valid rejection.
        assert!(
            err.to_string().contains("DEK binding mismatch")
                || err.to_string().contains("decrypting volume archive")
                || err.to_string().contains("authentication failure"),
            "got: {err}"
        );
    }

    #[test]
    fn mvm_managed_unlock_rejects_dek_bound_to_different_artifact() {
        // A DEK whose recorded binding points at a different content_hash than
        // the on-disk ciphertext is refused at admit.
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();

        // Corrupt only the binding, leaving the ciphertext intact.
        let mut catalog = LocalVolumeCatalog::load().unwrap();
        if let LocalVolumeEncryption::MvmManaged(enc) =
            &mut catalog.get_mut("work").unwrap().encryption
        {
            enc.wrapped_key.rebind_content("0".repeat(64)); // a hash the archive can't have
        }
        catalog.save().unwrap();

        let err = unlock("work").unwrap_err();
        assert!(
            err.to_string().contains("DEK binding mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn mvm_managed_unlock_rejects_missing_master_key() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        fs::remove_dir_all(local_master_key_dir()).unwrap();
        let err = unlock("work").unwrap_err();
        assert!(err.to_string().contains("loading master key"), "got: {err}");
    }

    #[test]
    fn create_rotates_stale_local_master_key_and_rewraps_catalog() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        // First volume mints master v1 and wraps "work" under it.
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();

        // Backdate the active KEK to 91 days old so the next mint trips the
        // 90-day rotation policy.
        let active_dir = local_master_key_dir();
        let mut manifest = key_rotation::load_manifest(&active_dir).unwrap();
        manifest.entries[0].created_at = chrono::Utc::now() - chrono::Duration::days(91);
        fs::write(
            active_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // Creating a second volume runs the rotation check.
        create("work2", Some(root.to_str().unwrap()), false, "16M").unwrap();

        // KEK advanced v1 → v2.
        let manifest = key_rotation::load_manifest(&active_dir).unwrap();
        assert_eq!(manifest.latest_version(), 2);

        // The pre-existing "work" volume was re-wrapped onto v2 …
        let catalog = LocalVolumeCatalog::load().unwrap();
        match &catalog.get("work").unwrap().encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.wrapped_key.master_key_version, 2);
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed"),
        }
        // … and still unlocks, proving the DEK survived the re-wrap.
        unlock("work").unwrap();
    }

    #[test]
    fn mvm_managed_unlock_rejects_wrong_master_key() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        let key_path = local_master_key_dir().join("v1.bin");
        fs::write(&key_path, [42u8; key_rotation::MASTER_KEY_BYTES]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = unlock("work").unwrap_err();
        assert!(
            err.to_string().contains("unwrapping data key")
                || err.to_string().contains("authentication"),
            "got: {err}"
        );
    }

    #[test]
    fn lifecycle_lock_refuses_a_concurrent_volume_mutation() {
        let _guard = DataDirGuard::new();
        let first = acquire_volume_lifecycle_lock().unwrap();
        let second = acquire_volume_lifecycle_lock();
        assert!(
            second.is_err(),
            "a second lifecycle mutation must not share the catalog lock"
        );
        drop(first);
        assert!(acquire_volume_lifecycle_lock().is_ok());
    }

    #[test]
    fn lease_key_is_stable_when_managed_plaintext_is_absent() {
        let guard = DataDirGuard::new();
        let parent = guard.path().join("materialized");
        fs::create_dir(&parent).unwrap();
        let host_path = parent.join("work.ext4");
        let absent_key = local_volume_lease_key(&host_path).unwrap();
        fs::write(&host_path, b"volume").unwrap();
        let present_key = local_volume_lease_key(&host_path).unwrap();
        assert_eq!(absent_key, present_key);
    }

    #[test]
    fn recovery_rolls_back_an_interrupted_seal_without_losing_plaintext() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();

        let mut catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap().clone();
        set_local_volume_state(&mut catalog, "work", LocalVolumeState::Locking).unwrap();
        catalog.save().unwrap();
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(encryption) => {
                PathBuf::from(&encryption.ciphertext_path)
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed volume"),
        };
        let staging = lock_staging_path(&ciphertext);
        fs::write(&staging, b"partial").unwrap();

        let recovered = recover_local_volume_catalog().unwrap();
        let recovered_entry = recovered.get("work").unwrap();
        assert!(Path::new(&recovered_entry.host_path).is_file());
        assert!(!staging.exists());
        assert!(matches!(
            &recovered_entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Unlocked,
                ..
            })
        ));
    }

    #[test]
    fn recovery_finishes_a_prepared_seal_and_preserves_bytes() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();

        let mut catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap().clone();
        let dek = unwrap_volume_key(&entry).unwrap();
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(encryption) => {
                PathBuf::from(&encryption.ciphertext_path)
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed volume"),
        };
        let staging = lock_staging_path(&ciphertext);
        write_encrypted_volume_file(Path::new(&entry.host_path), &staging, dek.expose_secret())
            .unwrap();
        let prepared_hash = ciphertext_content_hash(&staging).unwrap();
        let catalog_entry = catalog.get_mut("work").unwrap();
        let LocalVolumeEncryption::MvmManaged(encryption) = &mut catalog_entry.encryption else {
            panic!("expected mvm-managed volume")
        };
        encryption.wrapped_key.rebind_content(prepared_hash);
        encryption.state = LocalVolumeState::Publishing;
        catalog.save().unwrap();

        let recovered = recover_local_volume_catalog().unwrap();
        let recovered_entry = recovered.get("work").unwrap();
        assert!(!Path::new(&recovered_entry.host_path).exists());
        assert!(!staging.exists());
        assert!(ciphertext.is_file());
        assert!(matches!(
            &recovered_entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Locked,
                ..
            })
        ));
        unlock("work").unwrap();
        assert!(
            Path::new(
                &LocalVolumeCatalog::load()
                    .unwrap()
                    .get("work")
                    .unwrap()
                    .host_path
            )
            .is_file()
        );
    }

    #[test]
    fn recovery_finishes_a_prepared_restore_and_recovers_prior_bytes() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();

        let original = LocalVolumeCatalog::load().unwrap();
        let original_entry = original.get("work").unwrap();
        let (ciphertext, original_wrapped_key) = match &original_entry.encryption {
            LocalVolumeEncryption::MvmManaged(encryption) => (
                PathBuf::from(&encryption.ciphertext_path),
                encryption.wrapped_key.clone(),
            ),
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed volume"),
        };
        let staging = ciphertext.with_extension("restoring");
        fs::copy(&ciphertext, &staging).unwrap();

        unlock("work").unwrap();
        let unlocked = LocalVolumeCatalog::load().unwrap();
        let host_path = PathBuf::from(&unlocked.get("work").unwrap().host_path);
        let mut image = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&host_path)
            .unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut original_marker = [0u8; 1];
        image.read_exact(&mut original_marker).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[original_marker[0] ^ 0xff]).unwrap();
        image.sync_all().unwrap();
        lock("work").unwrap();

        let mut restoring = LocalVolumeCatalog::load().unwrap();
        let restoring_entry = restoring.get_mut("work").unwrap();
        let LocalVolumeEncryption::MvmManaged(encryption) = &mut restoring_entry.encryption else {
            panic!("expected mvm-managed volume")
        };
        encryption.wrapped_key = original_wrapped_key;
        encryption.state = LocalVolumeState::Restoring;
        restoring.save().unwrap();

        let recovered = recover_local_volume_catalog().unwrap();
        assert!(!staging.exists());
        assert!(matches!(
            &recovered.get("work").unwrap().encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Locked,
                ..
            })
        ));
        unlock("work").unwrap();
        let unlocked = LocalVolumeCatalog::load().unwrap();
        let mut image = File::open(&unlocked.get("work").unwrap().host_path).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut recovered_marker = [0u8; 1];
        image.read_exact(&mut recovered_marker).unwrap();
        assert_eq!(recovered_marker, original_marker);
    }
}
