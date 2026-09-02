//! Encrypted-volume lifecycle state machine: create, unlock, lock, and
//! crash recovery.
//!
//! An mvm-managed volume is authenticated ciphertext at rest (`MVSE`
//! whole-file AES-256-GCM over an ext4 image or a tar archive), with its data
//! key wrapped under a versioned local master KEK and bound to the ciphertext
//! content hash. The plaintext attachment artifact exists only between an
//! explicit unlock and the following lock. Every transition persists an
//! intermediate catalog state first, so an interrupted operation is driven
//! back to a terminal state by [`recover_local_volume_catalog`] before any
//! new lifecycle operation proceeds.

use std::fs::{self, File};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::crypto::key_rotation;
use mvm_core::crypto::rotation_policy;
use mvm_core::domain::volume::{MasterKeyState, OrgId, WrapAlgorithm, WrappedKey};
use mvm_runtime::vm::volume_registry::{
    LocalVolumeCatalog, LocalVolumeEncryption, LocalVolumeEntry, LocalVolumeKind, LocalVolumeState,
    MvmManagedVolumeEncryption,
};
use rand::Rng;
use secrecy::ExposeSecret;

use super::lease::ensure_volume_not_attached;
use super::service::HostEncryptionProbe;

/// Root for host-backed managed volume directories.
pub(crate) fn default_managed_volume_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("local")
}

/// Root for mvm-managed encrypted volume state (`encrypted/` + `unlocked/`).
pub(crate) fn default_mvm_volume_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("mvm-managed")
}

/// Directory holding the local master KEK versions (`v<N>.bin`, 0600).
pub(crate) fn local_master_key_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("master-keys")
        .join("local")
}

/// Exclusive host-wide lifecycle lock. Every mutating volume operation and
/// every launch-time lease acquisition serializes on this flock.
pub(crate) fn acquire_volume_lifecycle_lock() -> Result<mvm_core::util::atomic_io::FileLock> {
    mvm_core::util::atomic_io::FileLock::try_acquire(&LocalVolumeCatalog::path())?
        .context("another local volume lifecycle operation is already in progress")
}

pub(crate) fn unlock_staging_path(host_path: &Path) -> PathBuf {
    host_path.with_extension("unlocking")
}

pub(crate) fn lock_staging_path(ciphertext_path: &Path) -> PathBuf {
    ciphertext_path.with_extension("locking")
}

/// Create a volume directory with the whole chain under the mvm home private.
///
/// A second copy of this used to live here, chmodding only the leaf. That is
/// the ancestor bug: `create_dir_all` makes every missing parent at the
/// process umask, so `~/.mvm/volumes/<id>/ciphertext` could arrive with two
/// world-readable directories above it holding the same encrypted state.
/// Delegating keeps one implementation of the rule rather than two that drift.
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    mvm_core::config::create_private_dir(path)
        .with_context(|| format!("creating {} privately", path.display()))
}

/// Volume-name shape check for creation: the name doubles as the virtio-fs
/// tag the guest kernel sees, so it stays short and conservative.
pub(crate) fn validate_volume_name(name: &str) -> Result<()> {
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

pub(crate) fn set_local_volume_state(
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

/// Load the catalog and drive every interrupted lifecycle transition back to
/// a terminal state. Idempotent; must run under the lifecycle lock.
pub(crate) fn recover_local_volume_catalog() -> Result<LocalVolumeCatalog> {
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

/// Create a host-backed managed directory volume. The probe must confirm the
/// backing path lives on encrypted host storage.
pub(crate) fn create_host_backed(
    volume_name: &str,
    root: Option<&Path>,
    probe: &dyn HostEncryptionProbe,
) -> Result<LocalVolumeEntry> {
    let root = match root {
        Some(root) => root.to_path_buf(),
        None => default_managed_volume_root(),
    };
    if !root.is_absolute() {
        bail!(
            "managed volume root must be absolute, got {}",
            root.display()
        );
    }
    ensure_private_dir(&root)
        .with_context(|| format!("creating managed volume root {}", root.display()))?;
    probe.require_encrypted(&root)?;

    let host_path = root.join(volume_name);
    if host_path.exists() && !host_path.is_dir() {
        bail!(
            "managed volume path {} exists but is not a directory",
            host_path.display()
        );
    }
    ensure_private_dir(&host_path)
        .with_context(|| format!("creating managed volume {}", host_path.display()))?;
    probe.require_encrypted(&host_path)?;

    let mut catalog = LocalVolumeCatalog::load()?;
    let entry = LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        kind: LocalVolumeKind::Directory,
        encryption: LocalVolumeEncryption::HostBacked,
        created_at: mvm_core::util::time::utc_now(),
    };
    catalog.add(entry.clone())?;
    catalog.save()?;
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} host={} encrypted=true",
        host_path.display()
    );
    Ok(entry)
}

/// Create an mvm-managed encrypted block volume: an empty ext4 image sealed
/// as authenticated ciphertext, registered locked.
pub(crate) fn create_mvm_managed(
    volume_name: &str,
    root: Option<&Path>,
    capacity_mib: u32,
) -> Result<LocalVolumeEntry> {
    let root = match root {
        Some(root) => root.to_path_buf(),
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

    if capacity_mib == 0 {
        bail!("volume size must be greater than zero");
    }
    let size_bytes = u64::from(capacity_mib)
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
    let entry = LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        kind: LocalVolumeKind::BlockImage {
            size_mib: capacity_mib,
        },
        encryption: LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
            state: LocalVolumeState::Locked,
            ciphertext_path: ciphertext_path.to_string_lossy().into_owned(),
            wrapped_key,
        }),
        created_at: mvm_core::util::time::utc_now(),
    };
    catalog.add(entry.clone())?;
    catalog.save()?;
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} ciphertext={} state=locked",
        ciphertext_path.display()
    );
    Ok(entry)
}

/// Opportunistically roll the local master KEK when it is past its 90-day
/// lifetime, re-wrapping the catalog's mvm-managed volume keys onto the new
/// KEK. Invoked whenever a managed volume key is minted — the closest thing
/// to a periodic "on use" trigger the local lifecycle has.
///
/// Cheap and non-destructive: re-wrapping leaves the underlying DEK (and the
/// on-disk ciphertext) untouched, so an existing volume keeps decrypting.
/// Best-effort scope — only keys already at the current active version are
/// swept (a single re-wrap can't span mixed versions); a volume wrapped under
/// an older legacy KEK keeps unlocking via its recorded version and the
/// retained legacy key file.
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
        tracing::info!(
            from = from_version,
            to = to_version,
            migrated,
            "rotated local master KEK and re-wrapped volume keys"
        );
    }
    Ok(())
}

pub(crate) fn generate_wrapped_volume_key() -> Result<(WrappedKey, secrecy::SecretBox<Vec<u8>>)> {
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
    rand::rng().fill_bytes(&mut dek);
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
pub(crate) fn ciphertext_content_hash(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing ciphertext archive {}", path.display()))
}

pub(crate) fn unwrap_volume_key(entry: &LocalVolumeEntry) -> Result<secrecy::SecretBox<Vec<u8>>> {
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
            bail!("AES-KWP wrapped local volume keys are not supported by the local service")
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

pub(crate) fn write_encrypted_volume_archive(
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

pub(crate) fn write_encrypted_volume_file(
    src_file: &Path,
    ciphertext_path: &Path,
    dek: &[u8],
) -> Result<()> {
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

/// Decrypt a managed volume into its private plaintext attachment artifact.
/// The caller holds the lifecycle lock and passes a recovered catalog; the
/// intermediate `Unlocking` state is persisted before ciphertext is touched.
pub(crate) fn unlock_volume_locked(
    catalog: &mut LocalVolumeCatalog,
    volume_name: &str,
) -> Result<()> {
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
    set_local_volume_state(catalog, volume_name, LocalVolumeState::Unlocking)?;
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
    set_local_volume_state(catalog, volume_name, LocalVolumeState::Unlocked)?;
    catalog.save()?;
    mvm_core::audit_emit!(VolumeOpen, "volume={volume_name} state=unlocked");
    Ok(())
}

/// Seal a managed volume back into authenticated ciphertext and remove the
/// plaintext attachment artifact. The caller holds the lifecycle lock and
/// passes a recovered catalog.
pub(crate) fn lock_volume_locked(
    catalog: &mut LocalVolumeCatalog,
    volume_name: &str,
) -> Result<()> {
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
            bail!("volume {volume_name:?} is host-backed and cannot be sealed")
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
    set_local_volume_state(catalog, volume_name, LocalVolumeState::Locking)?;
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
    set_local_volume_state(catalog, volume_name, LocalVolumeState::Locked)?;
    catalog.save()?;
    remove_materialized_volume(&entry)?;
    mvm_core::audit_emit!(VolumeLock, "volume={volume_name} state=locked");
    Ok(())
}

/// Tolerant re-seal used by lease release: seals the volume when (and only
/// when) it is a managed volume currently unlocked. Missing, host-backed, or
/// already-locked volumes are a no-op, so a repeated release stays
/// idempotent. Returns `true` when a seal actually happened.
pub(crate) fn relock_if_unlocked(
    catalog: &mut LocalVolumeCatalog,
    volume_name: &str,
) -> Result<bool> {
    let Some(entry) = catalog.get(volume_name) else {
        return Ok(false);
    };
    match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) if enc.state == LocalVolumeState::Unlocked => {
            lock_volume_locked(catalog, volume_name)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
