//! Immutable encrypted snapshots for managed local block volumes.
//!
//! A snapshot copies the sealed ciphertext archive (never plaintext) plus a
//! canonical-JSON manifest binding the payload hash, size, artifact kind, and
//! the wrapped key that decrypts it. Restore verifies the manifest identity,
//! payload digest, and wrapped-key binding before replacing the live
//! ciphertext, staging the swap so an interrupted restore recovers cleanly.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::domain::volume::WrappedKey;
use mvm_runtime::vm::volume_registry::{
    LocalVolumeEncryption, LocalVolumeKind, LocalVolumeState, MvmManagedVolumeEncryption,
};
use serde::{Deserialize, Serialize};

use super::lease::ensure_volume_not_attached;
use super::lifecycle::{
    acquire_volume_lifecycle_lock, ciphertext_content_hash, ensure_private_dir,
    recover_local_volume_catalog, set_local_volume_state, validate_volume_name,
};

const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_PAYLOAD: &str = "volume.mvve";
const SNAPSHOT_MANIFEST: &str = "manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalVolumeSnapshotManifest {
    schema_version: u32,
    snapshot_id: String,
    volume_name: String,
    created_at: String,
    ciphertext_sha256: String,
    ciphertext_bytes: u64,
    kind: LocalVolumeKind,
    wrapped_key: WrappedKey,
}

/// Create an immutable encrypted snapshot of a locked managed volume.
pub(crate) fn create(volume_name: &str, snapshot_id: &str) -> Result<()> {
    validate_snapshot_inputs(volume_name, snapshot_id)?;
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    let catalog = recover_local_volume_catalog()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    ensure_volume_not_attached(&entry, "snapshot")?;
    let encryption = managed_locked_encryption(&entry.encryption, volume_name, "snapshot")?;
    let ciphertext = Path::new(&encryption.ciphertext_path);
    let ciphertext_sha256 = ciphertext_content_hash(ciphertext)?;
    if !encryption
        .wrapped_key
        .binding_matches_content(&ciphertext_sha256)
    {
        bail!("volume {volume_name:?} ciphertext binding mismatch; refusing snapshot");
    }
    let ciphertext_bytes = fs::metadata(ciphertext)
        .with_context(|| format!("reading ciphertext metadata for volume {volume_name:?}"))?
        .len();

    let root = snapshot_volume_root(volume_name);
    ensure_private_dir(&root)?;
    let final_dir = root.join(snapshot_id);
    if final_dir.exists() {
        bail!("snapshot {snapshot_id:?} already exists for volume {volume_name:?}");
    }
    let staging = root.join(format!(".{snapshot_id}.staging"));
    remove_staging_dir(&staging)?;
    fs::create_dir(&staging)
        .with_context(|| format!("creating snapshot staging dir {}", staging.display()))?;

    let result = (|| -> Result<()> {
        let payload = staging.join(SNAPSHOT_PAYLOAD);
        fs::copy(ciphertext, &payload)
            .with_context(|| format!("copying encrypted snapshot payload for {volume_name:?}"))?;
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o400))
            .with_context(|| format!("chmod 0400 {}", payload.display()))?;
        fs::File::open(&payload)
            .with_context(|| format!("opening snapshot payload {}", payload.display()))?
            .sync_all()
            .with_context(|| format!("syncing snapshot payload {}", payload.display()))?;
        verify_payload(&payload, ciphertext_bytes, &ciphertext_sha256)?;

        let manifest = LocalVolumeSnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: snapshot_id.to_string(),
            volume_name: volume_name.to_string(),
            created_at: mvm_core::util::time::utc_now(),
            ciphertext_sha256,
            ciphertext_bytes,
            kind: entry.kind.clone(),
            wrapped_key: encryption.wrapped_key.clone(),
        };
        let manifest_bytes = serde_jcs::to_vec(&manifest)
            .context("serializing canonical local volume snapshot manifest")?;
        let manifest_path = staging.join(SNAPSHOT_MANIFEST);
        mvm_core::util::atomic_io::atomic_write(&manifest_path, &manifest_bytes)
            .with_context(|| format!("writing snapshot manifest {}", manifest_path.display()))?;
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o400))
            .with_context(|| format!("chmod 0400 {}", manifest_path.display()))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o500))
            .with_context(|| format!("chmod 0500 {}", staging.display()))?;
        fs::rename(&staging, &final_dir).with_context(|| {
            format!(
                "publishing immutable snapshot {} -> {}",
                staging.display(),
                final_dir.display()
            )
        })?;
        fs::File::open(&root)
            .with_context(|| format!("opening snapshot root {}", root.display()))?
            .sync_all()
            .with_context(|| format!("syncing snapshot root {}", root.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::set_permissions(&staging, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    mvm_core::audit_emit!(
        VolumeSnapshot,
        "volume={volume_name} snapshot={snapshot_id} state=created"
    );
    Ok(())
}

/// Restore a locked managed volume from an immutable local snapshot.
pub(crate) fn restore(volume_name: &str, snapshot_id: &str) -> Result<()> {
    validate_snapshot_inputs(volume_name, snapshot_id)?;
    let _lifecycle_lock = acquire_volume_lifecycle_lock()?;
    let mut catalog = recover_local_volume_catalog()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    ensure_volume_not_attached(&entry, "restore")?;
    let encryption = managed_locked_encryption(&entry.encryption, volume_name, "restore")?;

    let snapshot_dir = snapshot_volume_root(volume_name).join(snapshot_id);
    let manifest = load_manifest(&snapshot_dir.join(SNAPSHOT_MANIFEST))?;
    validate_manifest(&manifest, volume_name, snapshot_id, &entry.kind)?;
    let payload = snapshot_dir.join(SNAPSHOT_PAYLOAD);
    verify_payload(
        &payload,
        manifest.ciphertext_bytes,
        &manifest.ciphertext_sha256,
    )?;
    if !manifest
        .wrapped_key
        .binding_matches_content(&manifest.ciphertext_sha256)
    {
        bail!("snapshot {snapshot_id:?} wrapped-key binding does not match its payload");
    }

    let ciphertext = PathBuf::from(&encryption.ciphertext_path);
    let staging = ciphertext.with_extension("restoring");
    if staging.exists() {
        fs::remove_file(&staging)
            .with_context(|| format!("removing stale restore staging {}", staging.display()))?;
    }
    fs::copy(&payload, &staging)
        .with_context(|| format!("staging snapshot {snapshot_id:?} for restore"))?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", staging.display()))?;
    fs::File::open(&staging)
        .with_context(|| format!("opening restore staging {}", staging.display()))?
        .sync_all()
        .with_context(|| format!("syncing restore staging {}", staging.display()))?;
    verify_payload(
        &staging,
        manifest.ciphertext_bytes,
        &manifest.ciphertext_sha256,
    )?;

    let catalog_entry = catalog
        .get_mut(volume_name)
        .with_context(|| format!("volume {volume_name:?} disappeared during restore"))?;
    let LocalVolumeEncryption::MvmManaged(catalog_encryption) = &mut catalog_entry.encryption
    else {
        bail!("volume {volume_name:?} changed encryption mode during restore");
    };
    catalog_encryption.wrapped_key = manifest.wrapped_key;
    catalog_encryption.state = LocalVolumeState::Restoring;
    catalog.save()?;
    fs::rename(&staging, &ciphertext).with_context(|| {
        format!(
            "publishing restored ciphertext {} -> {}",
            staging.display(),
            ciphertext.display()
        )
    })?;
    fs::set_permissions(&ciphertext, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", ciphertext.display()))?;
    set_local_volume_state(&mut catalog, volume_name, LocalVolumeState::Locked)?;
    catalog.save()?;
    mvm_core::audit_emit!(
        VolumeRestore,
        "volume={volume_name} snapshot={snapshot_id} state=restored"
    );
    Ok(())
}

fn managed_locked_encryption<'a>(
    encryption: &'a LocalVolumeEncryption,
    volume_name: &str,
    operation: &str,
) -> Result<&'a MvmManagedVolumeEncryption> {
    let LocalVolumeEncryption::MvmManaged(encryption) = encryption else {
        bail!("volume {volume_name:?} is host-backed and cannot perform {operation}");
    };
    if encryption.state != LocalVolumeState::Locked {
        bail!("volume {volume_name:?} must be locked before {operation}");
    }
    Ok(encryption)
}

fn validate_snapshot_inputs(volume_name: &str, snapshot_id: &str) -> Result<()> {
    validate_volume_name(volume_name)
        .with_context(|| format!("invalid volume name {volume_name:?}"))?;
    validate_volume_name(snapshot_id)
        .with_context(|| format!("invalid snapshot id {snapshot_id:?}"))
}

fn snapshot_volume_root(volume_name: &str) -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("snapshots")
        .join(volume_name)
}

fn remove_staging_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 stale staging {}", path.display()))?;
    fs::remove_dir_all(path)
        .with_context(|| format!("removing stale snapshot staging {}", path.display()))
}

fn load_manifest(path: &Path) -> Result<LocalVolumeSnapshotManifest> {
    let bytes =
        fs::read(path).with_context(|| format!("reading snapshot manifest {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing snapshot manifest {}", path.display()))
}

fn validate_manifest(
    manifest: &LocalVolumeSnapshotManifest,
    volume_name: &str,
    snapshot_id: &str,
    kind: &LocalVolumeKind,
) -> Result<()> {
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "snapshot schema {} is unsupported; expected {}",
            manifest.schema_version,
            SNAPSHOT_SCHEMA_VERSION
        );
    }
    if manifest.volume_name != volume_name || manifest.snapshot_id != snapshot_id {
        bail!("snapshot manifest identity does not match the requested volume and snapshot");
    }
    if &manifest.kind != kind {
        bail!("snapshot artifact kind does not match the target volume");
    }
    Ok(())
}

fn verify_payload(path: &Path, expected_bytes: u64, expected_sha256: &str) -> Result<()> {
    let actual_bytes = fs::metadata(path)
        .with_context(|| format!("reading snapshot payload metadata {}", path.display()))?
        .len();
    if actual_bytes != expected_bytes {
        bail!("snapshot payload length mismatch: expected {expected_bytes}, found {actual_bytes}");
    }
    let actual_sha256 = ciphertext_content_hash(path)?;
    if actual_sha256 != expected_sha256 {
        bail!("snapshot payload digest mismatch; refusing restore");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use mvm_runtime::vm::volume_registry::LocalVolumeCatalog;

    use super::super::service::{LocalVolumeService, VolumeService};
    use super::super::test_support::TestVolumeHome;
    use super::*;

    fn write_marker(value: u8) {
        let catalog = LocalVolumeCatalog::load().unwrap();
        let host = &catalog.get("work").unwrap().host_path;
        let mut image = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(host)
            .unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[value]).unwrap();
        image.sync_all().unwrap();
    }

    fn read_marker() -> u8 {
        let catalog = LocalVolumeCatalog::load().unwrap();
        let host = &catalog.get("work").unwrap().host_path;
        let mut image = fs::File::open(host).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut marker = [0u8; 1];
        image.read_exact(&mut marker).unwrap();
        marker[0]
    }

    #[test]
    fn snapshot_restore_roundtrip_recovers_prior_encrypted_bytes() {
        let home = TestVolumeHome::new();
        home.create_block("work", 16);
        let service = LocalVolumeService::new();
        service.unlock_volume("work").unwrap();
        write_marker(0x41);
        service.lock_volume("work").unwrap();
        create("work", "before").unwrap();

        service.unlock_volume("work").unwrap();
        write_marker(0x42);
        service.lock_volume("work").unwrap();
        restore("work", "before").unwrap();
        service.unlock_volume("work").unwrap();
        assert_eq!(read_marker(), 0x41);
    }

    #[test]
    fn restore_refuses_tampered_snapshot_without_replacing_current_ciphertext() {
        let home = TestVolumeHome::new();
        home.create_block("work", 16);
        create("work", "before").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let encryption = match &catalog.get("work").unwrap().encryption {
            LocalVolumeEncryption::MvmManaged(encryption) => encryption.clone(),
            LocalVolumeEncryption::HostBacked => panic!("expected managed encryption"),
        };
        let current = ciphertext_content_hash(Path::new(&encryption.ciphertext_path)).unwrap();
        let payload = snapshot_volume_root("work")
            .join("before")
            .join(SNAPSHOT_PAYLOAD);
        let mut bytes = fs::read(&payload).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&payload, bytes).unwrap();

        let error = restore("work", "before").unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));
        assert_eq!(
            ciphertext_content_hash(Path::new(&encryption.ciphertext_path)).unwrap(),
            current
        );
    }

    #[test]
    fn snapshot_manifest_is_canonical_strict_and_roundtrips() {
        let home = TestVolumeHome::new();
        home.create_block("work", 16);
        create("work", "before").unwrap();
        let manifest_path = snapshot_volume_root("work")
            .join("before")
            .join(SNAPSHOT_MANIFEST);
        let manifest = load_manifest(&manifest_path).unwrap();
        let canonical = serde_jcs::to_vec(&manifest).unwrap();
        assert_eq!(fs::read(&manifest_path).unwrap(), canonical);
        assert_eq!(
            serde_json::from_slice::<LocalVolumeSnapshotManifest>(&canonical).unwrap(),
            manifest
        );

        let mut value = serde_json::to_value(&manifest).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        let error = serde_json::from_value::<LocalVolumeSnapshotManifest>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
