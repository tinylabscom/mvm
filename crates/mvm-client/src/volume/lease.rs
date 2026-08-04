//! Exclusive attachment leases for local block volumes.
//!
//! A block volume image must never be attached to two VMs at once — a second
//! writer (or even a second reader against a live writer) corrupts ext4.
//! Leases are keyed by the sha256 of the canonicalized host artifact path and
//! persisted at `<mvm_home>/volumes/attachments.json` (0600, atomic writes) so
//! exclusivity survives process restarts and crashes.
//!
//! [`LaunchLease`] is the RAII guard the launch path holds: a failed launch
//! drops the guard uncommitted, which rolls the leases back — and re-seals any
//! volume the service had unlocked just in time — so nothing leaks.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_runtime::vm::volume_registry::LocalVolumeEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::dto::ReleaseOutcome;
use super::lifecycle;

/// Persistent catalog of live attachment leases.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentLeaseCatalog {
    #[serde(default)]
    pub(crate) leases: BTreeMap<String, AttachmentLeaseRecord>,
}

/// One live attachment lease. `relock_volume` names the managed volume the
/// service unlocked just in time for this attachment; the final release
/// re-seals it. Field names match the historical on-disk shape so existing
/// catalogs keep parsing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentLeaseRecord {
    pub(crate) vm_name: String,
    pub(crate) volume_name: String,
    pub(crate) read_only: bool,
    pub(crate) acquired_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) relock_volume: Option<String>,
}

impl AttachmentLeaseCatalog {
    pub(crate) fn path() -> PathBuf {
        PathBuf::from(mvm_core::config::mvm_home())
            .join("volumes")
            .join("attachments.json")
    }

    pub(crate) fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading volume leases {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing volume leases {}", path.display()))
    }

    pub(crate) fn save(&self) -> Result<()> {
        let path = Self::path();
        let bytes = serde_json::to_vec_pretty(self).context("serializing volume leases")?;
        mvm_core::util::atomic_io::atomic_write(&path, &bytes)
            .with_context(|| format!("saving volume leases {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        Ok(())
    }
}

/// Stable lease key for a host artifact: sha256 of the canonicalized path.
/// Canonicalizes the parent when the artifact itself does not exist yet, so
/// the key is identical whether or not the plaintext is materialized.
pub(crate) fn lease_key(host_path: &Path) -> Result<String> {
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

/// Refuse a lifecycle operation against a volume currently under lease.
pub(crate) fn ensure_volume_not_attached(entry: &LocalVolumeEntry, operation: &str) -> Result<()> {
    let key = lease_key(Path::new(&entry.host_path))?;
    if let Some(lease) = AttachmentLeaseCatalog::load()?.leases.get(&key) {
        bail!(
            "cannot {operation} volume {:?}: it is attached to VM {:?}",
            entry.volume_name,
            lease.vm_name
        );
    }
    Ok(())
}

/// One lease to take: the persisted record plus its catalog key.
#[derive(Debug, Clone)]
pub(crate) struct LeaseIntent {
    pub(crate) key: String,
    pub(crate) record: AttachmentLeaseRecord,
}

/// Check every intent against the live catalog without mutating it. Fails on
/// a conflicting live lease or a duplicate artifact within the same launch.
pub(crate) fn check_lease_conflicts(intents: &[LeaseIntent]) -> Result<()> {
    let catalog = AttachmentLeaseCatalog::load()?;
    let mut seen: Vec<&str> = Vec::new();
    for intent in intents {
        if let Some(existing) = catalog.leases.get(&intent.key) {
            bail!(
                "block volume for guest path {:?} is already attached to VM {:?}; detach or \
                 stop that VM before attaching another writer or reader",
                intent.record.volume_name,
                existing.vm_name
            );
        }
        if seen.contains(&intent.key.as_str()) {
            bail!(
                "block volume artifact for guest path {:?} is attached more than once in this \
                 launch",
                intent.record.volume_name
            );
        }
        seen.push(&intent.key);
    }
    Ok(())
}

/// RAII lease guard for one launch. Dropped uncommitted (failed launch, panic
/// unwind, early error) it releases every lease it took and re-seals any
/// just-in-time-unlocked volume; committed, the leases persist until the
/// owner's stop path calls [`release_leases_for_owner`].
#[derive(Debug)]
pub struct LaunchLease {
    owner: String,
    keys: Vec<String>,
    committed: bool,
}

impl LaunchLease {
    /// Persist `intents` as live leases. The caller holds the lifecycle lock
    /// and has already run [`check_lease_conflicts`].
    pub(crate) fn acquire(owner: &str, intents: Vec<LeaseIntent>) -> Result<Self> {
        let mut catalog = AttachmentLeaseCatalog::load()?;
        let mut keys = Vec::with_capacity(intents.len());
        for intent in intents {
            keys.push(intent.key.clone());
            catalog.leases.insert(intent.key, intent.record);
        }
        if !keys.is_empty() {
            catalog.save()?;
        }
        Ok(Self {
            owner: owner.to_string(),
            keys,
            committed: false,
        })
    }

    /// Mark the launch as successful: the leases outlive this guard.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    fn release(&self) -> Result<ReleaseOutcome> {
        if self.keys.is_empty() {
            return Ok(ReleaseOutcome::default());
        }
        let _lifecycle_lock = lifecycle::acquire_volume_lifecycle_lock()?;
        release_keys_for_owner(&self.owner, Some(&self.keys))
    }
}

impl Drop for LaunchLease {
    fn drop(&mut self) {
        if !self.committed
            && let Err(error) = self.release()
        {
            tracing::error!(
                vm = %self.owner,
                error = %error,
                "failed to roll back local volume attachment leases"
            );
        }
    }
}

/// Release every lease `owner` holds (all of them when `only_keys` is `None`),
/// re-sealing any volume the service unlocked just in time. Idempotent: a
/// second call finds nothing to release. The caller holds the lifecycle lock.
pub(crate) fn release_keys_for_owner(
    owner: &str,
    only_keys: Option<&[String]>,
) -> Result<ReleaseOutcome> {
    let mut catalog = AttachmentLeaseCatalog::load()?;
    let mut removed: Vec<AttachmentLeaseRecord> = Vec::new();
    catalog.leases.retain(|key, lease| {
        let owned =
            lease.vm_name == owner && only_keys.is_none_or(|keys| keys.iter().any(|k| k == key));
        if owned {
            removed.push(lease.clone());
        }
        !owned
    });
    if removed.is_empty() {
        return Ok(ReleaseOutcome::default());
    }
    catalog.save()?;

    let mut outcome = ReleaseOutcome {
        released: removed.len(),
        relocked: Vec::new(),
    };
    let relock: Vec<String> = removed
        .into_iter()
        .filter_map(|lease| lease.relock_volume)
        .collect();
    if !relock.is_empty() {
        let mut volume_catalog = lifecycle::recover_local_volume_catalog()?;
        for volume in relock {
            if lifecycle::relock_if_unlocked(&mut volume_catalog, &volume)
                .with_context(|| format!("re-sealing volume {volume:?} after lease release"))?
            {
                outcome.relocked.push(volume);
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_record_parses_the_historical_on_disk_shape() {
        let record: AttachmentLeaseRecord = serde_json::from_str(
            r#"{"vm_name":"vm-1","volume_name":"/data/work","read_only":true,
                "acquired_at":"2026-08-02T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(record.vm_name, "vm-1");
        assert_eq!(record.relock_volume, None);
    }

    #[test]
    fn lease_record_rejects_unknown_fields() {
        let err = serde_json::from_str::<AttachmentLeaseRecord>(
            r#"{"vm_name":"vm-1","volume_name":"w","read_only":true,
                "acquired_at":"t","smuggled":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn lease_key_is_stable_when_artifact_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let host_path = tmp.path().join("work.ext4");
        let absent = lease_key(&host_path).unwrap();
        fs::write(&host_path, b"volume").unwrap();
        let present = lease_key(&host_path).unwrap();
        assert_eq!(absent, present);
    }

    #[test]
    fn conflict_check_refuses_duplicate_artifact_in_one_launch() {
        let record = AttachmentLeaseRecord {
            vm_name: "vm-1".to_string(),
            volume_name: "/data/work".to_string(),
            read_only: true,
            acquired_at: "t".to_string(),
            relock_volume: None,
        };
        let intents = vec![
            LeaseIntent {
                key: "k1".to_string(),
                record: record.clone(),
            },
            LeaseIntent {
                key: "k1".to_string(),
                record,
            },
        ];
        // No live catalog needed for the duplicate check; an empty env still
        // finds the in-launch duplicate first when the catalog is empty.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let err = check_lease_conflicts(&intents).unwrap_err();
        assert!(
            err.to_string().contains("more than once in this"),
            "got: {err}"
        );
    }
}
