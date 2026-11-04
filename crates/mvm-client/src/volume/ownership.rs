//! Durable per-attempt ownership of the resources a transient launch takes.
//!
//! A transient launch registers volume attachments, takes attachment leases
//! and records a secret-reference sidecar. Automatic cleanup may only undo
//! what that attempt itself created, and only while nothing else has touched
//! it. The attempt writes a *receipt* naming exactly what it created, bound to
//! the owner's *epoch*: a counter, under a random incarnation, that every
//! supported registration writer advances while holding the volume lifecycle
//! lock. A receipt whose epoch no longer matches, or that is missing or
//! unreadable, never authorizes a destructive cleanup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::util::atomic_io::{FileLock, atomic_write};
use serde::{Deserialize, Serialize};

use super::lifecycle;
use sha2::{Digest, Sha256};

const EPOCH_FILENAME: &str = "volume_epoch.json";
const RECEIPT_FILENAME: &str = "volume-receipt.json";

/// A point in an owner's registration history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Epoch {
    incarnation: String,
    counter: u64,
}

fn epoch_path(owner: &str) -> PathBuf {
    mvm_core::config::instance_dir(owner).join(EPOCH_FILENAME)
}

/// The owner's current epoch. `None` when no registration writer has run;
/// an unreadable record is an error, never an empty history.
pub(crate) fn read_epoch(owner: &str) -> Result<Option<Epoch>> {
    read_json(&epoch_path(owner))
}

/// Advance the owner's epoch. Every writer of the owner's volume registry
/// calls this while holding the lifecycle lock, which the parameter proves.
pub(crate) fn advance_epoch(owner: &str, _lock: &FileLock) -> Result<Epoch> {
    let next = match read_epoch(owner)? {
        Some(current) => Epoch {
            counter: current.counter.saturating_add(1),
            ..current
        },
        None => Epoch {
            incarnation: uuid::Uuid::new_v4().simple().to_string(),
            counter: 1,
        },
    };
    write_json(&epoch_path(owner), &next)?;
    Ok(next)
}

/// One registration this attempt created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatedRegistration {
    pub(crate) volume: String,
    pub(crate) guest_path: String,
}

/// What one transient attempt created, and the epoch it created it at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionReceipt {
    generation: String,
    pub(crate) epoch: Option<Epoch>,
    #[serde(default)]
    pub(crate) created: Vec<CreatedRegistration>,
    #[serde(default)]
    pub(crate) lease_keys: Vec<String>,
    /// SHA-256 of the secret-reference sidecar this attempt wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret_refs_sha256: Option<String>,
}

impl SessionReceipt {
    /// A receipt for a fresh attempt with its own generation.
    pub(crate) fn begin() -> Self {
        Self {
            generation: uuid::Uuid::new_v4().simple().to_string(),
            epoch: None,
            created: Vec::new(),
            lease_keys: Vec::new(),
            secret_refs_sha256: None,
        }
    }

    /// Whether the owner's registrations are still exactly as this attempt
    /// left them.
    pub(crate) fn matches_current_epoch(&self, owner: &str) -> Result<bool> {
        Ok(self.epoch == read_epoch(owner)?)
    }
}

fn receipt_path(root: &Path, owner: &str) -> Result<PathBuf> {
    mvm_core::naming::validate_id(owner, "machine name")?;
    Ok(root.join(owner).join(RECEIPT_FILENAME))
}

/// The attempt's receipt. `None` when it never wrote one; an unreadable
/// receipt is an error so the caller retains rather than guesses.
pub(crate) fn load_receipt(root: &Path, owner: &str) -> Result<Option<SessionReceipt>> {
    read_json(&receipt_path(root, owner)?)
}

pub(crate) fn save_receipt(
    root: &Path,
    owner: &str,
    receipt: &SessionReceipt,
    _lock: &FileLock,
) -> Result<()> {
    write_json(&receipt_path(root, owner)?, receipt)
}

pub(crate) fn remove_receipt(root: &Path, owner: &str, _lock: &FileLock) -> Result<()> {
    let path = receipt_path(root, owner)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", path.display()))),
    }
}

/// Load `owner`'s receipt (or start one), change it, and persist it.
pub(crate) fn update_receipt(
    root: &Path,
    owner: &str,
    lock: &FileLock,
    change: impl FnOnce(&mut SessionReceipt),
) -> Result<()> {
    let mut receipt = load_receipt(root, owner)?.unwrap_or_else(SessionReceipt::begin);
    change(&mut receipt);
    save_receipt(root, owner, &receipt, lock)
}

impl SessionReceipt {
    fn holds_anything(&self) -> bool {
        !(self.created.is_empty()
            && self.lease_keys.is_empty()
            && self.secret_refs_sha256.is_none())
    }
}

/// Start a fresh attempt for `owner`. An earlier attempt whose receipt still
/// names resources has not been settled, so a new one is refused rather than
/// allowed to overwrite the only record of what to release.
pub(crate) fn begin_session(root: &Path, owner: &str) -> Result<()> {
    let lock = lifecycle::acquire_volume_lifecycle_lock()?;
    if load_receipt(root, owner)?.is_some_and(|earlier| earlier.holds_anything()) {
        anyhow::bail!(
            "machine {owner:?} still holds resources from an earlier launch that cleanup \
             retained; remove that machine first"
        );
    }
    let mut receipt = SessionReceipt::begin();
    receipt.epoch = read_epoch(owner)?;
    save_receipt(root, owner, &receipt, &lock)
}

/// Record the lease keys this attempt took.
pub(crate) fn note_leases(root: &Path, owner: &str, keys: &[String]) -> Result<()> {
    let lock = lifecycle::acquire_volume_lifecycle_lock()?;
    update_receipt(root, owner, &lock, |r| r.lease_keys = keys.to_vec())
}

/// Write the secret-reference sidecar for this attempt and bind its digest
/// into the receipt, under the lifecycle lock every other writer takes.
pub(crate) fn record_secret_refs(
    root: &Path,
    owner: &str,
    write: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let lock = lifecycle::acquire_volume_lifecycle_lock()?;
    write()?;
    let digest = file_digest(&crate::secret::refs::sidecar_path(root, owner)?)?;
    update_receipt(root, owner, &lock, |r| r.secret_refs_sha256 = digest)
}

/// Digest of a sidecar's exact bytes; `None` when it does not exist.
pub(crate) fn file_digest(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(hex::encode(Sha256::digest(bytes)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        mvm_core::config::create_private_dir(parent)
            .with_context(|| format!("creating parent of {}", path.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("serializing ownership record")?;
    atomic_write(path, &bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_matches_only_the_epoch_it_was_written_at() {
        let home = crate::volume::test_support::TestVolumeHome::new();
        let lock = super::super::lifecycle::acquire_volume_lifecycle_lock().unwrap();
        let mut receipt = SessionReceipt::begin();
        assert!(receipt.matches_current_epoch("owner").unwrap());
        receipt.epoch = Some(advance_epoch("owner", &lock).unwrap());
        assert!(receipt.matches_current_epoch("owner").unwrap());
        advance_epoch("owner", &lock).unwrap();
        assert!(!receipt.matches_current_epoch("owner").unwrap());
        drop((lock, home));
    }

    #[test]
    fn receipts_reject_unknown_fields() {
        let err = serde_json::from_str::<SessionReceipt>(
            r#"{"generation":"g","epoch":null,"smuggled":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
