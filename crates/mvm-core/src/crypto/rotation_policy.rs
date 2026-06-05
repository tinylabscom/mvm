//! Plan 122 B1 — when to roll the master KEK.
//!
//! [`key_rotation::rotate_master_key`](crate::crypto::key_rotation::rotate_master_key)
//! performs a rotation; this module decides *whether* one is due. The age
//! check is pure — `now` is injected rather than read from the wall clock —
//! so the policy is testable without freezing time, and [`rotate_if_due`]
//! is the one place that combines the check with the rotate + DEK re-wrap
//! sweep.

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use secrecy::ExposeSecret;

use crate::crypto::key_rotation::{
    MasterKeyManifest, MigrationOutcome, load_manifest, load_master_key, migrate_wrapped_keys,
    rotate_master_key,
};
use crate::domain::volume::{MasterKeyRef, MasterKeyState, OrgId, WrappedKey};

/// Default KEK lifetime before rotation is due: 90 days.
pub const DEFAULT_INTERVAL_DAYS: i64 = 90;

/// The default 90-day rotation interval as a [`Duration`]. A function
/// rather than a `const` because `chrono::Duration::days` is not `const`.
pub fn default_interval() -> Duration {
    Duration::days(DEFAULT_INTERVAL_DAYS)
}

/// The single `Active` entry in the manifest, if any.
fn active_entry(manifest: &MasterKeyManifest) -> Option<&MasterKeyRef> {
    manifest
        .entries
        .iter()
        .find(|e| e.state == MasterKeyState::Active)
}

/// True when the manifest's active KEK is at least `interval` old as of
/// `now`.
///
/// No active key → not due: minting the first key is initial provisioning,
/// not rotation. `now` is a parameter so the check never reads the wall
/// clock — that keeps it a pure, freely-testable function (the plan's
/// "time comes in as a parameter" rule).
pub fn rotation_due(manifest: &MasterKeyManifest, interval: Duration, now: DateTime<Utc>) -> bool {
    match active_entry(manifest) {
        Some(active) => now.signed_duration_since(active.created_at) >= interval,
        None => false,
    }
}

/// Outcome of [`rotate_if_due`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationDecision {
    /// The active KEK is younger than the interval (or none exists): no-op.
    NotDue,
    /// Rotated from `from_version` to `to_version`; `migrated` DEKs were
    /// re-wrapped onto the new KEK.
    Rotated {
        from_version: u32,
        to_version: u32,
        migrated: usize,
    },
}

/// Rotate the org's master KEK if its active version is past `interval`,
/// then re-wrap every DEK in `keys` onto the new KEK.
///
/// `keys` are the wrapped DEKs the caller holds (e.g. the local volume
/// catalog's per-volume keys); on a rotation they are migrated in place
/// from the prior active version to the new one, and the caller persists
/// them afterwards. Re-wrapping leaves the underlying DEK — and thus the
/// on-disk ciphertext — untouched, which is why this is cheap and safe to
/// run on a hot path or at boot.
///
/// `keys` must all sit at the current active version (the invariant a
/// previous sweep maintains); a key at any other version makes
/// [`migrate_wrapped_keys`] refuse rather than guess. `now` is injected
/// for the same testability reason as [`rotation_due`].
pub fn rotate_if_due(
    active_dir: &Path,
    org_id: &OrgId,
    keys: &mut [WrappedKey],
    interval: Duration,
    now: DateTime<Utc>,
) -> Result<RotationDecision> {
    let manifest = load_manifest(active_dir)?;
    if !rotation_due(&manifest, interval, now) {
        return Ok(RotationDecision::NotDue);
    }
    // `rotation_due` returning true implies an Active entry exists.
    let from_version = active_entry(&manifest)
        .expect("rotation_due implies an active KEK")
        .version;

    let old_master = load_master_key(active_dir, from_version)?;
    let new_ref = rotate_master_key(active_dir, org_id)?;
    let new_master = load_master_key(active_dir, new_ref.version)?;

    let outcomes = migrate_wrapped_keys(
        keys,
        from_version,
        new_ref.version,
        old_master.expose_secret().as_slice(),
        new_master.expose_secret().as_slice(),
    )?;
    let migrated = outcomes
        .iter()
        .filter(|o| matches!(o, MigrationOutcome::Migrated))
        .count();
    Ok(RotationDecision::Rotated {
        from_version,
        to_version: new_ref.version,
        migrated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::snapshot_crypto;
    use crate::domain::volume::WrapAlgorithm;

    fn org() -> OrgId {
        OrgId::new("local").unwrap()
    }

    fn manifest_active_created_at(created_at: DateTime<Utc>) -> MasterKeyManifest {
        MasterKeyManifest {
            entries: vec![MasterKeyRef {
                org_id: org(),
                version: 1,
                created_at,
                state: MasterKeyState::Active,
            }],
        }
    }

    fn wrap(dek: &[u8], master: &secrecy::SecretBox<[u8; 32]>, version: u32) -> WrappedKey {
        WrappedKey {
            master_key_version: version,
            wrapped: snapshot_crypto::encrypt(dek, master.expose_secret().as_slice()).unwrap(),
            algorithm: WrapAlgorithm::Aes256Gcm,
            bound: None,
        }
    }

    #[test]
    fn kek_due_for_rotation_past_interval() {
        let now = Utc::now();
        let interval = default_interval();
        let stale = manifest_active_created_at(now - Duration::days(91));
        assert!(rotation_due(&stale, interval, now));
        let fresh = manifest_active_created_at(now - Duration::days(10));
        assert!(!rotation_due(&fresh, interval, now));
    }

    #[test]
    fn rotation_due_false_with_no_active_key() {
        let now = Utc::now();
        assert!(!rotation_due(
            &MasterKeyManifest::default(),
            default_interval(),
            now
        ));
    }

    #[test]
    fn rotate_if_due_is_noop_when_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let v1 = rotate_master_key(tmp.path(), &org()).unwrap();
        let m1 = load_master_key(tmp.path(), v1.version).unwrap();
        let mut keys = vec![wrap(&[0x11u8; 32], &m1, 1)];
        let before = keys.clone();

        // `now` ~= the key's creation time → not due.
        let decision = rotate_if_due(
            tmp.path(),
            &org(),
            &mut keys,
            default_interval(),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(decision, RotationDecision::NotDue);
        assert_eq!(keys, before, "no rewrap when not due");
        assert_eq!(
            load_manifest(tmp.path()).unwrap().latest_version(),
            1,
            "no new version minted"
        );
    }

    #[test]
    fn rotate_if_due_rotates_and_rewraps_when_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let v1 = rotate_master_key(tmp.path(), &org()).unwrap();
        let m1 = load_master_key(tmp.path(), 1).unwrap();
        let dek_a = [0xAAu8; 32];
        let dek_b = [0xBBu8; 32];
        let mut keys = vec![wrap(&dek_a, &m1, 1), wrap(&dek_b, &m1, 1)];

        // Treat "now" as 91 days after the active key was created → due.
        let now = v1.created_at + Duration::days(91);
        let decision =
            rotate_if_due(tmp.path(), &org(), &mut keys, default_interval(), now).unwrap();
        assert_eq!(
            decision,
            RotationDecision::Rotated {
                from_version: 1,
                to_version: 2,
                migrated: 2,
            }
        );

        // Both DEKs now ride v2 and recover unchanged.
        let m2 = load_master_key(tmp.path(), 2).unwrap();
        assert_eq!(keys[0].master_key_version, 2);
        assert_eq!(
            snapshot_crypto::decrypt(&keys[0].wrapped, m2.expose_secret().as_slice()).unwrap(),
            dek_a
        );
        assert_eq!(
            snapshot_crypto::decrypt(&keys[1].wrapped, m2.expose_secret().as_slice()).unwrap(),
            dek_b
        );

        // Manifest advanced; v1 retired to Legacy.
        let manifest = load_manifest(tmp.path()).unwrap();
        assert_eq!(manifest.latest_version(), 2);
        assert_eq!(manifest.get(1).unwrap().state, MasterKeyState::Legacy);
        assert_eq!(manifest.get(2).unwrap().state, MasterKeyState::Active);
    }
}
