//! Versioned index of promoted packs with one active pointer per key.
//!
//! Pure in-memory data + logic: no filesystem access, no clock reads. A
//! caller records each promoted pack with its own recency timestamp, then
//! decides which version is "active" per `(kind, arch, backend)` slot.
//! Persisting this index and wiring it into `resolve_pack`'s lookup are
//! separate concerns handled elsewhere.

use serde::{Deserialize, Serialize};

use crate::arch::GuestArch;
use crate::packs::{PackBackend, PackKind, Sha256Hex};

/// Identifies one pack slot — a `(kind, arch, backend)` combination that can
/// have multiple promoted versions and exactly one active pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackKey {
    pub kind: PackKind,
    pub arch: GuestArch,
    pub backend: PackBackend,
}

/// One promoted pack version recorded in the index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackEntry {
    pub pack_hash: Sha256Hex,
    pub key: PackKey,
    /// `trust.channel_identity` from the pack manifest.
    pub channel: String,
    /// The release version from the download context, e.g. `"v0.17.0"`.
    pub release_version: String,
    /// Unix timestamp used for recency ordering; supplied by the caller —
    /// this type never reads the clock.
    pub promoted_at_unix: u64,
}

/// Versioned index of promoted packs, with one active pointer per
/// [`PackKey`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackIndex {
    entries: Vec<PackEntry>,
    active: Vec<(PackKey, Sha256Hex)>,
}

impl PackIndex {
    /// Upsert `e` by `pack_hash` — an existing entry with the same hash is
    /// replaced in place. The first entry ever recorded for `e.key` becomes
    /// that key's active version.
    pub fn record(&mut self, e: PackEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|entry| entry.pack_hash == e.pack_hash)
        {
            *existing = e;
            return;
        }
        let is_first_for_key = !self.entries.iter().any(|entry| entry.key == e.key);
        let key = e.key.clone();
        let hash = e.pack_hash.clone();
        self.entries.push(e);
        if is_first_for_key {
            self.active.push((key, hash));
        }
    }

    /// Point `key`'s active version at `hash`. Returns `false` and leaves the
    /// index unchanged if `hash` is not a recorded entry for `key`.
    pub fn set_active(&mut self, key: &PackKey, hash: &Sha256Hex) -> bool {
        if !self
            .entries
            .iter()
            .any(|entry| &entry.key == key && &entry.pack_hash == hash)
        {
            return false;
        }
        if let Some(slot) = self.active.iter_mut().find(|(k, _)| k == key) {
            slot.1 = hash.clone();
        } else {
            self.active.push((key.clone(), hash.clone()));
        }
        true
    }

    /// The active hash for `key`, if any.
    pub fn active_for(&self, key: &PackKey) -> Option<&Sha256Hex> {
        self.active
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, hash)| hash)
    }

    /// Every recorded entry, across every key, in insertion order. Used by
    /// callers that enumerate the whole index (e.g. an unfiltered version
    /// listing) rather than one key's versions.
    pub fn entries(&self) -> &[PackEntry] {
        &self.entries
    }

    /// Every recorded version for `key`, newest `promoted_at_unix` first.
    pub fn versions_for(&self, key: &PackKey) -> Vec<&PackEntry> {
        let mut versions: Vec<&PackEntry> = self
            .entries
            .iter()
            .filter(|entry| &entry.key == key)
            .collect();
        versions.sort_by_key(|entry| std::cmp::Reverse(entry.promoted_at_unix));
        versions
    }

    /// Drop the entry with `hash` and any active pointer referencing it.
    pub fn remove(&mut self, hash: &Sha256Hex) {
        self.entries.retain(|entry| &entry.pack_hash != hash);
        self.active.retain(|(_, active_hash)| active_hash != hash);
    }

    /// Per key: every hash except the active one and the newest
    /// `keep_recent` by `promoted_at_unix`.
    pub fn prunable(&self, keep_recent: usize) -> Vec<Sha256Hex> {
        let mut keys: Vec<&PackKey> = Vec::new();
        for entry in &self.entries {
            if !keys.iter().any(|seen| **seen == entry.key) {
                keys.push(&entry.key);
            }
        }
        let mut out = Vec::new();
        for key in keys {
            let versions = self.versions_for(key);
            let active = self.active_for(key);
            for (idx, entry) in versions.iter().enumerate() {
                let is_active = active == Some(&entry.pack_hash);
                let is_kept_recent = idx < keep_recent;
                if !is_active && !is_kept_recent {
                    out.push(entry.pack_hash.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::GuestArch;
    use crate::packs::{PackBackend, PackKind};

    fn key() -> PackKey {
        PackKey {
            kind: PackKind::Builder,
            arch: GuestArch::Aarch64,
            backend: PackBackend::Libkrun,
        }
    }
    fn entry(hash: &str, ver: &str, at: u64) -> PackEntry {
        PackEntry {
            pack_hash: Sha256Hex::new(hash).unwrap(),
            key: key(),
            channel: "stable".into(),
            release_version: ver.into(),
            promoted_at_unix: at,
        }
    }

    #[test]
    fn first_record_becomes_active() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        assert_eq!(
            ix.active_for(&key()),
            Some(&Sha256Hex::new("a".repeat(64)).unwrap())
        );
    }

    #[test]
    fn record_second_does_not_change_active_but_lists_both_newest_first() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        ix.record(entry(&"b".repeat(64), "v0.18.0", 20));
        assert_eq!(
            ix.active_for(&key()),
            Some(&Sha256Hex::new("a".repeat(64)).unwrap())
        );
        let v = ix.versions_for(&key());
        assert_eq!(v[0].release_version, "v0.18.0"); // newest first
        assert_eq!(v[1].release_version, "v0.17.0");
    }

    #[test]
    fn set_active_rejects_unknown_hash() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        assert!(!ix.set_active(&key(), &Sha256Hex::new("c".repeat(64)).unwrap()));
        assert!(ix.set_active(&key(), &Sha256Hex::new("a".repeat(64)).unwrap()));
    }

    #[test]
    fn remove_drops_entry_and_active_ref() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        ix.remove(&Sha256Hex::new("a".repeat(64)).unwrap());
        assert_eq!(ix.active_for(&key()), None);
        assert!(ix.versions_for(&key()).is_empty());
    }

    #[test]
    fn prunable_keeps_active_and_newest_n() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10)); // active
        ix.record(entry(&"b".repeat(64), "v0.18.0", 20));
        ix.record(entry(&"c".repeat(64), "v0.19.0", 30));
        // keep active (a) + newest 1 (c) -> b is prunable
        let p = ix.prunable(1);
        assert_eq!(p, vec![Sha256Hex::new("b".repeat(64)).unwrap()]);
    }

    #[test]
    fn json_roundtrip_denies_unknown_fields() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        let s = serde_json::to_string(&ix).unwrap();
        let back: PackIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(ix, back);
    }
}
