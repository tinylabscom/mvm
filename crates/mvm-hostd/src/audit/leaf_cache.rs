//! Cached leaf hashes for the prefix of an audit chain a published root
//! already attests.
//!
//! # Why a cache here is not a trust decision
//!
//! Believing a stored value about a log is what [`ChainCheckpoint`] gives up,
//! and why that fast path is confined to `doctor`. This one is different.
//!
//! The cache holds the leaf hashes of the first `tree_size` entries. A
//! published [`SignedAuditRoot`](mvm_contract::merkle::SignedAuditRoot) is a
//! host-signed statement that those leaves fold to `root_hash`. So the cache is
//! not believed — it is *checked*, by folding it and comparing against that
//! signature. A cache that has been corrupted, truncated, replaced or forged
//! does not fold to the signed root, and is discarded.
//!
//! What that buys is the cost model. Hashing leaves is proportional to the
//! log's bytes; folding leaf hashes is proportional to its entries, at 32 bytes
//! each. Re-deriving an unchanged prefix meant re-reading tens of megabytes of
//! JSON on every launch. Checking it means folding a few hundred kilobytes.
//!
//! # What it establishes about the files
//!
//! The fold proves the cached hashes are the ones the signed root committed
//! to. It says nothing about whether the segments those leaves came from still
//! hold the same bytes. Two different answers apply, on purpose:
//!
//! - **The live segment is read in full every time**, and the loader compares
//!   its cached portion line by line. An edit there is caught at publish time,
//!   exactly as before.
//! - **Sealed segments are not read.** They are checked by
//!   [`SealedFingerprint`] — sequence number, length and mtime. An edit that
//!   changes any of those is a miss and reaches the genesis walk; an edit that
//!   preserves all three is not caught here.
//!
//! That last case is a narrowing, and it is deliberate. Re-reading the sealed
//! set is the entire cost this module exists to remove, and the tamper it would
//! catch is a malicious host writing under `~/.mvm/audit/` — explicitly outside
//! the model where the host is trusted. It remains caught by `mvmctl trust audit verify`,
//! which always walks every interior from genesis, by `doctor`, and by any
//! inclusion proof, which re-hashes the real line. A root published over a
//! stale cache commits to the leaves the log actually had, so nothing here ever
//! signs a statement blessing altered content.
//!
//! [`ChainCheckpoint`]: crate::supervisor::audit_file::ChainCheckpoint

use std::path::{Path, PathBuf};

use mvm_contract::merkle::merkle_root_of_leaf_hashes;

/// File magic. A cache from a different build is a miss, not an error.
const MAGIC: &[u8; 8] = b"MVMLEAF2";

/// Bump when the layout below changes. An older file fails to parse and the
/// caller falls back, so this needs no migration path.
const VERSION: u32 = 2;

/// What a sealed segment looked like when the cache was written.
///
/// Not a hash: hashing means reading, and reading the sealed set is the cost
/// being removed. See this module's header for what that does and does not
/// establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedFingerprint {
    /// Sequence number.
    pub seq: u64,
    /// Length in bytes.
    pub len: u64,
    /// Modification time, nanoseconds since the Unix epoch. Zero when the
    /// platform did not supply one — which makes the field carry no evidence
    /// rather than false evidence, since a stored zero then matches a probed
    /// zero and the length still has to agree.
    pub mtime_nanos: u64,
}

impl SealedFingerprint {
    /// Fingerprint a sealed segment on disk, or `None` if it cannot be stat'd.
    #[must_use]
    pub fn probe(seq: u64, path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(0);
        Some(Self {
            seq,
            len: meta.len(),
            mtime_nanos,
        })
    }
}

/// Leaf hashes for an attested prefix, plus what they were derived against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCache {
    /// Every sealed segment, oldest first.
    pub sealed: Vec<SealedFingerprint>,
    /// Sequence number of the live segment.
    pub active_seq: u64,
    /// How many of the live segment's non-blank lines are inside the prefix.
    /// The rest of that segment is the suffix a loader still has to verify.
    pub prefix_lines_in_active: u64,
    /// One hash per attested leaf, in chain order.
    pub leaf_hashes: Vec<[u8; 32]>,
}

impl LeafCache {
    /// Leaves this cache covers.
    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    /// Whether these leaves fold to `root_hash`.
    ///
    /// The only reason to trust anything here. `root_hash` must come from a
    /// signature that has already been verified — this compares a fold to a
    /// string and cannot tell where the string came from.
    #[must_use]
    pub fn folds_to(&self, root_hash: &str) -> bool {
        hex::encode(merkle_root_of_leaf_hashes(&self.leaf_hashes)) == root_hash
    }

    /// The cached leaf hashes covering the live segment's first
    /// `prefix_lines_in_active` lines, or `None` if the cache is too small to
    /// hold them.
    #[must_use]
    pub fn active_prefix_hashes(&self) -> Option<&[[u8; 32]]> {
        let lines = usize::try_from(self.prefix_lines_in_active).ok()?;
        let start = self.leaf_hashes.len().checked_sub(lines)?;
        Some(&self.leaf_hashes[start..])
    }

    /// Encode for [`write`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.sealed.len() * 24 + self.leaf_hashes.len() * 32);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(self.sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.active_seq.to_le_bytes());
        out.extend_from_slice(&self.prefix_lines_in_active.to_le_bytes());
        out.extend_from_slice(&self.tree_size().to_le_bytes());
        for seg in &self.sealed {
            out.extend_from_slice(&seg.seq.to_le_bytes());
            out.extend_from_slice(&seg.len.to_le_bytes());
            out.extend_from_slice(&seg.mtime_nanos.to_le_bytes());
        }
        for hash in &self.leaf_hashes {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Decode, or `None` for anything that is not exactly this layout.
    ///
    /// Every malformed case is a miss rather than an error: the cache is an
    /// optimisation, and the fallback re-derives everything it would supply.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = bytes.strip_prefix(MAGIC)?;
        let version = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
        if version != VERSION {
            return None;
        }
        let sealed_count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
        let active_seq = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
        let prefix_lines_in_active = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
        let tree_size =
            usize::try_from(u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?)).ok()?;

        // Both counts came out of the file, so neither may size an allocation
        // before the bytes to fill it are known to be present. A file claiming
        // `u64::MAX` leaves would otherwise abort the process on
        // `Vec::with_capacity` rather than being the miss it is. Requiring the
        // body to be exactly this long also rejects trailing bytes.
        let body = sealed_count
            .checked_mul(24)?
            .checked_add(tree_size.checked_mul(32)?)?;
        if cursor.len() != body {
            return None;
        }

        let mut sealed = Vec::with_capacity(sealed_count);
        for _ in 0..sealed_count {
            sealed.push(SealedFingerprint {
                seq: u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?),
                len: u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?),
                mtime_nanos: u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?),
            });
        }
        let mut leaf_hashes = Vec::with_capacity(tree_size);
        for _ in 0..tree_size {
            let hash: [u8; 32] = take(&mut cursor, 32)?.try_into().ok()?;
            leaf_hashes.push(hash);
        }
        Some(Self {
            sealed,
            active_seq,
            prefix_lines_in_active,
            leaf_hashes,
        })
    }
}

/// Split `n` bytes off the front of `cursor`, or `None` if it is shorter.
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cursor.len() < n {
        return None;
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Some(head)
}

/// Where a tenant's cache lives.
#[must_use]
pub fn path_for_tenant(audit_dir: &Path, tenant: &str) -> PathBuf {
    audit_dir.join(format!("{tenant}.leafhashes"))
}

/// Load a tenant's cache, or `None` when there is not a readable one.
#[must_use]
pub fn read(audit_dir: &Path, tenant: &str) -> Option<LeafCache> {
    LeafCache::decode(&std::fs::read(path_for_tenant(audit_dir, tenant)).ok()?)
}

/// Persist a tenant's cache, best effort and without an fsync.
///
/// A write failure is dropped on purpose, and so is the durability barrier the
/// chain's own writes take. This is derived state: a cache lost to a crash is
/// re-derived on the next launch, and paying `F_FULLFSYNC` to protect it would
/// spend more than it saves — which is the whole reason this file exists.
///
/// The write is still atomic, so a torn cache is never observed.
pub(crate) fn write(audit_dir: &Path, tenant: &str, cache: &LeafCache) {
    let path = path_for_tenant(audit_dir, tenant);
    if let Err(e) = crate::audit::emitter::write_atomic_unsynced(&path, &cache.encode()) {
        tracing::debug!(error = %e, path = %path.display(), "could not persist the audit leaf cache");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::merkle::{leaf_hash, merkle_root};

    fn fingerprints() -> Vec<SealedFingerprint> {
        vec![
            SealedFingerprint {
                seq: 1,
                len: 4096,
                mtime_nanos: 1_700_000_000_000_000_000,
            },
            SealedFingerprint {
                seq: 2,
                len: 8192,
                mtime_nanos: 1_700_000_001_000_000_000,
            },
        ]
    }

    fn cache_of(lines: &[&str]) -> LeafCache {
        LeafCache {
            sealed: fingerprints(),
            active_seq: 3,
            prefix_lines_in_active: 2,
            leaf_hashes: lines.iter().map(|l| leaf_hash(l.as_bytes())).collect(),
        }
    }

    #[test]
    fn a_cache_round_trips_through_its_encoding() {
        let cache = cache_of(&["a", "b", "c"]);
        assert_eq!(LeafCache::decode(&cache.encode()), Some(cache));
    }

    #[test]
    fn an_empty_cache_round_trips() {
        let cache = LeafCache {
            sealed: Vec::new(),
            active_seq: 0,
            prefix_lines_in_active: 0,
            leaf_hashes: Vec::new(),
        };
        assert_eq!(LeafCache::decode(&cache.encode()), Some(cache));
    }

    #[test]
    fn a_cache_folds_to_the_root_its_lines_produce() {
        let lines = ["a", "b", "c", "d", "e"];
        let expected = hex::encode(merkle_root(&lines));
        assert!(cache_of(&lines).folds_to(&expected));
    }

    #[test]
    fn a_cache_whose_hashes_were_altered_does_not_fold_to_the_root() {
        let lines = ["a", "b", "c"];
        let expected = hex::encode(merkle_root(&lines));
        let mut cache = cache_of(&lines);
        cache.leaf_hashes[1][0] ^= 0xff;
        assert!(
            !cache.folds_to(&expected),
            "a flipped leaf hash must not fold to the signed root"
        );
    }

    #[test]
    fn the_active_prefix_hashes_are_the_tail_of_the_cache() {
        // The live segment's cached lines are the *end* of the prefix, because
        // the live segment is the end of the set. Taking them from the front
        // would compare the wrong lines and reject every healthy chain.
        let lines = ["a", "b", "c", "d"];
        let cache = cache_of(&lines);
        let tail = cache.active_prefix_hashes().expect("two lines fit");
        assert_eq!(
            tail,
            [leaf_hash(b"c"), leaf_hash(b"d")],
            "the active prefix must be the last `prefix_lines_in_active` hashes"
        );
    }

    #[test]
    fn an_active_prefix_larger_than_the_cache_has_no_hashes() {
        let mut cache = cache_of(&["a"]);
        cache.prefix_lines_in_active = 9;
        assert!(cache.active_prefix_hashes().is_none());
    }

    #[test]
    fn a_truncated_cache_is_a_miss_rather_than_a_short_read() {
        // The tail is the leaf hashes, so a truncation that keeps the header
        // would otherwise decode as a smaller, self-consistent tree.
        let encoded = cache_of(&["a", "b", "c"]).encode();
        assert!(LeafCache::decode(&encoded[..encoded.len() - 8]).is_none());
    }

    #[test]
    fn trailing_bytes_are_a_miss() {
        let mut encoded = cache_of(&["a", "b"]).encode();
        encoded.push(0);
        assert!(LeafCache::decode(&encoded).is_none());
    }

    #[test]
    fn a_foreign_or_reversioned_file_is_a_miss() {
        assert!(LeafCache::decode(b"not a leaf cache at all").is_none());
        let mut encoded = cache_of(&["a"]).encode();
        encoded[8] = 0xff;
        assert!(LeafCache::decode(&encoded).is_none());
    }

    #[test]
    fn a_declared_size_larger_than_the_body_is_a_miss() {
        // The length prefixes are attacker-controlled in the sense that
        // anything can write this file. An over-large declaration must not
        // become a huge allocation followed by a short read: `with_capacity`
        // aborts rather than returning an error, so this is a crash and not a
        // miss unless the body length is checked first.
        //
        // tree_size sits at 32..40 — magic(8) + version(4) + sealed_count(4) +
        // active_seq(8) + prefix_lines(8).
        let mut encoded = cache_of(&["a", "b"]).encode();
        encoded[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(LeafCache::decode(&encoded).is_none());
    }

    #[test]
    fn a_fingerprint_notices_a_changed_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.jsonl");
        std::fs::write(&path, b"one").unwrap();
        let before = SealedFingerprint::probe(1, &path).unwrap();
        std::fs::write(&path, b"one more").unwrap();
        let after = SealedFingerprint::probe(1, &path).unwrap();
        assert_ne!(
            before, after,
            "a rewritten segment must not fingerprint the same"
        );
    }

    #[test]
    fn a_missing_segment_cannot_be_fingerprinted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SealedFingerprint::probe(1, &dir.path().join("absent.jsonl")).is_none());
    }
}
