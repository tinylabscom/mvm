//! [`StreamRecord`]: one hash-chained chunk of captured workload output,
//! plus the [`StreamSource`]/[`StreamKind`] tags that classify it.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation prefix for [`StreamRecord::hash`]. Distinct from
/// `merkle::LEAF_PREFIX` (0x00) and `merkle::INTERIOR_PREFIX` (0x01) so a
/// stream-record hash can never be presented as a Merkle leaf or interior
/// hash, or vice versa.
const STREAM_RECORD_PREFIX: u8 = 0x02;

/// Which process produced a [`StreamRecord`].
///
/// Discriminants are explicit and folded into [`StreamRecord::hash`], so
/// they are a wire-stable encoding, not just a Rust implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum StreamSource {
    /// The interactive dev console (PTY-over-vsock).
    Console = 0,
    /// The workload entrypoint process.
    Entrypoint = 1,
}

/// Which output channel a [`StreamRecord`] carries.
///
/// Discriminants are explicit and folded into [`StreamRecord::hash`], so
/// they are a wire-stable encoding, not just a Rust implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum StreamKind {
    /// Standard output bytes.
    Stdout = 0,
    /// Standard error bytes.
    Stderr = 1,
    /// A structured control/trace record rather than raw stdio bytes.
    Trace = 2,
}

/// One hash-chained chunk of captured workload output.
///
/// `prev_hash` links each record to [`StreamRecord::hash`] of its
/// predecessor — the same chaining shape [`crate::verify`] gives the audit
/// log, applied per output stream rather than per tenant. The first record
/// of a whole stream carries an all-zero `prev_hash`; `stream::verify_chain`
/// enforces that genesis marker plus the unbroken link for every record
/// after it, while `stream::verify_chain_from` accepts any caller-supplied
/// anchor in place of the zero marker, for verifying a partial window of a
/// longer chain instead of the whole thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecord {
    /// 0-based position of this record in its stream.
    pub seq: u64,
    /// Which process produced this record.
    pub source: StreamSource,
    /// Which output channel this record carries.
    pub kind: StreamKind,
    /// Host wall-clock at capture time, nanoseconds since the Unix epoch.
    pub host_unix_nanos: u64,
    /// [`StreamRecord::hash`] of the previous record, or all-zero for the
    /// first record in the chain.
    pub prev_hash: [u8; 32],
    /// Captured bytes: raw stdio for `Stdout`/`Stderr`, an encoded control
    /// message for `Trace`.
    pub payload: Vec<u8>,
}

impl StreamRecord {
    /// Hash this record: a domain-separated SHA-256 over every field, in
    /// declaration order, each fixed-width field folded in ahead of the
    /// variable-length `payload` that trails them. The
    /// [`STREAM_RECORD_PREFIX`] tag keeps this hash space disjoint from a
    /// Merkle leaf or interior hash over the same bytes.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([STREAM_RECORD_PREFIX]);
        hasher.update(self.seq.to_be_bytes());
        hasher.update([self.source as u8]);
        hasher.update([self.kind as u8]);
        hasher.update(self.host_unix_nanos.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(&self.payload);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> StreamRecord {
        StreamRecord {
            seq: 0,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stdout,
            host_unix_nanos: 1_000,
            prev_hash: [0u8; 32],
            payload: vec![b'a'],
        }
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(sample().hash(), sample().hash());
    }

    #[test]
    fn hash_is_sensitive_to_every_field() {
        let base = sample().hash();

        let mut r = sample();
        r.seq = 1;
        assert_ne!(r.hash(), base, "seq");

        let mut r = sample();
        r.source = StreamSource::Console;
        assert_ne!(r.hash(), base, "source");

        let mut r = sample();
        r.kind = StreamKind::Stderr;
        assert_ne!(r.hash(), base, "kind");

        let mut r = sample();
        r.host_unix_nanos = 2_000;
        assert_ne!(r.hash(), base, "host_unix_nanos");

        let mut r = sample();
        r.prev_hash = [1u8; 32];
        assert_ne!(r.hash(), base, "prev_hash");

        let mut r = sample();
        r.payload = vec![b'b'];
        assert_ne!(r.hash(), base, "payload");
    }

    #[test]
    fn hash_does_not_collide_with_a_merkle_leaf_or_interior_hash() {
        let r = sample();
        assert_ne!(r.hash(), crate::merkle::leaf_hash(&r.payload));
        assert_ne!(
            r.hash(),
            crate::merkle::interior_hash(&r.prev_hash, &r.prev_hash)
        );
    }

    #[test]
    fn serde_round_trip() {
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        let back: StreamRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn rejects_unknown_field() {
        let r = sample();
        let mut value = serde_json::to_value(&r).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<StreamRecord>(&json).is_err());
    }
}
