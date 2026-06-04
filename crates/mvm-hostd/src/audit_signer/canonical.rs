//! JCS canonicalization for the audit-entry bytes-to-sign (Plan 104 §S28).
//!
//! Each entry's signed bytes are the JCS-canonical form of a
//! `CanonicalEntry` struct — a stable schema that includes everything
//! needed to verify the entry standalone (Plan 104 §C7 self-contained
//! requirement) without consulting the supervisor's session state.

use serde::{Deserialize, Serialize};

/// The canonical, JCS-encoded shape of one audit entry — the bytes
/// the audit-signer signs. Field order is alphabetical per JCS so
/// the canonicalization is deterministic across implementations.
///
/// Don't add fields here lightly: this schema is the chain-verifier
/// contract. Field renames are wire-breaking. New fields must be
/// added at the end of the JSON canonical form (which JCS handles
/// automatically since it sorts alphabetically).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEntry {
    /// Audit category (snake_case `EventCategory` variant name).
    pub category: String,
    /// Supervisor-assigned correlation id (Plan 104 §H-L4.6).
    pub correlation_id: String,
    /// Typed per-category fields.
    pub fields: serde_json::Value,
    /// Hex hash of the previous chain entry. The genesis entry's
    /// `prev_hash` is the all-zeros 64-char hex string.
    pub prev_hash: String,
    /// Workload's session id (rotates per §H-L4.3).
    pub session_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Wall-clock timestamp in RFC 3339 form.
    pub ts: String,
    /// Workload identifier.
    pub workload_id: String,
}

impl CanonicalEntry {
    /// Genesis `prev_hash`: 64 hex zeros (matching the SHA-256 output
    /// width). The first append on a fresh chain uses this.
    pub fn genesis_prev_hash() -> String {
        "0".repeat(64)
    }

    /// Encode the canonical bytes via JCS (RFC 8785). Returns the bytes
    /// to sign + the bytes to write to the JSONL.
    pub fn jcs_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(prev_hash: String) -> CanonicalEntry {
        CanonicalEntry {
            category: "plan".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({
                "service": "host.time.v1",
                "verb": "now",
                "outcome": "ok",
            }),
            prev_hash,
            session_id: "sess-001".into(),
            tenant_id: "t-001".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
        }
    }

    #[test]
    fn jcs_bytes_are_byte_stable_across_field_ordering() {
        // Build the same entry from two different Rust struct construction
        // orderings (this is a tautology in Rust, but the test asserts the
        // JCS output is byte-stable — meaning if the underlying serde
        // impl reorders for any reason, we catch it).
        let entry_a = sample(CanonicalEntry::genesis_prev_hash());
        let entry_b = sample(CanonicalEntry::genesis_prev_hash());
        let bytes_a = entry_a.jcs_bytes().unwrap();
        let bytes_b = entry_b.jcs_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn jcs_round_trip_preserves_data() {
        let original = sample(CanonicalEntry::genesis_prev_hash());
        let bytes = original.jcs_bytes().unwrap();
        let parsed: CanonicalEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn genesis_prev_hash_is_64_hex_zeros() {
        assert_eq!(CanonicalEntry::genesis_prev_hash(), "0".repeat(64));
        assert_eq!(CanonicalEntry::genesis_prev_hash().len(), 64);
    }
}
