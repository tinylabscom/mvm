//! VMGenID-style generation token for snapshot-resume reseed.
//!
//! Resuming two clones of one snapshot leaves both guests with identical
//! CSPRNG state — they'd generate the same nonces/keys, a real key-reuse
//! break. Hardware VMGenID exists on Firecracker but not libkrun/Vz, so the
//! host emits a fresh generation token over the config/vsock path on every
//! resume; the guest reseeds and drops its session when the token changes.
//!
//! The token is bound to the snapshot's content-address so a token minted
//! for one snapshot can't be replayed onto a different one.
//!
//! This module is the shared substrate: the host mints tokens
//! ([`fresh_generation_token`]); the guest tracks them (`GenIdState`) and
//! performs the reseed itself (the I/O side effect is kept out of here so the
//! change-detection stays pure and unit-testable).

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Generation-token width, in bytes. Mirrors the ACPI VMGenID's 128 bits.
pub const GENID_BYTES: usize = 16;

/// A fresh generation token plus the snapshot content-address it's bound to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationToken {
    /// Fresh random per resume — the reseed nonce the guest mixes in.
    pub token: [u8; GENID_BYTES],
    /// sha256-hex of the snapshot this token was minted for.
    /// The guest refuses a token whose binding doesn't match the snapshot it
    /// resumed, so a token can't be replayed onto a different snapshot.
    pub content_hash: String,
}

// allow(secret-debug): the token is a public reseed nonce, not a secret —
// but redact it anyway so it doesn't litter logs, printing only the binding.
impl std::fmt::Debug for GenerationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationToken")
            .field("token", &format_args!("<{GENID_BYTES} bytes>"))
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

/// Mint a fresh generation token bound to `content_hash`. Drawn from the OS
/// CSPRNG so every resume — including two clones of the same snapshot — gets
/// a distinct token, which is what forces the clones' CSPRNGs to diverge.
pub fn fresh_generation_token(content_hash: impl Into<String>) -> GenerationToken {
    let mut token = [0u8; GENID_BYTES];
    OsRng.fill_bytes(&mut token);
    GenerationToken {
        token,
        content_hash: content_hash.into(),
    }
}

/// Guest-side tracker: remembers the last generation token and reports
/// whether a newly-delivered one changed (→ the guest must reseed its CSPRNG
/// and drop its session). Pure — the reseed action itself is the guest's,
/// kept out of here so the decision is unit-testable.
#[derive(Debug, Clone)]
pub struct GenIdState {
    current: [u8; GENID_BYTES],
}

impl GenIdState {
    /// Seed the tracker with the token present at first boot/resume.
    pub const fn new(initial: [u8; GENID_BYTES]) -> Self {
        Self { current: initial }
    }

    /// Record `token`; return `true` iff it differs from the last one seen —
    /// the signal to reseed the CSPRNG and reset the session. Unchanged
    /// tokens are a no-op (a normal wake of the same VM, not a clone).
    pub fn on_genid(&mut self, token: [u8; GENID_BYTES]) -> bool {
        if token == self.current {
            false
        } else {
            self.current = token;
            true
        }
    }

    /// The token currently held.
    pub fn current(&self) -> [u8; GENID_BYTES] {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_tokens_are_distinct_for_same_snapshot() {
        // Two resumes of the same snapshot (same content-address) must still
        // get distinct tokens — that distinctness is what diverges the clones.
        let a = fresh_generation_token("deadbeef");
        let b = fresh_generation_token("deadbeef");
        assert_ne!(a.token, b.token);
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn token_is_bound_to_content_hash() {
        let t = fresh_generation_token("abc123");
        assert_eq!(t.content_hash, "abc123");
    }

    #[test]
    fn changed_genid_signals_reseed_unchanged_is_noop() {
        let mut s = GenIdState::new([1u8; GENID_BYTES]);
        assert!(!s.on_genid([1u8; GENID_BYTES]), "unchanged -> no reseed");
        assert!(s.on_genid([2u8; GENID_BYTES]), "changed -> reseed + reset");
        // Now [2;16] is current; presenting it again is a no-op.
        assert!(!s.on_genid([2u8; GENID_BYTES]));
        assert_eq!(s.current(), [2u8; GENID_BYTES]);
    }

    #[test]
    fn generation_token_serde_roundtrip() {
        let t = fresh_generation_token("feed");
        let json = serde_json::to_string(&t).unwrap();
        let back: GenerationToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
