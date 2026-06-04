//! Supervisor-side config envelope signer (Plan 104 §H-L3.6 / G1).
//!
//! Holds the per-instance signing key the supervisor uses to wrap each
//! subprocess's startup `SubprocessConfig` bytes before writing them to
//! stdin. Each subprocess verifies the envelope (via
//! [`mvm_core::protocol::signed_config::verify_envelope`]) against a
//! pinned verifying key before deserialising the inner config.
//!
//! W1b.2b.3 ships this helper standalone. Wiring lands later:
//! - W1b.2b.3.5 (or folded into W1b.2b.5): each subprocess crate's
//!   `config::parse` switches to `parse_signed` that calls
//!   `verify_envelope` first. Unsigned `parse` deleted per no-backcompat.
//! - W1b.2b.5 (admission ceremony): `ConfigSigner` is constructed at
//!   supervisor startup and threaded into
//!   `ProcessSpawner::with_config_signer(...)` so the spawner wraps
//!   bytes before stdin write. The corresponding verifying key is
//!   handed to each subprocess at spawn time.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mvm_core::protocol::signed_config::{SignedConfigEnvelope, encode_envelope, wrap_payload};
use mvm_core::security::SIG_ALG_ED25519;
use rand::rngs::OsRng;

/// Per-instance config signer. The signing key lives in memory only —
/// it's generated at supervisor startup and zeroed on drop (Ed25519's
/// `SigningKey` implements `Zeroize` via its drop impl in
/// `ed25519-dalek` v2).
///
/// The verifying key is exposed via [`ConfigSigner::verifying_key`] so
/// the supervisor can pass it to subprocesses at spawn time (the
/// subprocess uses it to verify the envelope it receives on stdin).
#[derive(Debug)]
pub struct ConfigSigner {
    signing_key: SigningKey,
}

impl ConfigSigner {
    /// Generate a fresh signing key from `OsRng`. Each supervisor
    /// instance gets its own key (the per-spawn ephemeral pattern
    /// from Plan 104 §H-L4.2 — the wave that wraps the proxy seam,
    /// not this one — has the same lifetime semantics: bound to the
    /// supervisor process).
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Build a signer from an existing signing key. Test convenience —
    /// production callers should use [`ConfigSigner::generate`].
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// The verifying key the subprocess must use to verify the
    /// envelope. Supervisor hands this to each subprocess at spawn
    /// time.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Canonical `signer_key_id` (hex SHA-256 of the verifying key) —
    /// same shape the subprocess's verify path expects.
    pub fn signer_key_id(&self) -> String {
        SignedConfigEnvelope::key_id_for(&self.signing_key.verifying_key())
    }

    /// Wrap `payload` (the raw inner-config JSON bytes) in a signed
    /// envelope ready to write to subprocess stdin. The wire bytes
    /// are JSON; the inner payload is base64-encoded inside the
    /// envelope.
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(payload);
        let signer_key_id = self.signer_key_id();
        let envelope = wrap_payload(
            payload,
            SIG_ALG_ED25519,
            signer_key_id,
            &signature.to_bytes(),
        );
        encode_envelope(&envelope)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use mvm_core::protocol::signed_config::{decode_envelope, verify_envelope};

    use super::*;

    #[test]
    fn sign_then_decode_then_verify_round_trip() {
        let signer = ConfigSigner::generate();
        let vk = signer.verifying_key();
        let payload = br#"{"workload_id":"wl-1","tenant_id":"t-1"}"#;
        let env_bytes = signer.sign(payload);

        let env = decode_envelope(&env_bytes).expect("envelope must parse");
        let recovered = verify_envelope(&env, &vk).expect("verify must succeed");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sign_is_deterministic_for_a_given_key_and_payload() {
        // Ed25519 is deterministic-from-key — same SigningKey + same
        // payload always produces the same signature bytes.
        let mut rng = rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut rng);
        let signer_a = ConfigSigner::from_signing_key(sk.clone());
        let signer_b = ConfigSigner::from_signing_key(sk);
        let payload = b"deterministic";
        assert_eq!(signer_a.sign(payload), signer_b.sign(payload));
    }

    #[test]
    fn distinct_signers_produce_distinct_envelopes() {
        let signer_a = ConfigSigner::generate();
        let signer_b = ConfigSigner::generate();
        let payload = b"same payload";
        assert_ne!(signer_a.sign(payload), signer_b.sign(payload));
    }

    #[test]
    fn signer_key_id_matches_envelope_signer_key_id() {
        let signer = ConfigSigner::generate();
        let payload = b"key-id-test";
        let env_bytes = signer.sign(payload);
        let env = decode_envelope(&env_bytes).expect("envelope must parse");
        assert_eq!(env.signer_key_id, signer.signer_key_id());
    }

    #[test]
    fn envelope_from_signer_a_does_not_verify_against_signer_b_key() {
        let signer_a = ConfigSigner::generate();
        let signer_b = ConfigSigner::generate();
        let payload = b"cross-key-check";
        let env_bytes = signer_a.sign(payload);
        let env = decode_envelope(&env_bytes).expect("envelope must parse");
        let result = verify_envelope(&env, &signer_b.verifying_key());
        assert!(result.is_err(), "verify against wrong key must fail");
    }
}
