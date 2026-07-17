//! Signed config envelope DTO + its error vocabulary.
//!
//! The wire shape only — wrapping, encoding, decoding, verifying, and
//! the key-id derivation (all of which need `ed25519-dalek`/`sha2` and
//! stay host-only) live in `mvm_core::protocol::signed_config`, which
//! re-exports [`SignedConfigEnvelope`] and [`SignedConfigError`] at
//! their existing paths.

use alloc::string::String;

use serde::{Deserialize, Serialize};

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignedConfigError {
    /// Envelope JSON did not parse.
    #[error("signed config: envelope parse failed: {source}")]
    EnvelopeParse {
        #[source]
        source: serde_json::Error,
    },
    /// Base64 decode of the payload or signature failed. Carries the
    /// formatted decode failure rather than `base64::DecodeError`
    /// itself — that type only implements `core::error::Error` under
    /// its `std` feature, which this no_std crate doesn't enable.
    #[error("signed config: base64 decode failed: {reason}")]
    BadEncoding { reason: String },
    /// Signature was the wrong length (Ed25519 is exactly 64 bytes).
    #[error("signed config: signature length {got} != expected {want}")]
    BadSignatureLength { got: usize, want: usize },
    /// The envelope's `signer_key_id` did not match the expected
    /// verifying key. Structurally distinct from `SignatureMismatch`
    /// so the audit trail can name the failure mode.
    #[error("signed config: signer_key_id {got} did not match expected {expected}")]
    UnexpectedSignerKey { got: String, expected: String },
    /// The signature didn't verify against the bundled key. Most
    /// likely cause: a compromised supervisor handed a forged config
    /// to a subprocess that's checking against the pinned release key.
    #[error("signed config: signature verification failed")]
    SignatureMismatch,
    /// `sig_alg` is not one this codepath knows how to verify.
    #[error("signed config: unsupported sig_alg {sig_alg} (only Ed25519 supported in W1b.2b.3)")]
    UnsupportedAlgorithm { sig_alg: u8 },
}

// ============================================================================
// Envelope
// ============================================================================

/// Wire envelope. The inner config bytes are base64-encoded so the
/// envelope is grep-friendly JSON; an alternative would have been
/// multipart binary, but the readability matches the project's other
/// audit / sidecar conventions. Per-byte overhead vs raw bytes is
/// ~33%, fine for a single subprocess startup config (~1-4 KiB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConfigEnvelope {
    /// Algorithm-identifier byte. One of `SIG_ALG_ED25519` or
    /// `SIG_ALG_ECDSA_P256` (the latter reserved for future use).
    pub sig_alg: u8,
    /// Hex-encoded SHA-256 of the signer's verifying key. Lets the
    /// subprocess sanity-check that the envelope is signed by the key
    /// it expects, *before* doing the more-expensive signature verify.
    pub signer_key_id: String,
    /// Base64-encoded inner config bytes (the
    /// `SubprocessConfig`-shaped JSON each subprocess crate parses).
    pub payload_b64: String,
    /// Base64-encoded signature over the (raw, pre-base64) inner
    /// config bytes.
    pub signature_b64: String,
}
