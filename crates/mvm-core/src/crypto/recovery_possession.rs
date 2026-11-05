//! Recovery possession only, not peer authentication or lifecycle authority.
//!
//! A receiver must retain its own expectation, authenticate the actual connected
//! peer and original owner, consume the challenge/sequence, and operate only on
//! that retained owner. Public channel nonces do not prevent socket forwarding.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand::Rng as _;
use serde::{Deserialize, Serialize};

use super::entrypoint_identity::EnrolledIdentity;
use crate::protocol::hvf_owner::{REQUEST_VERSION, RecoveryPhase, UntrustedRecoveryRequest};

const DOMAIN: &[u8] = b"mvm.controlling-principal.recovery-possession.v1\0";
/// Maximum encoded proof, checked before parsing any untrusted fields.
pub const MAX_PROOF_BYTES: usize = crate::protocol::hvf_owner::MAX_REQUEST_BYTES;
const MAX_LABEL_BYTES: usize = 512;
/// Maximum wall-clock challenge lifetime; transport also needs a monotonic deadline.
pub const MAX_CHALLENGE_SECONDS: u64 = 30;

/// Receiver-issued expectation for one exact request on one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryChallenge {
    pub request: UntrustedRecoveryRequest,
    pub identity: EnrolledIdentity,
    /// Fresh receiver-issued per-connection nonce, never endpoint discovery data.
    pub connection_nonce: [u8; 32],
    pub issued_at: u64,
}

/// Untrusted proof. Use `decode` for bounded parsing, then `verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryProof {
    pub challenge: RecoveryChallenge,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    challenge: WireChallenge,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireChallenge {
    request: UntrustedRecoveryRequest,
    identity: EnrolledIdentity,
    connection_nonce: [u8; 32],
    issued_at: u64,
}

/// Evidence of key possession only. Not admission, replay consumption or control.
#[derive(Debug)]
#[must_use]
pub struct RecoveryPossession {
    challenge: RecoveryChallenge,
}

/// Payload-free recovery proof refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryProofError {
    #[error("recovery proof exceeds its size bound")]
    TooLarge,
    #[error("recovery proof claims are malformed")]
    Invalid,
    #[error("recovery proof differs from retained claims")]
    Binding,
    #[error("recovery challenge is outside its freshness window")]
    Expired,
    #[error("recovery possession signature is invalid")]
    Signature,
}

type Result<T> = std::result::Result<T, RecoveryProofError>;

impl RecoveryChallenge {
    /// Issue once per authenticated connection; the receiver retains this value.
    ///
    /// # Errors
    /// Refuses malformed requests, enrollment or labels before serialization.
    pub fn fresh(
        request: UntrustedRecoveryRequest,
        identity: EnrolledIdentity,
        now: u64,
    ) -> Result<Self> {
        let mut connection_nonce = [0; 32];
        rand::rng().fill_bytes(&mut connection_nonce);
        let challenge = Self {
            request,
            identity,
            connection_nonce,
            issued_at: now,
        };
        challenge.validate(now)?;
        Ok(challenge)
    }

    fn validate(&self, now: u64) -> Result<()> {
        let binding = &self.request.binding;
        if self.request.version != REQUEST_VERSION
            || self.identity.installation.is_nil()
            || binding.controlling_principal != self.identity.public_key
            || self.connection_nonce == [0; 32]
        {
            return Err(RecoveryProofError::Invalid);
        }
        let label_valid = |s: &str| {
            !s.is_empty() && s.len() <= MAX_LABEL_BYTES && !s.chars().any(char::is_control)
        };
        if !label_valid(&binding.tenant_id) {
            return Err(RecoveryProofError::Invalid);
        }
        if let RecoveryPhase::Native { instance, .. } = &binding.phase
            && !label_valid(&instance.vm_id)
        {
            return Err(RecoveryProofError::Invalid);
        }
        // Only bounded labels reach serialization, including direct API calls.
        if serde_json::to_vec(&self.request)
            .map_err(|_| RecoveryProofError::Invalid)?
            .len()
            > crate::protocol::hvf_owner::MAX_REQUEST_BYTES
        {
            return Err(RecoveryProofError::TooLarge);
        }
        VerifyingKey::from_bytes(&self.identity.public_key)
            .map_err(|_| RecoveryProofError::Invalid)?;
        if now < self.issued_at || now - self.issued_at >= MAX_CHALLENGE_SECONDS {
            return Err(RecoveryProofError::Expired);
        }
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        // This fixed typed schema uses serde_json's exact u64 decimal encoding,
        // not JCS's IEEE-754 number conversion. Labels are bounded first.
        let mut message = DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self).map_err(|_| RecoveryProofError::Invalid)?;
        Ok(message)
    }
}

impl RecoveryProof {
    /// Sign this closed purpose using the actual loaded enrollment and key.
    ///
    /// # Errors
    /// Refuses invalid/future/expired claims or a different enrollment/key.
    pub fn sign(
        key: &SigningKey,
        identity: &EnrolledIdentity,
        challenge: &RecoveryChallenge,
        now: u64,
    ) -> Result<Self> {
        challenge.validate(now)?;
        if identity != &challenge.identity || key.verifying_key().to_bytes() != identity.public_key
        {
            return Err(RecoveryProofError::Binding);
        }
        let proof = Self {
            challenge: challenge.clone(),
            signature: key.sign(&challenge.message()?).to_bytes().to_vec(),
        };
        if serde_json::to_vec(&proof)
            .map_err(|_| RecoveryProofError::Invalid)?
            .len()
            > MAX_PROOF_BYTES
        {
            return Err(RecoveryProofError::TooLarge);
        }
        Ok(proof)
    }

    /// Parse bounded wire bytes without trusting any embedded expectation.
    ///
    /// The transport must reject oversized declared lengths before allocating
    /// its receive buffer. No unbounded Deserialize implementation is exposed.
    ///
    /// # Errors
    /// Refuses oversized or malformed input and invalid claims/signature lengths.
    pub fn decode(bytes: &[u8], now: u64) -> Result<Self> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(RecoveryProofError::TooLarge);
        }
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
            return Err(RecoveryProofError::Invalid);
        }
        let wire: WireProof =
            serde_json::from_slice(bytes).map_err(|_| RecoveryProofError::Invalid)?;
        let challenge = RecoveryChallenge {
            request: wire.challenge.request,
            identity: wire.challenge.identity,
            connection_nonce: wire.challenge.connection_nonce,
            issued_at: wire.challenge.issued_at,
        };
        challenge.validate(now)?;
        if wire.signature.len() != 64 {
            return Err(RecoveryProofError::Signature);
        }
        Ok(Self {
            challenge,
            signature: wire.signature,
        })
    }

    /// Check against independently retained request, connection and enrollment.
    ///
    /// # Errors
    /// Refuses mismatches, stale challenges, malformed claims or bad signatures.
    pub fn verify(&self, expected: &RecoveryChallenge, now: u64) -> Result<RecoveryPossession> {
        expected.validate(now)?;
        if &self.challenge != expected {
            return Err(RecoveryProofError::Binding);
        }
        let key = VerifyingKey::from_bytes(&expected.identity.public_key)
            .map_err(|_| RecoveryProofError::Invalid)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| RecoveryProofError::Signature)?;
        key.verify_strict(&expected.message()?, &signature)
            .map_err(|_| RecoveryProofError::Signature)?;
        Ok(RecoveryPossession {
            challenge: expected.clone(),
        })
    }
}

impl RecoveryPossession {
    /// The exact checked claims, never a lifecycle capability.
    pub fn challenge(&self) -> &RecoveryChallenge {
        &self.challenge
    }
}

#[cfg(test)]
#[path = "recovery_possession_tests.rs"]
mod tests;
