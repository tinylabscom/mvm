//! Purpose-bound caller possession for trusted entrypoint admission.
//!
//! A valid proof is not admission authority. The trusted launch path must
//! derive the expected binding from an actually admitted plan, install that
//! exact identity once, and consume its challenge. A producer cannot register
//! itself merely by presenting a proof or a generic host signature.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::entrypoint_identity::EnrolledIdentity;
use crate::plan::Nonce;

const DOMAIN: &[u8] = b"mvm.entrypoint-caller.registration.v1\0";
const MAX_LABEL_BYTES: usize = 512;
const MAX_CANONICAL_INTEGER: u64 = 9_007_199_254_740_991;

/// A closed purpose also fixes the only authorized producer stream kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPurpose {
    EntrypointStdoutAndStderrV1,
}

/// Expected launch identity, constructed by the trusted admission caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationBinding {
    pub tenant: String,
    /// Valid VM name, '/', then a nonnil lowercase hyphenated instance UUID.
    pub instance: String,
    pub plan_id: String,
    pub plan_nonce: Nonce,
    pub run: Uuid,
    pub producer: Uuid,
    pub session: Uuid,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationChallenge {
    pub purpose: RegistrationPurpose,
    pub binding: RegistrationBinding,
    pub identity: EnrolledIdentity,
    pub nonce: [u8; 32],
}

/// Untrusted wire proof until checked against independently expected claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProof {
    pub challenge: RegistrationChallenge,
    pub signature: Vec<u8>,
}

/// Possession checked against exact expected claims. Not a launch capability.
/// No Deserialize, Default, mutation accessor or public constructor.
#[derive(Debug)]
pub struct VerifiedCallerProof {
    proof: RegistrationProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    #[error("entrypoint registration claims are invalid")]
    Invalid,
    #[error("entrypoint registration does not match the expected launch identity")]
    Binding,
    #[error("entrypoint registration is outside its validity window")]
    Expired,
    #[error("entrypoint caller possession proof is invalid")]
    Proof,
}

type Result<T> = std::result::Result<T, DelegationError>;

impl RegistrationBinding {
    /// Validate the complete instance identity and return its bound VM name.
    /// Alternate UUID spellings are refused, never normalized before signing.
    pub fn instance_vm(&self) -> Result<&str> {
        let (vm, suffix) = self
            .instance
            .split_once('/')
            .ok_or(DelegationError::Invalid)?;
        crate::naming::validate_vm_name(vm).map_err(|_| DelegationError::Invalid)?;
        let instance = Uuid::parse_str(suffix).map_err(|_| DelegationError::Invalid)?;
        if instance.is_nil() || instance.to_string() != suffix {
            return Err(DelegationError::Invalid);
        }
        Ok(vm)
    }

    fn validate(&self, now: u64) -> Result<()> {
        self.instance_vm()?;
        for label in [&self.tenant, &self.plan_id] {
            if label.is_empty()
                || label.len() > MAX_LABEL_BYTES
                || label.chars().any(char::is_control)
            {
                return Err(DelegationError::Invalid);
            }
        }
        if self.run.is_nil()
            || self.producer.is_nil()
            || self.session.is_nil()
            || self.not_before >= self.not_after
            || self.not_after > MAX_CANONICAL_INTEGER
        {
            return Err(DelegationError::Invalid);
        }
        if now < self.not_before || now >= self.not_after {
            return Err(DelegationError::Expired);
        }
        Ok(())
    }
}

impl RegistrationChallenge {
    /// Mint at admission, never reuse across launches. The caller owns the
    /// single-use ledger and must not accept a producer-supplied expectation.
    pub fn fresh(
        binding: RegistrationBinding,
        identity: EnrolledIdentity,
        now: u64,
    ) -> Result<Self> {
        let mut nonce = [0; 32];
        rand::rng().fill_bytes(&mut nonce);
        let challenge = Self {
            purpose: RegistrationPurpose::EntrypointStdoutAndStderrV1,
            binding,
            identity,
            nonce,
        };
        challenge.validate(now)?;
        Ok(challenge)
    }

    fn validate(&self, now: u64) -> Result<()> {
        self.binding.validate(now)?;
        if self.identity.installation.is_nil() || self.nonce == [0; 32] {
            return Err(DelegationError::Invalid);
        }
        VerifyingKey::from_bytes(&self.identity.public_key)
            .map_err(|_| DelegationError::Invalid)?;
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        let canonical = serde_jcs::to_vec(self).map_err(|_| DelegationError::Invalid)?;
        let mut message = Vec::with_capacity(DOMAIN.len() + canonical.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }
}

impl RegistrationProof {
    /// Sign only this protocol's possession challenge. This grants no
    /// admission or installation authority, regardless of which key signs it.
    pub fn sign(
        key: &SigningKey,
        identity: &EnrolledIdentity,
        challenge: &RegistrationChallenge,
        now: u64,
    ) -> Result<Self> {
        challenge.validate(now)?;
        if &challenge.identity != identity || key.verifying_key().to_bytes() != identity.public_key
        {
            return Err(DelegationError::Binding);
        }
        Ok(Self {
            challenge: challenge.clone(),
            signature: key.sign(&challenge.message()?).to_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        expected: &RegistrationChallenge,
        now: u64,
    ) -> Result<VerifiedCallerProof> {
        expected.validate(now)?;
        if &self.challenge != expected {
            return Err(DelegationError::Binding);
        }
        let key = VerifyingKey::from_bytes(&expected.identity.public_key)
            .map_err(|_| DelegationError::Proof)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| DelegationError::Proof)?;
        key.verify_strict(&expected.message()?, &signature)
            .map_err(|_| DelegationError::Proof)?;
        Ok(VerifiedCallerProof {
            proof: self.clone(),
        })
    }
}

impl VerifiedCallerProof {
    pub fn challenge(&self) -> &RegistrationChallenge {
        &self.proof.challenge
    }

    /// Re-verifiable bytes for the authenticated trusted-launch transport.
    pub fn proof(&self) -> &RegistrationProof {
        &self.proof
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use zeroize::Zeroizing;

    pub fn identity(seed: [u8; 32], installation: Uuid) -> EnrolledIdentity {
        let seed = Zeroizing::new(seed);
        EnrolledIdentity {
            installation,
            public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        }
    }

    pub fn proof(
        seed: [u8; 32],
        challenge: &RegistrationChallenge,
        now: u64,
    ) -> Result<RegistrationProof> {
        let seed = Zeroizing::new(seed);
        RegistrationProof::sign(
            &SigningKey::from_bytes(&seed),
            &challenge.identity,
            challenge,
            now,
        )
    }
}

#[cfg(test)]
#[path = "entrypoint_delegation_tests.rs"]
mod tests;
