//! Experimental capture-purpose possession, not capture-write authority.
//!
//! These codecs do not authenticate a socket, establish launch custody, consume
//! a permit or authorize an append. The receiver must independently retain the
//! binding, check the actual live peers and atomically spend before Ready.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand::Rng as _;
use uuid::Uuid;

use super::entrypoint_delegation::RegistrationBinding;
use super::entrypoint_identity::EnrolledIdentity;

#[cfg(test)]
mod tests;
mod wire;

/// Whole control frame ceiling, including the four-byte length prefix.
pub const MAX_FRAME_BYTES: usize = 4096;
/// Wall-clock freshness only; a transport must also enforce a monotonic deadline.
pub const MAX_CHALLENGE_SECONDS: u64 = 30;

/// Immutable expected facts. Construction validates shape, not provenance.
/// No deserialization or mutation accessor can turn peer bytes into authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureBinding {
    identity: EnrolledIdentity,
    registration: RegistrationBinding,
    vm: String,
    startup: [u8; 32],
    call: Uuid,
    boot: [u8; 32],
    capture_run: String,
    producer_pid: u32,
    supervisor_pid: u32,
}

/// Incomplete bindings cannot be used for signing or verification.
#[derive(Debug)]
pub struct CaptureBindingBuilder {
    binding: CaptureBinding,
    startup: Option<[u8; 32]>,
}

/// One connection's receiver-issued challenge. A clone grants no write authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureChallenge {
    binding: CaptureBinding,
    nonce: [u8; 32],
    issued: u64,
    expires: u64,
}

/// Bounded, untrusted proof until verified against independently retained context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureProof {
    challenge: CaptureChallenge,
    signature: [u8; 64],
}

/// Key possession only, not peer identity, permit consumption or recorded output.
#[derive(Debug)]
#[must_use]
pub struct CapturePossession {
    challenge: CaptureChallenge,
}

/// Payload-free refusals; never include supplied labels or proof bytes in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureProofError {
    #[error("capture proof length is outside its bounds")]
    Bounds,
    #[error("capture proof claims are malformed")]
    Invalid,
    #[error("capture proof differs from retained context")]
    Binding,
    #[error("capture challenge is outside its validity window")]
    Expired,
    #[error("capture possession signature is invalid")]
    Signature,
}

type Result<T> = std::result::Result<T, CaptureProofError>;

impl CaptureBinding {
    pub fn builder(
        identity: EnrolledIdentity,
        registration: RegistrationBinding,
        vm: impl Into<String>,
    ) -> CaptureBindingBuilder {
        CaptureBindingBuilder {
            binding: Self {
                identity,
                registration,
                vm: vm.into(),
                startup: [0; 32],
                call: Uuid::nil(),
                boot: [0; 32],
                capture_run: String::new(),
                producer_pid: 0,
                supervisor_pid: 0,
            },
            startup: None,
        }
    }

    pub fn identity(&self) -> &EnrolledIdentity {
        &self.identity
    }

    pub fn producer_pid(&self) -> u32 {
        self.producer_pid
    }

    fn validate(&self) -> Result<()> {
        wire::label(&self.registration.tenant, 512)?;
        wire::label(&self.vm, 512)?;
        wire::label(&self.registration.instance, 512)?;
        wire::label(&self.capture_run, 128)?;
        if self
            .registration
            .instance_vm()
            .map_err(|_| CaptureProofError::Invalid)?
            != self.vm
        {
            return Err(CaptureProofError::Binding);
        }
        if [
            self.identity.installation,
            self.registration.run,
            self.registration.producer,
            self.registration.session,
            self.call,
        ]
        .iter()
        .any(Uuid::is_nil)
            || self.producer_pid <= 1
            || self.supervisor_pid <= 1
            || self.boot == [0; 32]
            || self.registration.not_before >= self.registration.not_after
        {
            return Err(CaptureProofError::Invalid);
        }
        VerifyingKey::from_bytes(&self.identity.public_key)
            .map_err(|_| CaptureProofError::Invalid)?;
        wire::plan_digest(&self.registration.plan_id)?;
        wire::digest::<16>(self.registration.plan_nonce.as_hex())?;
        Ok(())
    }
}

impl CaptureBindingBuilder {
    pub fn with_startup(mut self, digest: [u8; 32]) -> Self {
        self.startup = Some(digest);
        self
    }

    pub fn with_call(mut self, call: Uuid) -> Self {
        self.binding.call = call;
        self
    }

    pub fn with_boot(mut self, nonce: [u8; 32]) -> Self {
        self.binding.boot = nonce;
        self
    }

    pub fn with_capture_run(mut self, run: impl Into<String>) -> Self {
        self.binding.capture_run = run.into();
        self
    }

    pub fn with_peer_pids(mut self, producer: u32, supervisor: u32) -> Self {
        self.binding.producer_pid = producer;
        self.binding.supervisor_pid = supervisor;
        self
    }

    pub fn build(mut self) -> Result<CaptureBinding> {
        self.binding.startup = self.startup.ok_or(CaptureProofError::Invalid)?;
        self.binding.validate()?;
        Ok(self.binding)
    }
}

impl CaptureChallenge {
    /// Issue once for a connected peer. This does not authenticate that peer.
    pub fn fresh(binding: CaptureBinding, now: u64) -> Result<Self> {
        binding.validate()?;
        let mut nonce = [0; 32];
        rand::rng().fill_bytes(&mut nonce);
        let expires = now
            .checked_add(MAX_CHALLENGE_SECONDS)
            .ok_or(CaptureProofError::Expired)?
            .min(binding.registration.not_after);
        let challenge = Self {
            binding,
            nonce,
            issued: now,
            expires,
        };
        challenge.validate(now)?;
        Ok(challenge)
    }

    pub fn binding(&self) -> &CaptureBinding {
        &self.binding
    }

    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(self.issued)?;
        wire::frame(1, self, &[])
    }

    /// Decode only against independently held launch/native/peer expectations.
    /// The registration validity interval is retained context, not wire input.
    pub fn decode(bytes: &[u8], expected: &CaptureBinding, now: u64) -> Result<Self> {
        expected.validate()?;
        let body = wire::unframe(bytes, 1)?;
        let challenge = wire::parse(body, expected)?;
        challenge.validate(now)?;
        if &challenge.binding != expected {
            return Err(CaptureProofError::Binding);
        }
        Ok(challenge)
    }

    /// Recheck wall-clock freshness without repeating signature verification.
    /// A receiver must separately enforce its original monotonic deadline.
    pub fn validate(&self, now: u64) -> Result<()> {
        self.binding.validate()?;
        if self.nonce == [0; 32] {
            return Err(CaptureProofError::Invalid);
        }
        let lifetime = self
            .expires
            .checked_sub(self.issued)
            .ok_or(CaptureProofError::Expired)?;
        if !(1..=MAX_CHALLENGE_SECONDS).contains(&lifetime)
            || self.binding.registration.not_before > self.issued
            || self.issued > now
            || now >= self.expires
            || self.expires > self.binding.registration.not_after
        {
            return Err(CaptureProofError::Expired);
        }
        Ok(())
    }
}

impl CaptureProof {
    /// Sign only the closed capture-purpose schema, never arbitrary bytes.
    /// Admission, actual-peer checks and one-call spend remain separate.
    pub fn sign(
        key: &SigningKey,
        identity: &EnrolledIdentity,
        challenge: &CaptureChallenge,
        now: u64,
    ) -> Result<Self> {
        challenge.validate(now)?;
        if challenge.binding.identity() != identity
            || key.verifying_key().to_bytes() != identity.public_key
        {
            return Err(CaptureProofError::Binding);
        }
        let signature = key.sign(&wire::message(challenge)?).to_bytes();
        Ok(Self {
            challenge: challenge.clone(),
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.challenge.validate(self.challenge.issued)?;
        wire::frame(2, &self.challenge, &self.signature)
    }

    /// Bounded parsing is not signature verification or replay consumption.
    pub fn decode(bytes: &[u8], expected: &CaptureChallenge, now: u64) -> Result<Self> {
        expected.validate(now)?;
        let body = wire::unframe(bytes, 2)?;
        let split = body
            .len()
            .checked_sub(64)
            .ok_or(CaptureProofError::Bounds)?;
        let (fields, signature) = body.split_at(split);
        let challenge = wire::parse(fields, expected.binding())?;
        challenge.validate(now)?;
        if &challenge != expected {
            return Err(CaptureProofError::Binding);
        }
        Ok(Self {
            challenge,
            signature: signature
                .try_into()
                .map_err(|_| CaptureProofError::Bounds)?,
        })
    }

    /// Verify exact context and purpose. Repeated verification is deliberately
    /// not a replay ledger; only the receiver's atomic permit spend grants writes.
    pub fn verify(&self, expected: &CaptureChallenge, now: u64) -> Result<CapturePossession> {
        expected.validate(now)?;
        if &self.challenge != expected {
            return Err(CaptureProofError::Binding);
        }
        VerifyingKey::from_bytes(&expected.binding.identity.public_key)
            .map_err(|_| CaptureProofError::Invalid)?
            .verify_strict(
                &wire::message(expected)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CaptureProofError::Signature)?;
        Ok(CapturePossession {
            challenge: expected.clone(),
        })
    }
}

impl CapturePossession {
    pub fn challenge(&self) -> &CaptureChallenge {
        &self.challenge
    }
}
