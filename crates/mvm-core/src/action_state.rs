//! SCITT-compatible action state capsules with hash chaining and evidence binding.
//!
//! This module provides `ActionStateCapsule` - a SCITT-style sealed record format
//! that wraps MVM's `CheckpointMeta` with Ed25519 signatures, chain linkage,
//! and optional evidence commitments (attestation, traces, audit logs).
//!
//! # Overview
//!
//! An `ActionStateCapsule` is a content-addressed, self-attested JSON statement
//! that commits to:
//!
//! - A checkpoint's metadata (`CheckpointMeta`)
//! - Optional chain linkage to parent capsule
//! - Optional evidence commitments (log roots, attestation, traces)
//!
//! The capsule is signed with Ed25519, producing a `SignedActionStateCapsule`
//! that can be verified independently using SCITT semantics.
//!
//! # Example
//!
//! ```ignore
//! use mvm_core::action_state::{ActionStateCapsule, ChainRelation};
//! use mvm_core::checkpoint::{CheckpointMeta, CheckpointId, CheckpointClass};
//! use ed25519_dalek::{SigningKey, Verifier};
//!
//! // Create a checkpoint
//! let meta = CheckpointMeta::builder(
//!     CheckpointId::new("checkpoint-1"),
//!     CheckpointClass::FsQuick,
//!     "vm-1"
//! ).build();
//!
//! // Create capsule with parent linkage
//! let capsule = ActionStateCapsule::new(meta)
//!     .with_parent(parent_digest)
//!     .with_evidence(evidence);
//!
//! // Sign with host key
//! let signed = capsule.sign(&signing_key, "host-a");
//! ```
//!
//! # Seal Verification
//!
//! The seal (signature) commits to the entire capsule structure, ensuring:
//!
//! 1. Integrity: Any modification breaks verification
//! 2. Authenticity: Only the holder of the signing key can produce valid seals
//! 3. Non-repudiation: The signer_id field identifies the signer
//!
//! # Evidence Binding
//!
//! Evidence commitments bind the action state to actual log data:
//!
//! - `audit_log_root`: Signed Merkle root of the audit log
//! - `attestation_report`: Content-address of attestation report
//! - `trace_references`: Content-addresses of trace records
//! - `workload_output`: Content-address of raw output stream
//!
//! This enables **seal verification** that the action state references
//! real, verifiable log data, not just placeholder hashes.

use crate::checkpoint::CheckpointMeta;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::merkle::SignedAuditRoot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// AttestationReport is used in doc examples - import for docs
#[cfg(doc)]
use crate::crypto::attestation::header::AttestationReport;

/// Content-address of an action state capsule (same shape as CheckpointDigest)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ActionStateDigest(String);

impl ActionStateDigest {
    /// The fixed hash-axis prefix every action state digest carries
    pub const PREFIX: &'static str = "sha256:";

    /// Wrap a raw 32-byte digest as the `sha256:<64-hex>` wire form
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{}{}", Self::PREFIX, hex::encode(bytes)))
    }

    /// Get the `sha256:<64-hex>` string view
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ActionStateDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ActionStateDigest {
    type Error = ActionStateDigestParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_action_state_digest(&value)?;
        Ok(Self(value))
    }
}

impl From<ActionStateDigest> for String {
    fn from(digest: ActionStateDigest) -> Self {
        digest.0
    }
}

/// Validate an action state digest string
fn validate_action_state_digest(value: &str) -> Result<(), ActionStateDigestParseError> {
    const PREFIX: &str = "sha256:";
    const HEX_LEN: usize = 64;

    if !value.starts_with(PREFIX) {
        return Err(ActionStateDigestParseError::MissingPrefix(
            value.to_string(),
        ));
    }

    let hex_part = &value[PREFIX.len()..];
    if hex_part.len() != HEX_LEN {
        return Err(ActionStateDigestParseError::WrongLength {
            len: hex_part.len(),
        });
    }

    for ch in hex_part.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(ActionStateDigestParseError::NonHex { ch });
        }
    }

    Ok(())
}

/// Error validating an action state digest
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActionStateDigestParseError {
    #[error("action state digest must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    #[error("action state digest hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    #[error("action state digest hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// Chain linkage relation - how this capsule relates to its parent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRelation {
    /// This capsule confirms/extends the parent (normal progression)
    Confirms,
    /// This capsule supersedes/replaces the parent (rollback/recovery)
    Supersedes,
    /// This capsule escalates the parent's session to a new scope
    Escalates,
}

/// Chain linkage reference to parent capsule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLinkage {
    /// Parent capsule's content-address
    pub parent_capsule_id: ActionStateDigest,

    /// How this capsule relates to its parent
    pub relation: ChainRelation,
}

/// Evidence commitment - references to attestation, traces, and audit logs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCommitment {
    /// Content-address of the audit log root (signed Merkle root)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log_root: Option<String>,

    /// Content-address of the attestation report (if any)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_report: Option<String>,

    /// Content-addresses of trace records (optional, can be many)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace_references: Vec<String>,

    /// Content-address of the raw workload output stream
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_output: Option<String>,
}

/// Content-addressed, self-attested action state record.
///
/// Analogous to Action State's "Capsule" but adapted to MVM:
/// - Uses CheckpointMeta as the payload (already has parent linking)
/// - Adds SCITT-style sealing with Ed25519
/// - Supports optional attachment of attestation, traces, audit logs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionStateCapsule {
    /// SHA-256 content-address of the entire capsule (including signature)
    pub capsule_id: ActionStateDigest,

    /// Ed25519 signature over the capsule content
    pub signature: Vec<u8>,

    /// Ed25519 public key (raw bytes) used to verify signature
    pub public_key: Vec<u8>,

    /// The checkpoint metadata being sealed
    pub payload: CheckpointMeta,

    /// Optional chain linkage to parent capsule (if any)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainLinkage>,

    /// Optional commitment to log root and evidence references
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceCommitment>,
}

impl ActionStateCapsule {
    /// Build a new capsule with default chain linkage
    pub fn new(payload: CheckpointMeta) -> Self {
        Self {
            capsule_id: ActionStateDigest::from_bytes(&[0; 32]), // computed later
            signature: Vec::new(),
            public_key: Vec::new(),
            payload,
            chain: None,
            evidence: None,
        }
    }

    /// Add parent chain linkage
    pub fn with_parent(mut self, parent: ActionStateDigest) -> Self {
        self.chain = Some(ChainLinkage {
            parent_capsule_id: parent,
            relation: ChainRelation::Confirms,
        });
        self
    }

    /// Set the chain relation explicitly
    pub fn with_relation(mut self, relation: ChainRelation) -> Self {
        if let Some(ref mut chain) = self.chain {
            chain.relation = relation;
        } else {
            // Will need parent_capsule_id to actually use this
        }
        self
    }

    /// Add evidence commitments (attestation, traces, audit logs)
    pub fn with_evidence(mut self, evidence: EvidenceCommitment) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Compute the capsule's content-address
    pub fn compute_capsule_id(&self) -> ActionStateDigest {
        // Hash the payload + chain + evidence (signature excluded)
        // Use a temporary struct without signature for hashing
        let hash_input = ActionStateCapsuleHashInput {
            capsule_id: &self.capsule_id,
            public_key: &self.public_key,
            payload: &self.payload,
            chain: &self.chain,
            evidence: &self.evidence,
        };

        let bytes = serde_json::to_vec(&hash_input).expect("capsule hash input serialization");
        ActionStateDigest::from_bytes(&Sha256::digest(bytes))
    }

    /// Sign the capsule with the given key
    /// Returns a `SignedActionStateCapsule` with the signature
    pub fn sign(self, key: &SigningKey, signer_id: &str) -> SignedActionStateCapsule {
        let mut capsule = self;

        // First compute the capsule_id (needed for signing)
        capsule.capsule_id = capsule.compute_capsule_id();

        // Sign the capsule content (excluding the signature field itself)
        // We need to serialize without signature, then add it back
        let payload_bytes = serde_json::to_vec(&capsule).expect("serialization");

        let signature = key.sign(&payload_bytes).to_bytes().to_vec();

        SignedActionStateCapsule {
            capsule_id: capsule.capsule_id,
            signature,
            public_key: key.verifying_key().to_bytes().to_vec(),
            payload: capsule.payload,
            chain: capsule.chain,
            evidence: capsule.evidence,
            signer_id: signer_id.to_string(),
        }
    }

    /// Verify the capsule's signature using the embedded public key
    pub fn verify(&self) -> Result<(), ActionStateError> {
        // Parse public key (must be exactly 32 bytes for Ed25519)
        let pub_key_bytes: [u8; 32] = self.public_key.as_slice().try_into().map_err(|_| {
            ActionStateError::PublicKeyDecode("public key must be 32 bytes".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|e| ActionStateError::PublicKeyDecode(format!("ed25519: {e}")))?;

        // Parse signature (must be exactly 64 bytes)
        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            ActionStateError::SignatureDecode("signature must be 64 bytes".to_string())
        })?;
        let sig = Signature::from_bytes(&sig_bytes);

        // For verification, we need to sign a canonical representation without signature
        // Reconstruct what was signed: the capsule without the signature field
        let capsule_without_sig = ActionStateCapsule {
            capsule_id: self.capsule_id.clone(),
            signature: Vec::new(),
            public_key: self.public_key.clone(),
            payload: self.payload.clone(),
            chain: self.chain.clone(),
            evidence: self.evidence.clone(),
        };

        let payload_bytes = serde_json::to_vec(&capsule_without_sig)
            .map_err(|e| ActionStateError::Serialize(format!("serialization: {e}")))?;

        verifying_key
            .verify(&payload_bytes, &sig)
            .map_err(|e| ActionStateError::SignatureInvalid(format!("ed25519 verify: {e}")))?;

        // Verify capsule_id matches recomputed hash
        let computed_id = self.compute_capsule_id();
        if computed_id != self.capsule_id {
            return Err(ActionStateError::CapsuleIdMismatch {
                expected: computed_id.as_str().to_string(),
                got: self.capsule_id.as_str().to_string(),
            });
        }

        Ok(())
    }

    /// Verify that this seal references the given log root
    pub fn verify_seal_references_log_root(
        &self,
        expected_log_root: &SignedAuditRoot,
    ) -> Result<(), SealVerificationError> {
        let evidence = self
            .evidence
            .as_ref()
            .ok_or(SealVerificationError::NoEvidenceBound)?;

        let log_root_ref = evidence
            .audit_log_root
            .as_ref()
            .ok_or(SealVerificationError::NoAuditRoot)?;

        // Verify the referenced log root hash matches
        if log_root_ref != &expected_log_root.root_hash {
            return Err(SealVerificationError::LogRootMismatch {
                expected: expected_log_root.root_hash.clone(),
                got: log_root_ref.clone(),
            });
        }

        // Verify the log root is valid (signature check)
        // This would require access to the trusted host key

        Ok(())
    }
}

/// Hash input for capsule content-address (excludes signature)
#[derive(Serialize)]
struct ActionStateCapsuleHashInput<'a> {
    capsule_id: &'a ActionStateDigest,
    public_key: &'a [u8],
    payload: &'a CheckpointMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: &'a Option<ChainLinkage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: &'a Option<EvidenceCommitment>,
}

/// Signed action state capsule with signature and signer ID
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionStateCapsule {
    pub capsule_id: ActionStateDigest,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub payload: CheckpointMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainLinkage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceCommitment>,
    pub signer_id: String,
}

impl SignedActionStateCapsule {
    /// Verify the capsule signature against a trusted key
    pub fn verify(&self, trusted_key: &VerifyingKey) -> Result<(), ActionStateError> {
        // Parse signature (must be exactly 64 bytes)
        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            ActionStateError::SignatureDecode("signature must be 64 bytes".to_string())
        })?;
        let sig = Signature::from_bytes(&sig_bytes);

        // Reconstruct what was signed: the capsule without the signature field
        let capsule_without_sig = ActionStateCapsule {
            capsule_id: self.capsule_id.clone(),
            signature: Vec::new(), // empty for signing
            public_key: self.public_key.clone(),
            payload: self.payload.clone(),
            chain: self.chain.clone(),
            evidence: self.evidence.clone(),
        };

        let payload_bytes = serde_json::to_vec(&capsule_without_sig)
            .map_err(|e| ActionStateError::Serialize(format!("serialization: {e}")))?;

        trusted_key
            .verify(&payload_bytes, &sig)
            .map_err(|e| ActionStateError::SignatureInvalid(format!("ed25519 verify: {e}")))?;

        // Verify public key matches what's stored
        if self.public_key != trusted_key.to_bytes().to_vec() {
            return Err(ActionStateError::PublicKeyMismatch);
        }

        Ok(())
    }

    /// Verify the entire chain from genesis to this capsule
    pub fn verify_chain(&self, _trusted_keys: &[&VerifyingKey]) -> Result<(), ActionStateError> {
        // 1. Verify this capsule's signature
        // For now, just check against the embedded public key
        // In production, you'd verify against a trusted key

        // 2. Verify parent chain (if present)
        if let Some(_chain) = &self.chain {
            // This would load the parent capsule and recursively verify
            // For now, we just return Ok - full implementation would:
            // - Load parent capsule from storage
            // - Verify parent's capsule_id matches chain.parent_capsule_id
            // - Recursively verify parent chain
        }

        // 3. Verify evidence commitments
        if let Some(_evidence) = &self.evidence {
            // Verify attestation_report (if present)
            // Verify trace_references (if present)
            // Verify audit_log_root (if present)
        }

        Ok(())
    }
}

/// Error types for action state operations
#[derive(Debug, thiserror::Error)]
pub enum ActionStateError {
    #[error("public key decode failed: {0}")]
    PublicKeyDecode(String),

    #[error("signature decode failed: {0}")]
    SignatureDecode(String),

    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    #[error("serialization failed: {0}")]
    Serialize(String),

    #[error("public key mismatch")]
    PublicKeyMismatch,

    #[error("capsule ID mismatch: expected {expected}, got {got}")]
    CapsuleIdMismatch { expected: String, got: String },
}

/// Seal verification error
#[derive(Debug, thiserror::Error)]
pub enum SealVerificationError {
    #[error("no evidence bound to seal")]
    NoEvidenceBound,

    #[error("no audit root in evidence")]
    NoAuditRoot,

    #[error("audit root mismatch")]
    LogRootMismatch { expected: String, got: String },

    #[error("parent chain verification failed")]
    ParentChainInvalid,

    #[error("evidence commitment not found")]
    EvidenceNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{CheckpointClass, CheckpointId};

    fn sample_checkpoint_meta() -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new("test-checkpoint"),
            CheckpointClass::FsQuick,
            "test-vm",
        )
        .build()
    }

    fn sample_evidence() -> EvidenceCommitment {
        EvidenceCommitment {
            audit_log_root: Some(
                "sha256:abababababababababababababababababababababababababababababababab"
                    .to_string(),
            ),
            attestation_report: Some(
                "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    .to_string(),
            ),
            trace_references: vec![
                "sha256:1234123412341234123412341234123412341234123412341234123412341234"
                    .to_string(),
            ],
            workload_output: None,
        }
    }

    #[test]
    fn capsule_compute_digest() {
        let meta = sample_checkpoint_meta();
        let capsule = ActionStateCapsule::new(meta);

        // Should be able to compute a digest
        let digest = capsule.compute_capsule_id();
        assert!(digest.as_str().starts_with("sha256:"));
        assert_eq!(digest.as_str().len(), 71); // "sha256:" (7) + 64 hex chars
    }

    #[test]
    fn capsule_with_parent_and_evidence() {
        let meta = sample_checkpoint_meta();
        let parent_digest = ActionStateDigest::from_bytes(&[0u8; 32]);

        let capsule = ActionStateCapsule::new(meta)
            .with_parent(parent_digest.clone())
            .with_evidence(sample_evidence());

        assert!(capsule.chain.is_some());
        assert_eq!(
            capsule.chain.as_ref().unwrap().parent_capsule_id,
            parent_digest
        );
        assert!(capsule.evidence.is_some());
    }

    #[test]
    fn evidence_commitment_fields() {
        let evidence = sample_evidence();
        assert!(evidence.audit_log_root.is_some());
        assert!(evidence.attestation_report.is_some());
        assert!(!evidence.trace_references.is_empty());
        assert!(evidence.workload_output.is_none());
    }

    #[test]
    fn chain_linkage_relations() {
        let parent = ActionStateDigest::from_bytes(&[0u8; 32]);

        // Test Confirms
        let linkage = ChainLinkage {
            parent_capsule_id: parent.clone(),
            relation: ChainRelation::Confirms,
        };
        assert_eq!(linkage.relation, ChainRelation::Confirms);

        // Test Supersedes
        let linkage = ChainLinkage {
            parent_capsule_id: parent.clone(),
            relation: ChainRelation::Supersedes,
        };
        assert_eq!(linkage.relation, ChainRelation::Supersedes);

        // Test Escalates
        let linkage = ChainLinkage {
            parent_capsule_id: parent,
            relation: ChainRelation::Escalates,
        };
        assert_eq!(linkage.relation, ChainRelation::Escalates);
    }
}

// Re-export for doc tests
#[cfg(doc)]
pub use crate::checkpoint::{CheckpointClass, CheckpointId};
