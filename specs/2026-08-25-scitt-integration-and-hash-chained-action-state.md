# SCITT Integration and Hash-Chained Action State

**Date:** 2026-08-25
**Status:** Design phase
**Owner:** Agent

## Executive Summary

Design SCITT-compatible attestation format for MVM with hash-chained action states, following the Action State pattern but adapted to MVM's existing architecture. This will enable:

1. **Content-addressed action states** with parent_digest linking
2. **SCITT-compatible sealed records** with attestation, traces, and audit logs attached
3. **Verification** that action state references the root of the logs
4. **Optional attachment** of attestation, traces, and audit logs as evidence

## Background

### Action State Architecture

Action State Group's **SCITT (Structured Cryptographic Inscription and Transparency Technology)** provides:

- **Capsule format**: Content-addressed JSON with Ed25519 signatures (COSE_Sign1)
- **Sealed content**: Only digests of inputs/outputs stored, never raw data
- **Checkpoint size**: ~1-2 KB (metadata + 32-byte digest)
- **Hash chaining**: `parent_capsule_id` with relations (confirms/supersedes/escalates)
- **Transparency service**: RFC 6962/9162 CT log backed by PostgreSQL

### MVM Current State

MVM already has many matching patterns:

| MVM Concept | Action State Equivalent |
|------------|------------------------|
| `CheckpointMeta` | Capsule |
| `CheckpointDigest` | capsule_id (SHA-256) |
| `meta_digest` | Content-addressed seal |
| `CheckpointMeta.parent` | chain.parent_capsule_id |
| Audit log | Transparency log |
| SignedAuditRoot | SCITT receipt |
| AttestationReport | Signed payload |

**Key gaps:**
1. No formal SCITT capsule structure
2. No explicit `chain.relation` (confirms/supersedes/escalates)
3. Action state checkpoints don't reference log roots explicitly
4. No standardized way to attach attestation/trace/audit evidence

## Design

### 1. SCITT-Compatible Action State Capsule

Create a new `ActionStateCapsule` type that follows SCITT semantics while being compatible with MVM's existing structures.

```rust
// crates/mvm-core/src/action_state.rs

/// Content-addressed, self-attested action state record.
///
/// Analogous to Action State's "Capsule" but adapted to MVM:
/// - Uses CheckpointMeta as the payload (already has parent linking)
/// - Adds SCITT-style sealing with COSE_Sign1 (Ed25519)
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

    /// Add evidence commitments (attestation, traces, audit logs)
    pub fn with_evidence(mut self, evidence: EvidenceCommitment) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Compute the capsule's content-address
    pub fn compute_capsule_id(&self) -> ActionStateDigest {
        // Hash the payload + chain + evidence (signature excluded)
        let bytes = serde_json::to_vec(self).expect("capsule serialization");
        ActionStateDigest::from_bytes(&Sha256::digest(bytes))
    }

    /// Sign the capsule with the given key
    pub fn sign(self, key: &SigningKey, signer_id: &str) -> SignedActionStateCapsule {
        let mut capsule = self;
        capsule.capsule_id = capsule.compute_capsule_id();

        // Sign everything except the signature field itself
        let mut signed_bytes = serde_json::to_vec(&capsule).expect("serialization");
        // Remove the signature field from signing (will be added back after)
        // For now, sign the entire structure sans signature

        let signature = key.sign(&signed_bytes).to_bytes().to_vec();

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
        // Verify signer_id matches the key
        // Verify signature against capsule content
        // Verify capsule_id matches recomputed hash
        Ok(())
    }
}
```

### 2. Hash-Chained Action State Transitions

Extend existing checkpoint structures to support explicit hash chaining with relations.

```rust
// In crates/mvm-core/src/checkpoint.rs

/// Extension to CheckpointMeta for SCITT-style chaining
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionStateCheckpoint {
    pub meta: CheckpointMeta,
    pub capsule: SignedActionStateCapsule,
}

impl ActionStateCheckpoint {
    /// Create from checkpoint metadata and capsule
    pub fn new(meta: CheckpointMeta, capsule: SignedActionStateCapsule) -> Self {
        Self { meta, capsule }
    }

    /// Verify the entire chain from genesis to this checkpoint
    pub fn verify_chain(&self, trusted_keys: &[&VerifyingKey]) -> Result<(), ActionStateError> {
        // 1. Verify capsule signature
        self.capsule.verify(trusted_keys)?;

        // 2. Verify parent linkage (if any)
        if let Some(chain) = &self.capsule.chain {
            // Load parent capsule
            // Verify parent's capsule_id matches chain.parent_capsule_id
            // Recursively verify parent chain
        }

        // 3. Verify evidence commitments reference actual logs
        if let Some(evidence) = &self.capsule.evidence {
            // Verify audit_log_root points to signed root
            // Verify attestation_report exists
            // Verify trace_references are valid
        }

        Ok(())
    }
}
```

### 3. Log Root References and Evidence Binding

Create evidence binding structures that link action states to logs.

```rust
// crates/mvm-core/src/evidence_binding.rs

/// Evidence binding - establishes that an action state references real log data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    /// The action state that references this evidence
    pub action_state_id: ActionStateDigest,

    /// The log root this action state commits to
    pub log_root: SignedAuditRoot,

    /// Verification that the log contains the action state's evidence
    pub inclusion_proof: InclusionProof,
}

/// Evidence anchor - references a specific piece of evidence in a log
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAnchor {
    /// Which log (audit, trace, etc.)
    pub log_type: EvidenceLogType,

    /// The log entry hash
    pub entry_hash: String,

    /// Inclusion proof in the log's Merkle tree
    pub inclusion_proof: InclusionProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLogType {
    Audit,
    Trace,
    Attestation,
}
```

### 4. Seal Verification with Log Root Reference

Add verification that action state seals reference log roots.

```rust
// crates/mvm-core/src/seal_verification.rs

/// Verify that an action state's seal references the log root
pub fn verify_seal_references_log_root(
    capsule: &SignedActionStateCapsule,
    expected_log_root: &SignedAuditRoot,
) -> Result<(), SealVerificationError> {
    // Check evidence_commitment exists and has audit_log_root
    let evidence = capsule.evidence.as_ref()
        .ok_or(SealVerificationError::NoEvidenceBound)?;

    let log_root_ref = evidence.audit_log_root.as_ref()
        .ok_or(SealVerificationError::NoAuditRoot)?;

    // Verify the referenced log root matches expected
    if log_root_ref != &expected_log_root.root_hash {
        return Err(SealVerificationError::LogRootMismatch);
    }

    // Verify log_root signature is valid
    // (This would require access to the trusted key)

    Ok(())
}

/// Full verification of action state seal
pub fn verify_action_state_seal(
    capsule: &SignedActionStateCapsule,
    trusted_keys: &[&VerifyingKey],
    expected_log_root: &SignedAuditRoot,
) -> Result<(), SealVerificationError> {
    // 1. Verify signature
    capsule.verify(trusted_keys)?;

    // 2. Verify seal references log root
    verify_seal_references_log_root(capsule, expected_log_root)?;

    // 3. Verify parent chain (if present)
    if let Some(chain) = &capsule.chain {
        // Load and verify parent capsule
    }

    // 4. Verify evidence commitments are resolvable
    if let Some(evidence) = &capsule.evidence {
        // Check attestation_report exists
        // Check trace_references are valid
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SealVerificationError {
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("no evidence bound to seal")]
    NoEvidenceBound,
    #[error("no audit root in evidence")]
    NoAuditRoot,
    #[error("audit root mismatch: expected {expected}, got {got}")]
    LogRootMismatch { expected: String, got: String },
    #[error("parent chain verification failed")]
    ParentChainInvalid,
    #[error("evidence commitment not found")]
    EvidenceNotFound,
}
```

## Implementation Plan

### Phase 1: Core Structures (this PR)
- [ ] Create `ActionStateCapsule`, `SignedActionStateCapsule` types
- [ ] Create `ChainRelation`, `ChainLinkage` types
- [ ] Create `EvidenceCommitment`, `EvidenceBinding` types
- [ ] Add `seal` and `verify` methods to capsule types
- [ ] Create `SealVerificationError` enum

### Phase 2: Integration with Checkpoints
- [ ] Create `ActionStateCheckpoint` wrapping `CheckpointMeta` + `SignedActionStateCapsule`
- [ ] Add `with_evidence` method to build evidence commitments
- [ ] Implement chain verification (parent -> child)

### Phase 3: Log Root Binding
- [ ] Implement `verify_seal_references_log_root`
- [ ] Create `EvidenceAnchor` for specific log entries
- [ ] Integrate with `SignedAuditRoot` from `mvm-contract::merkle`

### Phase 4: CLI Support
- [ ] Add `mvmctl action-state seal` command
- [ ] Add `mvmctl action-state verify` command
- [ ] Add `mvmctl action-state link` for chain operations

## Benefits

1. **SCITT Compliance**: Action states can be verified independently using standard SCITT tools
2. **Content Privacy**: Only digests stored, never raw workload data
3. **Log Root Binding**: Seals explicitly reference log roots, preventing.detach attacks
4. **Optional Evidence**: Attestation, traces, audit logs attached as verifiable commitments
5. **Chain Relations**: Support for confirms/supersedes/escalates relationships

## Backwards Compatibility

- Existing `CheckpointMeta` and related structures remain unchanged
- New `ActionStateCheckpoint` type wraps existing types
- Serialization format compatible with JSON (serde_json)
- No breaking changes to existing APIs

## Alternatives Considered

1. **Direct SCITT capsule adoption**: Rejected - would require wholesale replacement of existing checkpoint structures
2. **Merkle log only**: Rejected - lacks explicit chain relations and seal binding
3. **Only signature extension**: Rejected - doesn't solve evidence binding problem

## Related Work

- Action State Group: `capsule-emit`, `capsule-ledger`, `capsule-anchor`
- SCITT: `draft-mih-scitt-agent-action-capsule`
- Certificate Transparency: RFC 6962, RFC 9162
- MVM's existing: `SignedAuditRoot`, `InclusionProof`, `AttestationReport`

## Migration Path

1. Add new `ActionStateCheckpoint` type
2. Keep existing `CheckpointMeta` for backwards compatibility
3. Gradually migrate to action state for new checkpoints
4. Old checkpoints remain verifiable via existing code path
