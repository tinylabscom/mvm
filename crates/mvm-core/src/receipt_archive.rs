//! The signed index of an evidence archive.
//!
//! An archive bundles one run's [`crate::receipt::ExecutionReceipt`]s with the
//! Merkle inclusion proofs that bind them to a host-signed audit root, the raw
//! chain lines they derive from, and a citation for every in-scope audit entry
//! that has no receipt mapping. This module is the manifest that indexes it:
//! what the archive covers, what it contains, and how complete that coverage
//! is.
//!
//! The manifest is content-addressed and signed exactly the way a receipt is —
//! `sha256(JCS(self))` with the id field blanked, then Ed25519 over the same
//! canonical bytes — so an archive carries its own identity rather than
//! borrowing its filename's.
//!
//! # Completeness is two different properties
//!
//! [`Completeness::Derivable`] means a reader can check coverage without
//! trusting anyone: the archive carries every leaf, so `leaves.len()` is
//! comparable against the signed root's `tree_size`.
//!
//! [`Completeness::Attested`] means the host asserted it. A plan-scoped
//! archive is a subsequence of the log, and a subsequence carries nothing that
//! would attest its own completeness — detecting an omitted entry needs the
//! whole tree. Readers must report the two differently; collapsing them into
//! one boolean is how an assertion gets read as a check.

use crate::did_key::DidKey;
use crate::receipt::{ReceiptError, canonical_json};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::merkle::SignedAuditRoot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Whether the archive's scope completeness was checked or asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Completeness {
    /// The host asserts the leaf set is every in-scope entry. A verifier
    /// cannot check this from a filtered archive alone.
    Attested,
    /// The archive carries every leaf, so a verifier derives completeness by
    /// comparing the leaf count against the signed root's tree size.
    Derivable,
}

/// What one archive covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ArchiveScope {
    /// One admitted plan — the default, and the unit a receipt is about.
    Plan {
        /// Content address of the plan.
        plan_id: String,
    },
    /// A whole tenant's chain.
    Tenant,
}

/// One audit-chain leaf the archive carries, and where it sits in the tree.
///
/// `index` addresses the real tree, not a position within the filtered set —
/// an inclusion proof built against a filtered index would not verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafCitation {
    /// 0-based leaf index in the full audit tree.
    pub index: u64,
    /// `sha256:<hex>` of the exact signed entry bytes.
    pub digest: String,
    /// The audit entry's `event` name.
    pub event: String,
    /// Archive-relative path of the member carrying this leaf.
    pub member: String,
}

/// A sealed transcript the archive points at.
///
/// `root` is the sealed manifest root the host already wrote into the audit
/// chain, so the citation resolves against a leaf whether or not the chunks
/// travel with the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptCitation {
    /// Capture identifier.
    pub capture_id: String,
    /// VM the capture came from.
    pub vm_name: String,
    /// `sha256:<hex>` root of the sealed transcript manifest.
    pub root: String,
    /// Number of chunks the capture holds.
    pub chunk_count: u64,
    /// Whether the ciphertext chunks are in this archive.
    pub embedded: bool,
    /// Leaf index of the chain entry that anchored this transcript.
    pub anchored_at_leaf: u64,
}

/// The signed index of an evidence archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    /// Wire schema version. Const `1` for this version.
    #[serde(default = "schema_version_default")]
    pub schema_version: u32,
    /// Content address of this manifest: `sha256(JCS(self with this blanked))`.
    pub archive_id: String,
    /// Tenant whose chain the archive draws from.
    pub tenant: String,
    /// What the archive covers.
    pub scope: ArchiveScope,
    /// `did:key` of the host that produced the archive.
    pub host_did: String,
    /// The host-signed Merkle root every inclusion proof binds to.
    pub audit_root: SignedAuditRoot,
    /// Every in-scope leaf, receipts and citations alike.
    pub leaves: Vec<LeafCitation>,
    /// Per-event counts over the in-scope range.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts_by_event: BTreeMap<String, u64>,
    /// Transcripts the archive cites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transcripts: Vec<TranscriptCitation>,
    /// Archive-relative member path → `sha256:<hex>` of its bytes.
    pub members: BTreeMap<String, String>,
    /// Whether scope completeness is checkable or merely asserted.
    pub completeness: Completeness,
}

fn schema_version_default() -> u32 {
    1
}

impl EvidenceManifest {
    /// Prefix on every content address this module emits.
    pub const ID_PREFIX: &'static str = "sha256:";

    /// Content address of this manifest.
    ///
    /// Computed over the canonical JSON with `archive_id` cleared: the id is
    /// part of the manifest, so it cannot be part of its own input.
    pub fn compute_id(&self) -> Result<String, ReceiptError> {
        let mut canonical_self = self.clone();
        canonical_self.archive_id.clear();
        let canonical = canonical_json(&canonical_self)?;
        let digest = Sha256::digest(&canonical);
        Ok(format!("{}{}", Self::ID_PREFIX, hex::encode(digest)))
    }

    /// Verify that `archive_id` matches the recomputed content address.
    pub fn verify_id(&self) -> Result<(), ReceiptError> {
        if self.compute_id()? == self.archive_id {
            Ok(())
        } else {
            Err(ReceiptError::ArchiveIdMismatch)
        }
    }
}

/// A signed evidence-archive manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceManifest {
    /// The signed manifest.
    pub manifest: EvidenceManifest,
    /// `did:key` of the signer.
    pub signed_by: String,
    /// RFC 3339 UTC timestamp of signing. **Not signed** — forgeable, exactly
    /// as on a receipt envelope.
    pub signed_at: String,
    /// Base64 Ed25519 signature over `canonical_json(manifest)`.
    pub signature: String,
}

impl SignedEvidenceManifest {
    /// Content-address and sign a manifest.
    ///
    /// Sets `archive_id` from [`EvidenceManifest::compute_id`] before signing,
    /// so the id is inside the signed bytes and cannot be swapped afterwards.
    pub fn sign(
        mut manifest: EvidenceManifest,
        signing_key: &SigningKey,
        signed_at: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        manifest.archive_id = manifest.compute_id()?;
        let did = DidKey::from_verifying_key(signing_key.verifying_key());
        let canonical = canonical_json(&manifest)?;
        let signature = signing_key.sign(&canonical);
        Ok(Self {
            manifest,
            signed_by: did.to_did_key(),
            signed_at: signed_at.into(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Verify the signature and content address of this manifest.
    ///
    /// Checks, in order: the archive id matches the recomputed address, the
    /// `did:key` parses, the signature is valid over the canonical manifest,
    /// and the signing key is the one `signed_by` names.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        self.manifest.verify_id()?;
        let did = DidKey::parse(&self.signed_by)?;
        let vk = did.verifying_key();
        let canonical = canonical_json(&self.manifest)?;
        let sig_bytes = BASE64_STANDARD
            .decode(&self.signature)
            .map_err(|e| ReceiptError::InvalidValueSpace(format!("base64: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)?;
        vk.verify(&canonical, &sig)?;
        if *vk != self.resolve_signer()? {
            return Err(ReceiptError::SignerMismatch);
        }
        Ok(())
    }

    /// Recover the signer's verifying key from `signed_by`.
    fn resolve_signer(&self) -> Result<VerifyingKey, ReceiptError> {
        Ok(*DidKey::parse(&self.signed_by)?.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_signed_root() -> SignedAuditRoot {
        SignedAuditRoot {
            tenant: "local".into(),
            tree_size: 41230,
            root_hash: "aa".repeat(32),
            timestamp: "2026-08-22T00:00:00Z".into(),
            signature: BASE64_STANDARD.encode([7u8; 64]),
            signer_pubkey: "bb".repeat(32),
        }
    }

    fn fixture_manifest() -> EvidenceManifest {
        EvidenceManifest {
            schema_version: 1,
            archive_id: String::new(),
            tenant: "local".into(),
            scope: ArchiveScope::Plan {
                plan_id: format!("sha256:{}", "cc".repeat(32)),
            },
            host_did: "did:key:z6MkTest".into(),
            audit_root: fixture_signed_root(),
            leaves: vec![LeafCitation {
                index: 903,
                digest: format!("sha256:{}", "dd".repeat(32)),
                event: "flow.egress.denied".into(),
                member: "cited/903.json".into(),
            }],
            counts_by_event: [("flow.egress.denied".to_string(), 1u64)]
                .into_iter()
                .collect(),
            transcripts: Vec::new(),
            members: [(
                "cited/903.json".to_string(),
                format!("sha256:{}", "dd".repeat(32)),
            )]
            .into_iter()
            .collect(),
            completeness: Completeness::Attested,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let m = fixture_manifest();
        let s = serde_json::to_string(&m).expect("serialize");
        let back: EvidenceManifest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(m, back);
    }

    #[test]
    fn completeness_serializes_as_a_word_not_a_bool() {
        // The distinction between checked and asserted has to survive the
        // wire; a boolean would erase it.
        assert_eq!(
            serde_json::to_string(&Completeness::Attested).expect("serialize"),
            "\"attested\""
        );
        assert_eq!(
            serde_json::to_string(&Completeness::Derivable).expect("serialize"),
            "\"derivable\""
        );
    }

    #[test]
    fn signing_populates_the_archive_id_as_a_content_address() {
        let signed =
            SignedEvidenceManifest::sign(fixture_manifest(), &key(), "2026-08-22T00:00:00Z")
                .expect("sign");
        assert!(signed.manifest.archive_id.starts_with("sha256:"));
        signed.verify().expect("verify");
    }

    #[test]
    fn a_tampered_manifest_field_fails_verification() {
        let mut signed =
            SignedEvidenceManifest::sign(fixture_manifest(), &key(), "2026-08-22T00:00:00Z")
                .expect("sign");
        signed.manifest.completeness = Completeness::Derivable;
        assert!(
            signed.verify().is_err(),
            "flipping completeness must break the signature"
        );
    }

    #[test]
    fn an_archive_id_swapped_after_signing_is_refused() {
        let mut signed =
            SignedEvidenceManifest::sign(fixture_manifest(), &key(), "2026-08-22T00:00:00Z")
                .expect("sign");
        signed.manifest.archive_id = format!("sha256:{}", "ee".repeat(32));
        assert!(
            matches!(signed.verify(), Err(ReceiptError::ArchiveIdMismatch)),
            "a swapped content address must be caught by the id check"
        );
    }

    #[test]
    fn an_unknown_manifest_field_is_refused() {
        // Serialize a valid manifest and inject a key, rather than hand-writing
        // JSON: a hand-written fixture fails on its own missing fields and the
        // test would pass without deny_unknown_fields doing anything.
        let mut value =
            serde_json::to_value(fixture_manifest()).expect("manifest serializes to a value");
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).expect("serialize");
        assert!(serde_json::from_str::<EvidenceManifest>(&json).is_err());
    }
}
