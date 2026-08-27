//! Signed, chainable execution receipts for mvm workloads.
//!
//! An [`ExecutionReceipt`] is a portable, offline-verifiable proof that a
//! specific workload ran under a specific authority at a specific time. It is
//! intentionally a *derived* artifact over the chain-signed audit log, not a
//! new runtime authority.
//!
//! The wire format is influenced by Project NANDA's Agency Receipt Protocol
//! (`sm-arp`) and Attested Action Envelope (`sm-aae`), but re-implemented on
//! mvm's existing Ed25519/JCS/SHA-256 stack without taking an external
//! dependency.
//!
//! # Envelope
//!
//! ```json
//! {
//!   "payload": { ... },
//!   "signed_by": "did:key:z6Mk...",
//!   "signed_at": "<rfc3339-utc>",
//!   "signature": "<base64-ed25519>"
//! }
//! ```
//!
//! The signature covers the RFC 8785 (JCS) canonicalization of `payload`. The
//! payload's value space is constrained to ASCII strings, integers, booleans,
//! null, and nested objects/arrays of the same — no floats, no non-ASCII
//! strings, no raw bytes. This makes the canonical form unambiguous across
//! implementations.

use crate::did_key::DidKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Wire-stable receipt types.
pub mod receipt_type {
    /// Emitted when a plan is admitted by the host.
    pub const PLAN_ADMITTED: &str = "plan.admitted";
    /// Emitted when a workload launches.
    pub const PLAN_LAUNCHED: &str = "plan.launched";
    /// Emitted when a workload exits.
    pub const PLAN_EXITED: &str = "plan.exited";
    /// Emitted when a checkpoint is created.
    pub const CHECKPOINT_CREATED: &str = "checkpoint.created";
    /// Emitted when a checkpoint is restored.
    pub const CHECKPOINT_RESTORED: &str = "checkpoint.restored";
    /// Emitted when a checkpoint is forked.
    pub const CHECKPOINT_FORKED: &str = "checkpoint.forked";
    /// Emitted when a workload input request is refused.
    pub const INPUT_REFUSED: &str = "stream.input_refused";
    /// Emitted when an assurance session is opened against an admitted plan.
    pub const ASSURANCE_SESSION_OPENED: &str = "assurance.session_opened";
    /// Emitted when an assurance trial completes and its outcome is derived.
    pub const ASSURANCE_TRIAL_COMPLETED: &str = "assurance.trial_completed";
    /// Emitted when the host observer commits its trial observation.
    pub const ASSURANCE_OBSERVER_COMPLETED: &str = "assurance.observer_completed";
    /// Emitted after the admitted disposable VM is confirmed stopped.
    pub const ASSURANCE_CLEANUP_COMPLETED: &str = "assurance.cleanup_completed";
    /// Emitted after a trusted runtime verifier joins a native quote to the
    /// admitted assurance session.
    pub const ASSURANCE_ATTESTATION_VERIFIED: &str = "assurance.attestation_verified";
}

/// Namespaced keys for the extensions an exporter attaches.
///
/// These are inside the signed payload, so a receipt lifted out of an archive
/// and forwarded on its own still names the log position it came from. All are
/// `mvm.`-prefixed: `extensions` is an open map, and an unprefixed key would
/// collide with whatever a future writer chooses.
pub mod extension_key {
    /// Lowercase hex SHA-256 of the exact signed audit-entry bytes.
    pub const AUDIT_DIGEST: &str = "mvm.audit_digest";
    /// Merkle root hash the receipt was exported against.
    pub const AUDIT_ROOT: &str = "mvm.audit_root";
    /// Tree size that root was published at.
    pub const TREE_SIZE: &str = "mvm.tree_size";
    /// Ciphertext-manifest root of the workload's sealed output transcript.
    ///
    /// Present only once the transcript has sealed, so a receipt exported
    /// mid-run does not carry one. Its value is the same root a reader
    /// verifies before decrypting anything -- never a plaintext digest.
    pub const TRANSCRIPT_ROOT: &str = "mvm.transcript_root";
    /// Lowest leaf index in the tenant's audit tree carrying an entry for
    /// this plan, and [`PLAN_LEAF_LAST`] the highest.
    ///
    /// **A bound, not an enumeration.** The tree is per-tenant, so another
    /// plan's entries can sit between these two indices. What the pair buys is
    /// that nothing for this plan sits outside them, so a verifier can restrict
    /// its scan to that window instead of walking the whole tree. Reading it as
    /// "every leaf in this range belongs to this plan" is wrong.
    pub const PLAN_LEAF_FIRST: &str = "mvm.plan_leaf_first";
    /// Highest leaf index for this plan. See [`PLAN_LEAF_FIRST`] for the
    /// bound-not-enumeration caveat.
    pub const PLAN_LEAF_LAST: &str = "mvm.plan_leaf_last";
    /// Whether that transcript was rebuilt from its journal rather than
    /// sealed by the process that captured it. `true` marks a floor: records
    /// the departed writer shed after its last durable append are in no file
    /// anywhere, so the transcript is an incomplete account of the run.
    pub const TRANSCRIPT_ADOPTED: &str = "mvm.transcript_adopted";
}

/// Outcome of the action described by a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptOutcome {
    /// The action was authorized but not yet executed.
    Authorized,
    /// The workload is running.
    Running,
    /// The workload completed successfully.
    Succeeded,
    /// The workload failed.
    Failed,
    /// The action was refused by policy.
    Refused,
}

/// The action described by a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptAction {
    /// The verb, e.g. `run`, `exec`, `checkpoint`.
    pub verb: String,
    /// The resource the verb acts on, typically a `plan_id`.
    pub resource: String,
    /// Optional named parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Value>,
}

/// The signed payload of an execution receipt.
///
/// Every field is part of the signed material. Keep secrets out: this payload
/// may be published to auditors or registries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Wire schema version. Const `1` for this version.
    #[serde(default = "schema_version_default")]
    pub schema_version: u32,
    /// Content-address of this receipt: `sha256(JCS(payload))`.
    pub receipt_id: String,
    /// Wire-stable receipt type, e.g. `plan.admitted`.
    pub receipt_type: String,
    /// Content-address of the admitted `ExecutionPlan`.
    pub plan_id: String,
    /// Optional content-address of the image lineage node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_node_digest: Option<String>,
    /// Optional identifier for the acting agent/workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Optional `did:key` of the principal the agent acts for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,
    /// `did:key` of the host signer.
    pub host_did: String,
    /// What action this receipt records.
    pub action: ReceiptAction,
    /// Outcome of the action.
    pub outcome: ReceiptOutcome,
    /// Optional citation to a grant or oversight approval receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    /// Optional hash link to the previous receipt in this chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_receipt_id: Option<String>,
    /// RFC 3339 UTC timestamp when the action started, if known.
    /// For `plan.exited`, this is the timestamp of the matching `plan.launched`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// RFC 3339 UTC timestamp when the action ended.
    /// For `plan.exited`, this is the timestamp of the exit entry itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// Captured process exit code, when the receipt records a workload exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Capability grants admitted for this workload, e.g. agent verbs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_capabilities: Vec<String>,
    /// Network destinations admitted for this workload, as (host, port) pairs.
    /// `port = 0` means "any port for this host".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_destinations: Vec<(String, u16)>,
    /// RFC 3339 UTC timestamp of when the action occurred.
    pub issued_at: String,
    /// Namespace-prefixed extensions. Unknown keys are preserved by verifiers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

fn schema_version_default() -> u32 {
    1
}

/// A signed execution receipt envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionReceipt {
    /// The signed payload.
    pub payload: ExecutionReceipt,
    /// `did:key` of the signer.
    pub signed_by: String,
    /// RFC 3339 UTC timestamp of signing. **Not signed** — forgeable.
    pub signed_at: String,
    /// Base64 Ed25519 signature over `canonical_json(payload)`.
    pub signature: String,
}

/// Error type for receipt operations.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    /// The payload value space was violated.
    #[error("payload contains a value outside the signed value space: {0}")]
    InvalidValueSpace(String),
    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Signing or verification failed.
    #[error("signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    /// The `signed_by` field did not match the signature's public key.
    #[error("signed_by did:key does not match the signature key")]
    SignerMismatch,
    /// The `receipt_id` did not match the recomputed content address.
    #[error("receipt_id does not match recomputed content address")]
    ReceiptIdMismatch,

    /// The archive's content address does not match its contents.
    #[error("archive_id does not match recomputed content address")]
    ArchiveIdMismatch,
    /// The `did:key` could not be parsed.
    #[error("did:key parse error: {0}")]
    DidKey(#[from] crate::did_key::DidKeyError),
}

impl ExecutionReceipt {
    /// Prefix for content-addressed receipt IDs.
    pub const ID_PREFIX: &'static str = "sha256:";

    /// Recompute the content-address of this receipt.
    ///
    /// The ID is `sha256:<hex>` over the JCS-canonical form of the payload
    /// with `receipt_id` temporarily cleared. This prevents a self-reference
    /// cycle: the id is part of the payload, but it cannot be part of its own
    /// input.
    pub fn compute_id(&self) -> Result<String, ReceiptError> {
        let mut canonical_self = self.clone();
        canonical_self.receipt_id.clear();
        let canonical = canonical_json(&canonical_self)?;
        let digest = Sha256::digest(&canonical);
        Ok(format!("{}{}", Self::ID_PREFIX, hex::encode(digest)))
    }

    /// Verify that `receipt_id` matches the recomputed content address.
    pub fn verify_id(&self) -> Result<(), ReceiptError> {
        let expected = self.compute_id()?;
        if expected == self.receipt_id {
            Ok(())
        } else {
            Err(ReceiptError::ReceiptIdMismatch)
        }
    }
}

impl SignedExecutionReceipt {
    /// Sign a receipt payload with an Ed25519 signing key.
    ///
    /// The `signed_at` timestamp is captured from the caller; it is not part of
    /// the signed material. The `issued_at` field inside the payload is signed.
    pub fn sign(
        payload: ExecutionReceipt,
        signing_key: &SigningKey,
        signed_at: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        payload.verify_id()?;
        let did = DidKey::from_verifying_key(signing_key.verifying_key());
        let canonical = canonical_json(&payload)?;
        let signature = signing_key.sign(&canonical);
        Ok(Self {
            payload,
            signed_by: did.to_did_key(),
            signed_at: signed_at.into(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Verify the signature and structural integrity of this receipt.
    ///
    /// Checks, in order:
    /// 1. `receipt_id` matches the recomputed content address.
    /// 2. `signed_by` is a valid `did:key`.
    /// 3. The signature is valid over the canonical payload.
    /// 4. The signing key matches `signed_by`.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        self.payload.verify_id()?;
        let did = DidKey::parse(&self.signed_by)?;
        let vk = did.verifying_key();
        let canonical = canonical_json(&self.payload)?;
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

/// Canonicalize a value into the constrained JCS form used for signing.
///
/// Returns an error if the value contains a float, a non-ASCII string, or any
/// other value outside the admissible space.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReceiptError> {
    let json_value = serde_json::to_value(value)?;
    validate_value_space(&json_value)?;
    Ok(serde_jcs::to_vec(&json_value)?)
}

fn validate_value_space(value: &Value) -> Result<(), ReceiptError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(()),
        Value::Number(n) => Err(ReceiptError::InvalidValueSpace(format!(
            "float or non-integer number: {n}"
        ))),
        Value::String(s) => {
            if s.is_ascii() {
                Ok(())
            } else {
                Err(ReceiptError::InvalidValueSpace(format!(
                    "non-ASCII string: {s:?}"
                )))
            }
        }
        Value::Array(values) => {
            for v in values {
                validate_value_space(v)?;
            }
            Ok(())
        }
        Value::Object(entries) => {
            for (k, v) in entries {
                if !k.is_ascii() {
                    return Err(ReceiptError::InvalidValueSpace(format!(
                        "non-ASCII object key: {k:?}"
                    )));
                }
                validate_value_space(v)?;
            }
            Ok(())
        }
    }
}

/// Verify the continuity of a receipt chain.
///
/// For each receipt after the first, checks that its `prev_receipt_id` equals
/// the previous receipt's `receipt_id`. Does not verify signatures; call
/// [`SignedExecutionReceipt::verify`] on each receipt first.
pub fn verify_receipt_chain(receipts: &[ExecutionReceipt]) -> Result<(), ReceiptError> {
    for window in receipts.windows(2) {
        let prev = &window[0];
        let curr = &window[1];
        let expected = curr
            .prev_receipt_id
            .as_deref()
            .ok_or_else(|| ReceiptError::InvalidValueSpace("missing prev_receipt_id".into()))?;
        if expected != prev.receipt_id {
            return Err(ReceiptError::InvalidValueSpace(
                "receipt chain broken".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> ExecutionReceipt {
        ExecutionReceipt {
            schema_version: 1,
            receipt_id: String::new(), // filled in by sign
            receipt_type: receipt_type::PLAN_ADMITTED.into(),
            plan_id: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            image_node_digest: None,
            agent_id: Some("agent-1".into()),
            principal_did: Some("did:key:z6MkhaXgZAgMVMFG8oYF1ADbc94YHQ6D98F4BAtRzGWsqd71".into()),
            host_did: String::new(), // filled in by sign
            action: ReceiptAction {
                verb: "run".into(),
                resource: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                params: BTreeMap::new(),
            },
            outcome: ReceiptOutcome::Authorized,
            granted_by: None,
            prev_receipt_id: None,
            started_at: None,
            ended_at: None,
            exit_code: None,
            granted_capabilities: Vec::new(),
            network_destinations: Vec::new(),
            issued_at: "2026-08-06T00:00:00+00:00".into(),
            extensions: BTreeMap::new(),
        }
    }

    fn signed_sample() -> SignedExecutionReceipt {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut receipt = sample_receipt();
        receipt.host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
        receipt.receipt_id = receipt.compute_id().unwrap();
        SignedExecutionReceipt::sign(receipt, &signing_key, "2026-08-06T00:00:00+00:00").unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signed = signed_sample();
        signed.verify().expect("verify own signature");
    }

    #[test]
    fn tampered_signature_fails() {
        let mut signed = signed_sample();
        signed.signature = BASE64_STANDARD.encode([0u8; 64]);
        assert!(signed.verify().is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let mut signed = signed_sample();
        signed.payload.outcome = ReceiptOutcome::Failed;
        assert!(signed.verify().is_err());
    }

    #[test]
    fn non_ascii_string_rejected() {
        let mut receipt = sample_receipt();
        receipt.agent_id = Some("Müller".into());
        assert!(matches!(
            receipt.compute_id(),
            Err(ReceiptError::InvalidValueSpace(_))
        ));
    }

    #[test]
    fn float_rejected() {
        let mut receipt = sample_receipt();
        receipt
            .action
            .params
            .insert("ratio".into(), serde_json::json!(1.5));
        assert!(matches!(
            receipt.compute_id(),
            Err(ReceiptError::InvalidValueSpace(_))
        ));
    }

    #[test]
    fn receipt_id_is_deterministic() {
        let signed1 = signed_sample();
        let signed2 = signed_sample();
        assert_eq!(signed1.payload.receipt_id, signed2.payload.receipt_id);
    }

    #[test]
    fn chain_continuity_ok() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut r1 = sample_receipt();
        r1.host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
        r1.receipt_id = r1.compute_id().unwrap();

        let signed1 =
            SignedExecutionReceipt::sign(r1.clone(), &signing_key, "2026-08-06T00:00:00+00:00")
                .unwrap();

        let mut r2 = sample_receipt();
        r2.receipt_type = receipt_type::PLAN_LAUNCHED.into();
        r2.outcome = ReceiptOutcome::Running;
        r2.prev_receipt_id = Some(signed1.payload.receipt_id.clone());
        r2.host_did = signed1.payload.host_did.clone();
        r2.receipt_id = r2.compute_id().unwrap();

        verify_receipt_chain(&[signed1.payload, r2]).expect("chain valid");
    }

    #[test]
    fn broken_chain_fails() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut r1 = sample_receipt();
        r1.host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
        r1.receipt_id = r1.compute_id().unwrap();

        let mut r2 = sample_receipt();
        r2.receipt_type = receipt_type::PLAN_LAUNCHED.into();
        r2.outcome = ReceiptOutcome::Running;
        r2.prev_receipt_id = Some("sha256:deadbeef".into());
        r2.host_did = r1.host_did.clone();
        r2.receipt_id = r2.compute_id().unwrap();

        assert!(verify_receipt_chain(&[r1, r2]).is_err());
    }
}
