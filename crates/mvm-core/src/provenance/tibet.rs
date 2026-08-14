//! Optional TIBET-compatible JSON serializer for decision records.
//!
//! TIBET (Transaction/Interaction-Based Evidence Trail) is a token format
//! used by some regulator-facing provenance platforms. This module is a
//! read-only, dependency-free mapper: it consumes `mvm_contract::provenance`
//! decision records and emits TIBET-shaped JSON using only the crates
//! already in `mvm-core` (`serde`, `serde_jcs`, `sha2`, `uuid`). No runtime
//! dependency on a TIBET platform crate is introduced.
//!
//! Limitations of the export:
//! - `token_id` is a deterministic UUIDv5 derived from the `DecisionId` so
//!   the same decision always produces the same token id.
//! - `signature` is left empty because this read-only export path does not
//!   have access to the host signer's private key. Verifiers should check
//!   the chain-signed audit entry referenced by `erachter.attestation`.

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use mvm_contract::provenance::{CausalLink, DecisionCategory, DecisionOutcome, DecisionRecord};

/// Namespace UUID used to derive TIBET token ids from `DecisionId`s.
const TOKEN_NAMESPACE: Uuid = Uuid::from_u128(0x7384183e_8a55_4bcc_8f7b_d453fceb424a);

/// A TIBET-shaped token produced from a [`DecisionRecord`].
// allow(secret-debug): "token" here is a provenance evidence document, not a
// credential — every field is already public in the exported JSON, and
// `signature` is an empty placeholder because this path holds no signing key.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TibetToken {
    /// Deterministic UUIDv5 derived from the decision content address.
    pub token_id: String,
    /// Token format version.
    pub version: u32,
    /// TIBET token type; always `"decision"` for decision records.
    #[serde(rename = "type")]
    pub token_type: String,
    /// RFC 3339 timestamp carried over from the decision record.
    pub timestamp: String,
    /// Actor URI in `local:<principal>` form.
    pub actor: String,
    /// Optional parent token id derived from the first causal link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// The decision category, outcome, and confidence.
    pub erin: serde_json::Value,
    /// Causal links and artifact digests that sit "on" the decision.
    pub eraan: serde_json::Value,
    /// Regulatory/policy scope that sits "around" the decision.
    pub eromheen: serde_json::Value,
    /// Reasoning and attestation binding that sit "behind" the decision.
    pub erachter: serde_json::Value,
    /// Derived decision state: `active`, `denied`, or `pending`.
    pub state: String,
    /// SHA-256 of the canonical JSON of this token excluding `hash` and
    /// `signature`, prefixed with `sha256:`.
    pub hash: String,
    /// Empty placeholder; real verification uses the chain signature.
    pub signature: String,
}

/// Body used to compute the TIBET token hash.
///
/// Identical to [`TibetToken`] except `hash` and `signature` are omitted,
/// matching the TIBET canonicalization rule.
// allow(secret-debug): the hash pre-image of a public evidence document; it is
// strictly a subset of `TibetToken`'s already-public fields.
#[derive(Debug, Clone, Serialize)]
struct TibetTokenBody {
    token_id: String,
    version: u32,
    #[serde(rename = "type")]
    token_type: String,
    timestamp: String,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    erin: serde_json::Value,
    eraan: serde_json::Value,
    eromheen: serde_json::Value,
    erachter: serde_json::Value,
    state: String,
}

impl From<&TibetToken> for TibetTokenBody {
    fn from(token: &TibetToken) -> Self {
        Self {
            token_id: token.token_id.clone(),
            version: token.version,
            token_type: token.token_type.clone(),
            timestamp: token.timestamp.clone(),
            actor: token.actor.clone(),
            parent_id: token.parent_id.clone(),
            erin: token.erin.clone(),
            eraan: token.eraan.clone(),
            eromheen: token.eromheen.clone(),
            erachter: token.erachter.clone(),
            state: token.state.clone(),
        }
    }
}

/// Map a [`DecisionRecord`] to a TIBET-compatible token.
pub fn decision_record_to_tibet_token(record: &DecisionRecord) -> TibetToken {
    let token_id = decision_id_to_token_id(&record.decision_id.0);
    let parent_id = record
        .causal_links
        .first()
        .map(|link| decision_id_to_token_id(&link.decision_id.0).to_string());

    let actor = format!("local:{}", actor_local_name(record));

    let erin = serde_json::json!({
        "category": decision_category_name(record.category),
        "outcome": decision_outcome_name(record.outcome),
        "confidence": record.confidence,
    });

    let eraan = serde_json::json!({
        "causal_links": record.causal_links.iter().map(tibet_causal_link).collect::<Vec<_>>(),
        "artifact_digests": record.attestation.artifact_digests.clone(),
        "plan_id": record.attestation.plan_id,
        "workload_addr": record.attestation.workload_addr,
    });

    let eromheen = serde_json::json!({
        "regulation_scope": record.metadata.regulation_scope,
        "policy_ref": record.metadata.policy_ref,
        "ticket_ref": record.metadata.ticket_ref,
    });

    let erachter = serde_json::json!({
        "reasoning": record.reasoning,
        "decision_id": record.decision_id.0,
        "attestation": {
            "audit_entry_hash": record.attestation.audit_entry_hash,
            "signer_pubkey": record.attestation.signer_pubkey,
            "plan_id": record.attestation.plan_id,
            "workload_addr": record.attestation.workload_addr,
            "artifact_digests": record.attestation.artifact_digests,
        },
    });

    let state = outcome_to_state(record.outcome);

    let mut token = TibetToken {
        token_id: token_id.to_string(),
        version: 1,
        token_type: "decision".to_string(),
        timestamp: record.timestamp.clone(),
        actor,
        parent_id,
        erin,
        eraan,
        eromheen,
        erachter,
        state: state.to_string(),
        hash: String::new(),
        signature: String::new(),
    };

    token.hash = compute_tibet_hash(&token);
    token
}

/// Recompute the `hash` field for a token.
pub fn compute_tibet_hash(token: &TibetToken) -> String {
    let body = TibetTokenBody::from(token);
    let canonical = serde_jcs::to_vec(&body).expect("TibetTokenBody serializes to JCS");
    let digest = Sha256::digest(&canonical);
    format!("sha256:{}", hex::encode(digest))
}

/// Convert a causal link to a TIBET-shaped object.
fn tibet_causal_link(link: &CausalLink) -> serde_json::Value {
    serde_json::json!({
        "relation": causal_relation_name(link.relation),
        "token_id": decision_id_to_token_id(&link.decision_id.0).to_string(),
    })
}

/// Derive a deterministic UUIDv5 token id from a `DecisionId` string.
fn decision_id_to_token_id(decision_id: &str) -> Uuid {
    Uuid::new_v5(&TOKEN_NAMESPACE, decision_id.as_bytes())
}

/// Pick the local actor identifier.
fn actor_local_name(record: &DecisionRecord) -> &str {
    if record.actor.principal.is_empty() {
        &record.actor.key_id
    } else {
        &record.actor.principal
    }
}

/// Render a [`DecisionCategory`] as a stable snake_case string.
fn decision_category_name(category: DecisionCategory) -> &'static str {
    match category {
        DecisionCategory::Admission => "admission",
        DecisionCategory::Launch => "launch",
        DecisionCategory::Egress => "egress",
        DecisionCategory::Checkpoint => "checkpoint",
        DecisionCategory::Approval => "approval",
        DecisionCategory::Policy => "policy",
        DecisionCategory::Control => "control",
    }
}

/// Render a [`DecisionOutcome`] as a stable snake_case string.
fn decision_outcome_name(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Approved => "approved",
        DecisionOutcome::Denied => "denied",
        DecisionOutcome::Deferred => "deferred",
    }
}

/// Render a [`mvm_contract::provenance::CausalRelation`] as snake_case.
fn causal_relation_name(relation: mvm_contract::provenance::CausalRelation) -> &'static str {
    use mvm_contract::provenance::CausalRelation;
    match relation {
        CausalRelation::Caused => "caused",
        CausalRelation::Influenced => "influenced",
        CausalRelation::PrecedentFor => "precedent_for",
        CausalRelation::Invalidated => "invalidated",
    }
}

/// Map an outcome to a TIBET state string.
fn outcome_to_state(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Approved => "active",
        DecisionOutcome::Denied => "denied",
        DecisionOutcome::Deferred => "pending",
    }
}

/// Export a slice of decision records as a pretty-printed TIBET-JSON array.
pub fn decision_records_to_tibet_json(records: &[DecisionRecord]) -> String {
    let tokens: Vec<TibetToken> = records.iter().map(decision_record_to_tibet_token).collect();
    serde_json::to_string_pretty(&tokens).expect("TibetToken array serializes to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use mvm_contract::provenance::{
        ActorRef, AttestationBinding, CausalLink, CausalRelation, DecisionActorRole,
        DecisionCategory, DecisionMetadata, DecisionOutcome, DecisionRecordBuilder,
        DecisionScenario,
    };

    fn sample_record() -> DecisionRecord {
        DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: Some(DecisionActorRole::Orchestrator),
            })
            .scenario(DecisionScenario {
                plan_id: Some("sha256:abc".to_string()),
                ..DecisionScenario::default()
            })
            .reasoning("plan satisfies grant ceiling")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z".to_string())
            .metadata(DecisionMetadata {
                ticket_ref: Some("CHG-123".to_string()),
                policy_ref: Some("POL-001".to_string()),
                regulation_scope: vec!["EU-AI-Act".to_string()],
            })
            .attestation(AttestationBinding {
                plan_id: Some("sha256:abc".to_string()),
                workload_addr: Some("uor:addr:xyz".to_string()),
                artifact_digests: BTreeMap::from([("rootfs".to_string(), "sha256:rf".to_string())]),
                audit_entry_hash: "sha256:entryhash".to_string(),
                signer_pubkey: "ed25519:pubkey".to_string(),
            })
            .build()
            .expect("valid decision record")
    }

    #[test]
    fn token_fields_map_from_decision_record() {
        let record = sample_record();
        let token = decision_record_to_tibet_token(&record);

        assert_eq!(token.token_type, "decision");
        assert_eq!(token.version, 1);
        assert_eq!(token.timestamp, "2026-08-13T00:00:00Z");
        assert_eq!(token.actor, "local:host:builder");
        assert_eq!(token.state, "active");
        assert!(token.hash.starts_with("sha256:"));
        assert!(token.signature.is_empty());

        assert_eq!(token.erin["category"], "admission");
        assert_eq!(token.erin["outcome"], "approved");
        assert!(token.erin["confidence"].is_null());

        assert_eq!(token.eraan["artifact_digests"]["rootfs"], "sha256:rf");
        assert_eq!(token.eraan["plan_id"], "sha256:abc");
        assert_eq!(token.eraan["workload_addr"], "uor:addr:xyz");

        assert_eq!(token.eromheen["regulation_scope"][0], "EU-AI-Act");
        assert_eq!(token.eromheen["ticket_ref"], "CHG-123");
        assert_eq!(token.eromheen["policy_ref"], "POL-001");

        assert_eq!(token.erachter["reasoning"], "plan satisfies grant ceiling");
        assert_eq!(
            token.erachter["attestation"]["audit_entry_hash"],
            "sha256:entryhash"
        );
    }

    #[test]
    fn token_id_is_deterministic_from_decision_id() {
        let record = sample_record();
        let token1 = decision_record_to_tibet_token(&record);
        let token2 = decision_record_to_tibet_token(&record);
        assert_eq!(token1.token_id, token2.token_id);
        assert_eq!(
            token1.token_id,
            Uuid::new_v5(&TOKEN_NAMESPACE, record.decision_id.0.as_bytes()).to_string()
        );
    }

    #[test]
    fn hash_excludes_hash_and_signature_fields() {
        let record = sample_record();
        let token = decision_record_to_tibet_token(&record);

        let body = TibetTokenBody::from(&token);
        let canonical = serde_jcs::to_string(&body).unwrap();
        assert!(!canonical.contains("\"hash\""));
        assert!(!canonical.contains("\"signature\""));

        assert_eq!(token.hash, compute_tibet_hash(&token));
    }

    #[test]
    fn parent_id_derived_from_first_causal_link() {
        let parent = sample_record();
        let child = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Launch)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: None,
            })
            .reasoning("launch after admission")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:01Z".to_string())
            .attestation(AttestationBinding {
                audit_entry_hash: "sha256:entryhash2".to_string(),
                signer_pubkey: "ed25519:pubkey".to_string(),
                ..AttestationBinding::default()
            })
            .causal_link(CausalLink {
                relation: CausalRelation::Caused,
                decision_id: parent.decision_id.clone(),
            })
            .build()
            .expect("valid child record");

        let token = decision_record_to_tibet_token(&child);
        assert_eq!(
            token.parent_id,
            Some(decision_id_to_token_id(&parent.decision_id.0).to_string())
        );
        assert_eq!(token.eraan["causal_links"][0]["relation"], "caused");
        assert_eq!(
            token.eraan["causal_links"][0]["token_id"],
            decision_id_to_token_id(&parent.decision_id.0).to_string()
        );
    }

    #[test]
    fn actor_falls_back_to_key_id_when_principal_empty() {
        let mut record = sample_record();
        record.actor.principal.clear();
        let token = decision_record_to_tibet_token(&record);
        assert_eq!(token.actor, "local:host-signer-1");
    }

    #[test]
    fn denied_outcome_maps_to_denied_state() {
        let mut record = sample_record();
        record.outcome = DecisionOutcome::Denied;
        let token = decision_record_to_tibet_token(&record);
        assert_eq!(token.state, "denied");
        assert_eq!(token.erin["outcome"], "denied");
    }

    #[test]
    fn json_export_produces_array() {
        let record = sample_record();
        let json = decision_records_to_tibet_json(std::slice::from_ref(&record));
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["type"], "decision");
        assert_eq!(
            parsed[0]["hash"],
            decision_record_to_tibet_token(&record).hash
        );
    }
}
