//! Integration tests for the plan signing + replay-protection contract.
//!
//! Covers the load-bearing properties of the cornerstone (whitepaper
//! §3.3, plan 37 Wave 1):
//!
//! - serde roundtrip
//! - signature verifies with the correct key
//! - signature rejected with the wrong key
//! - signature rejected after payload tampering
//! - signature rejected after envelope tampering
//! - validity window: not-yet, expired, inverted
//! - nonce replay: same nonce blocks; different nonce passes
//! - GC of expired nonces

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_plan::envelope::ENVELOPE_VERSION;
use mvm_plan::plan::{PlanId, Resources, WorkloadId};
use mvm_plan::refs::{
    ArtifactPolicy, AttestationRequirement, FsPolicyRef, KeyRotationSpec, PolicyRef,
    PostRunLifecycle, RuntimeProfileRef, SignedImageRef,
};
use mvm_plan::replay::{NonceStore, PlanValidityError, check_window};
use mvm_plan::{ExecutionPlan, sign_plan, verify_plan};
use rand::rngs::OsRng;

fn fixture_plan() -> ExecutionPlan {
    ExecutionPlan {
        plan_id: PlanId("test-plan-001".to_string()),
        plan_version: 1,
        tenant: "test-tenant".to_string(),
        workload: WorkloadId("test-workload".to_string()),
        runtime_profile: RuntimeProfileRef {
            name: "default-microvm".to_string(),
            digest: [0u8; 32],
        },
        image: SignedImageRef {
            name: "hello".to_string(),
            digest: [1u8; 32],
            signature_bundle_digest: [2u8; 32],
        },
        resources: Resources::default(),
        network_policy: PolicyRef::none(),
        fs_policy: FsPolicyRef::none(),
        egress_policy: PolicyRef::none(),
        tool_policy: PolicyRef::none(),
        secrets: vec![],
        artifact_policy: ArtifactPolicy::default(),
        key_rotation: KeyRotationSpec::default(),
        attestation: AttestationRequirement::default(),
        release_pin: None,
        post_run: PostRunLifecycle::default(),
        audit_labels: BTreeMap::new(),
        valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
        nonce: [42u8; 16],
    }
}

fn fresh_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

#[test]
fn plan_serde_roundtrip_is_stable() {
    let plan = fixture_plan();
    let bytes = serde_json::to_vec(&plan).expect("serialize");
    let back: ExecutionPlan = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(plan, back);
}

#[test]
fn canonical_bytes_are_deterministic() {
    let plan = fixture_plan();
    let a = plan.canonical_bytes().unwrap();
    let b = plan.canonical_bytes().unwrap();
    assert_eq!(a, b, "canonical bytes must be deterministic");
}

#[test]
fn signed_envelope_roundtrip_succeeds() {
    let (signing, verifying) = fresh_keypair();
    let plan = fixture_plan();
    let signed = sign_plan(&plan, &signing, "test-signer").expect("sign");
    assert_eq!(signed.envelope_version, ENVELOPE_VERSION);
    assert_eq!(signed.signer_id, "test-signer");
    let back = verify_plan(&signed, &verifying).expect("verify");
    assert_eq!(plan, back);
}

#[test]
fn signed_envelope_rejects_wrong_key() {
    let (signing, _verifying_a) = fresh_keypair();
    let (_signing_b, verifying_b) = fresh_keypair();
    let signed = sign_plan(&fixture_plan(), &signing, "signer-a").unwrap();
    let err = verify_plan(&signed, &verifying_b).unwrap_err();
    assert!(matches!(
        err,
        mvm_plan::envelope::EnvelopeError::SignatureMismatch
    ));
}

#[test]
fn signed_envelope_rejects_tampered_payload() {
    let (signing, verifying) = fresh_keypair();
    let mut signed = sign_plan(&fixture_plan(), &signing, "test-signer").unwrap();
    // Flip a byte in the payload.
    signed.payload_canonical[0] ^= 0xff;
    let err = verify_plan(&signed, &verifying).unwrap_err();
    assert!(matches!(
        err,
        mvm_plan::envelope::EnvelopeError::SignatureMismatch
    ));
}

#[test]
fn signed_envelope_rejects_tampered_signature() {
    let (signing, verifying) = fresh_keypair();
    let mut signed = sign_plan(&fixture_plan(), &signing, "test-signer").unwrap();
    signed.signature[0] ^= 0xff;
    let err = verify_plan(&signed, &verifying).unwrap_err();
    assert!(matches!(
        err,
        mvm_plan::envelope::EnvelopeError::SignatureMismatch
    ));
}

#[test]
fn signed_envelope_rejects_unsupported_version() {
    let (signing, verifying) = fresh_keypair();
    let mut signed = sign_plan(&fixture_plan(), &signing, "test-signer").unwrap();
    signed.envelope_version = 999;
    let err = verify_plan(&signed, &verifying).unwrap_err();
    assert!(matches!(
        err,
        mvm_plan::envelope::EnvelopeError::UnsupportedVersion(999)
    ));
}

#[test]
fn signed_envelope_rejects_malformed_signature_length() {
    let (signing, verifying) = fresh_keypair();
    let mut signed = sign_plan(&fixture_plan(), &signing, "test-signer").unwrap();
    signed.signature.truncate(32);
    let err = verify_plan(&signed, &verifying).unwrap_err();
    assert!(matches!(
        err,
        mvm_plan::envelope::EnvelopeError::MalformedSignature { .. }
    ));
}

#[test]
fn validity_window_accepts_now_inside() {
    let plan = fixture_plan();
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 30, 0).unwrap();
    check_window(&plan, now).expect("inside window");
}

#[test]
fn validity_window_rejects_before_valid_from() {
    let plan = fixture_plan();
    let now = Utc.with_ymd_and_hms(2026, 4, 30, 23, 0, 0).unwrap();
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::NotYetValid { .. }));
}

#[test]
fn validity_window_rejects_after_valid_until() {
    let plan = fixture_plan();
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 2, 0, 0).unwrap();
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::Expired { .. }));
}

#[test]
fn validity_window_rejects_inverted_window() {
    let mut plan = fixture_plan();
    plan.valid_until = plan.valid_from - chrono::TimeDelta::seconds(1);
    let now = plan.valid_from;
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::InvertedWindow { .. }));
}

#[test]
fn nonce_store_blocks_replay_same_signer() {
    let plan = fixture_plan();
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    let err = store.check_and_insert("signer-a", &plan).unwrap_err();
    assert!(matches!(err, PlanValidityError::NonceReplay { .. }));
}

#[test]
fn nonce_store_allows_same_nonce_different_signer() {
    let plan = fixture_plan();
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    // Same nonce on a different signer is fine — replay protection
    // is per-signer keyspace.
    store.check_and_insert("signer-b", &plan).unwrap();
}

#[test]
fn nonce_store_allows_different_nonces_same_signer() {
    let mut plan_a = fixture_plan();
    let mut plan_b = fixture_plan();
    plan_a.nonce = [1u8; 16];
    plan_b.nonce = [2u8; 16];
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan_a).unwrap();
    store.check_and_insert("signer-a", &plan_b).unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn nonce_store_gc_drops_expired() {
    let plan = fixture_plan();
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    assert_eq!(store.len(), 1);
    let after_window = plan.valid_until + chrono::TimeDelta::seconds(1);
    store.gc(after_window);
    assert!(store.is_empty(), "expired nonce should have been dropped");
}

#[test]
fn nonce_store_gc_preserves_unexpired() {
    let plan = fixture_plan();
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    let inside_window = plan.valid_from + chrono::TimeDelta::seconds(1);
    store.gc(inside_window);
    assert_eq!(store.len(), 1, "unexpired nonce should remain");
}

#[test]
fn artifact_policy_default_retention_is_seven_days() {
    let p = ArtifactPolicy::default();
    assert_eq!(p.retention, Duration::from_secs(7 * 24 * 60 * 60));
    assert_eq!(p.capture_path, "/artifacts");
    assert!(p.encrypt_at_rest);
    assert!(!p.sign);
}

#[test]
fn unknown_field_in_plan_is_rejected() {
    let bytes = br#"{
        "plan_id": "x", "plan_version": 1,
        "tenant": "t", "workload": "w",
        "runtime_profile": {"name": "a", "digest": []},
        "image": {"name": "a", "digest": [], "signature_bundle_digest": []},
        "resources": {"cpus": 1, "memory_mib": 1, "disk_mib": 1, "timeout_secs": 1},
        "network_policy": {"bundle_id": "x", "bundle_version": 0, "digest": []},
        "fs_policy": {"bundle_id": "x", "bundle_version": 0, "digest": []},
        "egress_policy": {"bundle_id": "x", "bundle_version": 0, "digest": []},
        "tool_policy": {"bundle_id": "x", "bundle_version": 0, "digest": []},
        "secrets": [], "artifact_policy": {"capture_path": "/a", "retention": 0, "encrypt_at_rest": true, "sign": false},
        "key_rotation": {"kind": "none"}, "attestation": {"tier": "none"},
        "release_pin": null, "post_run": {"kind": "destroy"},
        "audit_labels": {}, "valid_from": "2026-05-01T00:00:00Z",
        "valid_until": "2026-05-01T01:00:00Z", "nonce": [],
        "EXTRA_BAD_FIELD": 1
    }"#;
    // We expect rejection because of `deny_unknown_fields`.
    let result: Result<ExecutionPlan, _> = serde_json::from_slice(bytes);
    assert!(
        result.is_err(),
        "unknown field must be rejected by deny_unknown_fields"
    );
}
