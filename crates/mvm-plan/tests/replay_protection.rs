//! Integration tests for plan 37 Addendum G4 — replay protection.
//!
//! Covers `check_window` (validity timing), `NonceStore` (replay
//! ledger), and `Nonce` (wire format).

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use mvm_plan::types::{
    ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef, KeyRotationSpec, Nonce,
    NonceParseError, PlanId, PolicyRef, PostRunLifecycle, Resources, RuntimeProfileRef,
    SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
};
use mvm_plan::validity::{NonceStore, PlanValidityError, check_window};
use mvm_plan::{ExecutionPlan, SCHEMA_VERSION};

fn fixture_plan(nonce: [u8; 16]) -> ExecutionPlan {
    ExecutionPlan {
        schema_version: SCHEMA_VERSION,
        plan_id: PlanId("test-plan-001".to_string()),
        plan_version: 1,
        tenant: TenantId("test-tenant".to_string()),
        workload: WorkloadId("test-workload".to_string()),
        runtime_profile: RuntimeProfileRef("firecracker".to_string()),
        image: SignedImageRef {
            name: "test".to_string(),
            sha256: "0".repeat(64),
            cosign_bundle: None,
        },
        resources: Resources {
            cpus: 1,
            mem_mib: 256,
            disk_mib: 512,
            timeouts: TimeoutSpec {
                boot_secs: 30,
                exec_secs: 600,
            },
        },
        network_policy: PolicyRef("none".to_string()),
        fs_policy: FsPolicyRef("none".to_string()),
        secrets: vec![],
        egress_policy: PolicyRef("none".to_string()),
        tool_policy: PolicyRef("none".to_string()),
        artifact_policy: ArtifactPolicy {
            capture_paths: vec![],
            retention_days: 0,
        },
        audit_labels: BTreeMap::new(),
        key_rotation: KeyRotationSpec { interval_days: 0 },
        attestation: AttestationRequirement {
            mode: AttestationMode::Noop,
        },
        release_pin: None,
        post_run: PostRunLifecycle {
            destroy_on_exit: true,
            snapshot_on_idle: false,
            idle_secs: 0,
        },
        valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
        nonce: Nonce::from_bytes(nonce),
    }
}

// ----- check_window -----

#[test]
fn check_window_accepts_now_inside() {
    let plan = fixture_plan([0xaa; 16]);
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 30, 0).unwrap();
    check_window(&plan, now).expect("inside window");
}

#[test]
fn check_window_rejects_before_valid_from() {
    let plan = fixture_plan([0xaa; 16]);
    let now = Utc.with_ymd_and_hms(2026, 4, 30, 23, 59, 59).unwrap();
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::NotYetValid { .. }));
}

#[test]
fn check_window_rejects_at_valid_until_boundary() {
    let plan = fixture_plan([0xaa; 16]);
    // Boundary case: now == valid_until is rejected (closed-open
    // window).
    let now = plan.valid_until;
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::Expired { .. }));
}

#[test]
fn check_window_rejects_after_valid_until() {
    let plan = fixture_plan([0xaa; 16]);
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 2, 0, 0).unwrap();
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::Expired { .. }));
}

#[test]
fn check_window_rejects_inverted_window() {
    let mut plan = fixture_plan([0xaa; 16]);
    plan.valid_until = plan.valid_from - chrono::TimeDelta::seconds(1);
    let now = plan.valid_from;
    let err = check_window(&plan, now).unwrap_err();
    assert!(matches!(err, PlanValidityError::InvertedWindow { .. }));
}

#[test]
fn check_window_rejects_zero_duration_window() {
    let mut plan = fixture_plan([0xaa; 16]);
    plan.valid_until = plan.valid_from;
    let now = plan.valid_from;
    let err = check_window(&plan, now).unwrap_err();
    // Zero-duration is treated as inverted: valid_from >= valid_until.
    assert!(matches!(err, PlanValidityError::InvertedWindow { .. }));
}

// ----- NonceStore -----

#[test]
fn nonce_store_blocks_replay_same_signer() {
    let plan = fixture_plan([0x11; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    let err = store.check_and_insert("signer-a", &plan).unwrap_err();
    assert!(matches!(err, PlanValidityError::NonceReplay { .. }));
}

#[test]
fn nonce_store_allows_same_nonce_different_signer() {
    let plan = fixture_plan([0x22; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    // Same nonce on a different signer is fine — replay protection
    // is per-signer keyspace.
    store.check_and_insert("signer-b", &plan).unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn nonce_store_allows_different_nonces_same_signer() {
    let plan_a = fixture_plan([0x01; 16]);
    let plan_b = fixture_plan([0x02; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan_a).unwrap();
    store.check_and_insert("signer-a", &plan_b).unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn nonce_store_does_not_modify_state_on_replay_error() {
    let plan = fixture_plan([0x33; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    let err = store.check_and_insert("signer-a", &plan).unwrap_err();
    assert!(matches!(err, PlanValidityError::NonceReplay { .. }));
    // Length is still 1 — the failed insert did not corrupt the
    // ledger.
    assert_eq!(store.len(), 1);
}

#[test]
fn nonce_store_gc_drops_expired() {
    let plan = fixture_plan([0x44; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    assert_eq!(store.len(), 1);
    let after_window = plan.valid_until + chrono::TimeDelta::seconds(1);
    store.gc(after_window);
    assert!(store.is_empty(), "expired nonce should have been dropped");
}

#[test]
fn nonce_store_gc_preserves_unexpired() {
    let plan = fixture_plan([0x55; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    let inside_window = plan.valid_from + chrono::TimeDelta::seconds(1);
    store.gc(inside_window);
    assert_eq!(store.len(), 1, "unexpired nonce should remain");
}

#[test]
fn nonce_store_gc_drops_at_valid_until_boundary() {
    let plan = fixture_plan([0x66; 16]);
    let mut store = NonceStore::new();
    store.check_and_insert("signer-a", &plan).unwrap();
    // GC at valid_until exactly: stored entry has valid_until ==
    // plan.valid_until, GC drops where valid_until <= now.
    store.gc(plan.valid_until);
    assert!(store.is_empty(), "boundary GC should drop");
}

// ----- Nonce wire format -----

#[test]
fn nonce_from_bytes_lowercase_hex() {
    let n = Nonce::from_bytes([0xab; 16]);
    assert_eq!(n.as_hex(), "abababababababababababababababab");
}

#[test]
fn nonce_from_hex_accepts_valid() {
    let n = Nonce::from_hex("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(n.as_hex(), "00112233445566778899aabbccddeeff");
}

#[test]
fn nonce_from_hex_rejects_wrong_length() {
    let err = Nonce::from_hex("ab").unwrap_err();
    assert_eq!(err, NonceParseError::WrongLength { len: 2 });
}

#[test]
fn nonce_from_hex_rejects_uppercase() {
    let err = Nonce::from_hex("ABABABABABABABABABABABABABABABAB").unwrap_err();
    assert!(matches!(err, NonceParseError::NonHex { .. }));
}

#[test]
fn nonce_from_hex_rejects_non_hex() {
    let err = Nonce::from_hex("zzabababababababababababababababab").unwrap_err();
    // 33 chars triggers WrongLength first; check 32-char non-hex.
    assert!(matches!(err, NonceParseError::WrongLength { .. }));

    let err = Nonce::from_hex("zzababababababababababababababab").unwrap_err();
    assert!(matches!(err, NonceParseError::NonHex { ch: 'z' }));
}

#[test]
fn nonce_serde_roundtrip() {
    let n = Nonce::from_bytes([0x42; 16]);
    let json = serde_json::to_string(&n).unwrap();
    assert_eq!(json, "\"42424242424242424242424242424242\"");
    let back: Nonce = serde_json::from_str(&json).unwrap();
    assert_eq!(back, n);
}

#[test]
fn nonce_serde_rejects_uppercase_on_deserialize() {
    let json = "\"ABABABABABABABABABABABABABABABAB\"";
    let result: Result<Nonce, _> = serde_json::from_str(json);
    assert!(result.is_err());
}
