//! Plan 60 Phase 7a end-to-end: the operator/auditor pipeline.
//!
//! Drives the full Slice A + D shape as one cohesive test:
//!
//! 1. Build a per-tenant overlay tree with planted files
//! 2. Destroy it via `OverlayManager::destroy_overlay`
//! 3. Sign each receipt under an operator's host identity key
//! 4. Serialize the array as JSON (the overlay-erasure certificate
//!    batch format)
//! 5. Hand the JSON to `verify_destruction_receipt` (the same
//!    function `mvmctl audit verify-cert` uses internally)
//! 6. Assert: every cert verifies, the receipt fields match the
//!    pre-destroy state, the overlay directories are gone.
//!
//! ## Why this test exists
//!
//! Unit tests cover each piece (overlay create/destroy, sign,
//! verify, JSON round-trip). This integration test pins the
//! *interface contract* between the operator and the auditor:
//! the JSON the operator emits is exactly what the auditor's
//! verifier consumes, with no silent shape drift between
//! producer + consumer.
//!
//! ## Tampering invariants
//!
//! The test also flips one cert's `tenant` field after signing
//! and confirms the verifier refuses — this is the load-bearing
//! security invariant the whole certificate flow rests on, and
//! the test is the regression fence.

use ed25519_dalek::SigningKey;
use mvm::vm::overlay::{
    FsOverlayManager, OverlayManager, SignedDestructionReceipt, sign_destruction_receipt,
    verify_destruction_receipt,
};
use tempfile::tempdir;

/// Build a fake operator host with a tenant having `workloads`
/// overlays, each populated with one file of `bytes_per_file` bytes.
async fn populate_tenant(
    mgr: &FsOverlayManager,
    tenant: &str,
    workloads: &[&str],
    bytes_per_file: usize,
) {
    for wkl in workloads {
        let handle = mgr.create_overlay(tenant, wkl).await.unwrap();
        std::fs::write(handle.root.join("data.bin"), vec![0xa5u8; bytes_per_file]).unwrap();
    }
}

/// End-to-end: destroy + sign + serialize + parse + verify all
/// three workloads, then assert the overlay tree is gone.
#[tokio::test]
async fn operator_destroys_three_workloads_auditor_verifies_all_three() {
    let dir = tempdir().unwrap();
    let mgr = FsOverlayManager::with_root(dir.path()).unwrap();
    let signing_key = { let mut __ed_seed = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed); SigningKey::from_bytes(&__ed_seed) };
    let verifying_key = signing_key.verifying_key();

    let workloads = ["build-runner", "code-eval", "test-runner"];
    populate_tenant(&mgr, "acme", &workloads, 1024).await;

    // Operator side — exactly the overlay-erasure certificate loop.
    let overlays = mgr.list_overlays("acme").await.unwrap();
    assert_eq!(overlays.len(), 3);
    let mut certs: Vec<SignedDestructionReceipt> = Vec::new();
    for handle in &overlays {
        let receipt = mgr
            .destroy_overlay(&handle.tenant, &handle.workload)
            .await
            .unwrap();
        certs.push(sign_destruction_receipt(&receipt, &signing_key));
    }

    // Wire format the operator writes to stdout — the auditor
    // receives exactly this string.
    let on_wire = serde_json::to_string_pretty(&certs).unwrap();

    // Auditor side — parses the wire, verifies against the
    // operator's pubkey. The pubkey would in practice come from
    // a trust-store / out-of-band channel; here it comes from
    // the same SigningKey we generated.
    let parsed: Vec<SignedDestructionReceipt> = serde_json::from_str(&on_wire).unwrap();
    assert_eq!(parsed.len(), 3);
    for (i, cert) in parsed.iter().enumerate() {
        let receipt = verify_destruction_receipt(cert, Some(&verifying_key)).unwrap();
        assert_eq!(receipt.tenant, "acme");
        assert_eq!(receipt.workload, workloads[i]);
        assert_eq!(receipt.files_wiped, 1);
        assert_eq!(receipt.bytes_wiped, 1024);
    }

    // The overlay tree must be gone post-destroy.
    for wkl in &workloads {
        let path = dir.path().join("acme").join(wkl);
        assert!(!path.exists(), "overlay {path:?} should be removed");
    }
}

/// Negative test: tampering with the certificate's tenant field
/// after signing breaks verification. This is the load-bearing
/// security invariant — the auditor can detect that a malicious
/// hosted-cloud operator who destroys one tenant's overlay and
/// then forges a certificate claiming it was a different tenant
/// gets caught.
#[tokio::test]
async fn auditor_refuses_certificate_with_tampered_tenant_field() {
    let dir = tempdir().unwrap();
    let mgr = FsOverlayManager::with_root(dir.path()).unwrap();
    let key = { let mut __ed_seed = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed); SigningKey::from_bytes(&__ed_seed) };
    let vk = key.verifying_key();

    populate_tenant(&mgr, "acme", &["build"], 512).await;
    let receipt = mgr.destroy_overlay("acme", "build").await.unwrap();
    let mut signed = sign_destruction_receipt(&receipt, &key);

    // Tamper: change the tenant name. The signature was computed
    // over the original receipt; this MUST break verification.
    signed.receipt.tenant = "totally-different-tenant".to_string();

    let err = verify_destruction_receipt(&signed, Some(&vk)).unwrap_err();
    assert!(
        matches!(
            err,
            mvm::vm::overlay::DestructionVerifyError::SignatureInvalid
        ),
        "expected SignatureInvalid, got {err:?}"
    );
}

/// Negative test: a destination-mismatched pubkey is rejected
/// even if the embedded signature would itself verify cleanly
/// under a different (attacker-controlled) pubkey.
#[tokio::test]
async fn auditor_refuses_certificate_signed_by_wrong_pubkey() {
    let dir = tempdir().unwrap();
    let mgr = FsOverlayManager::with_root(dir.path()).unwrap();
    let operator_key = { let mut __ed_seed = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed); SigningKey::from_bytes(&__ed_seed) };
    let attacker_key = { let mut __ed_seed = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed); SigningKey::from_bytes(&__ed_seed) };

    populate_tenant(&mgr, "acme", &["build"], 256).await;
    let receipt = mgr.destroy_overlay("acme", "build").await.unwrap();
    // Sign under the ATTACKER's key but claim it's from the
    // operator.
    let signed = sign_destruction_receipt(&receipt, &attacker_key);

    // Auditor pins to the OPERATOR's known pubkey.
    let err = verify_destruction_receipt(&signed, Some(&operator_key.verifying_key())).unwrap_err();
    assert!(matches!(
        err,
        mvm::vm::overlay::DestructionVerifyError::PubkeyMismatch { .. }
    ));
}

/// Verifying with `expected_signer_pubkey = None` accepts a
/// cert whose embedded `signer_pubkey` is internally consistent
/// — useful for auditors who get the pubkey via the cert itself
/// (and trust it via some other channel).
#[tokio::test]
async fn auditor_can_verify_against_certs_embedded_pubkey() {
    let dir = tempdir().unwrap();
    let mgr = FsOverlayManager::with_root(dir.path()).unwrap();
    let key = { let mut __ed_seed = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed); SigningKey::from_bytes(&__ed_seed) };

    populate_tenant(&mgr, "acme", &["build"], 100).await;
    let receipt = mgr.destroy_overlay("acme", "build").await.unwrap();
    let signed = sign_destruction_receipt(&receipt, &key);

    // No `expected_signer_pubkey` — the verifier uses the
    // pubkey embedded in the cert.
    let recovered = verify_destruction_receipt(&signed, None).unwrap();
    assert_eq!(recovered.tenant, "acme");
    assert_eq!(recovered.workload, "build");
}

/// Pin the per-receipt signature payload format: a future
/// refactor that changes field order or delimiter without
/// bumping the version field would silently break every issued
/// certificate. This test catches that at the wire-format level
/// independently of the destroy/sign integration.
#[test]
fn signature_payload_format_pinned_at_v1() {
    let receipt = mvm::vm::overlay::DestructionReceipt {
        tenant: "acme".to_string(),
        workload: "wkl".to_string(),
        destroyed_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        files_wiped: 5,
        bytes_wiped: 1024,
    };
    let payload = receipt.signature_payload();
    let s = String::from_utf8(payload).unwrap();
    // The auditor's verifier reconstructs this byte-for-byte.
    // Any drift here invalidates every previously-issued cert.
    assert_eq!(s, "destruction|v1|acme|wkl|1700000000000000000|5|1024");
}
