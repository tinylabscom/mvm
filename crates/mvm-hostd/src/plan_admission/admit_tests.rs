#![cfg(test)]

use super::admit::admit_for_run;
use super::nonce_ledger::InMemoryNonceLedger;
use super::test_support::{FixedClock, fixture_input, host_with_ceiling};
use super::*;
use crate::audit::host_keypair::host_signer_id;
use chrono::TimeZone;
use chrono::Utc;
use mvm_core::plan::{Variant, check_window, sign_plan, synthesize_plan, verify_plan};

#[test]
fn happy_path_returns_admitted_plan_with_plan_id() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_for_run(
        &fixture_input("vm1"),
        &clock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy path");
    assert!(!admitted.plan_id().0.is_empty());
    assert!(admitted.signer_id().starts_with("host:"));
    // The signed envelope must be re-verifiable with the public
    // half of the host signer.
    let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
    let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
        [(admitted.signer_id(), &signer.verifying)];
    let recovered = mvm_core::plan::verify_plan(admitted.signed(), &trusted).unwrap();
    assert_eq!(&recovered.plan_id, admitted.plan_id());
}

#[test]
fn admitted_plan_id_is_a_content_address() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let admitted = admit_for_run(
        &fixture_input("vm1"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy path");
    assert!(
        admitted.plan_id().0.starts_with("sha256:"),
        "content-addressed, not a UUID: {}",
        admitted.plan_id().0
    );
    // The admission path enforces the content-address; the admitted plan
    // re-derives to exactly its stored id.
    assert_eq!(mvm_core::plan::verify_plan_id(admitted.plan()), Ok(()));
}

#[test]
fn rejects_replay_within_validity_window() {
    let dir = tempfile::tempdir().unwrap();
    // We can't naturally replay because synthesize_plan generates a
    // fresh nonce each call — instead, build the plan once, sign,
    // then ask the ledger to admit twice. The second call must
    // refuse with nonce-replay.
    let plan = synthesize_plan(&fixture_input("vm1")).unwrap();
    let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
    let signer_id = host_signer_id();
    let signed = sign_plan(&plan, &signer.signing, &signer_id);
    let verified =
        mvm_core::plan::verify_plan(&signed, &[(&signer_id, &signer.verifying)]).unwrap();

    let ledger = InMemoryNonceLedger::new();
    {
        let mut store = ledger.inner.lock().unwrap();
        assert!(store.check_and_insert(&signer_id, &verified).is_ok());
        assert!(
            store.check_and_insert(&signer_id, &verified).is_err(),
            "second insert of same (signer, nonce) must fail"
        );
    }
}

#[test]
fn rejects_plan_outside_validity_window() {
    // Construct a fixed clock 30 minutes in the future — past
    // the plan's 10-minute window from synthesis.
    let now_plus_30 = Utc.with_ymd_and_hms(2099, 1, 1, 12, 30, 0).unwrap();
    // Override time by constructing a plan with a known window
    // and a FixedClock outside it.
    let dir = tempfile::tempdir().unwrap();
    // To exercise the window check deterministically, we
    // pre-build a stale signed plan and feed it directly through
    // the check (synthesize_plan can't make a stale plan because
    // it uses Utc::now()).
    let mut plan = synthesize_plan(&fixture_input("vm1")).unwrap();
    plan.valid_from = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
    plan.valid_until = Utc.with_ymd_and_hms(2000, 1, 1, 0, 10, 0).unwrap();
    let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
    let signed = sign_plan(&plan, &signer.signing, &host_signer_id());
    let verified = verify_plan(&signed, &[(&host_signer_id(), &signer.verifying)]).unwrap();
    let _clock = FixedClock(now_plus_30);
    // Inline the window check (admit_for_run does it after
    // synthesis; we're proving the underlying assert).
    assert!(check_window(&verified, now_plus_30).is_err());
}

#[test]
fn admitted_plan_signed_field_round_trips_through_verify() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let admitted = admit_for_run(
        &fixture_input("vm1"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .unwrap();
    // The signed field is what the audit signer will hash;
    // proving it round-trips here closes the contract.
    let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
    let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
        [(admitted.signer_id(), &signer.verifying)];
    assert!(verify_plan(admitted.signed(), &trusted).is_ok());
}

#[test]
fn propagates_synthesis_failures() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let err = admit_for_run(
        &fixture_input(""), // empty vm_name fails synthesis
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("must refuse");
    assert!(
        err.to_string().contains("vm_name")
            || err.chain().any(|e| e.to_string().contains("vm_name"))
    );
}

#[test]
fn two_distinct_admit_calls_produce_distinct_plan_ids_and_nonces() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let ledger = InMemoryNonceLedger::new();
    let a1 = admit_for_run(
        &fixture_input("vm1"),
        &clock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .unwrap();
    let a2 = admit_for_run(
        &fixture_input("vm1"),
        &clock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .unwrap();
    assert_ne!(a1.plan_id, a2.plan_id);
    assert_ne!(a1.plan.nonce, a2.plan.nonce);
}

#[test]
fn caller_audit_labels_flow_through_admission() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let mut input = fixture_input("vm-label");
    input.audit_labels.insert(
        "origin.descriptor".to_string(),
        "blake3:testvalue".to_string(),
    );
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy path");
    assert_eq!(
        admitted.plan().audit_labels["origin.descriptor"],
        "blake3:testvalue"
    );
    // Profile-derived keys must still be present and authoritative.
    assert!(!admitted.plan().audit_labels["intent"].is_empty());
    assert!(!admitted.plan().audit_labels["admission_profile"].is_empty());
    assert_eq!(admitted.plan().audit_labels["seccomp_tier"], "standard");
}
