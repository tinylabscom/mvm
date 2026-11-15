#![cfg(test)]

use super::test_support::*;
use super::*;

/// The fleet issuer key the tests pin — or deliberately don't.
fn fleet_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn pin_for(signer_id: &str, key: &SigningKey) -> TrustedPlanSigner {
    TrustedPlanSigner {
        signer_id: signer_id.to_string(),
        ed25519_pubkey_hex: hex::encode(key.verifying_key().as_bytes()),
    }
}

/// Isolate `MVM_HOME` and write `cfg` as the host config. Admission reads
/// the trusted signer set (and the grant ceiling) from host config rather
/// than from a parameter, so a test that wants a trusting host has to
/// *be* one. The guard and home must both outlive the admission call.
fn host_with(cfg: MvmConfig) -> (TestEnv, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let pins = cfg.trusted_plan_signers.len();
    mvm_core::user_config::save(&cfg, None).expect("writing the host config");
    // Precondition, not a redundant assertion: if this fails the isolation
    // did not hold and every check below would measure some other host.
    assert_eq!(
        mvm_core::user_config::load(None).trusted_plan_signers.len(),
        pins,
        "the isolated host must read back the pins it was configured with"
    );
    (env, home)
}

fn host_pinning(signers: Vec<TrustedPlanSigner>) -> (TestEnv, tempfile::TempDir) {
    host_with(MvmConfig {
        trusted_plan_signers: signers,
        ..MvmConfig::default()
    })
}

fn signed_by_fleet(plan: &ExecutionPlan) -> SignedExecutionPlan {
    sign_plan(plan, &fleet_key(), "fleet-prod")
}

fn admit(signed: &SignedExecutionPlan, ledger: &InMemoryNonceLedger) -> Result<AdmittedPlan> {
    admit_signed_plan_for_run(
        signed,
        &SystemClock,
        ledger,
        None,
        RunPosture::without_backend(Variant::Dev),
    )
}

#[test]
fn a_pinned_fleet_signers_plan_is_admitted() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let plan = PlanFixture::new().tenant("fleet-tenant").build();
    let signed = signed_by_fleet(&plan);

    let admitted = admit(&signed, &InMemoryNonceLedger::new())
        .expect("a plan signed by a pinned fleet signer admits");

    assert_eq!(admitted.signer_id(), "fleet-prod");
    assert_eq!(admitted.plan().tenant.0, "fleet-tenant");
    // The admitted plan is content-addressed and the envelope the caller
    // handed in is carried verbatim — not re-signed under the host key.
    assert_eq!(admitted.plan_id(), &admitted.plan().plan_id);
    assert_eq!(admitted.signed().0.signer_id, "fleet-prod");
    assert_eq!(admitted.signed().0.signature, signed.0.signature);
}

#[test]
fn an_unpinned_host_refuses_every_signed_plan() {
    // The default: no pins, no externally-signed admissions. This is the
    // fail-closed posture a host is in before the operator delegates.
    let (_env, _home) = host_pinning(Vec::new());
    let signed = signed_by_fleet(&PlanFixture::new().build());

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a host that pins nobody must refuse");
    assert!(
        format!("{err:#}").contains("pins no trusted plan signers"),
        "got: {err:#}"
    );
}

#[test]
fn an_unknown_signer_is_refused() {
    // The host pins a *different* fleet issuer; the envelope names one it
    // never heard of.
    let other = SigningKey::from_bytes(&[7u8; 32]);
    let (_env, _home) = host_pinning(vec![pin_for("fleet-staging", &other)]);
    let signed = signed_by_fleet(&PlanFixture::new().build());

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("an unpinned signer must be refused");
    assert!(
        format!("{err:#}").contains("no trusted key matched signer_id fleet-prod"),
        "got: {err:#}"
    );
}

#[test]
fn a_tampered_payload_is_refused() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let mut signed = signed_by_fleet(&PlanFixture::new().build());
    signed.0.payload[0] ^= 0x01;

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a tampered payload must fail signature verification");
    assert!(
        format!("{err:#}").contains("signature verification failed"),
        "got: {err:#}"
    );
}

#[test]
fn an_expired_plan_is_refused() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let now = Utc::now();
    let plan = PlanFixture::new()
        .validity(now - Duration::hours(2), now - Duration::hours(1))
        .build();
    let signed = signed_by_fleet(&plan);

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a validly-signed but expired plan must be refused");
    assert!(
        format!("{err:#}").contains("plan validity window violated"),
        "got: {err:#}"
    );
}

#[test]
fn a_not_yet_valid_plan_is_refused() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let now = Utc::now();
    let plan = PlanFixture::new()
        .validity(now + Duration::hours(1), now + Duration::hours(2))
        .build();
    let signed = signed_by_fleet(&plan);

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a plan whose window has not opened must be refused");
    assert!(
        format!("{err:#}").contains("plan validity window violated"),
        "got: {err:#}"
    );
}

#[cfg(unix)]
#[test]
fn a_replayed_plan_is_refused_by_a_fresh_process_sharing_the_durable_ledger() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let signed = signed_by_fleet(&PlanFixture::new().build());
    let dir = tempfile::tempdir().expect("ledger dir");
    let ledger_dir = dir.path().join("plan-nonces");

    // Two ledgers on one directory stand in for two launches, which each
    // build their own ledger.
    let first = InMemoryNonceLedger::durable_in(&ledger_dir).expect("open ledger");
    admit(&signed, &first).expect("the first launch is admitted");
    let second = InMemoryNonceLedger::durable_in(&ledger_dir).expect("open ledger");
    let err = admit(&signed, &second).expect_err("the same plan in a later launch is a replay");
    assert!(format!("{err:#}").contains("replay"), "got: {err:#}");
}

#[cfg(unix)]
#[test]
fn a_plan_is_refused_when_its_nonce_cannot_be_recorded() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let signed = signed_by_fleet(&PlanFixture::new().build());
    let dir = tempfile::tempdir().expect("ledger dir");
    let ledger =
        InMemoryNonceLedger::durable_in(dir.path().join("plan-nonces")).expect("open ledger");
    std::fs::write(
        dir.path().join("plan-nonces").join("nonces.tsv"),
        "corrupt\n",
    )
    .expect("corrupt the ledger");
    let err = admit(&signed, &ledger).expect_err("an unreadable ledger must refuse");
    assert!(
        format!("{err:#}").contains("cannot be recorded"),
        "got: {err:#}"
    );
}

#[test]
fn a_replayed_nonce_is_refused() {
    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    let signed = signed_by_fleet(&PlanFixture::new().build());
    let ledger = InMemoryNonceLedger::new();

    admit(&signed, &ledger).expect("the first admission succeeds");
    let err = admit(&signed, &ledger).expect_err("the same plan admitted twice is a replay");
    assert!(format!("{err:#}").contains("replay"), "got: {err:#}");
}

#[test]
fn a_plan_id_that_does_not_address_its_content_is_refused() {
    use ed25519_dalek::Signer as _;

    let (_env, _home) = host_pinning(vec![pin_for("fleet-prod", &fleet_key())]);
    // sign_plan re-derives the content address, so a mismatched id cannot
    // come through it — build the envelope by hand: a valid signature over
    // a plan whose stored id does not address its body.
    let plan = PlanFixture::new()
        .plan_id("not-the-content-address")
        .build();
    let payload = serde_json::to_vec(&plan).expect("plan serializes");
    let signature = fleet_key().sign(&payload);
    let signed = SignedExecutionPlan(mvm_core::protocol::signing::SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: "fleet-prod".to_string(),
    });

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a signed plan whose id does not address its content must be refused");
    assert!(
        format!("{err:#}").contains("plan_id content-address check"),
        "got: {err:#}"
    );
}

#[test]
fn a_grant_over_the_host_ceiling_is_refused() {
    // The fleet's signature does not widen host policy: the ceiling the
    // operator configured still bounds what an externally-signed plan may
    // ask for.
    let (_env, _home) = host_with(MvmConfig {
        max_cpu_millicores: Some(2000),
        trusted_plan_signers: vec![pin_for("fleet-prod", &fleet_key())],
        ..MvmConfig::default()
    });
    let plan = PlanFixture::new()
        .grants(Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
            ..mvm_contract::grants::Grants::default()
        }))
        .build();
    let signed = signed_by_fleet(&plan);

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a grant above the host's ceiling must not be admitted");
    let msg = format!("{err:#}");
    assert!(msg.contains("ceiling"), "{msg}");
    assert!(msg.contains("64000") && msg.contains("2000"), "{msg}");
}

#[test]
fn a_malformed_pin_refuses_admission() {
    // A pin the operator mistyped fails the whole load — admission never
    // runs against a silently-truncated trust set.
    let (_env, _home) = host_pinning(vec![TrustedPlanSigner {
        signer_id: "fleet-prod".to_string(),
        ed25519_pubkey_hex: "not-hex".to_string(),
    }]);
    let signed = signed_by_fleet(&PlanFixture::new().build());

    let err = admit(&signed, &InMemoryNonceLedger::new())
        .expect_err("a malformed pin must refuse admission");
    assert!(format!("{err:#}").contains("fleet-prod"), "got: {err:#}");
}
