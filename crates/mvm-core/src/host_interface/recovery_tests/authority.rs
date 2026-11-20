use ed25519_dalek::Signer;

use super::*;

#[test]
fn companion_and_lease_must_verify_under_the_same_resolved_key() {
    let mut f = Fixture::new();
    let other = SigningKey::from_bytes(&[2; 32]);
    f.lease = SignedLease::sign(f.lease.lease, "issuer", &other).unwrap();
    f.companion.policy.lease_digest = signed_record_digest(&f.lease).unwrap();
    f.companion = SignedRecoveryPolicy::sign(f.companion.policy, &f.key).unwrap();
    assert!(matches!(
        f.verify(clock(150, 10)),
        Err(Denial::LeaseInvalid("signature does not verify"))
    ));
}

#[test]
fn companion_signature_and_identity_are_pinned() {
    let f = Fixture::new();
    assert_eq!(
        hex::encode(&f.companion.signature),
        "bf05b0983bf6e564fbbfb689ad0ae9cc024a9e1247dcc23238c2df89efd5318307230a8fc36951a70ddb8d79047c638b45d3f79fd92540a72849702328c3c406"
    );
    assert_eq!(
        hex::encode(signed_record_digest(&f.companion).unwrap()),
        "994957e542b0987dc374e16d53e79bdd3e678e469403ce72d224636990bc6d58"
    );
}

#[test]
fn legacy_signed_bytes_and_signatures_are_unchanged() {
    let f = Fixture::new();
    let lease = r#"{"allowed":["local_launch","egress"],"issued_at":100,"max_queued_messages":0,"node_id":"node","not_after":200,"policy_version":4}"#;
    let policy = r#"{"attestation":{"minimum":"hardware","required":false},"image_digests":[],"not_after":190,"scope":["node"],"version":4,"volumes":[]}"#;
    assert_eq!(serde_jcs::to_vec(&f.lease.lease).unwrap(), lease.as_bytes());
    assert_eq!(
        serde_jcs::to_vec(&f.policy.policy).unwrap(),
        policy.as_bytes()
    );
    assert_eq!(
        hex::encode(&f.lease.signature),
        "f7f6391ec35825359d9d908ba92c210df5a8cc35144e8c1939e7f671247f65cbf6a95b328d630d34b9ae28c686bdd60b20882f778800d1028b1c024229006308"
    );
    assert_eq!(
        hex::encode(&f.policy.signature),
        "1ef6914e55d77de38fce7afaa896f207ba17911524c5007ff9e7b725fa2ec26146ca5a70001fd8f994538f9cba7f92b8f115cc3afa45df77ebafc6b6c852d103"
    );
    let trusted = [("issuer".into(), f.key.verifying_key())];
    assert!(f.lease.verify(&trusted, "node", 150, 4).is_ok());
    assert!(f.policy.verify(&trusted, 150, 4).is_ok());
}

#[test]
fn companion_requires_domain_separation_and_exact_signature_length() {
    let mut f = Fixture::new();
    f.companion.signature = f
        .key
        .sign(&serde_jcs::to_vec(&f.companion.policy).unwrap())
        .to_bytes()
        .to_vec();
    assert!(matches!(
        f.verify(clock(150, 10)),
        Err(Denial::Offline(OfflineRefusal::Signature))
    ));
    for length in [0, 63, 65] {
        f.companion.signature = vec![0; length];
        assert!(matches!(
            f.verify(clock(150, 10)),
            Err(Denial::Offline(OfflineRefusal::Signature))
        ));
    }
}

#[test]
fn companion_roundtrips_and_refuses_unknown_nested_fields_and_versions() {
    let mut f = Fixture::new();
    let value = serde_json::to_value(&f.companion).unwrap();
    assert_eq!(
        serde_json::from_value::<SignedRecoveryPolicy>(value.clone()).unwrap(),
        f.companion
    );
    for path in [vec![], vec!["policy"], vec!["policy", "restart"]] {
        let mut changed = value.clone();
        let mut target = &mut changed;
        for key in path {
            target = &mut target[key];
        }
        target["unrecognized"] = true.into();
        assert!(serde_json::from_value::<SignedRecoveryPolicy>(changed).is_err());
    }
    f.companion.policy.version = 2;
    f.resign();
    assert!(matches!(
        f.verify(clock(150, 10)),
        Err(Denial::Offline(OfflineRefusal::Version))
    ));
}

#[test]
fn missing_managed_records_and_untrusted_or_ambiguous_issuers_refuse() {
    let f = Fixture::new();
    let trusted = [("issuer".into(), f.key.verifying_key())];
    for missing in 0..3 {
        let mut input = f.input(&trusted);
        match missing {
            0 => input.lease = None,
            1 => input.policy = None,
            2 => input.companion = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            VerifiedOfflineAuthority::verify(input, clock(150, 10)),
            Err(Denial::Offline(OfflineRefusal::AuthorityMissing))
        ));
    }
    for keys in [
        vec![],
        vec![trusted[0].clone(), trusted[0].clone()],
        vec![(
            "issuer".into(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
        )],
    ] {
        assert!(VerifiedOfflineAuthority::verify(f.input(&keys), clock(150, 10)).is_err());
    }
    let mut input = f.input(&trusted);
    input.policy_issuers = &[];
    assert!(VerifiedOfflineAuthority::verify(input, clock(150, 10)).is_err());
}

#[test]
fn inactive_nodes_policy_scope_and_explicit_ceilings_refuse() {
    let f = Fixture::new();
    let trusted = [("issuer".into(), f.key.verifying_key())];
    for state in [
        NodeState::Pending,
        NodeState::Quarantined,
        NodeState::Revoked,
    ] {
        let mut input = f.input(&trusted);
        input.expected.node_state = state;
        assert!(VerifiedOfflineAuthority::verify(input, clock(150, 10)).is_err());
    }
    for field in 0..3 {
        let mut input = f.input(&trusted);
        match field {
            0 => input.ceilings.lease_seconds = 99,
            1 => input.ceilings.restarts = 1,
            2 => input.ceilings.connection_attempts = 7,
            _ => unreachable!(),
        }
        assert!(VerifiedOfflineAuthority::verify(input, clock(150, 10)).is_err());
    }
    let mut f = Fixture::new();
    f.policy.policy.scope = vec!["other".into()];
    f.resign();
    assert!(matches!(f.verify(clock(150, 10)), Err(Denial::PolicyScope)));
}

#[test]
fn mailbox_authority_and_queueing_are_explicitly_unsupported() {
    for queue_only in [false, true] {
        let mut f = Fixture::new();
        if queue_only {
            f.lease.lease.max_queued_messages = 1;
        } else {
            f.lease.lease.allowed.push(LeaseOp::Mailbox);
        }
        f.resign();
        assert!(matches!(
            f.verify(clock(150, 10)),
            Err(Denial::LeaseOpNotAllowed("mailbox"))
        ));
    }
}

#[test]
fn restart_needs_both_lease_operation_and_companion_permission() {
    for denied_by_lease in [false, true] {
        let mut f = Fixture::new();
        if denied_by_lease {
            f.lease.lease.allowed = vec![LeaseOp::Egress];
        } else {
            f.companion.policy.restart = RestartAllowance::Denied;
        }
        f.resign();
        let mut r = f.recovery();
        assert!(r.request(request(), clock(150, 10)).is_err());
        assert!(r.binding().is_none());
    }
}

#[test]
fn interval_uncertainty_shortens_deadline_and_checks_not_before() {
    let f = Fixture::new();
    let time = ClockEvidence::Bounded {
        earliest_unix: 145,
        latest_unix: 155,
        monotonic_seconds: 10,
        continuity: [7; 16],
    };
    let a = f.verify(time).unwrap();
    assert_eq!(a.deadline(), 45);
    let uncertain_start = ClockEvidence::Bounded {
        earliest_unix: 99,
        latest_unix: 101,
        monotonic_seconds: 10,
        continuity: [7; 16],
    };
    assert!(f.verify(uncertain_start).is_err());
}

#[test]
fn nonexpiring_local_policy_does_not_make_offline_lease_infinite() {
    let mut f = Fixture::new();
    f.policy.policy.not_after = None;
    f.resign();
    let a = f.verify(clock(150, 10)).unwrap();
    assert_eq!(a.expiry(), 200);
    assert_eq!(a.deadline(), 60);
    assert_eq!(
        a.permits(LeaseOp::LocalLaunch, clock(200, 60)),
        Err(Denial::LeaseExpired)
    );
}

#[test]
fn checked_integer_boundaries_never_wrap_or_saturate_into_authority() {
    let mut f = Fixture::new();
    f.companion.policy.restart = RestartAllowance::SamePackage {
        max_restarts: 1,
        first_epoch: ExecutionEpoch::new(u64::MAX).unwrap(),
        last_epoch: ExecutionEpoch::new(u64::MAX).unwrap(),
    };
    f.resign();
    let mut history = f.history();
    history.epoch_high_water = ExecutionEpoch::new(u64::MAX - 1).unwrap();
    let mut r = Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).unwrap();
    let mut req = request();
    req.proposed_epoch = ExecutionEpoch::new(u64::MAX).unwrap();
    assert_eq!(
        r.request(req, clock(150, 10)).unwrap().action,
        RecoveryAction::Reserve
    );
    let mut history = f.history();
    history.epoch_high_water = ExecutionEpoch::new(u64::MAX).unwrap();
    history.last_operation = u64::MAX;
    let mut r = Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).unwrap();
    assert!(r.request(request(), clock(150, 10)).is_err());

    for end in [99, 100] {
        f.lease.lease.not_after = end;
        f.resign();
        assert!(f.verify(clock(100, 10)).is_err());
    }
}
