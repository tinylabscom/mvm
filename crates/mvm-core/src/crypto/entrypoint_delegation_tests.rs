use super::*;

fn fixture() -> (SigningKey, RegistrationChallenge) {
    let key = SigningKey::from_bytes(&[31; 32]);
    let identity = EnrolledIdentity {
        installation: Uuid::new_v4(),
        public_key: key.verifying_key().to_bytes(),
    };
    let binding = RegistrationBinding {
        tenant: "tenant".into(),
        instance: format!("concrete-vm/{}", Uuid::new_v4()),
        plan_id: "plan-id".into(),
        plan_nonce: Nonce::from_bytes([1; 16]),
        run: Uuid::new_v4(),
        producer: Uuid::new_v4(),
        session: Uuid::new_v4(),
        not_before: 100,
        not_after: 200,
    };
    (
        key,
        RegistrationChallenge::fresh(binding, identity, 100).unwrap(),
    )
}

#[test]
fn proof_roundtrips_and_verifies_exact_canonical_claims() {
    let (key, expected) = fixture();
    let proof = RegistrationProof::sign(&key, &expected.identity, &expected, 100).unwrap();
    let wire = serde_json::to_vec(&proof).unwrap();
    let received: RegistrationProof = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        received.challenge.binding.instance_vm().unwrap(),
        "concrete-vm"
    );
    assert_eq!(
        received.verify(&expected, 100).unwrap().challenge(),
        &expected
    );
    assert_eq!(received.verify(&expected, 199).unwrap().proof(), &proof);
    assert!(matches!(
        received.verify(&expected, 99),
        Err(DelegationError::Expired)
    ));
    assert!(matches!(
        received.verify(&expected, 200),
        Err(DelegationError::Expired)
    ));
}

#[test]
fn every_construction_and_verification_path_refuses_noncanonical_instance_identities() {
    let (key, expected) = fixture();
    let valid = RegistrationProof::sign(&key, &expected.identity, &expected, 100).unwrap();
    let id = Uuid::parse_str("abcdefab-cdef-4abc-8def-abcdefabcdef").unwrap();
    for vm in ["a".into(), "0".into(), "vm-1".into(), "a".repeat(63)] {
        let mut canonical = expected.clone();
        canonical.binding.instance = format!("{vm}/{id}");
        assert_eq!(canonical.binding.instance_vm().unwrap(), vm);
        let proof = RegistrationProof::sign(&key, &canonical.identity, &canonical, 100).unwrap();
        assert_eq!(
            proof.verify(&canonical, 100).unwrap().challenge(),
            &canonical
        );
    }
    for instance in [
        "concrete-instance".into(),
        id.to_string(),
        format!("vm/{}", Uuid::nil()),
        format!("vm/{}", id.to_string().to_uppercase()),
        format!("vm/{}", id.simple()),
        format!("vm/{{{id}}}"),
        format!("vm/urn:uuid:{id}"),
        format!("VM/{id}"),
        format!("-vm/{id}"),
        format!("vm-/{id}"),
        format!("vm_name/{id}"),
        format!("{}/{id}", "a".repeat(64)),
        format!("vm name/{id}"),
        format!("/{id}"),
        format!("vm/extra/{id}"),
        format!("vm/{id}/extra"),
    ] {
        let mut malformed = expected.clone();
        malformed.binding.instance = instance;
        assert_eq!(
            malformed.binding.instance_vm(),
            Err(DelegationError::Invalid)
        );
        assert!(matches!(
            RegistrationChallenge::fresh(
                malformed.binding.clone(),
                malformed.identity.clone(),
                100
            ),
            Err(DelegationError::Invalid)
        ));
        assert!(matches!(
            RegistrationProof::sign(&key, &malformed.identity, &malformed, 100),
            Err(DelegationError::Invalid)
        ));
        let forged = RegistrationProof {
            challenge: malformed.clone(),
            signature: valid.signature.clone(),
        };
        assert!(matches!(
            forged.verify(&malformed, 100),
            Err(DelegationError::Invalid)
        ));
    }
}

#[test]
fn every_binding_dimension_is_signed_and_compared_with_trusted_expectation() {
    let (key, expected) = fixture();
    let proof = RegistrationProof::sign(&key, &expected.identity, &expected, 100).unwrap();
    let mutations: &[fn(&mut RegistrationChallenge)] = &[
        |c| c.binding.tenant.push('x'),
        |c| c.binding.instance = format!("other-vm/{}", Uuid::new_v4()),
        |c| c.binding.plan_id.push('x'),
        |c| c.binding.plan_nonce = Nonce::from_bytes([2; 16]),
        |c| c.binding.run = Uuid::new_v4(),
        |c| c.binding.producer = Uuid::new_v4(),
        |c| c.binding.session = Uuid::new_v4(),
        |c| c.binding.not_before = 99,
        |c| c.binding.not_after = 201,
        |c| c.identity.installation = Uuid::new_v4(),
        |c| c.identity.public_key = SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
        |c| c.nonce[0] ^= 1,
    ];
    for mutate in mutations {
        let mut swapped = proof.clone();
        mutate(&mut swapped.challenge);
        assert!(matches!(
            swapped.verify(&expected, 100),
            Err(DelegationError::Binding)
        ));
        // Even if the attacker changes the expected wire copy, its old signature fails.
        assert!(matches!(
            swapped.verify(&swapped.challenge, 100),
            Err(DelegationError::Proof)
        ));
    }
}

#[test]
fn malformed_signature_other_key_and_generic_signature_are_not_possession() {
    let (key, expected) = fixture();
    let mut proof = RegistrationProof::sign(&key, &expected.identity, &expected, 100).unwrap();
    proof.signature[0] ^= 1;
    assert!(matches!(
        proof.verify(&expected, 100),
        Err(DelegationError::Proof)
    ));
    proof.signature = vec![0; 65];
    assert!(matches!(
        proof.verify(&expected, 100),
        Err(DelegationError::Proof)
    ));
    proof.signature = SigningKey::from_bytes(&[9; 32])
        .sign(&expected.message().unwrap())
        .to_bytes()
        .to_vec();
    assert!(matches!(
        proof.verify(&expected, 100),
        Err(DelegationError::Proof)
    ));
    proof.signature = key
        .sign(&serde_jcs::to_vec(&expected).unwrap())
        .to_bytes()
        .to_vec();
    assert!(matches!(
        proof.verify(&expected, 100),
        Err(DelegationError::Proof)
    ));
}

#[test]
fn fresh_challenge_refuses_replayed_proof_and_wrong_namespace() {
    let (key, expected) = fixture();
    let proof = RegistrationProof::sign(&key, &expected.identity, &expected, 100).unwrap();
    let fresh =
        RegistrationChallenge::fresh(expected.binding.clone(), expected.identity.clone(), 100)
            .unwrap();
    assert_ne!(fresh.nonce, expected.nonce);
    assert!(matches!(
        proof.verify(&fresh, 100),
        Err(DelegationError::Binding)
    ));
    let mut wrong = expected.identity.clone();
    wrong.installation = Uuid::new_v4();
    assert!(matches!(
        RegistrationProof::sign(&key, &wrong, &expected, 100),
        Err(DelegationError::Binding)
    ));
}

#[test]
fn purpose_unknown_fields_invalid_windows_and_empty_claims_fail_closed() {
    let (_, mut challenge) = fixture();
    let mut wire = serde_json::to_value(&challenge).unwrap();
    wire["purpose"] = serde_json::json!("uart");
    assert!(serde_json::from_value::<RegistrationChallenge>(wire).is_err());
    let mut wire = serde_json::to_value(&challenge).unwrap();
    wire["trust_root"] = serde_json::json!("request-chosen");
    assert!(serde_json::from_value::<RegistrationChallenge>(wire).is_err());
    challenge.binding.not_after = challenge.binding.not_before;
    assert!(matches!(
        challenge.validate(100),
        Err(DelegationError::Invalid)
    ));
    challenge.binding.not_after = u64::MAX;
    assert!(matches!(
        challenge.validate(100),
        Err(DelegationError::Invalid)
    ));
    challenge.binding.not_after = 200;
    challenge.binding.instance.clear();
    assert!(matches!(
        challenge.validate(100),
        Err(DelegationError::Invalid)
    ));
}
