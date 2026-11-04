use super::*;
use crate::protocol::hvf_control::HvfInstance;
use crate::protocol::hvf_owner::{RecoveryBinding, RecoveryOperation};
use std::num::NonZeroU64;
use uuid::Uuid;

fn fixture() -> (SigningKey, RecoveryChallenge) {
    // Explicit synthetic in-memory key, never a credential-store operation.
    let key = SigningKey::from_bytes(&[17; 32]);
    let identity = EnrolledIdentity {
        installation: Uuid::from_u128(1),
        public_key: key.verifying_key().to_bytes(),
    };
    let request = UntrustedRecoveryRequest {
        version: REQUEST_VERSION,
        binding: RecoveryBinding {
            operation_id: [1; 32],
            request_digest: [2; 32],
            controlling_principal: identity.public_key,
            tenant_id: "tenant-a".into(),
            owner_incarnation: [3; 32],
            phase: RecoveryPhase::Native {
                plan_digest: [4; 32],
                effective_config_digest: [5; 32],
                instance: HvfInstance {
                    vm_id: "vm-a".into(),
                    boot_nonce: [6; 32],
                },
            },
        },
        sequence: NonZeroU64::new(u64::MAX).unwrap(),
        action: RecoveryOperation::Observe {},
    };
    (
        key,
        RecoveryChallenge::fresh(request, identity, 100).unwrap(),
    )
}

#[test]
fn roundtrips_all_actions_phases_and_full_u64_without_authorizing_or_consuming() {
    let (key, original) = fixture();
    for phase in [
        RecoveryPhase::BeforeAdmission {
            proposed_plan_digest: [7; 32],
        },
        RecoveryPhase::Admitted {
            plan_digest: [4; 32],
            effective_config_digest: [5; 32],
        },
        original.request.binding.phase.clone(),
    ] {
        for action in [
            RecoveryOperation::Observe {},
            RecoveryOperation::CancelStop {},
            RecoveryOperation::AcknowledgeResult {
                revision: NonZeroU64::new(u64::MAX).unwrap(),
            },
        ] {
            let mut challenge = original.clone();
            challenge.request.binding.phase = phase.clone();
            challenge.request.action = action;
            let proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
            let bytes = serde_json::to_vec(&proof).unwrap();
            assert!(bytes.len() <= MAX_PROOF_BYTES);
            assert!(
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .contains("18446744073709551615")
            );
            let decoded = RecoveryProof::decode(&bytes, 100).unwrap();
            assert_eq!(decoded, proof);
            for _ in 0..2 {
                assert_eq!(
                    decoded.verify(&challenge, 100).unwrap().challenge(),
                    &challenge
                );
            }
            let mut adjacent = challenge.clone();
            adjacent.request.sequence = NonZeroU64::new(u64::MAX - 1).unwrap();
            assert_ne!(challenge.message().unwrap(), adjacent.message().unwrap());
            assert!(decoded.verify(&adjacent, 100).is_err());
        }
    }
}

#[test]
fn every_changed_retained_claim_and_payload_mutation_refuses() {
    let (key, challenge) = fixture();
    let proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    for field in 0..15 {
        let mut altered = challenge.clone();
        match field {
            0 => altered.request.binding.operation_id[0] ^= 1,
            1 => altered.request.binding.request_digest[0] ^= 1,
            2 => altered.request.binding.controlling_principal[0] ^= 1,
            3 => altered.request.binding.tenant_id.push('b'),
            4 => altered.request.binding.owner_incarnation[0] ^= 1,
            5 => altered.request.action = RecoveryOperation::CancelStop {},
            6 => altered.request.sequence = NonZeroU64::new(1).unwrap(),
            7 => altered.identity.installation = Uuid::from_u128(2),
            8 => {
                altered.identity.public_key =
                    SigningKey::from_bytes(&[18; 32]).verifying_key().to_bytes()
            }
            9 => altered.connection_nonce[0] ^= 1,
            10 => altered.issued_at = 99,
            11..=14 => {
                let RecoveryPhase::Native {
                    plan_digest,
                    effective_config_digest,
                    instance,
                } = &mut altered.request.binding.phase
                else {
                    unreachable!()
                };
                match field {
                    11 => plan_digest[0] ^= 1,
                    12 => effective_config_digest[0] ^= 1,
                    13 => instance.vm_id.push('b'),
                    14 => instance.boot_nonce[0] ^= 1,
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
        assert!(
            proof.verify(&altered, 100).is_err(),
            "retained field {field}"
        );
        let mut mutated = proof.clone();
        mutated.challenge = altered.clone();
        assert!(
            mutated.verify(&challenge, 100).is_err(),
            "payload field {field}"
        );
        // Even when the attacker supplies matching public expectations, the
        // original signature cannot validate an altered message.
        assert!(
            mutated.verify(&altered, 100).is_err(),
            "signature field {field}"
        );
    }
}

#[test]
fn enrollment_key_domain_and_signature_are_independent_checks() {
    let (key, challenge) = fixture();
    let wrong_key = SigningKey::from_bytes(&[18; 32]);
    assert!(RecoveryProof::sign(&wrong_key, &challenge.identity, &challenge, 100).is_err());
    let mut wrong_installation = challenge.identity.clone();
    wrong_installation.installation = Uuid::from_u128(2);
    assert!(RecoveryProof::sign(&key, &wrong_installation, &challenge, 100).is_err());
    let mut other_enrollment = challenge.clone();
    other_enrollment.identity = wrong_installation;
    let freshly_signed =
        RecoveryProof::sign(&key, &other_enrollment.identity, &other_enrollment, 100).unwrap();
    assert!(freshly_signed.verify(&other_enrollment, 100).is_ok());
    assert!(matches!(
        freshly_signed.verify(&challenge, 100),
        Err(RecoveryProofError::Binding)
    ));
    let mut proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    for message in [
        serde_json::to_vec(&challenge).unwrap(),
        [
            b"mvm.entrypoint-caller.registration.v1\0".as_slice(),
            &serde_json::to_vec(&challenge).unwrap(),
        ]
        .concat(),
    ] {
        proof.signature = key.sign(&message).to_bytes().to_vec();
        assert!(matches!(
            proof.verify(&challenge, 100),
            Err(RecoveryProofError::Signature)
        ));
    }
    proof.signature = wrong_key
        .sign(&challenge.message().unwrap())
        .to_bytes()
        .to_vec();
    assert!(proof.verify(&challenge, 100).is_err());
    proof.signature.clear();
    assert!(proof.verify(&challenge, 100).is_err());
}

#[test]
fn actual_registration_proofs_cannot_be_reused_in_either_direction() {
    use crate::crypto::entrypoint_delegation::{
        RegistrationBinding, RegistrationChallenge, RegistrationProof,
    };
    let (key, challenge) = fixture();
    let registration = RegistrationChallenge::fresh(
        RegistrationBinding {
            tenant: "tenant-a".into(),
            instance: format!("vm-a/{}", Uuid::from_u128(2)),
            plan_id: "plan-a".into(),
            plan_nonce: crate::plan::Nonce::from_bytes([1; 16]),
            run: Uuid::from_u128(3),
            producer: Uuid::from_u128(4),
            session: Uuid::from_u128(5),
            not_before: 100,
            not_after: 200,
        },
        challenge.identity.clone(),
        100,
    )
    .unwrap();
    let mut registration_proof =
        RegistrationProof::sign(&key, &challenge.identity, &registration, 100).unwrap();
    let mut recovery = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    std::mem::swap(&mut recovery.signature, &mut registration_proof.signature);
    assert!(recovery.verify(&challenge, 100).is_err());
    assert!(registration_proof.verify(&registration, 100).is_err());
}

#[test]
fn malformed_direct_claims_and_altered_acknowledgements_refuse() {
    let (key, mut challenge) = fixture();
    challenge.request.action = RecoveryOperation::AcknowledgeResult {
        revision: NonZeroU64::new(u64::MAX).unwrap(),
    };
    let proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    let mut altered = challenge.clone();
    altered.request.action = RecoveryOperation::AcknowledgeResult {
        revision: NonZeroU64::new(u64::MAX - 1).unwrap(),
    };
    assert!(proof.verify(&altered, 100).is_err());
    for field in 0..4 {
        let mut invalid = challenge.clone();
        match field {
            0 => invalid.connection_nonce = [0; 32],
            1 => invalid.identity.installation = Uuid::nil(),
            2 => invalid.request.version = 2,
            3 => invalid.request.binding.controlling_principal = [0; 32],
            _ => unreachable!(),
        }
        assert!(RecoveryProof::sign(&key, &invalid.identity, &invalid, 100).is_err());
        assert!(
            RecoveryProof::decode(
                &serde_json::to_vec(&RecoveryProof {
                    challenge: invalid,
                    signature: vec![0; 64]
                })
                .unwrap(),
                100,
            )
            .is_err()
        );
    }
}

#[test]
fn freshness_boundaries_and_direct_label_bounds_fail_before_serialization() {
    let (key, challenge) = fixture();
    let proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    for now in [100, 129] {
        assert!(proof.verify(&challenge, now).is_ok());
    }
    for now in [0, 99, 130, u64::MAX] {
        assert!(matches!(
            proof.verify(&challenge, now),
            Err(RecoveryProofError::Expired)
        ));
        assert!(RecoveryProof::sign(&key, &challenge.identity, &challenge, now).is_err());
    }
    let mut late = challenge.clone();
    late.issued_at = u64::MAX;
    assert!(RecoveryProof::sign(&key, &late.identity, &late, u64::MAX).is_ok());
    for native_label in [false, true] {
        for length in [MAX_LABEL_BYTES, MAX_LABEL_BYTES + 1] {
            let mut altered = challenge.clone();
            let label = if native_label {
                let RecoveryPhase::Native { instance, .. } = &mut altered.request.binding.phase
                else {
                    unreachable!()
                };
                &mut instance.vm_id
            } else {
                &mut altered.request.binding.tenant_id
            };
            *label = "a".repeat(length);
            assert_eq!(
                RecoveryProof::sign(&key, &altered.identity, &altered, 100).is_ok(),
                length == MAX_LABEL_BYTES
            );
        }
    }
    for invalid in ["", "tenant\n"] {
        let mut altered = challenge.clone();
        altered.request.binding.tenant_id = invalid.into();
        assert!(RecoveryProof::sign(&key, &altered.identity, &altered, 100).is_err());
    }
}

#[test]
fn bounded_decode_rejects_malformed_oversized_unknown_duplicate_and_truncated_data() {
    let (key, challenge) = fixture();
    let proof = RecoveryProof::sign(&key, &challenge.identity, &challenge, 100).unwrap();
    let mut bytes = serde_json::to_vec(&proof).unwrap();
    let original = bytes.clone();
    bytes.resize(MAX_PROOF_BYTES, b' ');
    assert!(RecoveryProof::decode(&bytes, 100).is_ok());
    bytes.push(b' ');
    assert_eq!(
        RecoveryProof::decode(&bytes, 100),
        Err(RecoveryProofError::TooLarge)
    );
    assert_eq!(
        RecoveryProof::decode(&vec![b'!'; MAX_PROOF_BYTES + 1], 100),
        Err(RecoveryProofError::TooLarge)
    );
    for end in 0..original.len() {
        assert!(RecoveryProof::decode(&original[..end], 100).is_err());
    }
    let text = String::from_utf8(original).unwrap();
    let duplicated = text.replacen(
        "\"issued_at\":100",
        "\"issued_at\":100,\"issued_at\":100",
        1,
    );
    assert!(RecoveryProof::decode(duplicated.as_bytes(), 100).is_err());
    let mut value = serde_json::to_value(&proof).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(RecoveryProof::decode(&serde_json::to_vec(&value).unwrap(), 100).is_err());
    assert!(RecoveryProof::decode(b"[]", 100).is_err());
}
