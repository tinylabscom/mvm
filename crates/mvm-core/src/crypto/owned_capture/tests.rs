//! Deterministic possession/codec checks, not receiver or native custody qualification.

use super::*;
use crate::plan::Nonce;
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn key() -> SigningKey {
    // Public RFC 8032 test-vector seed, never an enrolled runtime credential.
    let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
}

fn fixture(tenant: &str, call: u128, nonce: u8) -> CaptureChallenge {
    CaptureChallenge {
        binding: CaptureBinding {
            identity: EnrolledIdentity {
                installation: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
                public_key: key().verifying_key().to_bytes(),
            },
            registration: RegistrationBinding {
                tenant: tenant.into(),
                instance: "vm-a/11223344-5566-7788-99aa-bbccddeeff00".into(),
                plan_id: format!("sha256:{}", "22".repeat(32)),
                plan_nonce: Nonce::from_bytes([0x33; 16]),
                run: Uuid::from_u128(2),
                producer: Uuid::from_u128(3),
                session: Uuid::from_u128(4),
                not_before: 100,
                not_after: 200,
            },
            vm: "vm-a".into(),
            startup: [0x44; 32],
            call: Uuid::from_u128(call),
            boot: [0x55; 32],
            capture_run: "4242".into(),
            producer_pid: 1234,
            supervisor_pid: 5678,
        },
        nonce: [nonce; 32],
        issued: 110,
        expires: 120,
    }
}

fn sign(challenge: &CaptureChallenge) -> CaptureProof {
    CaptureProof::sign(&key(), &challenge.binding.identity, challenge, 111).unwrap()
}

fn verify(bytes: &[u8], expected: &CaptureChallenge, now: u64) -> Result<()> {
    CaptureProof::decode(bytes, expected, now)?
        .verify(expected, now)
        .map(|_| ())
}

fn raw_frame(body: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut frame = u32::try_from(1 + body.len() + signature.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.push(2);
    frame.extend_from_slice(body);
    frame.extend_from_slice(signature);
    frame
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Golden {
    tenant: String,
    call: u128,
    challenge: u8,
    message_hex: Vec<String>,
    message_bytes: usize,
    sha256: String,
    signature_hex: String,
}

#[test]
fn deterministic_message_and_signature_vectors_match_independent_encoding() {
    let vectors: Vec<Golden> = serde_json::from_str(include_str!("proof_vectors.json")).unwrap();
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let challenge = fixture(&vector.tenant, vector.call, vector.challenge);
        let message = wire::message(&challenge).unwrap();
        assert_eq!(message.len(), vector.message_bytes);
        assert_eq!(hex::encode(&message), vector.message_hex.concat());
        assert_eq!(hex::encode(Sha256::digest(&message)), vector.sha256);
        let proof = sign(&challenge);
        assert_eq!(hex::encode(proof.signature), vector.signature_hex);
        let encoded = proof.encode().unwrap();
        assert_eq!(verify(&encoded, &challenge, 111), Ok(()));
        let decoded = CaptureProof::decode(&encoded, &challenge, 111).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(
            decoded.verify(&challenge, 111).unwrap().challenge(),
            &challenge
        );
        let hello = challenge.encode().unwrap();
        assert_eq!(
            CaptureChallenge::decode(&hello, challenge.binding(), 111).unwrap(),
            challenge
        );
    }
}

#[test]
fn alternate_instance_spelling_nil_and_vm_mismatch_are_never_normalized() {
    let canonical = fixture("tenant-a", 5, 0x66);
    for instance in [
        "vm-a/11223344-5566-7788-99AA-BBCCDDEEFF00",
        "vm-a/112233445566778899aabbccddeeff00",
        "vm-a/{11223344-5566-7788-99aa-bbccddeeff00}",
        "vm-a/00000000-0000-0000-0000-000000000000",
        "vm-b/11223344-5566-7788-99aa-bbccddeeff00",
    ] {
        let mut invalid = canonical.clone();
        invalid.binding.registration.instance = instance.into();
        assert!(CaptureProof::sign(&key(), &invalid.binding.identity, &invalid, 111).is_err());
        let body = wire::body(&invalid).unwrap();
        let signature = key().sign(&[wire::DOMAIN, &body].concat()).to_bytes();
        assert!(verify(&raw_frame(&body, &signature), &canonical, 111).is_err());
    }
}

#[test]
fn malformed_lengths_utf8_versions_and_trailing_bytes_refuse() {
    let challenge = fixture("tenant-a", 5, 0x66);
    let proof = sign(&challenge);
    let encoded = proof.encode().unwrap();
    let hello = challenge.encode().unwrap();
    for end in 0..encoded.len() {
        assert!(verify(&encoded[..end], &challenge, 111).is_err());
    }
    for end in 0..hello.len() {
        assert!(CaptureChallenge::decode(&hello[..end], challenge.binding(), 111).is_err());
    }
    // Prefix, tag, version, enrollment, tenant/VM and plan/nonce/startup fields.
    let instance_length = 5
        + 1
        + 16
        + 32
        + 2
        + challenge.binding.registration.tenant.len()
        + 2
        + challenge.binding.vm.len()
        + 32
        + 16
        + 32;
    for length in [0_u16, 513, u16::MAX] {
        let mut invalid = encoded.clone();
        invalid[instance_length..instance_length + 2].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            verify(&invalid, &challenge, 111),
            Err(CaptureProofError::Bounds)
        );
    }
    for length in [40_u16, 42] {
        let mut invalid = encoded.clone();
        invalid[instance_length..instance_length + 2].copy_from_slice(&length.to_be_bytes());
        assert!(verify(&invalid, &challenge, 111).is_err());
    }
    let mut invalid = encoded.clone();
    invalid[instance_length + 2] = 0xff;
    assert_eq!(
        verify(&invalid, &challenge, 111),
        Err(CaptureProofError::Invalid)
    );
    for offset in [4, 5] {
        let mut invalid = encoded.clone();
        invalid[offset] = 255;
        assert_eq!(
            verify(&invalid, &challenge, 111),
            Err(CaptureProofError::Invalid)
        );
        let mut invalid = hello.clone();
        invalid[offset] = 255;
        assert_eq!(
            CaptureChallenge::decode(&invalid, challenge.binding(), 111),
            Err(CaptureProofError::Invalid)
        );
    }
    let mut trailing = wire::body(&challenge).unwrap();
    trailing.push(0);
    assert_eq!(
        verify(&raw_frame(&trailing, &[0; 64]), &challenge, 111),
        Err(CaptureProofError::Invalid)
    );
    assert_eq!(
        verify(&vec![0; MAX_FRAME_BYTES + 1], &challenge, 111),
        Err(CaptureProofError::Bounds)
    );
    let mut forged_length = encoded.clone();
    forged_length[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        verify(&forged_length, &challenge, 111),
        Err(CaptureProofError::Bounds)
    );
}

#[test]
fn every_changed_binding_or_challenge_prevents_proof_reuse() {
    let challenge = fixture("tenant-a", 5, 0x66);
    let signature = sign(&challenge).signature;
    let encoded = sign(&challenge).encode().unwrap();
    let mutations: [fn(&mut CaptureChallenge); 19] = [
        |c| c.binding.identity.installation = Uuid::from_u128(9),
        |c| {
            c.binding.identity.public_key =
                SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()
        },
        |c| c.binding.registration.tenant.push('x'),
        |c| {
            c.binding.vm = "vm-b".into();
            c.binding.registration.instance = "vm-b/11223344-5566-7788-99aa-bbccddeeff00".into();
        },
        |c| c.binding.registration.instance = format!("vm-a/{}", Uuid::from_u128(9)),
        |c| c.binding.registration.plan_id = format!("sha256:{}", "ab".repeat(32)),
        |c| c.binding.registration.plan_nonce = Nonce::from_bytes([0xab; 16]),
        |c| c.binding.registration.run = Uuid::from_u128(9),
        |c| c.binding.registration.producer = Uuid::from_u128(9),
        |c| c.binding.registration.session = Uuid::from_u128(9),
        |c| c.binding.call = Uuid::from_u128(9),
        |c| c.binding.startup[0] ^= 1,
        |c| c.binding.boot[0] ^= 1,
        |c| c.binding.capture_run.push('1'),
        |c| c.binding.producer_pid += 1,
        |c| c.binding.supervisor_pid += 1,
        |c| c.nonce[0] ^= 1,
        |c| c.issued = 111,
        |c| c.expires = 121,
    ];
    for mutate in mutations {
        let mut changed = challenge.clone();
        mutate(&mut changed);
        assert_eq!(
            verify(&encoded, &changed, 111),
            Err(CaptureProofError::Binding)
        );
        assert_eq!(
            verify(
                &raw_frame(&wire::body(&changed).unwrap(), &signature),
                &changed,
                111
            ),
            Err(CaptureProofError::Signature)
        );
    }
}

#[test]
fn wrong_enrollment_key_purpose_and_time_refuse() {
    let challenge = fixture("tenant-a", 5, 0x66);
    let other = SigningKey::from_bytes(&[1; 32]);
    assert_eq!(
        CaptureProof::sign(&other, &challenge.binding.identity, &challenge, 111),
        Err(CaptureProofError::Binding)
    );
    let mut identity = challenge.binding.identity.clone();
    identity.installation = Uuid::from_u128(9);
    assert_eq!(
        CaptureProof::sign(&key(), &identity, &challenge, 111),
        Err(CaptureProofError::Binding)
    );
    for domain in [
        b"mvm.entrypoint-caller.registration.v1\0".as_slice(),
        b"mvm.controlling-principal.recovery-possession.v1\0".as_slice(),
    ] {
        let body = wire::body(&challenge).unwrap();
        let signature = key().sign(&[domain, &body].concat()).to_bytes();
        assert_eq!(
            verify(&raw_frame(&body, &signature), &challenge, 111),
            Err(CaptureProofError::Signature)
        );
    }
    let encoded = sign(&challenge).encode().unwrap();
    for now in [0, 109, 120, u64::MAX] {
        assert_eq!(
            verify(&encoded, &challenge, now),
            Err(CaptureProofError::Expired)
        );
    }
    for (issued, expires) in [(110, 110), (120, 110), (110, 141), (99, 120), (190, 201)] {
        let mut invalid = challenge.clone();
        invalid.issued = issued;
        invalid.expires = expires;
        assert!(CaptureProof::sign(&key(), &invalid.binding.identity, &invalid, issued).is_err());
    }
}

#[test]
fn direct_api_bounds_and_required_fields_cannot_bypass_wire_checks() {
    let challenge = fixture("tenant-a", 5, 0x66);
    let mutations: &[fn(&mut CaptureBinding)] = &[
        |b| b.registration.tenant.clear(),
        |b| b.registration.tenant = "a".repeat(513),
        |b| b.registration.tenant.push('\n'),
        |b| b.vm = "bad/name".into(),
        |b| b.registration.plan_id = format!("sha256:{}", "AB".repeat(32)),
        |b| b.registration.plan_id.clear(),
        |b| b.identity.installation = Uuid::nil(),
        |b| b.registration.run = Uuid::nil(),
        |b| b.registration.producer = Uuid::nil(),
        |b| b.registration.session = Uuid::nil(),
        |b| b.call = Uuid::nil(),
        |b| b.boot = [0; 32],
        |b| b.capture_run.clear(),
        |b| b.capture_run = "a".repeat(129),
        |b| b.capture_run.push('\0'),
        |b| b.producer_pid = 1,
        |b| b.supervisor_pid = 0,
        |b| b.registration.not_after = b.registration.not_before,
    ];
    for mutate in mutations {
        let mut invalid = challenge.clone();
        mutate(&mut invalid.binding);
        assert!(CaptureChallenge::fresh(invalid.binding, 111).is_err());
    }
    let mut invalid = challenge;
    invalid.nonce = [0; 32];
    assert!(CaptureProof::sign(&key(), &invalid.binding.identity, &invalid, 111).is_err());
}

#[test]
fn builder_requires_complete_binding_and_fresh_challenges_do_not_alias() {
    let binding = fixture("tenant-a", 5, 0x66).binding;
    let builder = || {
        CaptureBinding::builder(
            binding.identity.clone(),
            binding.registration.clone(),
            &binding.vm,
        )
    };
    assert!(builder().build().is_err());
    let built = builder()
        .with_startup(binding.startup)
        .with_call(binding.call)
        .with_boot(binding.boot)
        .with_capture_run(&binding.capture_run)
        .with_peer_pids(binding.producer_pid, binding.supervisor_pid)
        .build()
        .unwrap();
    assert_eq!(built, binding);
    let first = CaptureChallenge::fresh(built.clone(), 111).unwrap();
    let second = CaptureChallenge::fresh(built.clone(), 111).unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(first.expires, 141);
    assert_eq!(CaptureChallenge::fresh(built, 195).unwrap().expires, 200);
    let proof = CaptureProof::sign(&key(), &binding.identity, &first, 111).unwrap();
    assert_eq!(
        verify(&proof.encode().unwrap(), &second, 111),
        Err(CaptureProofError::Binding)
    );
}

#[cfg(unix)]
#[test]
fn codecs_roundtrip_over_mock_io_without_authenticating_the_peer() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let challenge = fixture("tenant-a", 5, 0x66);
    let (mut producer, mut receiver) = UnixStream::pair().unwrap();
    for stream in [&producer, &receiver] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let hello = challenge.encode().unwrap();
    receiver.write_all(&hello).unwrap();
    let mut input = vec![0; hello.len()];
    producer.read_exact(&mut input).unwrap();
    let decoded = CaptureChallenge::decode(&input, challenge.binding(), 111).unwrap();
    let proof = sign(&decoded).encode().unwrap();
    producer.write_all(&proof).unwrap();
    let mut input = vec![0; proof.len()];
    receiver.read_exact(&mut input).unwrap();
    assert_eq!(verify(&input, &challenge, 111), Ok(()));
}
