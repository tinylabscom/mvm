//! Private proof-encoding vectors, not a credential operation or authenticated transport.
//!
//! The public deterministic key and all identities are fixtures. Parsing a supplied
//! slice does not qualify a socket receiver's allocation, peer or deadline checks.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mvm_core::crypto::entrypoint_delegation::RegistrationBinding;
use mvm_core::crypto::entrypoint_identity::EnrolledIdentity;
use mvm_core::plan::Nonce;
use serde::Deserialize;
use uuid::Uuid;

const DOMAIN: &[u8] = b"mvm.owned-hvf.capture-possession.v1\0";
const MAX_FRAME: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fields {
    identity: EnrolledIdentity,
    registration: RegistrationBinding,
    vm: String,
    startup: [u8; 32],
    call: Uuid,
    boot: [u8; 32],
    capture_run: String,
    producer_pid: u32,
    supervisor_pid: u32,
    challenge: [u8; 32],
    issued: u64,
    expires: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Bounds,
    Invalid,
    Binding,
    Signature,
}

type Result<T> = std::result::Result<T, Refusal>;

fn key() -> SigningKey {
    // Public RFC 8032 test-vector seed, never an enrolled runtime credential.
    let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
}

fn fixture(tenant: &str, call: u128, challenge: u8) -> Fields {
    Fields {
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
        challenge: [challenge; 32],
        issued: 110,
        expires: 120,
    }
}

fn label(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(Refusal::Bounds);
    }
    if value.chars().any(char::is_control) {
        return Err(Refusal::Invalid);
    }
    Ok(())
}

fn digest(value: &str, length: usize) -> Result<Vec<u8>> {
    if value.len() != length * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::Invalid);
    }
    hex::decode(value).map_err(|_| Refusal::Invalid)
}

fn validate(fields: &Fields, now: u64) -> Result<()> {
    label(&fields.registration.tenant, 512)?;
    label(&fields.vm, 512)?;
    label(&fields.registration.instance, 512)?;
    label(&fields.capture_run, 128)?;
    if fields
        .registration
        .instance_vm()
        .map_err(|_| Refusal::Invalid)?
        != fields.vm
    {
        return Err(Refusal::Binding);
    }
    if [
        fields.identity.installation,
        fields.registration.run,
        fields.registration.producer,
        fields.registration.session,
        fields.call,
    ]
    .iter()
    .any(Uuid::is_nil)
        || fields.producer_pid <= 1
        || fields.supervisor_pid <= 1
        || fields.boot == [0; 32]
        || fields.challenge == [0; 32]
    {
        return Err(Refusal::Invalid);
    }
    VerifyingKey::from_bytes(&fields.identity.public_key).map_err(|_| Refusal::Invalid)?;
    digest(
        fields
            .registration
            .plan_id
            .strip_prefix("sha256:")
            .ok_or(Refusal::Invalid)?,
        32,
    )?;
    digest(fields.registration.plan_nonce.as_hex(), 16)?;
    let lifetime = fields
        .expires
        .checked_sub(fields.issued)
        .ok_or(Refusal::Invalid)?;
    if !(1..=30).contains(&lifetime)
        || fields.registration.not_before > fields.issued
        || fields.issued > now
        || now >= fields.expires
        || fields.expires > fields.registration.not_after
    {
        return Err(Refusal::Invalid);
    }
    Ok(())
}

fn put_text(body: &mut Vec<u8>, text: &str) -> Result<()> {
    let length = u16::try_from(text.len()).map_err(|_| Refusal::Bounds)?;
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    Ok(())
}

// Intentionally permits noncanonical fixture strings to construct adversarial frames.
fn raw_body(fields: &Fields) -> Result<Vec<u8>> {
    let mut body = vec![1];
    body.extend_from_slice(fields.identity.installation.as_bytes());
    body.extend_from_slice(&fields.identity.public_key);
    put_text(&mut body, &fields.registration.tenant)?;
    put_text(&mut body, &fields.vm)?;
    body.extend_from_slice(&digest(
        fields
            .registration
            .plan_id
            .strip_prefix("sha256:")
            .ok_or(Refusal::Invalid)?,
        32,
    )?);
    body.extend_from_slice(&digest(fields.registration.plan_nonce.as_hex(), 16)?);
    body.extend_from_slice(&fields.startup);
    put_text(&mut body, &fields.registration.instance)?;
    for id in [
        fields.registration.run,
        fields.registration.producer,
        fields.registration.session,
        fields.call,
    ] {
        body.extend_from_slice(id.as_bytes());
    }
    body.extend_from_slice(&fields.boot);
    put_text(&mut body, &fields.capture_run)?;
    body.extend_from_slice(&fields.producer_pid.to_be_bytes());
    body.extend_from_slice(&fields.supervisor_pid.to_be_bytes());
    body.extend_from_slice(&fields.challenge);
    body.extend_from_slice(&fields.issued.to_be_bytes());
    body.extend_from_slice(&fields.expires.to_be_bytes());
    Ok(body)
}

fn message(fields: &Fields) -> Result<Vec<u8>> {
    validate(fields, 111)?;
    Ok([DOMAIN, &raw_body(fields)?].concat())
}

fn frame(body: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut frame = u32::try_from(1 + body.len() + signature.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    frame.push(2);
    frame.extend_from_slice(body);
    frame.extend_from_slice(signature);
    frame
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.0.get(..N).ok_or(Refusal::Bounds)?;
        let value = bytes.try_into().map_err(|_| Refusal::Bounds)?;
        self.0 = &self.0[N..];
        Ok(value)
    }

    fn text(&mut self, maximum: usize) -> Result<&'a str> {
        let length = usize::from(u16::from_be_bytes(self.take()?));
        if length == 0 || length > maximum {
            return Err(Refusal::Bounds);
        }
        let bytes = self.0.get(..length).ok_or(Refusal::Bounds)?;
        let value = std::str::from_utf8(bytes).map_err(|_| Refusal::Invalid)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
}

fn verify_frame(bytes: &[u8], expected: &Fields, now: u64) -> Result<()> {
    if bytes.len() > MAX_FRAME || bytes.len() < 69 {
        return Err(Refusal::Bounds);
    }
    let mut cursor = Cursor(bytes);
    let declared =
        usize::try_from(u32::from_be_bytes(cursor.take()?)).map_err(|_| Refusal::Bounds)?;
    if declared.checked_add(4) != Some(bytes.len()) {
        return Err(Refusal::Bounds);
    }
    if cursor.take::<1>()? != [2] {
        return Err(Refusal::Invalid);
    }
    let (body, signature) = cursor.0.split_at(cursor.0.len() - 64);
    let mut cursor = Cursor(body);
    if cursor.take::<1>()? != [1] {
        return Err(Refusal::Invalid);
    }
    let mut decoded = expected.clone();
    decoded.identity.installation = Uuid::from_bytes(cursor.take()?);
    decoded.identity.public_key = cursor.take()?;
    decoded.registration.tenant = cursor.text(512)?.into();
    decoded.vm = cursor.text(512)?.into();
    decoded.registration.plan_id = format!("sha256:{}", hex::encode(cursor.take::<32>()?));
    decoded.registration.plan_nonce = Nonce::from_bytes(cursor.take()?);
    decoded.startup = cursor.take()?;
    decoded.registration.instance = cursor.text(512)?.into();
    decoded.registration.run = Uuid::from_bytes(cursor.take()?);
    decoded.registration.producer = Uuid::from_bytes(cursor.take()?);
    decoded.registration.session = Uuid::from_bytes(cursor.take()?);
    decoded.call = Uuid::from_bytes(cursor.take()?);
    decoded.boot = cursor.take()?;
    decoded.capture_run = cursor.text(128)?.into();
    decoded.producer_pid = u32::from_be_bytes(cursor.take()?);
    decoded.supervisor_pid = u32::from_be_bytes(cursor.take()?);
    decoded.challenge = cursor.take()?;
    decoded.issued = u64::from_be_bytes(cursor.take()?);
    decoded.expires = u64::from_be_bytes(cursor.take()?);
    if !cursor.0.is_empty() {
        return Err(Refusal::Invalid);
    }
    validate(&decoded, now)?;
    if decoded != *expected {
        return Err(Refusal::Binding);
    }
    let signature = Signature::from_slice(signature).map_err(|_| Refusal::Signature)?;
    VerifyingKey::from_bytes(&expected.identity.public_key)
        .map_err(|_| Refusal::Invalid)?
        .verify_strict(&[DOMAIN, body].concat(), &signature)
        .map_err(|_| Refusal::Signature)
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
    use sha2::{Digest, Sha256};
    let vectors: Vec<Golden> =
        serde_json::from_str(include_str!("owned_capture_proof_vectors.json")).unwrap();
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let fields = fixture(&vector.tenant, vector.call, vector.challenge);
        let message = message(&fields).unwrap();
        assert_eq!(message.len(), vector.message_bytes);
        assert_eq!(hex::encode(&message), vector.message_hex.concat());
        assert_eq!(hex::encode(Sha256::digest(&message)), vector.sha256);
        let signature = key().sign(&message).to_bytes();
        assert_eq!(hex::encode(signature), vector.signature_hex);
        let wire = frame(&message[DOMAIN.len()..], &signature);
        assert_eq!(verify_frame(&wire, &fields, 111), Ok(()));
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
        invalid.registration.instance = instance.into();
        assert!(message(&invalid).is_err());
        let body = raw_body(&invalid).unwrap();
        let signature = key().sign(&[DOMAIN, &body].concat()).to_bytes();
        assert!(verify_frame(&frame(&body, &signature), &invalid, 111).is_err());
    }
}

#[test]
fn malformed_lengths_utf8_versions_and_trailing_bytes_refuse() {
    let fields = fixture("tenant-a", 5, 0x66);
    let message = message(&fields).unwrap();
    let body = &message[DOMAIN.len()..];
    let wire = frame(body, &key().sign(&message).to_bytes());
    for end in 0..wire.len() {
        assert!(verify_frame(&wire[..end], &fields, 111).is_err());
    }
    // Prefix, tag, version, enrollment, tenant/VM and plan/nonce/startup fields.
    let instance_length =
        5 + 1 + 16 + 32 + 2 + fields.registration.tenant.len() + 2 + fields.vm.len() + 32 + 16 + 32;
    for length in [0_u16, 513, u16::MAX] {
        let mut invalid = wire.clone();
        invalid[instance_length..instance_length + 2].copy_from_slice(&length.to_be_bytes());
        assert_eq!(verify_frame(&invalid, &fields, 111), Err(Refusal::Bounds));
    }
    for length in [40_u16, 42] {
        let mut invalid = wire.clone();
        invalid[instance_length..instance_length + 2].copy_from_slice(&length.to_be_bytes());
        assert!(verify_frame(&invalid, &fields, 111).is_err());
    }
    let mut invalid = wire.clone();
    invalid[instance_length + 2] = 0xff;
    assert_eq!(verify_frame(&invalid, &fields, 111), Err(Refusal::Invalid));
    for offset in [4, 5] {
        let mut invalid = wire.clone();
        invalid[offset] = 255;
        assert_eq!(verify_frame(&invalid, &fields, 111), Err(Refusal::Invalid));
    }
    let mut trailing = body.to_vec();
    trailing.push(0);
    assert_eq!(
        verify_frame(&frame(&trailing, &[0; 64]), &fields, 111),
        Err(Refusal::Invalid)
    );
    assert_eq!(
        verify_frame(&vec![0; MAX_FRAME + 1], &fields, 111),
        Err(Refusal::Bounds)
    );
}

#[test]
fn changed_binding_challenge_signature_or_purpose_cannot_reuse_a_proof() {
    let fields = fixture("tenant-a", 5, 0x66);
    let original = message(&fields).unwrap();
    let signature = key().sign(&original).to_bytes();
    let wire = frame(&original[DOMAIN.len()..], &signature);
    let mutations: [fn(&mut Fields); 19] = [
        |fields| fields.identity.installation = Uuid::from_u128(9),
        |fields| {
            fields.identity.public_key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()
        },
        |fields| fields.registration.tenant.push('x'),
        |fields| {
            fields.vm = "vm-b".into();
            fields.registration.instance = "vm-b/11223344-5566-7788-99aa-bbccddeeff00".into();
        },
        |fields| fields.registration.instance = format!("vm-a/{}", Uuid::from_u128(9)),
        |fields| fields.registration.plan_id = format!("sha256:{}", "ab".repeat(32)),
        |fields| fields.registration.plan_nonce = Nonce::from_bytes([0xab; 16]),
        |fields| fields.registration.run = Uuid::from_u128(9),
        |fields| fields.registration.producer = Uuid::from_u128(9),
        |fields| fields.registration.session = Uuid::from_u128(9),
        |fields| fields.call = Uuid::from_u128(9),
        |fields| fields.startup[0] ^= 1,
        |fields| fields.boot[0] ^= 1,
        |fields| fields.capture_run.push('1'),
        |fields| fields.producer_pid += 1,
        |fields| fields.supervisor_pid += 1,
        |fields| fields.challenge[0] ^= 1,
        |fields| fields.issued = 111,
        |fields| fields.expires = 121,
    ];
    for mutate in mutations {
        let mut changed = fields.clone();
        mutate(&mut changed);
        assert_eq!(verify_frame(&wire, &changed, 111), Err(Refusal::Binding));
        assert_eq!(
            verify_frame(
                &frame(&raw_body(&changed).unwrap(), &signature),
                &changed,
                111
            ),
            Err(Refusal::Signature)
        );
    }
    for domain in [
        b"mvm.entrypoint-caller.registration.v1\0".as_slice(),
        b"mvm.controlling-principal.recovery-possession.v1\0".as_slice(),
    ] {
        let wrong = key()
            .sign(&[domain, &raw_body(&fields).unwrap()].concat())
            .to_bytes();
        assert_eq!(
            verify_frame(&frame(&raw_body(&fields).unwrap(), &wrong), &fields, 111),
            Err(Refusal::Signature)
        );
    }
    assert_eq!(verify_frame(&wire, &fields, 109), Err(Refusal::Invalid));
    assert_eq!(verify_frame(&wire, &fields, 120), Err(Refusal::Invalid));
}
