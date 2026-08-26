use ed25519_dalek::SigningKey;
use mvm_core::receipt::{ReceiptError, canonical_json};
use mvm_core::receipt_archive::{EVIDENCE_MANIFEST_SCHEMA_VERSION, SignedEvidenceManifest};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorSet {
    schema_version: u32,
    valid: Vec<ValidVector>,
    invalid: Vec<InvalidVector>,
    signed_manifest: SignedManifestVector,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidVector {
    name: String,
    input: Value,
    canonical: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidVector {
    name: String,
    input: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifestVector {
    test_only_secret_key_hex: String,
    canonical_manifest: String,
    envelope: SignedEvidenceManifest,
}

fn vectors() -> VectorSet {
    serde_json::from_str(include_str!(
        "../../../tests/vectors/mvmev-canonicalization-v1.json"
    ))
    .expect("frozen .mvmev vectors must deserialize")
}

#[test]
fn frozen_valid_vectors_have_the_documented_canonical_bytes() {
    let vectors = vectors();
    assert_eq!(vectors.schema_version, EVIDENCE_MANIFEST_SCHEMA_VERSION);

    for vector in vectors.valid {
        let actual = canonical_json(&vector.input)
            .unwrap_or_else(|error| panic!("{} must canonicalize: {error}", vector.name));
        assert_eq!(actual, vector.canonical.as_bytes(), "{}", vector.name);
    }
}

#[test]
fn frozen_invalid_vectors_are_outside_the_schema_one_value_space() {
    for vector in vectors().invalid {
        assert!(
            matches!(
                canonical_json(&vector.input),
                Err(ReceiptError::InvalidValueSpace(_))
            ),
            "{} must be refused",
            vector.name
        );
    }
}

#[test]
fn frozen_signed_manifest_pins_archive_id_and_ed25519_material() {
    let vector = vectors().signed_manifest;
    let key_bytes: [u8; 32] = hex::decode(&vector.test_only_secret_key_hex)
        .expect("test key must be hexadecimal")
        .try_into()
        .expect("test key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let regenerated = SignedEvidenceManifest::sign(
        vector.envelope.manifest.clone(),
        &signing_key,
        vector.envelope.signed_at.clone(),
    )
    .expect("frozen manifest must sign");

    assert_eq!(regenerated, vector.envelope);
    assert_eq!(
        canonical_json(&regenerated.manifest).expect("manifest must canonicalize"),
        vector.canonical_manifest.as_bytes()
    );
    regenerated.verify().expect("frozen signature must verify");
}
