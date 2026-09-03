//! in-toto provenance statement (SLSA v1.0 predicate) as a DSSE envelope.
//!
//! At seal time, beside the verity-sealed `rootfs.ext4` we emit
//! `<stem>.intoto.json`: an in-toto Statement whose subject is the sealed
//! image file (SHA-256) and whose predicate is the SLSA v1.0 provenance
//! of the seal operation, wrapped in a DSSE envelope signed by the same
//! builder key that wrote the in-rootfs provenance mark.
//!
//! This is an interchange format, not an internal model: compliance
//! tooling that speaks in-toto/SLSA can consume the sidecar directly,
//! while our own verification goes through [`verify_sidecar`].

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::provenance_mark::{SealEvidence, builder_id, jcs_bytes, key_fingerprint};

/// DSSE payload type for in-toto statements.
pub const DSSE_IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// in-toto Statement `_type` (v1).
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// SLSA provenance predicate type (v1).
pub const SLSA_PROVENANCE_PREDICATE: &str = "https://slsa.dev/provenance/v1";

/// Our buildType URI for the OCI run-image seal.
pub const MVM_BUILD_TYPE: &str = "https://mvm.dev/buildType/run-image/v1";

/// Sidecar suffix for the DSSE-sealed provenance statement.
pub const INTOTO_SIDECAR_SUFFIX: &str = ".intoto.json";

/// in-toto Statement with an SLSA v1.0 provenance predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<StatementSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaProvenance,
}

/// One named subject with content digests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementSubject {
    pub name: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

/// SLSA v1.0 provenance predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaProvenance {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}

/// SLSA buildDefinition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: serde_json::Value,
    #[serde(rename = "internalParameters")]
    pub internal_parameters: serde_json::Value,
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<serde_json::Value>,
}

/// SLSA runDetails.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunDetails {
    pub builder: BuilderId,
    pub metadata: RunMetadata,
    pub byproducts: Vec<serde_json::Value>,
}

/// SLSA builder identity — the same `mvm:builder:ed25519:sha256:<hex>`
/// fingerprint the in-rootfs mark carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderId {
    pub id: String,
}

/// SLSA run metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    #[serde(rename = "startedOn")]
    pub started_on: String,
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
}

/// Build a provenance statement for one sealed image file.
///
/// `subject_sha256` is the hex SHA-256 of the exact sealed artifact
/// bytes (the caller hashes the file after sealing, so the statement
/// can never name bytes that were not sealed).
pub fn build_statement(
    evidence: &SealEvidence<'_>,
    subject_name: &str,
    subject_sha256: &str,
    started_on: &str,
    finished_on: &str,
) -> ProvenanceStatement {
    let verifying = evidence.signer().verifying_key();
    let mut digest = std::collections::BTreeMap::new();
    digest.insert("sha256".to_string(), subject_sha256.to_string());
    let mut external = serde_json::json!({});
    if let Some(image_ref) = evidence.image_ref() {
        external["imageRef"] = serde_json::Value::String(image_ref.to_string());
    }
    if let Some(image_digest) = evidence.image_digest() {
        external["imageDigest"] = serde_json::Value::String(image_digest.to_string());
    }
    ProvenanceStatement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
        subject: vec![StatementSubject {
            name: subject_name.to_string(),
            digest,
        }],
        predicate_type: SLSA_PROVENANCE_PREDICATE.to_string(),
        predicate: SlsaProvenance {
            build_definition: BuildDefinition {
                build_type: MVM_BUILD_TYPE.to_string(),
                external_parameters: external,
                internal_parameters: serde_json::json!({}),
                resolved_dependencies: Vec::new(),
            },
            run_details: RunDetails {
                builder: BuilderId {
                    id: builder_id(&verifying),
                },
                metadata: RunMetadata {
                    started_on: started_on.to_string(),
                    finished_on: finished_on.to_string(),
                },
                byproducts: Vec::new(),
            },
        },
    }
}

/// A DSSE envelope (`payloadType` + base64 payload + signatures).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

/// One DSSE signature. `keyid` is the builder key fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

/// DSSE Pre-Authentication-Encoding, RFC 8032-style framing:
/// `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
/// with SP = 0x20 and decimal ASCII lengths.
pub fn pae_encode(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Sign a statement into a DSSE envelope with the builder key.
pub fn sign_envelope(statement: &ProvenanceStatement, signer: &SigningKey) -> Result<DsseEnvelope> {
    let payload = serde_json::to_vec(statement).context("serialize in-toto statement")?;
    let pae = pae_encode(DSSE_IN_TOTO_PAYLOAD_TYPE, &payload);
    let signature = signer.sign(&pae);
    Ok(DsseEnvelope {
        payload_type: DSSE_IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: B64.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: key_fingerprint(&signer.verifying_key()),
            sig: B64.encode(signature.to_bytes()),
        }],
    })
}

/// The verified contents of a DSSE envelope over an in-toto statement.
#[derive(Debug, Clone)]
pub struct VerifiedStatement {
    /// The parsed statement.
    pub statement: ProvenanceStatement,
    /// Builder key fingerprint that produced the (accepted) signature.
    pub signer_fingerprint: String,
}

/// Verify a DSSE envelope against an explicit trust-anchor key and
/// parse the in-toto statement payload.
pub fn verify_sidecar(envelope: &DsseEnvelope, anchor: &VerifyingKey) -> Result<VerifiedStatement> {
    if envelope.payload_type != DSSE_IN_TOTO_PAYLOAD_TYPE {
        anyhow::bail!(
            "unsupported DSSE payloadType {:?}; want {DSSE_IN_TOTO_PAYLOAD_TYPE}",
            envelope.payload_type
        );
    }
    let payload = B64
        .decode(&envelope.payload)
        .context("decode DSSE payload base64")?;
    if envelope.signatures.len() != 1 {
        anyhow::bail!(
            "expected exactly one DSSE signature, got {}",
            envelope.signatures.len()
        );
    }
    let signature_bytes: [u8; 64] = B64
        .decode(&envelope.signatures[0].sig)
        .context("decode DSSE signature base64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("DSSE signature is not 64 bytes"))?;
    let pae = pae_encode(&envelope.payload_type, &payload);
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    anchor
        .verify(&pae, &signature)
        .context("DSSE signature invalid against trust anchor")?;
    let fingerprint = key_fingerprint(anchor);
    if envelope.signatures[0].keyid != fingerprint {
        anyhow::bail!(
            "DSSE keyid {} does not match verifying key fingerprint {}",
            envelope.signatures[0].keyid,
            fingerprint
        );
    }
    let statement: ProvenanceStatement =
        serde_json::from_slice(&payload).context("parse in-toto statement payload")?;
    Ok(VerifiedStatement {
        statement,
        signer_fingerprint: fingerprint,
    })
}

/// Sidecar path for a sealed image: `<stem>.intoto.json`.
pub fn sidecar_path(image: &Path) -> std::path::PathBuf {
    let stem = image.with_extension("");
    std::path::PathBuf::from(format!("{}{INTOTO_SIDECAR_SUFFIX}", stem.display()))
}

/// Emit and write the `<stem>.intoto.json` sidecar beside a sealed
/// image. `subject_sha256` is the hex digest of the sealed file's exact
/// bytes; `started_on`/`finished_on` bracket the seal operation.
pub fn write_sidecar(
    image: &Path,
    subject_sha256: &str,
    evidence: &SealEvidence<'_>,
    started_on: &str,
    finished_on: &str,
) -> Result<std::path::PathBuf> {
    let subject_name = image
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rootfs.ext4".to_string());
    let statement = build_statement(
        evidence,
        &subject_name,
        subject_sha256,
        started_on,
        finished_on,
    );
    let envelope = sign_envelope(&statement, evidence.signer())?;
    let bytes = jcs_bytes(&envelope)?;
    let path = sidecar_path(image);
    std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    tracing::info!(sidecar = %path.display(), "in-toto provenance sidecar written");
    Ok(path)
}

/// Read + verify a `<stem>.intoto.json` sidecar against a trust anchor.
pub fn read_sidecar(image: &Path, anchor: &VerifyingKey) -> Result<Option<VerifiedStatement>> {
    let path = sidecar_path(image);
    if !path.is_file() {
        return Ok(None);
    }
    let envelope: DsseEnvelope = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    verify_sidecar(&envelope, anchor).map(Some)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[99; 32])
    }

    fn evidence(key: &SigningKey) -> SealEvidence<'_> {
        SealEvidence::builder(key)
            .with_image_ref("docker.io/library/nginx:1.27")
            .with_image_digest("sha256:deadbeef")
            .with_created("2026-09-02T00:00:01Z")
            .build()
    }

    #[test]
    fn pae_encoding_matches_the_dsse_spec_shape() {
        // DSSE PAE: "DSSEv1 <pt-len> <pt> <payload-len> <payload>"; the
        // in-toto JSON payload type is 28 bytes.
        let pae = pae_encode("application/vnd.in-toto+json", b"abc");
        assert_eq!(
            pae,
            b"DSSEv1 28 application/vnd.in-toto+json 3 abc".to_vec()
        );
    }

    #[test]
    fn statement_carries_slsa_v1_provenance() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        assert_eq!(statement.statement_type, IN_TOTO_STATEMENT_TYPE);
        assert_eq!(statement.predicate_type, SLSA_PROVENANCE_PREDICATE);
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].digest["sha256"], "f0e12d3");
        assert_eq!(
            statement.predicate.build_definition.build_type,
            MVM_BUILD_TYPE
        );
        assert_eq!(
            statement.predicate.build_definition.external_parameters["imageRef"],
            "docker.io/library/nginx:1.27"
        );
        assert_eq!(
            statement.predicate.run_details.builder.id,
            builder_id(&key.verifying_key())
        );
    }

    #[test]
    fn envelope_roundtrips_through_sign_and_verify() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        let envelope = sign_envelope(&statement, &key).unwrap();
        assert_eq!(envelope.payload_type, DSSE_IN_TOTO_PAYLOAD_TYPE);
        let verified = verify_sidecar(&envelope, &key.verifying_key()).unwrap();
        assert_eq!(verified.statement, statement);
        assert_eq!(
            verified.signer_fingerprint,
            key_fingerprint(&key.verifying_key())
        );
    }

    #[test]
    fn envelope_signed_by_another_key_fails_against_anchor() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        let envelope = sign_envelope(&statement, &key).unwrap();
        let other = SigningKey::from_bytes(&[1; 32]);
        assert!(verify_sidecar(&envelope, &other.verifying_key()).is_err());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        let mut envelope = sign_envelope(&statement, &key).unwrap();
        // Swap the payload for a same-shape statement with a different digest.
        let mut other = statement.clone();
        other.subject[0]
            .digest
            .insert("sha256".into(), "tampered".into());
        envelope.payload = B64.encode(serde_json::to_vec(&other).unwrap());
        assert!(verify_sidecar(&envelope, &key.verifying_key()).is_err());
    }

    #[test]
    fn keyid_claim_must_match_the_verifying_key() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        let mut envelope = sign_envelope(&statement, &key).unwrap();
        envelope.signatures[0].keyid = "00".repeat(32);
        assert!(verify_sidecar(&envelope, &key.verifying_key()).is_err());
    }

    #[test]
    fn wrong_payload_type_is_refused() {
        let key = key();
        let statement = build_statement(
            &evidence(&key),
            "rootfs.ext4",
            "f0e12d3",
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        );
        let mut envelope = sign_envelope(&statement, &key).unwrap();
        envelope.payload_type = "text/plain".to_string();
        assert!(verify_sidecar(&envelope, &key.verifying_key()).is_err());
    }

    #[test]
    fn sidecar_roundtrips_beside_the_image() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs.ext4");
        std::fs::write(&image, b"ext4-bytes").unwrap();
        let key = key();
        let evidence = evidence(&key);
        let path = write_sidecar(
            &image,
            "f0e12d3",
            &evidence,
            "2026-09-02T00:00:00Z",
            "2026-09-02T00:00:02Z",
        )
        .unwrap();
        assert_eq!(path, dir.path().join("rootfs.intoto.json"));
        let verified = read_sidecar(&image, &key.verifying_key())
            .unwrap()
            .expect("sidecar present");
        assert_eq!(verified.statement.subject[0].digest["sha256"], "f0e12d3");
        assert!(
            read_sidecar(&dir.path().join("absent.ext4"), &key.verifying_key())
                .unwrap()
                .is_none()
        );
    }
}
