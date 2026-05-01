//! `SignedPolicyBundle` — Ed25519-signed envelope around a
//! `PolicyBundle`. Same shape `mvm-plan` uses for
//! `SignedExecutionPlan`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::protocol::signing::SignedPayload;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bundle::{PolicyBundle, SCHEMA_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedPolicyBundle(pub SignedPayload);

#[derive(Debug, Error)]
pub enum BundleVerifyError {
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("bundle parse failed: {0}")]
    Parse(String),

    #[error("schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("no trusted key matched signer_id {signer_id}")]
    UnknownSigner { signer_id: String },
}

pub fn sign_bundle(bundle: &PolicyBundle, key: &SigningKey, signer_id: &str) -> SignedPolicyBundle {
    let payload = serde_json::to_vec(bundle).expect("PolicyBundle must serialise to JSON");
    let signature: Signature = key.sign(&payload);
    SignedPolicyBundle(SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.to_string(),
    })
}

/// Same verification order as `mvm-plan::verify_plan`: signature →
/// schema version → JSON parse. Fail-closed on unknown signer
/// before exposing the payload bytes.
pub fn verify_bundle(
    signed: &SignedPolicyBundle,
    trusted_keys: &[(&str, &VerifyingKey)],
) -> Result<PolicyBundle, BundleVerifyError> {
    let envelope = &signed.0;

    let key = trusted_keys
        .iter()
        .find_map(|(id, k)| (*id == envelope.signer_id).then_some(*k))
        .ok_or_else(|| BundleVerifyError::UnknownSigner {
            signer_id: envelope.signer_id.clone(),
        })?;

    let signature = Signature::from_slice(&envelope.signature).map_err(|e| {
        BundleVerifyError::SignatureInvalid(format!("malformed signature bytes: {e}"))
    })?;

    key.verify(&envelope.payload, &signature)
        .map_err(|e| BundleVerifyError::SignatureInvalid(e.to_string()))?;

    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: u32,
    }
    let probe: VersionProbe = serde_json::from_slice(&envelope.payload)
        .map_err(|e| BundleVerifyError::Parse(format!("schema_version probe failed: {e}")))?;
    if probe.schema_version > SCHEMA_VERSION {
        return Err(BundleVerifyError::UnsupportedSchema {
            found: probe.schema_version,
            supported: SCHEMA_VERSION,
        });
    }

    let bundle: PolicyBundle = serde_json::from_slice(&envelope.payload)
        .map_err(|e| BundleVerifyError::Parse(e.to_string()))?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{PolicyId, TenantOverlay};
    use crate::policies::*;
    use ed25519_dalek::SigningKey;
    use mvm_plan::TenantId;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: SCHEMA_VERSION,
            bundle_id: PolicyId("01HXBUNDLE0000000000000000".to_string()),
            bundle_version: 1,
            network: NetworkPolicy {
                preset: Some("agent".to_string()),
            },
            egress: EgressPolicy {
                mode: Some("l3_plus_l7".to_string()),
            },
            pii: PiiPolicy {
                mode: Some("redact".to_string()),
                categories: vec!["email".to_string(), "cc_number".to_string()],
            },
            tool: ToolPolicy {
                allowed: vec!["read_file".to_string()],
            },
            artifact: ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 30,
            },
            keys: KeyPolicy {
                rotation_interval_days: 7,
            },
            audit: AuditPolicy {
                chain_signing: true,
                stream_destinations: vec!["audit://tenant-a".to_string()],
            },
            tenant_overlays: BTreeMap::from([(
                TenantId("tenant-a".to_string()),
                TenantOverlay {
                    pii: Some(PiiPolicy {
                        mode: Some("refuse".to_string()),
                        categories: vec![],
                    }),
                    ..Default::default()
                },
            )]),
        }
    }

    fn fresh_key() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let b = sample_bundle();
        let bytes = serde_json::to_vec(&b).unwrap();
        let parsed: PolicyBundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, b);
    }

    #[test]
    fn signed_bundle_roundtrip() {
        let b = sample_bundle();
        let (sk, vk) = fresh_key();
        let signed = sign_bundle(&b, &sk, "test");
        let recovered = verify_bundle(&signed, &[("test", &vk)]).unwrap();
        assert_eq!(recovered, b);
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let b = sample_bundle();
        let (sk, vk) = fresh_key();
        let mut signed = sign_bundle(&b, &sk, "test");
        signed.0.payload[0] ^= 0x01;
        match verify_bundle(&signed, &[("test", &vk)]) {
            Err(BundleVerifyError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signer_fails() {
        let b = sample_bundle();
        let (sk, _vk) = fresh_key();
        let signed = sign_bundle(&b, &sk, "alice");
        let (_sk2, vk2) = fresh_key();
        match verify_bundle(&signed, &[("bob", &vk2)]) {
            Err(BundleVerifyError::UnknownSigner { signer_id }) => assert_eq!(signer_id, "alice"),
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_schema_fails_closed() {
        let mut b = sample_bundle();
        b.schema_version = SCHEMA_VERSION + 1;
        let (sk, vk) = fresh_key();
        let signed = sign_bundle(&b, &sk, "test");
        match verify_bundle(&signed, &[("test", &vk)]) {
            Err(BundleVerifyError::UnsupportedSchema { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn unknown_field_in_bundle_rejected() {
        let mut value: serde_json::Value = serde_json::to_value(sample_bundle()).unwrap();
        value["new_future_field"] = serde_json::json!("hi");
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(serde_json::from_slice::<PolicyBundle>(&bytes).is_err());
    }

    #[test]
    fn empty_trusted_set_fails() {
        let b = sample_bundle();
        let (sk, _vk) = fresh_key();
        let signed = sign_bundle(&b, &sk, "alice");
        match verify_bundle(&signed, &[]) {
            Err(BundleVerifyError::UnknownSigner { .. }) => {}
            other => panic!("expected UnknownSigner, got {other:?}"),
        }
    }

    #[test]
    fn tenant_overlay_resolution_shape() {
        // Sanity: a tenant overlay with only `pii: Some(_)` leaves
        // every other field as None (inherit-from-base semantics).
        // The actual base+overlay merge function lives in
        // mvm-runtime's PolicyResolver (Wave 2); here we only assert
        // that the wire format is what the resolver will read.
        let b = sample_bundle();
        let overlay = b
            .tenant_overlays
            .get(&TenantId("tenant-a".to_string()))
            .unwrap();
        assert!(overlay.pii.is_some());
        assert!(overlay.network.is_none());
        assert!(overlay.egress.is_none());
        assert!(overlay.tool.is_none());
        assert!(overlay.artifact.is_none());
        assert!(overlay.keys.is_none());
        assert!(overlay.audit.is_none());
    }
}
