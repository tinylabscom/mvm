//! The signed topology envelope.
//!
//! A topology is signed as a [`SignedPayload`], the envelope plans use, with
//! the signature algorithm named beside it. Verification runs through
//! [`verify_signed_payload`], the same routine as `verify_plan`, and then
//! checks the algorithm and the topology's structure. The validity window and
//! the generation are not checked here: they belong to host admission.

use alloc::string::ToString;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{SignatureSuite, TOPOLOGY_SCHEMA_VERSION, Topology, TopologyValidationError};
use crate::protocol::signing::{SignedPayload, SignedPayloadError, verify_signed_payload};

/// A topology, its signature and the algorithm the signature claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTopology {
    /// The algorithm of `signed.signature`. Not covered by the signature, so
    /// verification refuses it unless it equals the suite the signed body
    /// names.
    pub sig_alg: SignatureSuite,
    pub signed: SignedPayload,
}

/// Why a topology could not be signed or did not verify.
#[derive(Debug, thiserror::Error)]
pub enum TopologySignatureError {
    #[error("signature algorithm {0:?} is not implemented in this build")]
    UnsupportedAlgorithm(SignatureSuite),
    #[error("the envelope names {envelope:?} but the signed topology names {body:?}")]
    AlgorithmMismatch {
        envelope: SignatureSuite,
        body: SignatureSuite,
    },
    #[error(transparent)]
    Envelope(#[from] SignedPayloadError),
    #[error("the signed topology is structurally invalid: {0}")]
    Invalid(#[from] TopologyValidationError),
}

fn require_implemented(suite: SignatureSuite) -> Result<(), TopologySignatureError> {
    match suite {
        SignatureSuite::Ed25519 => Ok(()),
        SignatureSuite::Ed25519MlDsa65 | SignatureSuite::Ed25519MlDsa87 => {
            Err(TopologySignatureError::UnsupportedAlgorithm(suite))
        }
    }
}

/// Sign `topology` under the suite it names. Refuses a suite this build does
/// not implement rather than signing it with only its classical half.
pub fn sign_topology(
    topology: &Topology,
    key: &SigningKey,
    signer_id: &str,
) -> Result<SignedTopology, TopologySignatureError> {
    let sig_alg = topology.suite.signature;
    require_implemented(sig_alg)?;
    let payload = serde_json::to_vec(topology).expect("a topology serializes to JSON");
    let signature = key.sign(&payload).to_bytes().to_vec();
    Ok(SignedTopology {
        sig_alg,
        signed: SignedPayload {
            payload,
            signature,
            signer_id: signer_id.to_string(),
        },
    })
}

/// Verify a signed topology against `(signer_id, key)` pairs and return it.
///
/// Refuses, in order: an envelope algorithm this build does not implement; an
/// unknown signer, a bad signature, a newer schema or an unparseable body (the
/// shared payload checks); an envelope algorithm that differs from the suite
/// inside the signed body; and a structurally invalid topology.
pub fn verify_topology(
    signed: &SignedTopology,
    trusted_keys: &[(&str, &VerifyingKey)],
) -> Result<Topology, TopologySignatureError> {
    require_implemented(signed.sig_alg)?;
    let topology: Topology =
        verify_signed_payload(&signed.signed, trusted_keys, TOPOLOGY_SCHEMA_VERSION)?;
    if topology.suite.signature != signed.sig_alg {
        return Err(TopologySignatureError::AlgorithmMismatch {
            envelope: signed.sig_alg,
            body: topology.suite.signature,
        });
    }
    topology.validate()?;
    Ok(topology)
}

#[cfg(test)]
mod tests {
    use super::super::Collection;
    use super::super::tests::full;
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sign(topology: &Topology) -> SignedTopology {
        sign_topology(topology, &key(1), "host").unwrap()
    }

    fn verify(signed: &SignedTopology) -> Result<Topology, TopologySignatureError> {
        verify_topology(signed, &[("host", &key(1).verifying_key())])
    }

    /// Sign arbitrary body bytes under `sig_alg`, bypassing `sign_topology`'s
    /// own refusal, so verification is tested against what an attacker or a
    /// newer build could produce.
    fn forge(topology: &Topology, sig_alg: SignatureSuite) -> SignedTopology {
        let payload = serde_json::to_vec(topology).unwrap();
        let signature = key(1).sign(&payload).to_bytes().to_vec();
        SignedTopology {
            sig_alg,
            signed: SignedPayload {
                payload,
                signature,
                signer_id: "host".to_string(),
            },
        }
    }

    #[test]
    fn a_signed_topology_round_trips() {
        let topology = full();
        let signed = sign(&topology);
        assert_eq!(signed.sig_alg, SignatureSuite::Ed25519);
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(verify(&back).unwrap(), topology);
    }

    #[test]
    fn signing_is_deterministic_for_a_fixed_key() {
        let (a, b) = (sign(&full()), sign(&full()));
        assert_eq!(a.signed.payload, b.signed.payload);
        assert_eq!(a.signed.signature, b.signed.signature);
    }

    #[test]
    fn an_envelope_algorithm_that_differs_from_the_body_is_refused() {
        let mut topology = full();
        topology.suite.signature = SignatureSuite::Ed25519MlDsa65;
        let error = verify(&forge(&topology, SignatureSuite::Ed25519)).unwrap_err();
        assert!(
            matches!(
                error,
                TopologySignatureError::AlgorithmMismatch {
                    envelope: SignatureSuite::Ed25519,
                    body: SignatureSuite::Ed25519MlDsa65,
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn an_unimplemented_algorithm_is_refused_to_sign_and_to_verify() {
        for suite in [
            SignatureSuite::Ed25519MlDsa65,
            SignatureSuite::Ed25519MlDsa87,
        ] {
            let mut topology = full();
            topology.suite.signature = suite;
            assert!(matches!(
                sign_topology(&topology, &key(1), "host"),
                Err(TopologySignatureError::UnsupportedAlgorithm(s)) if s == suite
            ));
            assert!(matches!(
                verify(&forge(&topology, suite)),
                Err(TopologySignatureError::UnsupportedAlgorithm(s)) if s == suite
            ));
        }
    }

    #[test]
    fn a_topology_from_an_unknown_signer_is_refused() {
        let error =
            verify_topology(&sign(&full()), &[("other", &key(1).verifying_key())]).unwrap_err();
        assert!(
            matches!(
                &error,
                TopologySignatureError::Envelope(SignedPayloadError::UnknownSigner { signer_id })
                    if signer_id == "host"
            ),
            "{error:?}"
        );
        assert!(matches!(
            verify_topology(&sign(&full()), &[]),
            Err(TopologySignatureError::Envelope(
                SignedPayloadError::UnknownSigner { .. }
            ))
        ));
    }

    #[test]
    fn a_tampered_payload_or_signature_is_refused() {
        let mut payload = sign(&full());
        let last = payload.signed.payload.len() - 2;
        payload.signed.payload[last] ^= 0x01;
        let mut signature = sign(&full());
        signature.signed.signature[0] ^= 0x01;
        let mut truncated = sign(&full());
        truncated.signed.signature.pop();
        for signed in [payload, signature, truncated] {
            assert!(matches!(
                verify(&signed),
                Err(TopologySignatureError::Envelope(
                    SignedPayloadError::SignatureInvalid(_)
                ))
            ));
        }
    }

    #[test]
    fn a_topology_signed_under_one_key_does_not_verify_under_another() {
        let signed = sign(&full());
        assert!(matches!(
            verify_topology(&signed, &[("host", &key(2).verifying_key())]),
            Err(TopologySignatureError::Envelope(
                SignedPayloadError::SignatureInvalid(_)
            ))
        ));
    }

    #[test]
    fn a_newer_schema_is_refused_before_its_fields_are_read() {
        let mut newer = serde_json::to_value(full()).unwrap();
        newer["schema_version"] = (TOPOLOGY_SCHEMA_VERSION + 1).into();
        newer["field_from_the_future"] = true.into();
        let payload = serde_json::to_vec(&newer).unwrap();
        let signed = SignedTopology {
            sig_alg: SignatureSuite::Ed25519,
            signed: SignedPayload {
                signature: key(1).sign(&payload).to_bytes().to_vec(),
                payload,
                signer_id: "host".to_string(),
            },
        };
        let error = verify(&signed).unwrap_err();
        assert!(
            matches!(
                error,
                TopologySignatureError::Envelope(SignedPayloadError::UnsupportedSchema {
                    found,
                    supported: TOPOLOGY_SCHEMA_VERSION,
                }) if found == TOPOLOGY_SCHEMA_VERSION + 1
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_structurally_invalid_topology_is_refused_after_its_signature_holds() {
        let mut topology = full();
        topology.units.swap(0, 1);
        assert!(matches!(
            verify(&sign(&topology)),
            Err(TopologySignatureError::Invalid(
                TopologyValidationError::Unsorted {
                    collection: Collection::Units
                }
            ))
        ));
    }

    #[test]
    fn the_envelope_names_its_algorithm_on_the_wire() {
        let json = serde_json::to_value(sign(&full())).unwrap();
        assert_eq!(json["sig_alg"], "ed25519");
    }
}
