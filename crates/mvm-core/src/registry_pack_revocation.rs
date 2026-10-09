//! Signed revocation data for user-facing registry packs.
//!
//! A verified document is intentionally separate from the revocation list for
//! MVM's runtime and build artifacts. A caller must authenticate a pack's
//! actual signing identity before applying an identity revocation, and must
//! durably retain the returned checkpoint to detect rollback on the next load.

#[cfg(any(feature = "manifest-verify", test))]
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packs::{KeylessTrust, Sha256Hex};
use crate::registry_pack::VerifiedRegistryPack;

/// Supported signed registry-pack revocation document schema.
pub const REGISTRY_PACK_REVOCATION_SCHEMA_VERSION: u32 = 1;
#[cfg(any(feature = "manifest-verify", test))]
const MAX_REVOCATION_DOCUMENT_BYTES: usize = 1024 * 1024;
#[cfg(any(feature = "manifest-verify", test))]
const MAX_REVOCATION_BUNDLE_BYTES: usize = 1024 * 1024;

/// The official feed has a longer signed validity window than operator feeds.
/// Both kinds still expire at their authenticated `not_after` time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryPackRevocationValidity {
    Operator,
    Official,
}

impl RegistryPackRevocationValidity {
    #[cfg(any(feature = "manifest-verify", test))]
    fn maximum(self) -> chrono::Duration {
        match self {
            Self::Operator => chrono::Duration::hours(48),
            Self::Official => chrono::Duration::days(30),
        }
    }
}

/// An authenticated, monotonically increasing position in the revocation feed.
///
/// Store this outside the fetched document and pass it to the next verification.
/// Keeping only a sequence is insufficient: another document at the same
/// sequence could silently change the revocation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackRevocationCheckpoint {
    pub sequence: u64,
    pub sha256: Sha256Hex,
}

/// Wire format signed by a registry-pack revocation release identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryPackRevocationDocument {
    schema_version: u32,
    sequence: u64,
    issued_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    #[serde(default)]
    revoked_identities: Vec<String>,
    #[serde(default)]
    revoked_manifests: Vec<Sha256Hex>,
}

/// A document whose exact bytes have passed signature, freshness, and
/// checkpoint verification. It does not identify the signer of a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryPackRevocations {
    document: RegistryPackRevocationDocument,
    checkpoint: RegistryPackRevocationCheckpoint,
}

impl VerifiedRegistryPackRevocations {
    /// Checkpoint to persist atomically after accepting this document.
    pub fn checkpoint(&self) -> &RegistryPackRevocationCheckpoint {
        &self.checkpoint
    }

    /// Refuse a revoked signing identity or exact manifest digest.
    ///
    /// The signer and digest come from the authenticated pack, never from
    /// untrusted manifest metadata or a caller-supplied identity. A caller
    /// may not use this result after `not_after`.
    pub fn check_verified_pack_at(
        &self,
        verified_pack: &VerifiedRegistryPack,
        now: DateTime<Utc>,
    ) -> Result<(), RegistryPackRevocationError> {
        self.check_pack_at(
            &verified_pack.signer().identity,
            verified_pack.manifest_sha256(),
            now,
        )
    }

    fn check_pack_at(
        &self,
        authenticated_signer: &str,
        manifest_sha256: &Sha256Hex,
        now: DateTime<Utc>,
    ) -> Result<(), RegistryPackRevocationError> {
        validate_time(&self.document, now)?;
        if self
            .document
            .revoked_identities
            .iter()
            .any(|identity| identity == authenticated_signer)
        {
            return Err(RegistryPackRevocationError::RevokedIdentity {
                identity: authenticated_signer.to_string(),
            });
        }
        if self.document.revoked_manifests.contains(manifest_sha256) {
            return Err(RegistryPackRevocationError::RevokedManifest {
                sha256: manifest_sha256.clone(),
            });
        }
        Ok(())
    }
}

/// Reasons registry-pack revocation trust cannot be established.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryPackRevocationError {
    #[error("registry-pack revocation document or signature bundle exceeds the 1 MiB limit")]
    TooLarge,
    #[error("registry-pack revocation signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("registry-pack revocation document is not valid JSON: {0}")]
    Parse(String),
    #[error("unsupported registry-pack revocation schema {got}; expected {expected}")]
    UnsupportedSchema { got: u32, expected: u32 },
    #[error("registry-pack revocation sequence must be positive")]
    InvalidSequence,
    #[error("registry-pack revocation document has an invalid validity window")]
    InvalidValidityWindow,
    #[error("registry-pack revocation document validity exceeds the allowed maximum")]
    ValidityTooLong,
    #[error("registry-pack revocation document was issued in the future")]
    IssuedInFuture,
    #[error("registry-pack revocation document is expired")]
    Expired,
    #[error(
        "registry-pack revocation document contains an empty, repeated, or control-containing identity"
    )]
    InvalidIdentity,
    #[error("registry-pack revocation document repeats a manifest digest")]
    DuplicateManifest,
    #[error("registry-pack revocation sequence rolled back from {previous} to {received}")]
    Rollback { previous: u64, received: u64 },
    #[error("registry-pack revocation sequence {sequence} has a different digest")]
    Equivocation { sequence: u64 },
    #[error("registry-pack signing identity {identity} is revoked")]
    RevokedIdentity { identity: String },
    #[error("registry-pack manifest digest {sha256:?} is revoked")]
    RevokedManifest { sha256: Sha256Hex },
}

/// Authenticate a fetched revocation document before examining its JSON.
///
/// The caller supplies the independently trusted release identity and a
/// durable checkpoint from the last accepted document. A missing, invalid,
/// expired, or rolled-back document is an error, never an empty revocation set.
#[cfg(feature = "manifest-verify")]
pub fn verify_registry_pack_revocations(
    document_bytes: &[u8],
    signature_bundle: &[u8],
    release_trust: &KeylessTrust,
    now: DateTime<Utc>,
    previous: Option<&RegistryPackRevocationCheckpoint>,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError> {
    verify_registry_pack_revocations_for_validity(
        document_bytes,
        signature_bundle,
        release_trust,
        now,
        previous,
        RegistryPackRevocationValidity::Operator,
    )
}

#[cfg(feature = "manifest-verify")]
pub(crate) fn verify_registry_pack_revocations_for_validity(
    document_bytes: &[u8],
    signature_bundle: &[u8],
    release_trust: &KeylessTrust,
    now: DateTime<Utc>,
    previous: Option<&RegistryPackRevocationCheckpoint>,
    validity: RegistryPackRevocationValidity,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError> {
    verify_registry_pack_revocations_with_validity(
        document_bytes,
        signature_bundle,
        release_trust,
        now,
        previous,
        validity,
        |document, bundle, trust| {
            let identities: Vec<&str> = trust
                .accepted_identities
                .iter()
                .map(String::as_str)
                .collect();
            crate::crypto::image_verify::verify_signed_payload_under_any_identity(
                document,
                bundle,
                &identities,
                &trust.issuer,
            )
            .map_err(|error| error.to_string())
        },
    )
}

/// Builds without signature verification cannot accept revocation data.
#[cfg(not(feature = "manifest-verify"))]
pub fn verify_registry_pack_revocations(
    _document_bytes: &[u8],
    _signature_bundle: &[u8],
    _release_trust: &KeylessTrust,
    _now: DateTime<Utc>,
    _previous: Option<&RegistryPackRevocationCheckpoint>,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError> {
    Err(RegistryPackRevocationError::SignatureInvalid(
        "manifest-verify feature disabled in this build".to_string(),
    ))
}

#[cfg(not(feature = "manifest-verify"))]
pub(crate) fn verify_registry_pack_revocations_for_validity(
    document_bytes: &[u8],
    signature_bundle: &[u8],
    release_trust: &KeylessTrust,
    now: DateTime<Utc>,
    previous: Option<&RegistryPackRevocationCheckpoint>,
    _validity: RegistryPackRevocationValidity,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError> {
    verify_registry_pack_revocations(
        document_bytes,
        signature_bundle,
        release_trust,
        now,
        previous,
    )
}

#[cfg(test)]
pub(crate) fn verify_registry_pack_revocations_with<F>(
    document_bytes: &[u8],
    signature_bundle: &[u8],
    release_trust: &KeylessTrust,
    now: DateTime<Utc>,
    previous: Option<&RegistryPackRevocationCheckpoint>,
    verify_signature: F,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError>
where
    F: FnOnce(&[u8], &[u8], &KeylessTrust) -> Result<(), String>,
{
    verify_registry_pack_revocations_with_validity(
        document_bytes,
        signature_bundle,
        release_trust,
        now,
        previous,
        RegistryPackRevocationValidity::Operator,
        verify_signature,
    )
}

#[cfg(any(feature = "manifest-verify", test))]
pub(crate) fn verify_registry_pack_revocations_with_validity<F>(
    document_bytes: &[u8],
    signature_bundle: &[u8],
    release_trust: &KeylessTrust,
    now: DateTime<Utc>,
    previous: Option<&RegistryPackRevocationCheckpoint>,
    validity: RegistryPackRevocationValidity,
    verify_signature: F,
) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError>
where
    F: FnOnce(&[u8], &[u8], &KeylessTrust) -> Result<(), String>,
{
    if document_bytes.len() > MAX_REVOCATION_DOCUMENT_BYTES
        || signature_bundle.len() > MAX_REVOCATION_BUNDLE_BYTES
    {
        return Err(RegistryPackRevocationError::TooLarge);
    }
    verify_signature(document_bytes, signature_bundle, release_trust)
        .map_err(RegistryPackRevocationError::SignatureInvalid)?;
    let document: RegistryPackRevocationDocument = serde_json::from_slice(document_bytes)
        .map_err(|error| RegistryPackRevocationError::Parse(error.to_string()))?;
    validate_document(&document, now, validity)?;
    let checkpoint = RegistryPackRevocationCheckpoint {
        sequence: document.sequence,
        sha256: Sha256Hex::from_bytes(document_bytes),
    };
    if let Some(previous) = previous {
        if checkpoint.sequence < previous.sequence {
            return Err(RegistryPackRevocationError::Rollback {
                previous: previous.sequence,
                received: checkpoint.sequence,
            });
        }
        if checkpoint.sequence == previous.sequence && checkpoint.sha256 != previous.sha256 {
            return Err(RegistryPackRevocationError::Equivocation {
                sequence: checkpoint.sequence,
            });
        }
    }
    Ok(VerifiedRegistryPackRevocations {
        document,
        checkpoint,
    })
}

#[cfg(any(feature = "manifest-verify", test))]
fn validate_document(
    document: &RegistryPackRevocationDocument,
    now: DateTime<Utc>,
    validity: RegistryPackRevocationValidity,
) -> Result<(), RegistryPackRevocationError> {
    if document.schema_version != REGISTRY_PACK_REVOCATION_SCHEMA_VERSION {
        return Err(RegistryPackRevocationError::UnsupportedSchema {
            got: document.schema_version,
            expected: REGISTRY_PACK_REVOCATION_SCHEMA_VERSION,
        });
    }
    if document.sequence == 0 {
        return Err(RegistryPackRevocationError::InvalidSequence);
    }
    if document.issued_at >= document.not_after {
        return Err(RegistryPackRevocationError::InvalidValidityWindow);
    }
    if document.not_after - document.issued_at > validity.maximum() {
        return Err(RegistryPackRevocationError::ValidityTooLong);
    }
    validate_time(document, now)?;
    let mut identities = BTreeSet::new();
    for identity in &document.revoked_identities {
        if identity.trim().is_empty()
            || identity.bytes().any(|byte| byte.is_ascii_control())
            || !identities.insert(identity)
        {
            return Err(RegistryPackRevocationError::InvalidIdentity);
        }
    }
    let mut manifests = BTreeSet::new();
    for digest in &document.revoked_manifests {
        if !manifests.insert(digest) {
            return Err(RegistryPackRevocationError::DuplicateManifest);
        }
    }
    Ok(())
}

fn validate_time(
    document: &RegistryPackRevocationDocument,
    now: DateTime<Utc>,
) -> Result<(), RegistryPackRevocationError> {
    if document.issued_at > now {
        return Err(RegistryPackRevocationError::IssuedInFuture);
    }
    if document.not_after <= now {
        return Err(RegistryPackRevocationError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::crypto::image_verify::VerifiedSigner;
    use crate::registry_pack::{
        PackAdoption, PackReference, RegistryPackFile, RegistryPackManifest, RegistryPackPublisher,
        RegistryPackPublisherPolicy, RegistryPackVerificationError, adopt_registry_pack_with,
    };

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, 0, 0, 0)
            .single()
            .expect("valid date")
    }

    fn trust() -> KeylessTrust {
        KeylessTrust {
            accepted_identities: vec!["release identity".to_string()],
            issuer: "release issuer".to_string(),
        }
    }

    fn document(sequence: u64) -> RegistryPackRevocationDocument {
        RegistryPackRevocationDocument {
            schema_version: REGISTRY_PACK_REVOCATION_SCHEMA_VERSION,
            sequence,
            issued_at: at(6),
            not_after: at(8),
            revoked_identities: vec!["old identity".to_string()],
            revoked_manifests: vec![Sha256Hex::from_bytes(b"bad manifest")],
        }
    }

    fn signed(
        document: &RegistryPackRevocationDocument,
        previous: Option<&RegistryPackRevocationCheckpoint>,
    ) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationError> {
        let bytes = serde_json::to_vec(document).expect("serialize document");
        verify_registry_pack_revocations_with(
            &bytes,
            b"signature",
            &trust(),
            at(7),
            previous,
            |payload, bundle, keyless| {
                if payload.is_empty()
                    || bundle != b"signature"
                    || keyless.accepted_identities != ["release identity"]
                {
                    return Err("invalid test signature".to_string());
                }
                Ok(())
            },
        )
    }

    fn test_pack_signature(
        _manifest: &[u8],
        bundle: &[u8],
        trust: &KeylessTrust,
    ) -> Result<VerifiedSigner, RegistryPackVerificationError> {
        let identity = std::str::from_utf8(bundle)
            .map_err(|error| RegistryPackVerificationError::SignatureInvalid(error.to_string()))?;
        if !trust
            .accepted_identities
            .iter()
            .any(|allowed| allowed == identity)
        {
            return Err(RegistryPackVerificationError::SignatureInvalid(
                "test identity is not trusted".to_string(),
            ));
        }
        Ok(VerifiedSigner {
            identity: identity.to_string(),
            issuer: trust.issuer.clone(),
        })
    }

    fn verified_pack(identity: &str) -> VerifiedRegistryPack {
        let reference: PackReference = "runtime/example@1.0.0".parse().expect("valid reference");
        let manifest_bytes = serde_json::to_vec(&RegistryPackManifest {
            schema_version: 1,
            reference: reference.clone(),
            description: "Example workload".to_string(),
            image: None,
            files: vec![RegistryPackFile {
                path: "pack/profile.toml".to_string(),
                sha256: Sha256Hex::from_bytes(b"profile"),
                size: 7,
            }],
        })
        .expect("serialize manifest");
        let policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "runtime",
                "test issuer",
                vec!["new identity".to_string(), "old identity".to_string()],
            )
            .expect("valid publisher"),
        ])
        .expect("valid policy");
        let adoption = PackAdoption {
            requested: &reference,
            manifest_bytes: &manifest_bytes,
            signature_bundle: identity.as_bytes(),
            publisher_policy: &policy,
        };
        adopt_registry_pack_with(&adoption, test_pack_signature).expect("verified test pack")
    }

    #[test]
    fn signed_document_checks_identity_and_manifest_revocations() {
        let verified = signed(&document(1), None).expect("valid signed document");
        let checkpoint = verified.checkpoint();
        assert_eq!(checkpoint.sequence, 1);
        let good = verified_pack("new identity");
        let old = verified_pack("old identity");
        assert_eq!(verified.check_verified_pack_at(&good, at(7)), Ok(()));
        assert!(matches!(
            verified.check_verified_pack_at(&old, at(7)),
            Err(RegistryPackRevocationError::RevokedIdentity { .. })
        ));
        let mut digest_revocation = document(1);
        digest_revocation.revoked_manifests = vec![good.manifest_sha256().clone()];
        let verified_digest = signed(&digest_revocation, None).expect("valid digest revocation");
        assert!(matches!(
            verified_digest.check_verified_pack_at(&good, at(7)),
            Err(RegistryPackRevocationError::RevokedManifest { .. })
        ));
        assert_eq!(
            verified.check_verified_pack_at(&good, at(31)),
            Err(RegistryPackRevocationError::Expired)
        );
    }

    #[test]
    fn invalid_signature_refuses_before_json_parse() {
        let error = verify_registry_pack_revocations_with(
            b"not json",
            b"bad signature",
            &trust(),
            at(7),
            None,
            |_, _, _| Err("rejected".to_string()),
        )
        .expect_err("signature must fail first");
        assert_eq!(
            error,
            RegistryPackRevocationError::SignatureInvalid("rejected".to_string())
        );
    }

    #[test]
    fn tampered_document_and_unavailable_bundle_are_refused() {
        let original = serde_json::to_vec(&document(1)).expect("serialize document");
        let mut tampered = document(1);
        tampered.revoked_identities.clear();
        let tampered = serde_json::to_vec(&tampered).expect("serialize tampered document");
        for (bytes, bundle) in [
            (tampered.as_slice(), b"signature".as_slice()),
            (original.as_slice(), b"".as_slice()),
        ] {
            let error = verify_registry_pack_revocations_with(
                bytes,
                bundle,
                &trust(),
                at(7),
                None,
                |payload, signature, _| {
                    if payload == original && signature == b"signature" {
                        Ok(())
                    } else {
                        Err("signature does not bind these bytes".to_string())
                    }
                },
            )
            .expect_err("unauthenticated revocations must fail");
            assert!(matches!(
                error,
                RegistryPackRevocationError::SignatureInvalid(_)
            ));
        }
    }

    #[test]
    fn oversized_document_is_refused_before_signature_check() {
        let bytes = vec![b' '; MAX_REVOCATION_DOCUMENT_BYTES + 1];
        let error = verify_registry_pack_revocations_with(
            &bytes,
            b"signature",
            &trust(),
            at(7),
            None,
            |_, _, _| panic!("oversized data must not reach signature verification"),
        )
        .expect_err("oversized document");
        assert_eq!(error, RegistryPackRevocationError::TooLarge);
    }

    #[test]
    fn oversized_bundle_is_refused_before_signature_check() {
        let bytes = serde_json::to_vec(&document(1)).expect("serialize");
        let bundle = vec![b' '; MAX_REVOCATION_BUNDLE_BYTES + 1];
        let error = verify_registry_pack_revocations_with(
            &bytes,
            &bundle,
            &trust(),
            at(7),
            None,
            |_, _, _| panic!("oversized bundle must not reach signature verification"),
        )
        .expect_err("oversized bundle");
        assert_eq!(error, RegistryPackRevocationError::TooLarge);
    }

    #[test]
    fn expiry_future_issue_and_window_are_refused() {
        let bytes = serde_json::to_vec(&document(1)).expect("serialize");
        let verify_at = |now| {
            verify_registry_pack_revocations_with(
                &bytes,
                b"signature",
                &trust(),
                now,
                None,
                |_, _, _| Ok(()),
            )
        };
        assert_eq!(
            verify_at(at(31)).expect_err("expired"),
            RegistryPackRevocationError::Expired
        );
        assert_eq!(
            verify_at(at(1) - chrono::Duration::seconds(1)).expect_err("future"),
            RegistryPackRevocationError::IssuedInFuture
        );
        let mut invalid = document(1);
        invalid.not_after = invalid.issued_at;
        assert_eq!(
            signed(&invalid, None).expect_err("invalid window"),
            RegistryPackRevocationError::InvalidValidityWindow
        );
        let mut too_long = document(1);
        too_long.not_after += chrono::Duration::seconds(1);
        assert_eq!(
            signed(&too_long, None).expect_err("overlong window"),
            RegistryPackRevocationError::ValidityTooLong
        );
    }

    #[test]
    fn official_validity_accepts_thirty_days_but_not_longer() {
        let mut feed = document(1);
        feed.not_after = feed.issued_at + chrono::Duration::days(30);
        let bytes = serde_json::to_vec(&feed).expect("serialize");
        let verify = |policy| {
            verify_registry_pack_revocations_with_validity(
                &bytes,
                b"signature",
                &trust(),
                at(7),
                None,
                policy,
                |_, _, _| Ok(()),
            )
        };
        assert!(verify(RegistryPackRevocationValidity::Official).is_ok());
        assert_eq!(
            verify(RegistryPackRevocationValidity::Operator).expect_err("operator limit"),
            RegistryPackRevocationError::ValidityTooLong
        );
        feed.not_after += chrono::Duration::seconds(1);
        let overlong = serde_json::to_vec(&feed).expect("serialize");
        assert_eq!(
            verify_registry_pack_revocations_with_validity(
                &overlong,
                b"signature",
                &trust(),
                at(7),
                None,
                RegistryPackRevocationValidity::Official,
                |_, _, _| Ok(()),
            )
            .expect_err("official maximum"),
            RegistryPackRevocationError::ValidityTooLong
        );
    }

    #[test]
    fn official_validity_still_expires_at_not_after() {
        let mut feed = document(1);
        feed.not_after = feed.issued_at + chrono::Duration::days(30);
        let bytes = serde_json::to_vec(&feed).expect("serialize");
        assert_eq!(
            verify_registry_pack_revocations_with_validity(
                &bytes,
                b"signature",
                &trust(),
                feed.not_after,
                None,
                RegistryPackRevocationValidity::Official,
                |_, _, _| Ok(()),
            )
            .expect_err("expired at bound"),
            RegistryPackRevocationError::Expired
        );
    }

    #[test]
    fn rollback_and_same_sequence_equivocation_are_refused() {
        let first = signed(&document(2), None).expect("first list");
        assert_eq!(
            signed(&document(1), Some(first.checkpoint())).expect_err("rollback"),
            RegistryPackRevocationError::Rollback {
                previous: 2,
                received: 1
            }
        );
        let mut changed = document(2);
        changed.revoked_identities.push("new identity".to_string());
        assert_eq!(
            signed(&changed, Some(first.checkpoint())).expect_err("equivocation"),
            RegistryPackRevocationError::Equivocation { sequence: 2 }
        );
        assert!(signed(&document(2), Some(first.checkpoint())).is_ok());
        assert!(signed(&document(3), Some(first.checkpoint())).is_ok());
    }

    #[test]
    fn malformed_or_duplicate_entries_are_refused() {
        let mut duplicate = document(1);
        duplicate
            .revoked_identities
            .push("old identity".to_string());
        assert_eq!(
            signed(&duplicate, None).expect_err("duplicate identity"),
            RegistryPackRevocationError::InvalidIdentity
        );
        let mut control = document(1);
        control.revoked_identities = vec!["workflow\nforged log line".to_string()];
        assert_eq!(
            signed(&control, None).expect_err("control character"),
            RegistryPackRevocationError::InvalidIdentity
        );
        let mut duplicate = document(1);
        duplicate
            .revoked_manifests
            .push(Sha256Hex::from_bytes(b"bad manifest"));
        assert_eq!(
            signed(&duplicate, None).expect_err("duplicate digest"),
            RegistryPackRevocationError::DuplicateManifest
        );
        let mut zero = document(0);
        assert_eq!(
            signed(&zero, None).expect_err("zero sequence"),
            RegistryPackRevocationError::InvalidSequence
        );
        zero.sequence = 1;
        zero.schema_version = 2;
        assert!(matches!(
            signed(&zero, None),
            Err(RegistryPackRevocationError::UnsupportedSchema { .. })
        ));
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn no_feature_build_refuses_fetched_document() {
        assert!(matches!(
            verify_registry_pack_revocations(b"{}", b"bundle", &trust(), at(7), None),
            Err(RegistryPackRevocationError::SignatureInvalid(_))
        ));
    }
}
