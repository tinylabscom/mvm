//! Built-in publisher migration policy and exact signed historical manifests.

use super::{
    DateTime, LEGACY_PACK_SIGNING_CUTOFF, LEGACY_PACK_SIGNING_IDENTITY,
    OFFICIAL_PACK_SIGNING_IDENTITY, OFFICIAL_PACK_SIGNING_ISSUER, PackReference,
    PublisherPolicyProvenance, RegistryPackPublisher, RegistryPackPublisherPolicy,
    RegistryPackVerificationError, Sha256Hex, Utc, VerifiedRegistryPack,
};

/// The publisher trust policy that applies when the operator has made no
/// trust decision of their own. The `mvm` namespace is reserved to the exact
/// current release identity. An operator policy may exclude it but cannot
/// assign a different signer.
/// Legacy `agent` and `runtime` identities expire at the stated cutoff and
/// authenticate only the nine exact historical manifest reference/digest pairs.
/// Serializing and loading this policy is an explicit operator trust decision;
/// the built-in historical exception is not inferred from publisher entries.
pub fn official_publisher_policy() -> RegistryPackPublisherPolicy {
    let publishers = ["agent", "runtime", "mvm"]
        .into_iter()
        .map(|namespace| {
            let mut identities = vec![OFFICIAL_PACK_SIGNING_IDENTITY.to_string()];
            if namespace != "mvm" {
                identities.push(LEGACY_PACK_SIGNING_IDENTITY.to_string());
            }
            RegistryPackPublisher::new(namespace, OFFICIAL_PACK_SIGNING_ISSUER, identities)
                .expect("the built-in publisher policy is built from valid constants")
        })
        .collect();
    let mut policy = RegistryPackPublisherPolicy::new(publishers)
        .expect("the built-in publisher policy has unique namespaces");
    policy.provenance = PublisherPolicyProvenance::BuiltinDefault;
    policy.legacy_identity_expires_at = Some(
        DateTime::parse_from_rfc3339(LEGACY_PACK_SIGNING_CUTOFF)
            .expect("the built-in legacy identity cutoff is valid")
            .with_timezone(&Utc),
    );
    policy
}

// Applied only after signature authentication and canonical reference validation.
// These are SHA-256 hashes of the exact signed manifest bytes, not payload hashes.
// Producer evidence: tinylabscom/mvm-packs bef6dea6cea2b982596e3429dcb3c9c4c265588e.
pub(super) fn enforce_legacy_manifest_policy(
    policy: &RegistryPackPublisherPolicy,
    verified: VerifiedRegistryPack,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    check_legacy_manifest_policy(
        policy,
        &verified.signer.identity,
        &verified.manifest.reference,
        &verified.manifest_sha256,
    )?;
    Ok(verified)
}

pub(super) fn check_legacy_manifest_policy(
    policy: &RegistryPackPublisherPolicy,
    verified_identity: &str,
    reference: &PackReference,
    digest: &Sha256Hex,
) -> Result<(), RegistryPackVerificationError> {
    if policy.provenance == PublisherPolicyProvenance::BuiltinDefault
        && verified_identity == LEGACY_PACK_SIGNING_IDENTITY
        && !legacy_manifest_allowed(reference, digest)
    {
        return Err(RegistryPackVerificationError::LegacyManifestNotAllowed);
    }
    Ok(())
}

fn legacy_manifest_allowed(reference: &PackReference, digest: &Sha256Hex) -> bool {
    const HISTORICAL: [(&str, &str); 9] = [
        (
            "agent/claude@1.0.1",
            "c4be773ef57a0f4365730858e522207c5e609f9fda76f1499eab3d6b0c6293f5",
        ),
        (
            "agent/codex@1.0.0",
            "63f7c363966fe3bacb894e50be1e04e720ea6ac4e9a2d878fb2c811dc21bea7c",
        ),
        (
            "agent/goose@1.0.0",
            "043fe83720bd8dc25aa1c11c298993957a1b4ec23a71d0a7d2343b0b13024506",
        ),
        (
            "agent/opencode@1.0.0",
            "1304b068122bc84fbae7c795727d9d7ccf3bf852cbb8309ab2e9d4903fdf2a1a",
        ),
        (
            "agent/pi@1.0.0",
            "f4049d71e7f18fcb23cb90f01898fe7af06b66daf958920416010a9aa8438272",
        ),
        (
            "runtime/go@1.0.0",
            "ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50",
        ),
        (
            "runtime/node@1.0.0",
            "e10d2c7f070e00a1b5d8c713568c0aebe608cc4e346c091a4cb25057ffd25bd3",
        ),
        (
            "runtime/python@1.0.0",
            "80903c11a95708dcf493d673bf76a99f3828a41a4e640550e19b76fd8affa229",
        ),
        (
            "runtime/rust@1.0.0",
            "e9e27c4055186d2416af010804000410cbd54b86d530084aa706cb0bf79c344e",
        ),
    ];
    let reference = reference.to_string();
    HISTORICAL.iter().any(|(expected_ref, expected_digest)| {
        reference == *expected_ref && digest.as_str() == *expected_digest
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "manifest-verify")]
    use super::super::check_registry_pack_signature;
    use super::super::{
        KeylessTrust, PackAdoption, PackLockfile, RegistryPackVerification, VerifiedSigner,
        adopt_registry_pack_with_at,
        tests::{pin, reference, signed_manifest_bytes},
        verify_registry_pack_with_at,
    };
    use super::*;
    #[cfg(feature = "manifest-verify")]
    use std::path::Path;

    #[test]
    fn historical_filter_requires_exact_reference_and_manifest_bytes() {
        let digest =
            Sha256Hex::new("ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50")
                .unwrap();
        assert!(legacy_manifest_allowed(
            &reference("runtime/go@1.0.0"),
            &digest
        ));
        for name in [
            "runtime/go",
            "runtime/go@1.0.1",
            "runtime/unlisted@1.0.0",
            "agent/go@1.0.0",
            "mvm/go@1.0.0",
        ] {
            assert!(
                !legacy_manifest_allowed(&reference(name), &digest),
                "{name}"
            );
        }
        assert!(!legacy_manifest_allowed(
            &reference("runtime/go@1.0.0"),
            &Sha256Hex::from_bytes(b"altered manifest bytes"),
        ));
        let builtin = official_publisher_policy();
        let unlisted = reference("runtime/unlisted@1.0.0");
        assert!(matches!(
            check_legacy_manifest_policy(
                &builtin,
                LEGACY_PACK_SIGNING_IDENTITY,
                &unlisted,
                &digest,
            ),
            Err(RegistryPackVerificationError::LegacyManifestNotAllowed)
        ));
        // Policy-decision tests only: these do not manufacture verified signers.
        check_legacy_manifest_policy(&builtin, OFFICIAL_PACK_SIGNING_IDENTITY, &unlisted, &digest)
            .unwrap();
        let operator: RegistryPackPublisherPolicy =
            serde_json::from_slice(&serde_json::to_vec(&builtin).unwrap()).unwrap();
        check_legacy_manifest_policy(&operator, LEGACY_PACK_SIGNING_IDENTITY, &unlisted, &digest)
            .unwrap();
    }

    #[test]
    fn serialized_builtin_policy_is_an_explicit_operator_policy() {
        let builtin = official_publisher_policy();
        let decoded: RegistryPackPublisherPolicy =
            serde_json::from_slice(&serde_json::to_vec(&builtin).unwrap()).unwrap();
        assert_eq!(
            builtin.provenance,
            PublisherPolicyProvenance::BuiltinDefault
        );
        assert_eq!(decoded.provenance, PublisherPolicyProvenance::Operator);
        assert_eq!(decoded.publishers(), builtin.publishers());
        let after = DateTime::parse_from_rfc3339("2026-11-06T00:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            decoded
                .trust_for_namespace_at("runtime", after)
                .unwrap()
                .accepted_identities
                .iter()
                .any(|identity| identity == LEGACY_PACK_SIGNING_IDENTITY)
        );
    }

    // Synthetic wiring checker: deliberately no cryptographic verification.
    // It asserts the caller supplied the legacy trust and returns a test signer
    // so removal of either post-authentication enforcement call fails its test.
    fn synthetic_legacy_signature(
        payload: &[u8],
        bundle: &[u8],
        trust: &KeylessTrust,
    ) -> Result<VerifiedSigner, RegistryPackVerificationError> {
        assert_eq!(payload, signed_manifest_bytes("runtime/unlisted@1.0.0"));
        assert_eq!(bundle, b"synthetic wiring bundle, not a Sigstore signature");
        assert_eq!(trust.issuer, OFFICIAL_PACK_SIGNING_ISSUER);
        assert!(
            trust
                .accepted_identities
                .iter()
                .any(|identity| identity == LEGACY_PACK_SIGNING_IDENTITY)
        );
        Ok(VerifiedSigner {
            identity: LEGACY_PACK_SIGNING_IDENTITY.to_string(),
            issuer: OFFICIAL_PACK_SIGNING_ISSUER.to_string(),
        })
    }

    #[test]
    fn synthetic_legacy_adoption_enforces_historical_manifest_filter() {
        let requested = reference("runtime/unlisted@1.0.0");
        let manifest = signed_manifest_bytes("runtime/unlisted@1.0.0");
        let policy = official_publisher_policy();
        let before = DateTime::parse_from_rfc3339("2026-11-05T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let adoption = PackAdoption {
            requested: &requested,
            manifest_bytes: &manifest,
            signature_bundle: b"synthetic wiring bundle, not a Sigstore signature",
            publisher_policy: &policy,
        };
        assert!(matches!(
            adopt_registry_pack_with_at(&adoption, synthetic_legacy_signature, before),
            Err(RegistryPackVerificationError::LegacyManifestNotAllowed)
        ));
        // Positive control: these exact bytes are canonical and otherwise valid.
        let operator: RegistryPackPublisherPolicy =
            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
        adopt_registry_pack_with_at(
            &PackAdoption {
                publisher_policy: &operator,
                ..adoption
            },
            synthetic_legacy_signature,
            before,
        )
        .unwrap();
    }

    #[test]
    fn synthetic_legacy_locked_verification_enforces_historical_manifest_filter() {
        let requested = reference("runtime/unlisted@1.0.0");
        let manifest = signed_manifest_bytes("runtime/unlisted@1.0.0");
        let bundle = b"synthetic wiring bundle, not a Sigstore signature";
        let policy = official_publisher_policy();
        let lock = PackLockfile::new(vec![pin("runtime/unlisted@1.0.0", &manifest)]).unwrap();
        let before = DateTime::parse_from_rfc3339("2026-11-05T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let locked = RegistryPackVerification::new(&requested, &manifest, bundle, &lock, &policy);
        assert!(matches!(
            verify_registry_pack_with_at(&locked, synthetic_legacy_signature, before),
            Err(RegistryPackVerificationError::LegacyManifestNotAllowed)
        ));
        // Positive control: a matching lock and canonical manifest pass outside
        // the built-in restriction; no real signature acceptance is claimed.
        let operator: RegistryPackPublisherPolicy =
            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
        let locked = RegistryPackVerification::new(&requested, &manifest, bundle, &lock, &operator);
        verify_registry_pack_with_at(&locked, synthetic_legacy_signature, before).unwrap();
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn real_historical_signature_is_digest_bound_and_expires_in_builtin_policy() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-cli/tests/fixtures/signed-registry-go");
        let manifest = std::fs::read(fixture.join("manifest.json")).unwrap();
        let bundle = std::fs::read(fixture.join("manifest.sigstore.json")).unwrap();
        let requested = reference("runtime/go@1.0.0");
        let policy = official_publisher_policy();
        let adoption = PackAdoption {
            requested: &requested,
            manifest_bytes: &manifest,
            signature_bundle: &bundle,
            publisher_policy: &policy,
        };
        let before = DateTime::parse_from_rfc3339("2026-11-05T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let verified =
            adopt_registry_pack_with_at(&adoption, check_registry_pack_signature, before).unwrap();
        assert_eq!(verified.signer().identity, LEGACY_PACK_SIGNING_IDENTITY);
        assert_eq!(
            verified.manifest_sha256(),
            &Sha256Hex::from_bytes(&manifest)
        );
        assert!(legacy_manifest_allowed(
            &verified.manifest().reference,
            verified.manifest_sha256(),
        ));
        let lock = PackLockfile::new(vec![pin("runtime/go@1.0.0", &manifest)]).unwrap();
        let locked = RegistryPackVerification::new(&requested, &manifest, &bundle, &lock, &policy);
        verify_registry_pack_with_at(&locked, check_registry_pack_signature, before).unwrap();
        for timestamp in [LEGACY_PACK_SIGNING_CUTOFF, "2026-11-06T00:00:01Z"] {
            let now = DateTime::parse_from_rfc3339(timestamp)
                .unwrap()
                .with_timezone(&Utc);
            assert!(matches!(
                adopt_registry_pack_with_at(&adoption, check_registry_pack_signature, now),
                Err(RegistryPackVerificationError::SignatureInvalid(_))
            ));
            assert!(matches!(
                verify_registry_pack_with_at(&locked, check_registry_pack_signature, now),
                Err(RegistryPackVerificationError::SignatureInvalid(_))
            ));
        }
        let mut altered = manifest.clone();
        altered.push(b'\n');
        assert!(matches!(
            adopt_registry_pack_with_at(
                &PackAdoption {
                    manifest_bytes: &altered,
                    ..adoption
                },
                check_registry_pack_signature,
                before,
            ),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
        for name in ["runtime/go@1.0.1", "runtime/unlisted@1.0.0"] {
            let wrong = reference(name);
            assert!(matches!(
                adopt_registry_pack_with_at(
                    &PackAdoption {
                        requested: &wrong,
                        ..adoption
                    },
                    check_registry_pack_signature,
                    before,
                ),
                Err(RegistryPackVerificationError::ManifestReferenceMismatch { .. })
            ));
        }
        let operator: RegistryPackPublisherPolicy =
            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
        let after = DateTime::parse_from_rfc3339("2026-11-06T00:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        adopt_registry_pack_with_at(
            &PackAdoption {
                publisher_policy: &operator,
                ..adoption
            },
            check_registry_pack_signature,
            after,
        )
        .unwrap();
    }
}
