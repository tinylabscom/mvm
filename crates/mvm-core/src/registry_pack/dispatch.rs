//! Authenticated manifest dispatch. Bundle metadata is not bundle admission.

use super::application::{RegistryApplicationManifest, parse_application_manifest};
use super::*;

/// Publisher-authenticated metadata only; no archive has been acquired.
///
/// This is not bundle trust, signing-key enrollment, or execution authority.
/// Consumers must check current revocations before acquisition or use. The
/// original bytes and signature bundle are retained for re-verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryApplication {
    manifest: RegistryApplicationManifest,
    manifest_bytes: Vec<u8>,
    signature_bundle: Vec<u8>,
    manifest_sha256: Sha256Hex,
    signer: VerifiedSigner,
}

impl VerifiedRegistryApplication {
    pub fn manifest(&self) -> &RegistryApplicationManifest {
        &self.manifest
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    pub fn signature_bundle(&self) -> &[u8] {
        &self.signature_bundle
    }

    /// Require a current, independently authenticated revocation feed before use.
    ///
    /// Official applications use the built-in MVM feed. Other applications
    /// require operator-configured trust and a verified cached feed. This does
    /// not acquire an archive or grant permission to execute it.
    pub fn check_current_revocations(
        &self,
    ) -> Result<(), crate::registry_pack_store::RegistryPackStoreError> {
        crate::registry_pack_store::check_application_revocations(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedRegistryManifest {
    Legacy(VerifiedRegistryPack),
    Application(VerifiedRegistryApplication),
}

mod sealed {
    pub trait Sealed {}
}

/// Evidence exposed only by publisher-authenticated manifests.
pub trait AuthenticatedRegistryManifest: sealed::Sealed {
    fn reference(&self) -> &PackReference;
    fn manifest_sha256(&self) -> &Sha256Hex;
    fn signer(&self) -> &VerifiedSigner;
    fn requires_operator_revocations(&self) -> bool;
}

impl sealed::Sealed for VerifiedRegistryPack {}
impl AuthenticatedRegistryManifest for VerifiedRegistryPack {
    fn reference(&self) -> &PackReference {
        &self.manifest().reference
    }
    fn manifest_sha256(&self) -> &Sha256Hex {
        self.manifest_sha256()
    }
    fn signer(&self) -> &VerifiedSigner {
        self.signer()
    }
    fn requires_operator_revocations(&self) -> bool {
        matches!(self.manifest().image, Some(RegistryPackImage::Built(_)))
    }
}

impl sealed::Sealed for VerifiedRegistryApplication {}
impl AuthenticatedRegistryManifest for VerifiedRegistryApplication {
    fn reference(&self) -> &PackReference {
        &self.manifest.reference
    }
    fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }
    fn signer(&self) -> &VerifiedSigner {
        &self.signer
    }
    fn requires_operator_revocations(&self) -> bool {
        false
    }
}

impl sealed::Sealed for VerifiedRegistryManifest {}
impl AuthenticatedRegistryManifest for VerifiedRegistryManifest {
    fn reference(&self) -> &PackReference {
        match self {
            Self::Legacy(pack) => pack.reference(),
            Self::Application(application) => application.reference(),
        }
    }

    fn manifest_sha256(&self) -> &Sha256Hex {
        match self {
            Self::Legacy(pack) => pack.manifest_sha256(),
            Self::Application(application) => application.manifest_sha256(),
        }
    }

    fn signer(&self) -> &VerifiedSigner {
        match self {
            Self::Legacy(pack) => pack.signer(),
            Self::Application(application) => application.signer(),
        }
    }

    fn requires_operator_revocations(&self) -> bool {
        match self {
            Self::Legacy(pack) => pack.requires_operator_revocations(),
            Self::Application(application) => application.requires_operator_revocations(),
        }
    }
}

/// Verify lock drift and the namespace publisher before dispatching original bytes.
pub fn verify_registry_manifest(
    request: &RegistryPackVerification<'_>,
) -> Result<VerifiedRegistryManifest, RegistryPackVerificationError> {
    verify_with(request, check_registry_pack_signature)
}

pub(super) fn verify_with(
    request: &RegistryPackVerification<'_>,
    check: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryManifest, RegistryPackVerificationError> {
    let pin = request
        .lock
        .verify_manifest(request.requested, request.manifest_bytes)?;
    adopt_with(
        &PackAdoption {
            requested: pin.reference(),
            manifest_bytes: request.manifest_bytes,
            signature_bundle: request.signature_bundle,
            publisher_policy: request.publisher_policy,
        },
        check,
    )
}

/// First adoption authenticates the publisher; it does not persist a pin.
pub fn adopt_registry_manifest(
    request: &PackAdoption<'_>,
) -> Result<VerifiedRegistryManifest, RegistryPackVerificationError> {
    adopt_with(request, check_registry_pack_signature)
}

pub(super) fn adopt_with(
    request: &PackAdoption<'_>,
    check: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryManifest, RegistryPackVerificationError> {
    let trust = request
        .publisher_policy
        .trust_for_namespace(request.requested.namespace())?;
    let signer = check(request.manifest_bytes, request.signature_bundle, &trust)?;
    // This header chooses one strict parser, never a fallback parser. Duplicate
    // discriminators are rejected here; nested duplicates by the selected parser.
    #[derive(Deserialize)]
    struct Header {
        schema_version: u32,
        kind: Option<String>,
    }
    let header: Header = serde_json::from_slice(request.manifest_bytes)
        .map_err(|error| RegistryPackVerificationError::ManifestParse(error.to_string()))?;
    match (header.schema_version, header.kind.as_deref()) {
        (1, None) => {
            let verified = finish_registry_pack_verification(
                request.requested,
                request.manifest_bytes,
                request.signature_bundle,
                signer,
                None,
            )?;
            enforce_legacy_manifest_policy(request.publisher_policy, verified)
                .map(VerifiedRegistryManifest::Legacy)
        }
        (2, Some("application")) => {
            let manifest = parse_application_manifest(request.manifest_bytes)?;
            if manifest.reference.coordinate != request.requested.coordinate
                || request
                    .requested
                    .version
                    .as_ref()
                    .is_some_and(|v| Some(v) != manifest.reference.version.as_ref())
            {
                return Err(RegistryPackVerificationError::ManifestReferenceMismatch {
                    manifest: manifest.reference.to_string(),
                    locked: request.requested.to_string(),
                });
            }
            let manifest_sha256 = Sha256Hex::from_bytes(request.manifest_bytes);
            historical::check_legacy_manifest_policy(
                request.publisher_policy,
                &signer.identity,
                &manifest.reference,
                &manifest_sha256,
            )?;
            Ok(VerifiedRegistryManifest::Application(
                VerifiedRegistryApplication {
                    manifest,
                    manifest_sha256,
                    signer,
                    manifest_bytes: request.manifest_bytes.to_vec(),
                    signature_bundle: request.signature_bundle.to_vec(),
                },
            ))
        }
        _ => Err(RegistryPackVerificationError::ManifestParse(
            "unsupported registry manifest kind/schema pair".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_pack::tests::{accept_signature, publisher_policy, reject_signature};

    const APPLICATION: &[u8] = include_bytes!("application_manifest_v2.json");

    fn application_bytes() -> Vec<u8> {
        String::from_utf8(APPLICATION.to_vec())
            .unwrap()
            .replace("test/hello@1.0.0", "runtime/python@1.2.3")
            .into_bytes()
    }

    #[test]
    fn application_evidence_uses_the_existing_current_revocation_feed() {
        use crate::registry_pack_revocation::{
            RegistryPackRevocationError, verify_registry_pack_revocations_with,
        };
        let policy = publisher_policy();
        let reference = "runtime/python@1.2.3".parse().unwrap();
        let bytes = application_bytes();
        let request = PackAdoption {
            requested: &reference,
            manifest_bytes: &bytes,
            signature_bundle: b"bundle",
            publisher_policy: &policy,
        };
        let verified = adopt_with(&request, accept_signature).unwrap();
        assert_eq!(verified.reference(), &reference);
        assert_eq!(verified.manifest_sha256(), &Sha256Hex::from_bytes(&bytes));
        let VerifiedRegistryManifest::Application(app) = verified else {
            panic!("expected application")
        };
        let now = Utc::now();
        let trust = KeylessTrust {
            issuer: "independent issuer".to_string(),
            accepted_identities: vec!["independent release identity".to_string()],
        };
        for (identities, manifests, expected) in [
            (Vec::new(), Vec::new(), "allowed"),
            (vec![app.signer().identity.clone()], Vec::new(), "identity"),
            (Vec::new(), vec![app.manifest_sha256().clone()], "digest"),
        ] {
            let document = serde_json::json!({
                "schema_version": 1,
                "sequence": 1,
                "issued_at": now - chrono::Duration::hours(1),
                "not_after": now + chrono::Duration::hours(1),
                "revoked_identities": identities,
                "revoked_manifests": manifests,
            });
            let feed = verify_registry_pack_revocations_with(
                &serde_json::to_vec(&document).unwrap(),
                b"signed feed",
                &trust,
                now,
                None,
                |_, _, _| Ok(()),
            )
            .unwrap();
            let result = feed.check_verified_pack_at(&app, now);
            match expected {
                "allowed" => assert!(result.is_ok()),
                "identity" => assert!(matches!(
                    result,
                    Err(RegistryPackRevocationError::RevokedIdentity { .. })
                )),
                "digest" => assert!(matches!(
                    result,
                    Err(RegistryPackRevocationError::RevokedManifest { .. })
                )),
                _ => unreachable!(),
            }
            assert!(
                feed.check_verified_pack_at(&app, now + chrono::Duration::hours(2))
                    .is_err()
            );
        }
    }

    #[test]
    fn application_checks_the_namespace_authority_not_a_descriptor_claim() {
        let policy = publisher_policy();
        let reference = "runtime/python@1.2.3".parse().unwrap();
        let bytes = application_bytes();
        let request = PackAdoption {
            requested: &reference,
            manifest_bytes: &bytes,
            signature_bundle: b"wrong publisher",
            publisher_policy: &policy,
        };
        fn check_publisher(
            _: &[u8],
            bundle: &[u8],
            trust: &KeylessTrust,
        ) -> Result<VerifiedSigner, RegistryPackVerificationError> {
            let identity = std::str::from_utf8(bundle).unwrap();
            if !trust
                .accepted_identities
                .iter()
                .any(|allowed| allowed == identity)
            {
                return Err(RegistryPackVerificationError::SignatureInvalid(
                    "wrong test publisher".to_string(),
                ));
            }
            Ok(VerifiedSigner {
                identity: identity.to_string(),
                issuer: trust.issuer.clone(),
            })
        }
        assert!(matches!(
            adopt_with(&request, check_publisher),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
        assert!(matches!(
            adopt_with(
                &PackAdoption {
                    signature_bundle: OFFICIAL_PACK_SIGNING_IDENTITY.as_bytes(),
                    ..request
                },
                check_publisher
            )
            .unwrap(),
            VerifiedRegistryManifest::Application(_)
        ));
    }

    #[test]
    fn strict_dispatch_refuses_unknown_hybrid_duplicate_and_malformed_descriptors() {
        let policy = publisher_policy();
        let reference = "runtime/python@1.2.3".parse().unwrap();
        let good = String::from_utf8(application_bytes()).unwrap();
        let cases = [
            good.replace("\"application\"", "\"unknown\""),
            good.replace("\"schema_version\": 2", "\"schema_version\": 3"),
            good.replacen("\"kind\":", "\"kind\": \"application\", \"kind\":", 1),
            good.replacen("\"description\":", "\"files\": [], \"description\":", 1),
            good.replace("runtime/python@1.2.3", "runtime/python@9.0.0"),
            "not JSON".to_string(),
        ];
        for bytes in cases {
            assert_ne!(bytes, good, "test must change fixture");
            let request = PackAdoption {
                requested: &reference,
                manifest_bytes: bytes.as_bytes(),
                signature_bundle: b"bundle",
                publisher_policy: &policy,
            };
            assert!(adopt_with(&request, accept_signature).is_err(), "{bytes}");
        }
    }

    #[test]
    fn legacy_dispatch_preserves_strict_legacy_validation() {
        let policy = publisher_policy();
        let reference = "runtime/python@1.2.3".parse().unwrap();
        let bytes = crate::registry_pack::tests::signed_manifest_bytes("runtime/python@1.2.3");
        let request = PackAdoption {
            requested: &reference,
            manifest_bytes: &bytes,
            signature_bundle: b"bundle",
            publisher_policy: &policy,
        };
        assert!(matches!(
            adopt_with(&request, accept_signature).unwrap(),
            VerifiedRegistryManifest::Legacy(_)
        ));
    }

    #[test]
    fn application_dispatch_authenticates_before_parsing_and_checks_pins() {
        let policy = publisher_policy();
        let reference = "runtime/python@1.2.3".parse().unwrap();
        let bytes = String::from_utf8(APPLICATION.to_vec())
            .unwrap()
            .replace("test/hello@1.0.0", "runtime/python@1.2.3")
            .into_bytes();
        let request = PackAdoption {
            requested: &reference,
            manifest_bytes: &bytes,
            signature_bundle: b"bundle",
            publisher_policy: &policy,
        };
        assert!(matches!(
            adopt_with(&request, reject_signature),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
        let VerifiedRegistryManifest::Application(app) =
            adopt_with(&request, accept_signature).unwrap()
        else {
            panic!("not an application")
        };
        assert_eq!(app.reference(), &reference);
        assert_eq!(app.manifest_bytes(), bytes);
        assert_eq!(app.manifest_sha256(), &Sha256Hex::from_bytes(&bytes));
        let lock = PackLockfile::new(vec![
            PackPin::new(reference.clone(), Sha256Hex::from_bytes(b"drift")).unwrap(),
        ])
        .unwrap();
        let pinned = RegistryPackVerification::new(&reference, &bytes, b"bundle", &lock, &policy);
        assert!(matches!(
            verify_with(&pinned, accept_signature),
            Err(RegistryPackVerificationError::Lock(_))
        ));
        let lock = PackLockfile::new(vec![
            PackPin::new(reference.clone(), app.manifest_sha256().clone()).unwrap(),
        ])
        .unwrap();
        let pinned = RegistryPackVerification::new(&reference, &bytes, b"bundle", &lock, &policy);
        assert!(matches!(
            verify_with(&pinned, accept_signature).unwrap(),
            VerifiedRegistryManifest::Application(_)
        ));
        let untrusted = RegistryPackPublisherPolicy::new(Vec::new()).unwrap();
        assert!(matches!(
            adopt_with(
                &PackAdoption {
                    publisher_policy: &untrusted,
                    ..request
                },
                accept_signature
            ),
            Err(RegistryPackVerificationError::UntrustedNamespace { .. })
        ));
    }
}
