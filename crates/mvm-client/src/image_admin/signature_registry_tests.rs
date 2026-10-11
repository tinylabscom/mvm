use super::*;
use mvm_fs::oci::test_registry::MemoryRegistry;
use mvm_fs::oci::{ClientConfig, ClientProtocol, OciManifestFetcher, RegistryAuthConfig};
use serde_json::json;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

fn image(registry: &MemoryRegistry) -> ImageReference {
    format!("{}/team/image:latest", registry.host())
        .parse()
        .unwrap()
}

fn fetcher(registry: &MemoryRegistry) -> OciManifestFetcher {
    OciManifestFetcher::with_config_and_auth(
        ClientConfig {
            protocol: ClientProtocol::Http,
        },
        RegistryAuthConfig::bearer(registry.host(), "registry-token"),
    )
}

fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn identity() -> CosignIdentity {
    CosignIdentity {
        certificate_identity: "https://example.test/workflow".to_string(),
        certificate_oidc_issuer: "https://issuer.example.test".to_string(),
    }
}

#[test]
fn referrers_404_falls_back_to_legacy_in_the_same_authenticated_repository() {
    let registry = MemoryRegistry::start();
    registry.require_token("registry-token");
    let image = image(&registry);
    let fetcher = fetcher(&registry);
    let verifier = runtime()
        .block_on(RegistrySignatureVerifier::acquire(
            fetcher.registry_client(),
            &image,
            &digest(),
        ))
        .unwrap();
    assert!(verifier.evidence.is_empty());
    assert!(verifier.failures.is_empty());
    assert!(verifier.acquisition_failures.is_empty());
    let requests = registry.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].path,
        format!("/v2/team/image/referrers/{}", digest())
    );
    assert_eq!(
        requests[1].path,
        format!("/v2/team/image/manifests/sha256-{}.sig", "a".repeat(64))
    );
    assert!(
        requests
            .iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer registry-token"))
    );
    #[cfg(feature = "manifest-verify")]
    assert!(matches!(
        verifier.verify(&verifier.reference, &identity()),
        Err(CosignVerifyError::MissingSignature(_))
    ));
}

#[test]
fn referrers_auth_failure_is_not_missing_or_anonymous_fallback() {
    let registry = MemoryRegistry::start();
    registry.require_token("a-different-token");
    let result = runtime().block_on(RegistrySignatureVerifier::acquire(
        fetcher(&registry).registry_client(),
        &image(&registry),
        &digest(),
    ));
    let verifier = result.expect("acquisition retains authentication refusals");
    assert!(
        verifier
            .acquisition_failures
            .iter()
            .all(|error| error.contains("401"))
    );
    assert_eq!(verifier.acquisition_failures.len(), 2);
    assert_eq!(registry.requests().len(), 2);
    assert!(
        registry
            .requests()
            .iter()
            .all(|request| request.path != "/token")
    );
}

#[test]
fn legacy_forbidden_remains_an_acquisition_failure() {
    let registry = MemoryRegistry::start();
    registry.respond_to_get(
        &format!("/v2/team/image/manifests/sha256-{}.sig", "a".repeat(64)),
        403,
        b"forbidden",
        &[],
    );
    let verifier = runtime()
        .block_on(RegistrySignatureVerifier::acquire(
            fetcher(&registry).registry_client(),
            &image(&registry),
            &digest(),
        ))
        .unwrap();
    assert_eq!(verifier.acquisition_failures.len(), 1);
    #[cfg(feature = "manifest-verify")]
    assert!(matches!(
        verifier.verify(&verifier.reference, &identity()),
        Err(CosignVerifyError::AcquisitionFailed(_))
    ));
}

fn seed_bundle(registry: &MemoryRegistry, target: &str, bytes: &[u8]) -> String {
    let blob = registry.insert_blob(bytes);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "subject": {"digest": target},
        "layers": [{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "digest": blob, "size": bytes.len()
        }]
    }))
    .unwrap();
    let digest = mvm_fs::oci::test_registry::sha256_digest(&manifest);
    registry.insert_manifest("team/image", &digest, MANIFEST_TYPES[0], &manifest);
    digest
}

fn referrer_index(digests: &[String]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "manifests": digests.iter().map(|digest| json!({
            "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "digest": digest,
        })).collect::<Vec<_>>()
    }))
    .unwrap()
}

#[test]
fn acquisition_searches_all_candidates_and_pages_after_a_bad_first_manifest() {
    let registry = MemoryRegistry::start();
    let path = format!("/v2/team/image/referrers/{}", digest());
    let first = seed_bundle(
        &registry,
        &format!("sha256:{}", "b".repeat(64)),
        b"wrong subject",
    );
    let second = seed_bundle(&registry, &digest(), b"second candidate");
    registry.respond_to_get(
        &path,
        200,
        &referrer_index(&[first]),
        &[("Link", &format!("<{path}?last=second>; rel=\"next\""))],
    );
    registry.respond_to_get(
        &format!("{path}?last=second"),
        200,
        &referrer_index(&[second]),
        &[],
    );
    let verifier = runtime()
        .block_on(RegistrySignatureVerifier::acquire(
            fetcher(&registry).registry_client(),
            &image(&registry),
            &digest(),
        ))
        .unwrap();
    assert_eq!(verifier.failures.len(), 1);
    assert_eq!(verifier.evidence.len(), 1);
    assert!(
        matches!(&verifier.evidence[0], Evidence::Bundle(bytes) if bytes == b"second candidate")
    );
}

#[test]
fn acquired_evidence_cannot_be_reused_for_another_requested_repository() {
    let verifier = RegistrySignatureVerifier {
        reference: format!("registry.test/one@{}", digest()),
        digest: digest(),
        evidence: Vec::new(),
        failures: Vec::new(),
        acquisition_failures: Vec::new(),
    };
    assert!(matches!(
        verifier.verify(&format!("registry.test/two@{}", digest()), &identity()),
        Err(CosignVerifyError::InvalidSignature(_))
    ));
}

#[test]
fn legacy_claim_type_and_selected_platform_digest_are_checked_before_crypto() {
    let mut payload = json!({
        "critical": {
            "type": "cosign container image signature",
            "image": {"docker-manifest-digest": digest()},
            "identity": {"docker-reference": "registry.test/an-original-repository"}
        }
    });
    let wrong_digest = format!("sha256:{}", "b".repeat(64));
    let error = verify_evidence(
        &Evidence::Legacy {
            payload: serde_json::to_vec(&payload).unwrap(),
            bundles: vec![b"{}".to_vec()],
        },
        &wrong_digest,
        &identity(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("selected platform digest"),
        "{error}"
    );
    payload["critical"]["type"] = json!(42);
    let error = verify_evidence(
        &Evidence::Legacy {
            payload: serde_json::to_vec(&payload).unwrap(),
            bundles: vec![b"{}".to_vec()],
        },
        &digest(),
        &identity(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("critical type"), "{error}");
}

#[cfg(feature = "manifest-verify")]
mod real {
    use super::*;
    use std::time::Duration;

    const MODERN: &[u8] =
        include_bytes!("../../tests/fixtures/oci-signatures/modern-oci-attestation.sigstore.json");
    const LEGACY_MANIFEST: &[u8] =
        include_bytes!("../../tests/fixtures/oci-signatures/legacy-signature-manifest.json");
    const LEGACY_PAYLOAD: &[u8] =
        include_bytes!("../../tests/fixtures/oci-signatures/legacy-simple-signing-payload.json");
    const LEGACY_REKOR: &[u8] =
        include_bytes!("../../tests/fixtures/oci-signatures/legacy-rekor-entry-with-proof.json");
    const MODERN_DIGEST: &str =
        "sha256:732112270d7e59418a8c080b134b24cabd67d250d0d0147a97ed95ba5c280aa4";
    const LEGACY_DIGEST: &str =
        "sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3";

    fn modern_identity() -> CosignIdentity {
        CosignIdentity {
            certificate_identity: "cody@soyland.com".to_string(),
            certificate_oidc_issuer: "https://github.com/login/oauth".to_string(),
        }
    }

    fn legacy_identity() -> CosignIdentity {
        CosignIdentity {
            certificate_identity: "keyless@distroless.iam.gserviceaccount.com".to_string(),
            certificate_oidc_issuer: "https://accounts.google.com".to_string(),
        }
    }

    fn legacy_manifest_with_proof() -> Value {
        let mut manifest: Value = serde_json::from_slice(LEGACY_MANIFEST).unwrap();
        let entry: Value = serde_json::from_slice(LEGACY_REKOR).unwrap();
        let entry = entry.as_object().unwrap().values().next().unwrap();
        let annotations = &mut manifest["layers"][0]["annotations"];
        let mut bundle: Value =
            serde_json::from_str(annotations["dev.sigstore.cosign/bundle"].as_str().unwrap())
                .unwrap();
        bundle["Payload"]["inclusionProof"] = entry["verification"]["inclusionProof"].clone();
        annotations["dev.sigstore.cosign/bundle"] = json!(bundle.to_string());
        manifest
    }

    fn seed_legacy(registry: &MemoryRegistry, manifest: &Value) {
        registry.insert_blob(LEGACY_PAYLOAD);
        registry.insert_manifest(
            "team/image",
            &format!("sha256-{}.sig", &LEGACY_DIGEST[7..]),
            MANIFEST_TYPES[0],
            &serde_json::to_vec(manifest).unwrap(),
        );
    }

    fn acquire(registry: &MemoryRegistry, digest: &str) -> RegistrySignatureVerifier {
        runtime()
            .block_on(RegistrySignatureVerifier::acquire(
                fetcher(registry).registry_client(),
                &image(registry),
                digest,
            ))
            .unwrap()
    }

    fn advertise_modern(registry: &MemoryRegistry) {
        let descriptor = seed_bundle(registry, MODERN_DIGEST, MODERN);
        registry.respond_to_get(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            200,
            &referrer_index(&[descriptor]),
            &[],
        );
    }

    #[test]
    fn real_canonical_oci_attestation_verifies_through_authenticated_registry() {
        let registry = MemoryRegistry::start();
        registry.require_token("registry-token");
        advertise_modern(&registry);
        let verifier = acquire(&registry, MODERN_DIGEST);
        verifier
            .verify(&verifier.reference, &modern_identity())
            .unwrap();
        assert!(
            registry
                .requests()
                .iter()
                .all(|request| request.authorization.as_deref() == Some("Bearer registry-token"))
        );
        // The real signed subject names a different repository. Cosign binds
        // its digest, not that name; requested-reference evidence is separate.
        assert!(verifier.reference.contains("/team/image@"));
    }

    #[test]
    fn real_legacy_oci_signature_verifies_payload_certificate_and_checkpoint() {
        let registry = MemoryRegistry::start();
        registry.require_token("registry-token");
        seed_legacy(&registry, &legacy_manifest_with_proof());
        let verifier = acquire(&registry, LEGACY_DIGEST);
        verifier
            .verify(&verifier.reference, &legacy_identity())
            .unwrap();
        assert!(
            registry
                .requests()
                .iter()
                .all(|request| request.authorization.as_deref() == Some("Bearer registry-token"))
        );
    }

    #[test]
    fn real_signature_survives_bad_first_candidate_and_bad_first_identity() {
        let registry = MemoryRegistry::start();
        let bad = seed_bundle(&registry, MODERN_DIGEST, b"not a bundle");
        let good = seed_bundle(&registry, MODERN_DIGEST, MODERN);
        registry.respond_to_get(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            200,
            &referrer_index(&[bad, good]),
            &[],
        );
        let verifier = acquire(&registry, MODERN_DIGEST);
        let policy = super::super::super::oci_types::OciRegistryPolicy {
            allowed_registries: vec![registry.host()],
            require_signatures: true,
            cosign: vec![identity(), modern_identity()],
        };
        super::super::super::trust_policy::enforce_oci_trust_policy_with(
            &image(&registry),
            MODERN_DIGEST,
            &policy,
            &verifier,
        )
        .unwrap();
    }

    #[test]
    fn real_canonical_rejects_wrong_digest_identity_issuer_and_transparency() {
        let evidence = Evidence::Bundle(MODERN.to_vec());
        verify_evidence(&evidence, MODERN_DIGEST, &modern_identity()).unwrap();
        verify_evidence(&evidence, LEGACY_DIGEST, &modern_identity()).unwrap_err();
        let mut wrong = modern_identity();
        wrong.certificate_identity = "someone-else@example.test".to_string();
        verify_evidence(&evidence, MODERN_DIGEST, &wrong).unwrap_err();
        wrong = modern_identity();
        wrong.certificate_oidc_issuer = "https://wrong-issuer.example.test".to_string();
        verify_evidence(&evidence, MODERN_DIGEST, &wrong).unwrap_err();
        let mut bundle: Value = serde_json::from_slice(MODERN).unwrap();
        bundle["verificationMaterial"]["tlogEntries"] = json!([]);
        verify_evidence(
            &Evidence::Bundle(serde_json::to_vec(&bundle).unwrap()),
            MODERN_DIGEST,
            &modern_identity(),
        )
        .unwrap_err();
    }

    #[test]
    fn real_canonical_rejects_malformed_missing_and_mismatched_subjects() {
        for subjects in [
            None,
            Some(json!(null)),
            Some(json!([])),
            Some(json!([{"digest":{"sha256":"00".repeat(32)}}])),
        ] {
            let mut bundle: Value = serde_json::from_slice(MODERN).unwrap();
            let payload = STANDARD
                .decode(bundle["dsseEnvelope"]["payload"].as_str().unwrap())
                .unwrap();
            let mut statement: Value = serde_json::from_slice(&payload).unwrap();
            if let Some(subjects) = subjects {
                statement["subject"] = subjects;
            } else {
                statement.as_object_mut().unwrap().remove("subject");
            }
            bundle["dsseEnvelope"]["payload"] =
                json!(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
            verify_evidence(
                &Evidence::Bundle(serde_json::to_vec(&bundle).unwrap()),
                MODERN_DIGEST,
                &modern_identity(),
            )
            .unwrap_err();
        }
    }

    #[test]
    fn real_legacy_rejects_wrong_digest_identity_issuer_and_transparency() {
        let registry = MemoryRegistry::start();
        let mut manifest = legacy_manifest_with_proof();
        seed_legacy(&registry, &manifest);
        let verifier = acquire(&registry, LEGACY_DIGEST);
        let evidence = verifier.evidence.first().expect("legacy evidence");
        verify_evidence(evidence, LEGACY_DIGEST, &legacy_identity()).unwrap();
        verify_evidence(evidence, MODERN_DIGEST, &legacy_identity()).unwrap_err();
        let mut wrong = legacy_identity();
        wrong.certificate_identity = modern_identity().certificate_identity;
        verify_evidence(evidence, LEGACY_DIGEST, &wrong).unwrap_err();
        wrong = legacy_identity();
        wrong.certificate_oidc_issuer = modern_identity().certificate_oidc_issuer;
        verify_evidence(evidence, LEGACY_DIGEST, &wrong).unwrap_err();
        let mut bundle: Value = serde_json::from_str(
            manifest["layers"][0]["annotations"]["dev.sigstore.cosign/bundle"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        bundle["Payload"]["inclusionProof"]["rootHash"] = json!("00".repeat(32));
        manifest["layers"][0]["annotations"]["dev.sigstore.cosign/bundle"] =
            json!(bundle.to_string());
        seed_legacy(&registry, &manifest);
        let verifier = acquire(&registry, LEGACY_DIGEST);
        assert!(matches!(
            verifier.verify(&verifier.reference, &legacy_identity()),
            Err(CosignVerifyError::InvalidSignature(_))
        ));
    }

    #[test]
    fn malformed_referrers_do_not_shadow_a_real_valid_legacy_signature() {
        for body in [b"invalid json".as_slice(), b"{}"] {
            let registry = MemoryRegistry::start();
            seed_legacy(&registry, &legacy_manifest_with_proof());
            registry.respond_to_get(
                &format!("/v2/team/image/referrers/{LEGACY_DIGEST}"),
                200,
                body,
                &[],
            );
            let verifier = acquire(&registry, LEGACY_DIGEST);
            assert!(!verifier.acquisition_failures.is_empty());
            verifier
                .verify(&verifier.reference, &legacy_identity())
                .unwrap();
        }
    }

    #[test]
    fn failed_second_page_preserves_real_first_page_evidence() {
        let registry = MemoryRegistry::start();
        let descriptor = seed_bundle(&registry, MODERN_DIGEST, MODERN);
        let path = format!("/v2/team/image/referrers/{MODERN_DIGEST}");
        registry.respond_to_get(
            &path,
            200,
            &referrer_index(&[descriptor]),
            &[("Link", &format!("<{path}?last=next>; rel=\"next\""))],
        );
        registry.respond_to_get(&format!("{path}?last=next"), 503, b"unavailable", &[]);
        let verifier = acquire(&registry, MODERN_DIGEST);
        assert!(!verifier.acquisition_failures.is_empty());
        verifier
            .verify(&verifier.reference, &modern_identity())
            .unwrap();
    }

    #[test]
    fn malformed_link_does_not_discard_its_real_signed_page() {
        let registry = MemoryRegistry::start();
        let descriptor = seed_bundle(&registry, MODERN_DIGEST, MODERN);
        registry.respond_to_get(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            200,
            &referrer_index(&[descriptor]),
            &[("Link", "not a Link header")],
        );
        let verifier = acquire(&registry, MODERN_DIGEST);
        assert!(!verifier.acquisition_failures.is_empty());
        verifier
            .verify(&verifier.reference, &modern_identity())
            .unwrap();
    }

    #[test]
    fn malformed_discovery_without_valid_evidence_is_acquisition_failure_not_missing() {
        let registry = MemoryRegistry::start();
        registry.respond_to_get(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            200,
            b"not json",
            &[],
        );
        let verifier = acquire(&registry, MODERN_DIGEST);
        assert!(matches!(
            verifier.verify(&verifier.reference, &modern_identity()),
            Err(CosignVerifyError::AcquisitionFailed(_))
        ));
    }

    #[test]
    fn foreign_continuation_never_receives_credentials_or_shadows_valid_evidence() {
        let registry = MemoryRegistry::start();
        let foreign = MemoryRegistry::start();
        let descriptor = seed_bundle(&registry, MODERN_DIGEST, MODERN);
        registry.respond_to_get(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            200,
            &referrer_index(&[descriptor]),
            &[(
                "Link",
                &format!(
                    "<http://{}/v2/team/image/referrers/{MODERN_DIGEST}>; rel=\"next\"",
                    foreign.host()
                ),
            )],
        );
        let verifier = acquire(&registry, MODERN_DIGEST);
        verifier
            .verify(&verifier.reference, &modern_identity())
            .unwrap();
        assert!(foreign.requests().is_empty());
        assert!(!verifier.acquisition_failures.is_empty());
    }

    #[test]
    fn overall_deadline_bounds_slow_drip_and_preserves_real_prior_evidence() {
        let registry = MemoryRegistry::start();
        let descriptor = seed_bundle(&registry, MODERN_DIGEST, MODERN);
        let path = format!("/v2/team/image/referrers/{MODERN_DIGEST}");
        registry.respond_to_get(
            &path,
            200,
            &referrer_index(&[descriptor]),
            &[("Link", &format!("<{path}?last=slow>; rel=\"next\""))],
        );
        registry.respond_to_get_slowly(
            &format!("{path}?last=slow"),
            &[b' '; 1024],
            Duration::from_millis(10),
        );
        let start = std::time::Instant::now();
        let verifier = runtime()
            .block_on(RegistrySignatureVerifier::acquire_with_budget(
                fetcher(&registry).registry_client(),
                &image(&registry),
                MODERN_DIGEST,
                Duration::from_secs(1),
            ))
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(
            verifier
                .acquisition_failures
                .iter()
                .any(|failure| failure.contains("deadline"))
        );
        verifier
            .verify(&verifier.reference, &modern_identity())
            .unwrap();
    }

    #[test]
    fn slow_drip_without_evidence_expires_as_acquisition_failure() {
        let registry = MemoryRegistry::start();
        registry.respond_to_get_slowly(
            &format!("/v2/team/image/referrers/{MODERN_DIGEST}"),
            &[b' '; 1024],
            Duration::from_millis(10),
        );
        let verifier = runtime()
            .block_on(RegistrySignatureVerifier::acquire_with_budget(
                fetcher(&registry).registry_client(),
                &image(&registry),
                MODERN_DIGEST,
                Duration::from_millis(100),
            ))
            .unwrap();
        assert!(matches!(
            verifier.verify(&verifier.reference, &modern_identity()),
            Err(CosignVerifyError::AcquisitionFailed(_))
        ));
        assert_eq!(
            registry.requests().len(),
            1,
            "no requests after the shared deadline"
        );
    }

    #[test]
    fn correct_signature_blob_with_contradictory_digest_header_is_rejected() {
        let registry = MemoryRegistry::start();
        advertise_modern(&registry);
        let blob = mvm_fs::oci::test_registry::sha256_digest(MODERN);
        registry.respond_to_get(
            &format!("/v2/team/image/blobs/{blob}"),
            200,
            MODERN,
            &[("Docker-Content-Digest", LEGACY_DIGEST)],
        );
        let verifier = acquire(&registry, MODERN_DIGEST);
        assert!(verifier.evidence.is_empty());
        assert!(matches!(
            verifier.verify(&verifier.reference, &modern_identity()),
            Err(CosignVerifyError::InvalidSignature(_))
        ));
    }
}
