//! Production OCI trust policy: registry allowlisting, mandatory cosign
//! signature verification, and the on-disk policy file the two enforce
//! against. This is the conformance-claim surface — moved byte-identical.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use mvm_fs::oci::ImageReference;

use super::oci_types::{CachedOciImage, OciRegistryPolicy, OciTrustDecision};
use super::trust::CosignVerifier;

pub(super) fn trust_decision_for_cached_image(
    image_ref: &ImageReference,
    image: &CachedOciImage,
    prod: bool,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    enforce_oci_trust_policy(image_ref, &image.resolved_digest, prod, verifier)
}

pub(super) fn enforce_oci_trust_policy(
    image_ref: &ImageReference,
    resolved_digest: &str,
    prod: bool,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    if !prod {
        return Ok(OciTrustDecision::dev_digest_only(image_ref));
    }
    let policy = load_oci_registry_policy()?;
    enforce_oci_trust_policy_with(image_ref, resolved_digest, &policy, verifier)
}

pub(super) fn enforce_oci_trust_policy_with(
    image_ref: &ImageReference,
    resolved_digest: &str,
    policy: &OciRegistryPolicy,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    enforce_registry_allowlist(image_ref, policy)?;
    ensure_signature_policy_is_configured(policy)?;
    let verification_ref = cosign_verification_reference(image_ref, resolved_digest);
    let mut failures = Vec::new();
    for identity in &policy.cosign {
        match verifier.verify(&verification_ref, identity) {
            Ok(()) => return Ok(OciTrustDecision::cosign_verified(identity)),
            Err(err) => failures.push(err.to_string()),
        }
    }
    bail!(
        "cosign verification failed for {} under production OCI policy: {}",
        verification_ref,
        failures.join("; ")
    );
}

pub(super) fn enforce_registry_allowlist(
    image_ref: &ImageReference,
    policy: &OciRegistryPolicy,
) -> Result<()> {
    if !policy.allowed_registries.is_empty()
        && !policy
            .allowed_registries
            .iter()
            .any(|registry| registry == &image_ref.registry)
    {
        bail!(
            "OCI registry '{}' is denied by production policy",
            image_ref.registry
        );
    }
    Ok(())
}

pub(super) fn ensure_signature_policy_is_configured(policy: &OciRegistryPolicy) -> Result<()> {
    if !policy.require_signatures {
        bail!("production OCI policy cannot disable cosign signatures");
    }
    if policy.cosign.is_empty() {
        bail!("production OCI policy requires signatures but has no [[cosign]] trusted identity");
    }
    Ok(())
}

pub(super) fn cosign_verification_reference(
    image_ref: &ImageReference,
    resolved_digest: &str,
) -> String {
    format!(
        "{}/{}@{}",
        image_ref.registry, image_ref.repository, resolved_digest
    )
}

pub(super) fn load_oci_registry_policy() -> Result<OciRegistryPolicy> {
    let path = match std::env::var_os("MVM_OCI_POLICY") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(mvm_core::config::mvm_home()).join("oci-policy.toml"),
    };
    if !path.exists() {
        bail!(
            "mvmctl image --prod requires an OCI registry policy at {} \
             (or set MVM_OCI_POLICY to a policy file)",
            path.display()
        );
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading OCI registry policy {}", path.display()))?;
    parse_oci_registry_policy(&text)
        .with_context(|| format!("parsing OCI registry policy {}", path.display()))
}

pub(super) fn parse_oci_registry_policy(text: &str) -> Result<OciRegistryPolicy> {
    let policy: OciRegistryPolicy = toml::from_str(text)?;
    validate_oci_registry_policy(&policy)?;
    Ok(policy)
}

pub(super) fn validate_oci_registry_policy(policy: &OciRegistryPolicy) -> Result<()> {
    ensure_signature_policy_is_configured(policy)?;
    for registry in &policy.allowed_registries {
        if registry.is_empty()
            || registry.contains("://")
            || registry.contains('/')
            || registry.chars().any(char::is_whitespace)
        {
            bail!("invalid OCI policy registry host {registry:?}");
        }
    }
    for identity in &policy.cosign {
        if identity.certificate_identity.is_empty()
            || identity.certificate_oidc_issuer.is_empty()
            || identity.certificate_identity.chars().any(char::is_control)
            || identity
                .certificate_oidc_issuer
                .chars()
                .any(char::is_control)
        {
            bail!("invalid empty or control-character cosign identity in OCI policy");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use super::super::oci_types::CosignIdentity;
    use super::super::trust::{CosignVerifier, CosignVerifyError};

    struct MockCosignVerifier {
        results: RefCell<Vec<Result<(), CosignVerifyError>>>,
    }

    impl MockCosignVerifier {
        fn new(results: Vec<Result<(), CosignVerifyError>>) -> Self {
            Self {
                results: RefCell::new(results),
            }
        }
    }

    impl CosignVerifier for MockCosignVerifier {
        fn verify(
            &self,
            _reference: &str,
            _identity: &CosignIdentity,
        ) -> Result<(), CosignVerifyError> {
            self.results.borrow_mut().remove(0)
        }
    }

    fn policy_text() -> &'static str {
        r#"
allowed_registries = ["docker.io", "ghcr.io"]
require_signatures = true

[[cosign]]
certificate_identity = "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.14.0"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
"#
    }

    #[test]
    fn oci_policy_parses_registry_allowlist_and_cosign_identity() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");

        assert_eq!(policy.allowed_registries, vec!["docker.io", "ghcr.io"]);
        assert!(policy.require_signatures);
        assert_eq!(policy.cosign.len(), 1);
        assert_eq!(
            policy.cosign[0].certificate_oidc_issuer,
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn production_policy_accepts_valid_cosign_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Ok(())]);

        let trust = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect("valid signature accepted");

        assert_eq!(trust.trust_policy, "prod-cosign-required");
        assert!(trust.verification_status.contains("cosign-verified"));
    }

    #[test]
    fn production_policy_rejects_missing_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Err(CosignVerifyError::MissingSignature(
            "no matching signatures".to_string(),
        ))]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("missing signature rejected");

        assert!(err.to_string().contains("missing signature"));
    }

    #[test]
    fn production_policy_rejects_invalid_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Err(CosignVerifyError::InvalidSignature(
            "certificate identity mismatch".to_string(),
        ))]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("invalid signature rejected");

        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn production_policy_rejects_denied_registry_before_cosign() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "quay.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Ok(())]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("registry denial rejected");

        assert!(err.to_string().contains("denied by production policy"));
        assert!(verifier.results.borrow().len() == 1, "cosign must not run");
    }

    #[test]
    fn production_policy_requires_trusted_identity_when_signatures_required() {
        let err = parse_oci_registry_policy("allowed_registries = [\"docker.io\"]\n")
            .expect_err("missing identity rejected");

        assert!(err.to_string().contains("no [[cosign]] trusted identity"));
    }

    #[test]
    fn production_policy_rejects_signature_opt_out() {
        let err = parse_oci_registry_policy(
            r#"
allowed_registries = ["docker.io"]
require_signatures = false
"#,
        )
        .expect_err("prod policy cannot opt out of signatures");

        assert!(
            err.to_string().contains("cannot disable cosign signatures"),
            "unexpected error: {err}"
        );
    }
}
