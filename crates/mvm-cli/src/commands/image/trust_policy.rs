//! Production OCI trust policy: registry allowlisting, mandatory cosign
//! signature verification, and the on-disk policy file the two enforce
//! against. This is the conformance-claim surface — moved byte-identical.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mvm_fs::oci::ImageReference;

use super::oci_types::{CachedOciImage, OciRegistryPolicy, OciTrustDecision};
use super::trust::CosignVerifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OciVerificationReceipt {
    schema_version: u32,
    verification_reference: String,
    resolved_digest: String,
    policy_fingerprint: String,
    verification_status: String,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct OciVerificationReceiptPayload<'a> {
    schema_version: u32,
    verification_reference: &'a str,
    resolved_digest: &'a str,
    policy_fingerprint: &'a str,
    verification_status: &'a str,
}

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

pub(super) fn write_verification_receipt(
    cache_root: &Path,
    image_ref: &ImageReference,
    resolved_digest: &str,
    policy: &OciRegistryPolicy,
    trust: &OciTrustDecision,
) -> Result<String> {
    let verification_reference = cosign_verification_reference(image_ref, resolved_digest);
    let policy_fingerprint = policy_fingerprint(policy)?;
    let payload = OciVerificationReceiptPayload {
        schema_version: 1,
        verification_reference: &verification_reference,
        resolved_digest,
        policy_fingerprint: &policy_fingerprint,
        verification_status: &trust.verification_status,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("serialize OCI verification receipt payload")?;
    let signer = crate::commands::vm::host_signer::load_or_init()
        .context("load host signing key for OCI verification receipt")?;
    let receipt = OciVerificationReceipt {
        schema_version: payload.schema_version,
        verification_reference,
        resolved_digest: resolved_digest.to_string(),
        policy_fingerprint,
        verification_status: trust.verification_status.clone(),
        signature: signer.signing.sign(&payload_bytes).to_bytes().to_vec(),
    };
    let digest_hex = resolved_digest
        .strip_prefix("sha256:")
        .context("OCI verification receipt requires a sha256 digest")?;
    let receipt_key = hex::encode(Sha256::digest(&payload_bytes));
    let relative = format!("trust/{digest_hex}-{receipt_key}.verification.json");
    super::cache::write_cache_file(
        cache_root,
        &relative,
        &serde_json::to_vec_pretty(&receipt).context("serialize OCI verification receipt")?,
    )?;
    Ok(relative)
}

pub(super) fn trust_decision_from_verification_receipt(
    cache_root: &Path,
    image_ref: &ImageReference,
    image: &CachedOciImage,
) -> Result<OciTrustDecision> {
    let policy = load_oci_registry_policy()?;
    enforce_registry_allowlist(image_ref, &policy)?;
    ensure_signature_policy_is_configured(&policy)?;
    let relative = image.verification_receipt_path.as_deref().with_context(|| {
        format!(
            "cached OCI image {} has no production verification receipt; run `mvmctl image pull {}` first",
            image.reference, image.reference
        )
    })?;
    let receipt_path = super::cache::safe_cache_path(cache_root, relative)?;
    let bytes = fs::read(&receipt_path).with_context(|| {
        format!(
            "cached OCI image {} has invalid production verification evidence at {}; run `mvmctl image pull {}` first",
            image.reference,
            receipt_path.display(),
            image.reference
        )
    })?;
    let receipt: OciVerificationReceipt =
        serde_json::from_slice(&bytes).context("parse OCI verification receipt")?;
    let public_key_path = crate::commands::vm::host_signer::default_keys_dir()?
        .join(crate::commands::vm::host_signer::PUBLIC_FILENAME);
    let public_key_bytes = fs::read(&public_key_path).with_context(|| {
        format!(
            "read host public key for OCI verification receipt {}",
            public_key_path.display()
        )
    })?;
    let public_key: [u8; crate::commands::vm::host_signer::KEY_BYTES] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("host public key must contain exactly 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .context("parse host public key for OCI verification receipt")?;
    verify_verification_receipt(
        &receipt,
        image_ref,
        &image.resolved_digest,
        &image.reference,
        &policy,
        &verifying_key,
    )
}

fn verify_verification_receipt(
    receipt: &OciVerificationReceipt,
    image_ref: &ImageReference,
    resolved_digest: &str,
    cached_reference: &str,
    policy: &OciRegistryPolicy,
    verifying_key: &VerifyingKey,
) -> Result<OciTrustDecision> {
    let expected_reference = cosign_verification_reference(image_ref, resolved_digest);
    let expected_policy = policy_fingerprint(policy)?;
    anyhow::ensure!(
        receipt.schema_version == 1
            && receipt.verification_reference == expected_reference
            && receipt.resolved_digest == resolved_digest
            && receipt.policy_fingerprint == expected_policy,
        "cached OCI production verification receipt is stale or mismatched; run `mvmctl image pull {cached_reference}` first"
    );
    let payload = OciVerificationReceiptPayload {
        schema_version: receipt.schema_version,
        verification_reference: &receipt.verification_reference,
        resolved_digest: &receipt.resolved_digest,
        policy_fingerprint: &receipt.policy_fingerprint,
        verification_status: &receipt.verification_status,
    };
    let signature = Signature::from_slice(&receipt.signature)
        .context("invalid OCI verification receipt signature")?;
    verifying_key
        .verify_strict(
            &serde_json::to_vec(&payload)
                .context("serialize OCI verification receipt payload")?,
            &signature,
        )
        .with_context(|| {
            format!(
                "cached OCI production verification receipt signature is invalid; run `mvmctl image pull {cached_reference}` first"
            )
        })?;
    Ok(OciTrustDecision {
        trust_policy: "prod-cosign-required".to_string(),
        verification_status: receipt.verification_status.clone(),
    })
}

fn policy_fingerprint(policy: &OciRegistryPolicy) -> Result<String> {
    let bytes = serde_json::to_vec(policy).context("serialize OCI registry policy")?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
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
    let (path, text) = read_oci_registry_policy()?;
    parse_oci_registry_policy(&text)
        .with_context(|| format!("parsing OCI registry policy {}", path.display()))
}

/// Load the policy for its registry allowlist alone, without requiring the
/// signature section: a caller whose artifacts carry their own signatures
/// (signed bundles) has no use for cosign identities, but is bound by the same
/// list of registries.
pub(super) fn load_oci_registry_allowlist() -> Result<OciRegistryPolicy> {
    let (path, text) = read_oci_registry_policy()?;
    let policy: OciRegistryPolicy = toml::from_str(&text)
        .with_context(|| format!("parsing OCI registry policy {}", path.display()))?;
    validate_oci_registry_policy_entries(&policy)
        .with_context(|| format!("parsing OCI registry policy {}", path.display()))?;
    Ok(policy)
}

fn read_oci_registry_policy() -> Result<(PathBuf, String)> {
    let path = match std::env::var_os("MVM_OCI_POLICY") {
        Some(path) => PathBuf::from(path),
        None => mvm_core::config::oci_policy_path(),
    };
    if !path.exists() {
        bail!(
            "--prod requires an OCI registry policy at {} \
             (or set MVM_OCI_POLICY to a policy file)",
            path.display()
        );
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading OCI registry policy {}", path.display()))?;
    Ok((path, text))
}

pub(super) fn parse_oci_registry_policy(text: &str) -> Result<OciRegistryPolicy> {
    let policy: OciRegistryPolicy = toml::from_str(text)?;
    validate_oci_registry_policy(&policy)?;
    Ok(policy)
}

pub(super) fn validate_oci_registry_policy(policy: &OciRegistryPolicy) -> Result<()> {
    ensure_signature_policy_is_configured(policy)?;
    validate_oci_registry_policy_entries(policy)
}

/// Shape checks on the entries a policy lists, independent of whether the
/// signature section is required.
fn validate_oci_registry_policy_entries(policy: &OciRegistryPolicy) -> Result<()> {
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
    fn authenticated_receipt_binds_digest_policy_and_signature_offline() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let verification_reference = cosign_verification_reference(&image_ref, digest);
        let fingerprint = policy_fingerprint(&policy).unwrap();
        let status = "cosign-verified identity=test issuer=test";
        let payload = OciVerificationReceiptPayload {
            schema_version: 1,
            verification_reference: &verification_reference,
            resolved_digest: digest,
            policy_fingerprint: &fingerprint,
            verification_status: status,
        };
        let signature = signing
            .sign(&serde_json::to_vec(&payload).unwrap())
            .to_bytes()
            .to_vec();
        let receipt = OciVerificationReceipt {
            schema_version: 1,
            verification_reference,
            resolved_digest: digest.to_string(),
            policy_fingerprint: fingerprint,
            verification_status: status.to_string(),
            signature,
        };

        verify_verification_receipt(
            &receipt,
            &image_ref,
            digest,
            "alpine",
            &policy,
            &signing.verifying_key(),
        )
        .expect("matching receipt verifies without cosign");

        let mut wrong_digest = receipt.clone();
        wrong_digest.resolved_digest = format!("sha256:{}", "b".repeat(64));
        assert!(
            verify_verification_receipt(
                &wrong_digest,
                &image_ref,
                digest,
                "alpine",
                &policy,
                &signing.verifying_key(),
            )
            .is_err()
        );

        let mut wrong_policy = policy.clone();
        wrong_policy
            .allowed_registries
            .push("registry.example".into());
        assert!(
            verify_verification_receipt(
                &receipt,
                &image_ref,
                digest,
                "alpine",
                &wrong_policy,
                &signing.verifying_key(),
            )
            .is_err()
        );

        let mut bad_signature = receipt;
        bad_signature.signature[0] ^= 1;
        assert!(
            verify_verification_receipt(
                &bad_signature,
                &image_ref,
                digest,
                "alpine",
                &policy,
                &signing.verifying_key(),
            )
            .is_err()
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
