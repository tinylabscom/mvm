//! Registry acquisition is confined to explicit preparation. The returned
//! evidence verifier is offline, including for each allowed signer identity.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use mvm_fs::oci::{ImageReference, RegistryClient, RegistryResponse, verify_sha256_digest};
use serde_json::Value;

use super::oci_types::CosignIdentity;
use super::trust::{CosignVerifier, CosignVerifyError};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const MAX_CANDIDATES: usize = 1024;
const MANIFEST_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

enum Evidence {
    Bundle(Vec<u8>),
    Legacy {
        payload: Vec<u8>,
        bundles: Vec<Vec<u8>>,
    },
}

impl Evidence {
    fn byte_len(&self) -> usize {
        match self {
            Self::Bundle(bytes) => bytes.len(),
            Self::Legacy { payload, bundles } => payload
                .len()
                .saturating_add(bundles.iter().map(Vec::len).sum()),
        }
    }
}

pub(super) struct RegistrySignatureVerifier {
    reference: String,
    digest: String,
    evidence: Vec<Evidence>,
    failures: Vec<String>,
    acquisition_failures: Vec<String>,
}

impl RegistrySignatureVerifier {
    pub(super) async fn acquire(
        client: &RegistryClient,
        image: &ImageReference,
        digest: &str,
    ) -> Result<Self> {
        Self::acquire_with_budget(client, image, digest, std::time::Duration::from_secs(120)).await
    }

    async fn acquire_with_budget(
        client: &RegistryClient,
        image: &ImageReference,
        digest: &str,
        budget: std::time::Duration,
    ) -> Result<Self> {
        super::cache::sha256_hex(digest)?;
        let mut verifier = Self {
            reference: super::trust_policy::cosign_verification_reference(image, digest),
            digest: digest.to_string(),
            evidence: Vec::new(),
            failures: Vec::new(),
            acquisition_failures: Vec::new(),
        };
        let deadline = tokio::time::Instant::now() + budget;
        match tokio::time::timeout_at(deadline, verifier.acquire_referrers(client, image, digest))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => verifier
                .acquisition_failures
                .push(format!("referrers discovery: {error:#}")),
            Err(_) => verifier.acquisition_failures.push(
                "overall signature acquisition deadline exceeded during referrers discovery"
                    .to_string(),
            ),
        }
        let mut legacy = image.clone();
        legacy.digest = None;
        legacy.tag = Some(format!("sha256-{}.sig", super::cache::sha256_hex(digest)?));
        if tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(
                deadline,
                verifier.acquire_manifest(client, &legacy, true),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => verifier.record_failure(error),
                Err(_) => verifier.acquisition_failures.push(
                    "overall signature acquisition deadline exceeded during legacy discovery"
                        .to_string(),
                ),
            }
        } else {
            verifier.acquisition_failures.push(
                "overall signature acquisition deadline exhausted before legacy discovery"
                    .to_string(),
            );
        }
        Ok(verifier)
    }

    async fn acquire_referrers(
        &mut self,
        client: &RegistryClient,
        image: &ImageReference,
        digest: &str,
    ) -> Result<()> {
        let mut next = None;
        let mut seen = std::collections::HashSet::new();
        for page in 0..32 {
            let Some(response) = client.get_referrers(image, digest, next.as_deref()).await? else {
                break;
            };
            let continuation = next_page(&response);
            let index: Value = serde_json::from_slice(&read_body(response.response).await?)?;
            let manifests = index["manifests"]
                .as_array()
                .context("referrers response has no manifests")?;
            for descriptor in manifests {
                let kind = descriptor["artifactType"].as_str().unwrap_or_default();
                if !kind.starts_with("application/vnd.dev.sigstore.bundle") {
                    continue;
                }
                let Some(candidate_digest) = descriptor["digest"].as_str() else {
                    self.failures
                        .push("referrer is missing its digest".to_string());
                    continue;
                };
                if !seen.insert(candidate_digest.to_string()) {
                    continue;
                }
                ensure!(seen.len() <= MAX_CANDIDATES, "too many signature referrers");
                let mut reference = image.clone();
                reference.tag = None;
                reference.digest = Some(candidate_digest.to_string());
                if let Err(error) = self.acquire_manifest(client, &reference, false).await {
                    self.record_failure(error);
                }
            }
            next = continuation?;
            if next.is_none() {
                break;
            }
            ensure!(page < 31, "too many referrers pages");
        }
        Ok(())
    }

    fn record_failure(&mut self, error: anyhow::Error) {
        if matches!(
            error.downcast_ref::<mvm_fs::oci::OciError>(),
            Some(mvm_fs::oci::OciError::Registry(_))
        ) || error.downcast_ref::<mvm_http::Error>().is_some()
            || matches!(
                error.downcast_ref::<CosignVerifyError>(),
                Some(CosignVerifyError::AcquisitionFailed(_))
            )
        {
            self.acquisition_failures.push(format!("{error:#}"));
        } else {
            self.failures.push(format!("{error:#}"));
        }
    }

    async fn acquire_manifest(
        &mut self,
        client: &RegistryClient,
        reference: &ImageReference,
        legacy: bool,
    ) -> Result<()> {
        if let Some(digest) = &reference.digest {
            super::cache::sha256_hex(digest)?;
        }
        let Some(response) = client
            .get_optional_manifest(reference, MANIFEST_TYPES)
            .await?
        else {
            if !legacy {
                bail!("advertised signature manifest is missing");
            }
            return Ok(());
        };
        let advertised = response.docker_content_digest.clone();
        let bytes = read_body(response.response).await?;
        if let Some(digest) = &reference.digest {
            verify_sha256_digest(&bytes, digest)?;
        }
        if let Some(digest) = advertised {
            verify_sha256_digest(&bytes, &digest)?;
        }
        let manifest: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest["schemaVersion"] == 2,
            "invalid signature manifest schema"
        );
        if !legacy {
            ensure!(
                manifest["subject"]["digest"].as_str() == Some(self.digest.as_str()),
                "signature referrer subject does not match selected platform digest"
            );
        }
        let layers = manifest["layers"]
            .as_array()
            .context("signature manifest has no layers")?;
        ensure!(layers.len() <= MAX_CANDIDATES, "too many signature layers");
        for layer in layers {
            let media = layer["mediaType"].as_str().unwrap_or_default();
            if legacy && media != "application/vnd.dev.cosign.simplesigning.v1+json" {
                continue;
            }
            if !legacy && !media.starts_with("application/vnd.dev.sigstore.bundle") {
                continue;
            }
            match acquire_layer(client, reference, layer, legacy).await {
                Ok(evidence) => {
                    let retained: usize = self.evidence.iter().map(Evidence::byte_len).sum();
                    ensure!(
                        retained.saturating_add(evidence.byte_len()) <= MAX_RETAINED_BYTES,
                        "signature evidence exceeds total size limit"
                    );
                    self.evidence.push(evidence);
                }
                Err(error) => self.record_failure(error),
            }
            ensure!(
                self.evidence.len() + self.failures.len() + self.acquisition_failures.len()
                    <= MAX_CANDIDATES,
                "too many signature candidates"
            );
        }
        Ok(())
    }
}

async fn acquire_layer(
    client: &RegistryClient,
    reference: &ImageReference,
    layer: &Value,
    legacy: bool,
) -> Result<Evidence> {
    let digest = layer["digest"]
        .as_str()
        .context("signature layer has no digest")?;
    super::cache::sha256_hex(digest)?;
    let size = layer["size"]
        .as_u64()
        .context("signature layer has no size")?;
    ensure!(
        size <= MAX_BYTES as u64,
        "signature layer exceeds size limit"
    );
    let response = client.get_blob(reference, digest).await?;
    let advertised_digest = response.docker_content_digest;
    let bytes = read_body(response.response).await?;
    ensure!(bytes.len() as u64 == size, "signature layer size mismatch");
    verify_sha256_digest(&bytes, digest)?;
    if let Some(advertised_digest) = advertised_digest {
        verify_sha256_digest(&bytes, &advertised_digest)?;
    }
    if legacy {
        let bundles = super::signature_legacy::bundles(&bytes, &layer["annotations"]).await?;
        Ok(Evidence::Legacy {
            payload: bytes,
            bundles,
        })
    } else {
        Ok(Evidence::Bundle(bytes))
    }
}

impl CosignVerifier for RegistrySignatureVerifier {
    fn verify(&self, reference: &str, identity: &CosignIdentity) -> Result<(), CosignVerifyError> {
        if reference != self.reference {
            return Err(CosignVerifyError::InvalidSignature(
                "signature evidence belongs to another image reference".to_string(),
            ));
        }
        if !mvm_core::crypto::image_verify::keyless_verifier_available() {
            return Err(CosignVerifyError::ToolUnavailable(
                "this build has no in-process keyless verifier".to_string(),
            ));
        }
        let mut failures = self.failures.clone();
        for evidence in &self.evidence {
            match verify_evidence(evidence, &self.digest, identity) {
                Ok(()) => return Ok(()),
                Err(error) => failures.push(format!("{error:#}")),
            }
        }
        if !self.acquisition_failures.is_empty() {
            Err(CosignVerifyError::AcquisitionFailed(
                self.acquisition_failures.join("; "),
            ))
        } else if failures.is_empty() {
            Err(CosignVerifyError::MissingSignature(self.reference.clone()))
        } else {
            Err(CosignVerifyError::InvalidSignature(failures.join("; ")))
        }
    }
}

fn verify_evidence(evidence: &Evidence, digest: &str, identity: &CosignIdentity) -> Result<()> {
    use mvm_core::crypto::image_verify::{verify_signed_payload, verify_signed_sha256};
    match evidence {
        Evidence::Bundle(bundle) => {
            let parsed: Value = serde_json::from_slice(bundle)?;
            let envelope = &parsed["dsseEnvelope"];
            ensure!(
                envelope["payloadType"] == "application/vnd.in-toto+json",
                "OCI signature bundle must contain an in-toto signature statement"
            );
            let payload = STANDARD.decode(
                envelope["payload"]
                    .as_str()
                    .context("missing DSSE payload")?,
            )?;
            let statement: Value = serde_json::from_slice(&payload)?;
            ensure!(
                matches!(
                    statement["_type"].as_str(),
                    Some("https://in-toto.io/Statement/v0.1" | "https://in-toto.io/Statement/v1")
                ),
                "OCI bundle is not an in-toto statement"
            );
            verify_signed_sha256(
                &super::cache::sha256_hex(digest)?,
                bundle,
                &identity.certificate_identity,
                &identity.certificate_oidc_issuer,
            )?;
        }
        Evidence::Legacy { payload, bundles } => {
            // Cosign's claim verifier binds the digest, not the claimed
            // repository or critical.type value. The requested repository is
            // instead constrained by registry policy, transport credentials,
            // and the host-authenticated preparation receipt.
            let claim: Value = serde_json::from_slice(payload)?;
            if let Some(kind) = claim["critical"].get("type") {
                ensure!(
                    kind.is_null() || kind.is_string(),
                    "invalid simple-signing critical type"
                );
            }
            ensure!(
                claim["critical"]["image"]["docker-manifest-digest"].as_str() == Some(digest),
                "simple-signing digest does not match selected platform digest"
            );
            let mut failures = Vec::new();
            for bundle in bundles {
                match verify_signed_payload(
                    payload,
                    bundle,
                    &identity.certificate_identity,
                    &identity.certificate_oidc_issuer,
                ) {
                    Ok(()) => return Ok(()),
                    Err(error) => failures.push(error.to_string()),
                }
            }
            bail!("no legacy log candidate verified: {}", failures.join("; "));
        }
    }
    Ok(())
}

pub(super) async fn read_body(mut response: mvm_http::Response) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_BYTES,
            "signature metadata exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn next_page(response: &RegistryResponse) -> Result<Option<String>> {
    let Some(link) = response.response.headers().get("link") else {
        return Ok(None);
    };
    let link = link.to_str().context("invalid referrers Link header")?;
    for part in link.split(',') {
        let (target, parameters) = part
            .trim()
            .split_once('>')
            .context("invalid referrers Link")?;
        if parameters
            .split(';')
            .any(|p| matches!(p.trim(), "rel=\"next\"" | "rel=next"))
        {
            return Ok(Some(
                target
                    .strip_prefix('<')
                    .context("invalid referrers Link target")?
                    .to_string(),
            ));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "signature_registry_tests.rs"]
mod tests;
