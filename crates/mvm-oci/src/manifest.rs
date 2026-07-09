//! Manifest fetch + content-digest verification.
//!
//! The [`ManifestFetcher`] trait is the contract that downstream
//! code consumes; [`OciManifestFetcher`] is the real implementation
//! over the crate's internal registry client. Splitting the trait from the impl lets test
//! code substitute a fixture without standing up a registry — the
//! hermetic in-process registry fixture in `tests/common.rs`
//! exercises [`OciManifestFetcher`] directly via a tiny localhost
//! HTTP server.
//!
//! Digest verification is always content-addressable: the SHA-256
//! over the manifest bytes is compared against the digest the caller
//! pinned (or the digest the registry advertised). A mismatch is a
//! hard error; we never paper over it with a warning.

use crate::OciError;
use crate::layer::LayerDescriptor;
use crate::manifest_types::OciManifest;
use crate::reference::ImageReference;
use crate::registry::{ClientConfig, RegistryAuthConfig, RegistryClient};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// Result of a manifest fetch. Bytes are kept verbatim because
/// digest verification is byte-exact — any normalization
/// (whitespace, key ordering) would change the digest and break the
/// pin.
#[derive(Debug, Clone)]
pub struct FetchedManifest {
    /// The reference the manifest was fetched against, after
    /// canonicalization.
    pub reference: ImageReference,
    /// SHA-256 digest as `sha256:<lowercase-hex>`. Always verified
    /// against the bytes before this struct is constructed.
    pub digest: String,
    /// Raw manifest bytes as received from the registry.
    pub bytes: Vec<u8>,
    /// `Content-Type` the registry advertised
    /// (e.g. `application/vnd.oci.image.manifest.v1+json`).
    /// Carried so the caller can distinguish OCI from Docker v2
    /// schemas without reparsing.
    pub media_type: String,
}

/// Linux platform selector for OCI image indexes / Docker manifest
/// lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPlatform {
    /// OCI architecture string (`amd64`, `arm64`, ...).
    pub architecture: String,
    /// Optional architecture variant (`v8` for linux/arm64/v8).
    pub variant: Option<String>,
}

impl LinuxPlatform {
    /// Platform matching the current host CPU while explicitly
    /// targeting Linux guests.
    pub fn for_current_arch() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self {
                architecture: "arm64".to_string(),
                variant: Some("v8".to_string()),
            }
        } else if cfg!(target_arch = "x86_64") {
            Self {
                architecture: "amd64".to_string(),
                variant: None,
            }
        } else {
            Self {
                architecture: std::env::consts::ARCH.to_string(),
                variant: None,
            }
        }
    }
}

impl FetchedManifest {
    /// Parse the manifest bytes and extract the layer descriptors
    /// in order. For an image manifest (single platform) this
    /// returns the layers verbatim; for an image index (multi-arch
    /// manifest list) this returns an error because platform
    /// selection is the caller's responsibility (handled alongside
    /// `--platform` support).
    pub fn layers(&self) -> Result<Vec<LayerDescriptor>, OciError> {
        let manifest: OciManifest = serde_json::from_slice(&self.bytes)
            .map_err(|e| OciError::Registry(format!("parse manifest: {e}")))?;
        match manifest {
            OciManifest::Image(img) => Ok(img
                .layers
                .into_iter()
                .map(|l| LayerDescriptor {
                    digest: l.digest,
                    size: l.size as u64,
                    media_type: l.media_type,
                })
                .collect()),
            OciManifest::ImageIndex(_) => Err(OciError::Registry(
                "manifest is an image index — platform selection not yet implemented \
                 (lands in a later W1 PR)"
                    .to_string(),
            )),
        }
    }
}

/// Contract for "fetch the manifest of this image and verify its
/// digest." Returns the raw bytes; parsing into typed layer
/// descriptors is the caller's responsibility.
#[async_trait]
pub trait ManifestFetcher: Send + Sync {
    async fn fetch(&self, reference: &ImageReference) -> Result<FetchedManifest, OciError>;
}

/// Real fetcher backed by the crate's internal registry client.
pub struct OciManifestFetcher {
    client: RegistryClient,
}

impl Default for OciManifestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl OciManifestFetcher {
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// Construct a fetcher with a custom `ClientConfig`. Used by
    /// tests to point at a hermetic localhost registry with
    /// `protocol: ClientProtocol::HttpsExcept(vec![local_addr])`,
    /// and by future production callers that need to thread proxy
    /// or timeout settings through.
    pub fn with_config(config: ClientConfig) -> Self {
        Self {
            client: RegistryClient::new(config, RegistryAuthConfig::Anonymous),
        }
    }

    pub fn with_auth(auth: RegistryAuthConfig) -> Self {
        Self::with_config_and_auth(ClientConfig::default(), auth)
    }

    pub fn with_config_and_auth(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self {
            client: RegistryClient::new(config, auth),
        }
    }

    /// Construct from a pre-built `reqwest::Client`. Useful when tests
    /// point the fetcher at a hermetic localhost registry without
    /// rebuilding the underlying transport.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client: RegistryClient::with_http_client(
                client,
                ClientConfig::default(),
                RegistryAuthConfig::Anonymous,
            ),
        }
    }

    pub fn with_client_and_auth(client: reqwest::Client, auth: RegistryAuthConfig) -> Self {
        Self {
            client: RegistryClient::with_http_client(client, ClientConfig::default(), auth),
        }
    }

    pub(crate) fn client(&self) -> &RegistryClient {
        &self.client
    }

    /// Fetch a platform-specific Linux image manifest.
    ///
    /// If `reference` resolves directly to an image manifest, this
    /// returns it unchanged. If it resolves to an image index, this
    /// follows one descriptor matching `platform` and fetches that
    /// manifest by digest, preserving byte-exact digest verification
    /// for the returned bytes.
    pub async fn fetch_linux_platform_manifest(
        &self,
        reference: &ImageReference,
        platform: &LinuxPlatform,
    ) -> Result<FetchedManifest, OciError> {
        let fetched = self.fetch(reference).await?;
        let manifest: OciManifest = serde_json::from_slice(&fetched.bytes)
            .map_err(|e| OciError::Registry(format!("parse manifest: {e}")))?;
        let OciManifest::ImageIndex(index) = manifest else {
            return Ok(fetched);
        };

        let descriptor = index
            .manifests
            .iter()
            .find(|entry| {
                entry.platform.as_ref().is_some_and(|p| {
                    p.os == "linux"
                        && p.architecture == platform.architecture
                        && p.variant.as_deref() == platform.variant.as_deref()
                })
            })
            .ok_or_else(|| {
                let wanted = match &platform.variant {
                    Some(v) => format!("linux/{}/{}", platform.architecture, v),
                    None => format!("linux/{}", platform.architecture),
                };
                OciError::Registry(format!("image index has no manifest for {wanted}"))
            })?;

        let mut by_digest = reference.clone();
        by_digest.tag = None;
        by_digest.digest = Some(descriptor.digest.clone());
        self.fetch(&by_digest).await
    }
}

/// The OCI media types we accept on a manifest fetch. Listed in
/// the `Accept` header sent to the registry; the registry picks
/// one and serves the matching manifest variant. Image manifest,
/// Docker v2 (which most registries still serve by default), and
/// the multi-arch index (which we surface as an error from
/// [`FetchedManifest::layers`] until platform selection lands).
const ACCEPTED_MANIFEST_MEDIA: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

#[async_trait]
impl ManifestFetcher for OciManifestFetcher {
    async fn fetch(&self, reference: &ImageReference) -> Result<FetchedManifest, OciError> {
        let response = self
            .client
            .get_manifest(reference, ACCEPTED_MANIFEST_MEDIA)
            .await?;
        let bytes = response
            .response
            .bytes()
            .await
            .map_err(|e| OciError::Registry(format!("read manifest response body: {e}")))?;
        let computed = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if let Some(advertised_digest) = response.docker_content_digest {
            if computed != advertised_digest {
                return Err(OciError::DigestMismatch {
                    expected: advertised_digest,
                    computed,
                });
            }
        }
        if let Some(pinned) = &reference.digest {
            if pinned != &computed {
                return Err(OciError::DigestMismatch {
                    expected: pinned.clone(),
                    computed,
                });
            }
        }

        // Parse the bytes once more to classify the media type
        // for the caller's downstream branching (image vs index).
        // This parse is purely diagnostic; the *digest* check
        // above is the load-bearing one.
        let manifest: OciManifest = serde_json::from_slice(&bytes).map_err(|e| {
            OciError::Registry(format!(
                "parse manifest after digest verify: {e}; content_type={:?}; bytes={}",
                response.content_type,
                bytes.len()
            ))
        })?;
        let media_type = response
            .content_type
            .unwrap_or_else(|| manifest_media_type(&manifest).to_string());

        Ok(FetchedManifest {
            reference: reference.clone(),
            digest: computed,
            bytes: bytes.to_vec(),
            media_type,
        })
    }
}

fn manifest_media_type(manifest: &OciManifest) -> &'static str {
    match manifest {
        OciManifest::Image(_) => "application/vnd.oci.image.manifest.v1+json",
        OciManifest::ImageIndex(_) => "application/vnd.oci.image.index.v1+json",
    }
}

/// Verify that `bytes` hashes to `expected` (a `sha256:<hex>`
/// string). Used by callers that already have manifest bytes in
/// hand (e.g. from a cache) and want to assert content integrity
/// without going through the full fetcher.
///
/// Always fails closed. Returns [`OciError::DigestMismatch`] on
/// content drift, [`OciError::MalformedDigest`] if `expected` does
/// not match `sha256:<64 lowercase hex chars>`,
/// [`OciError::UnsupportedDigestAlgorithm`] for non-sha256 inputs.
pub fn verify_sha256_digest(bytes: &[u8], expected: &str) -> Result<(), OciError> {
    let (alg, hex_part) = expected.split_once(':').ok_or_else(|| {
        OciError::MalformedDigest(format!("missing algorithm prefix: {expected:?}"))
    })?;
    if alg != "sha256" {
        return Err(OciError::UnsupportedDigestAlgorithm(alg.to_string()));
    }
    if hex_part.len() != 64 {
        return Err(OciError::MalformedDigest(format!(
            "sha256 digest must be 64 hex chars, got {} in {expected:?}",
            hex_part.len()
        )));
    }
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OciError::MalformedDigest(format!(
            "digest hex must be lowercase ascii: {expected:?}"
        )));
    }

    let computed = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if computed != expected {
        return Err(OciError::DigestMismatch {
            expected: expected.to_string(),
            computed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_BYTES: &[u8] = b"hello mvm";
    // sha256("hello mvm") — kept as a constant so the test for
    // `known_digest_constant_is_self_consistent` flags any
    // accidental edit. Recompute via:
    //   printf 'hello mvm' | shasum -a 256
    const KNOWN_DIGEST: &str =
        "sha256:790aa64759a490e14bb0197b875b2d41d7ecea8d73fedcaea7eb88b6d59b691d";

    fn computed_digest(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn verify_digest_accepts_matching_content() {
        let digest = computed_digest(KNOWN_BYTES);
        verify_sha256_digest(KNOWN_BYTES, &digest).expect("matching content must verify");
    }

    #[test]
    fn verify_digest_rejects_tampered_content() {
        let digest = computed_digest(KNOWN_BYTES);
        let tampered: Vec<u8> = KNOWN_BYTES
            .iter()
            .copied()
            .chain(std::iter::once(b'!'))
            .collect();
        let err = verify_sha256_digest(&tampered, &digest).unwrap_err();
        match err {
            OciError::DigestMismatch { .. } => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_digest_rejects_unsupported_algorithm() {
        let err = verify_sha256_digest(KNOWN_BYTES, "sha512:abc").unwrap_err();
        match err {
            OciError::UnsupportedDigestAlgorithm(alg) => assert_eq!(alg, "sha512"),
            other => panic!("expected UnsupportedDigestAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn verify_digest_rejects_missing_algorithm_prefix() {
        let err = verify_sha256_digest(KNOWN_BYTES, "abc").unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn verify_digest_rejects_wrong_hex_length() {
        let err = verify_sha256_digest(KNOWN_BYTES, "sha256:abc").unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn verify_digest_rejects_uppercase_hex() {
        // 64 uppercase hex chars — wrong-case rather than wrong-length.
        let upper = format!("sha256:{}", "A".repeat(64));
        let err = verify_sha256_digest(KNOWN_BYTES, &upper).unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn known_digest_constant_is_self_consistent() {
        // Guard against future edits to KNOWN_DIGEST breaking the
        // other tests silently. If this fires, recompute the
        // constant via:
        //   echo -n "hello mvm" | shasum -a 256
        let computed = computed_digest(KNOWN_BYTES);
        assert_eq!(computed, KNOWN_DIGEST);
    }
}
