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

use crate::oci::OciError;
use crate::oci::layer::LayerDescriptor;
use crate::oci::manifest_types::OciManifest;
use crate::oci::reference::ImageReference;
use crate::oci::registry::{ClientConfig, RegistryAuthConfig, RegistryClient};
use async_trait::async_trait;
use mvm_contract::oci::{LinuxPlatform, matches_linux_platform};
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

/// Platform matching the current host CPU while explicitly targeting Linux
/// guests.
///
/// A free function rather than an inherent method: `LinuxPlatform` lives in
/// `mvm-contract` so a browser can select a platform, and "what architecture
/// is this host" is a question only a host can answer.
pub fn current_linux_platform() -> LinuxPlatform {
    if cfg!(target_arch = "aarch64") {
        LinuxPlatform {
            architecture: "arm64".to_string(),
            variant: Some("v8".to_string()),
        }
    } else if cfg!(target_arch = "x86_64") {
        LinuxPlatform {
            architecture: "amd64".to_string(),
            variant: None,
        }
    } else {
        LinuxPlatform {
            architecture: std::env::consts::ARCH.to_string(),
            variant: None,
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
                entry
                    .platform
                    .as_ref()
                    .is_some_and(|p| matches_linux_platform(p, platform))
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

/// Hard cap on a manifest body, enforced before the bytes are buffered.
///
/// An OCI image manifest is a few kilobytes and a multi-arch index is still
/// well under a megabyte; 4 MiB is generous by three orders of magnitude and
/// still small enough that a hostile registry cannot use it to exhaust the
/// host. The bound has to be here rather than after the read because the
/// integrity check operates on bytes we have already committed memory to.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// A body accumulator that refuses to grow past `cap`.
///
/// Split out from the network call so the bound itself is unit-testable
/// without standing up a registry: the interesting behaviour is the arithmetic
/// on the running total, not the transport.
struct CappedBody {
    cap: u64,
    buf: Vec<u8>,
}

impl CappedBody {
    fn new(cap: u64) -> Self {
        Self {
            cap,
            buf: Vec::new(),
        }
    }

    /// Admit one chunk, or refuse if it would carry the total past the cap.
    /// The check is on the sum rather than the chunk so a body delivered as
    /// many small chunks is bounded the same as one delivered whole.
    fn push(&mut self, chunk: &[u8]) -> Result<(), OciError> {
        let total = self.buf.len() as u64 + chunk.len() as u64;
        if total > self.cap {
            return Err(OciError::ManifestTooLarge { cap: self.cap });
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// Reject a body whose declared length already exceeds the cap.
///
/// `Content-Length` is only a hint — absent under chunked transfer encoding,
/// and understated at will by a registry that means us harm — so this is an
/// optimisation, not the enforcement. [`CappedBody`] is the enforcement.
fn declared_length_within_cap(declared: Option<u64>, cap: u64) -> Result<(), OciError> {
    match declared {
        Some(n) if n > cap => Err(OciError::ManifestTooLarge { cap }),
        _ => Ok(()),
    }
}

/// Read a response body, refusing to buffer more than `cap` bytes.
async fn read_body_capped(mut response: reqwest::Response, cap: u64) -> Result<Vec<u8>, OciError> {
    declared_length_within_cap(response.content_length(), cap)?;
    let mut body = CappedBody::new(cap);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| OciError::Registry(format!("read manifest response body: {e}")))?
    {
        body.push(&chunk)?;
    }
    Ok(body.into_inner())
}

#[async_trait]
impl ManifestFetcher for OciManifestFetcher {
    async fn fetch(&self, reference: &ImageReference) -> Result<FetchedManifest, OciError> {
        let response = self
            .client
            .get_manifest(reference, ACCEPTED_MANIFEST_MEDIA)
            .await?;
        let bytes = read_body_capped(response.response, MAX_MANIFEST_BYTES).await?;
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
