//! Manifest fetch + content-digest verification.
//!
//! The [`ManifestFetcher`] trait is the contract that downstream
//! code consumes; [`OciManifestFetcher`] is the real implementation
//! over `oci-client`. Splitting the trait from the impl lets test
//! code substitute a fixture without standing up a registry — the
//! hermetic in-process registry fixture in `tests/common.rs`
//! exercises [`OciManifestFetcher`] directly via a wiremock-backed
//! HTTP server on a random localhost port.
//!
//! Digest verification is always content-addressable: the SHA-256
//! over the manifest bytes is compared against the digest the caller
//! pinned (or the digest the registry advertised). A mismatch is a
//! hard error; we never paper over it with a warning.

use crate::OciError;
use crate::layer::LayerDescriptor;
use crate::reference::ImageReference;
use async_trait::async_trait;
use oci_client::client::Client;
pub use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::OciManifest;
use oci_client::secrets::RegistryAuth;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

/// Explicit registry authentication material for OCI pulls.
///
/// This deliberately does not read Docker credential helpers or
/// `~/.docker/config.json`. Callers pass the credential source they
/// trust, and this crate only forwards it to the OCI Distribution
/// client for the current process.
#[derive(Clone, Default)]
pub enum RegistryAuthConfig {
    #[default]
    Anonymous,
    Bearer {
        token: SecretString,
    },
    Basic {
        username: String,
        password: SecretString,
    },
}

impl std::fmt::Debug for RegistryAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => f.write_str("RegistryAuthConfig::Anonymous"),
            Self::Bearer { .. } => f.write_str("RegistryAuthConfig::Bearer { token: REDACTED }"),
            Self::Basic { username, .. } => f
                .debug_struct("RegistryAuthConfig::Basic")
                .field("username", username)
                .field("password", &"REDACTED")
                .finish(),
        }
    }
}

impl RegistryAuthConfig {
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: SecretString::from(token.into()),
        }
    }

    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            username: username.into(),
            password: SecretString::from(password.into()),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
        }
    }

    pub fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    pub(crate) fn to_registry_auth(&self) -> RegistryAuth {
        match self {
            Self::Anonymous => RegistryAuth::Anonymous,
            Self::Bearer { token } => RegistryAuth::Bearer(token.expose_secret().to_string()),
            Self::Basic { username, password } => {
                RegistryAuth::Basic(username.clone(), password.expose_secret().to_string())
            }
        }
    }
}

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

/// Real fetcher backed by [`oci_client`]. Private-registry auth
/// flows the credential material through [`secrecy::SecretString`]
/// and the `check-no-display-on-secret-types` lint.
pub struct OciManifestFetcher {
    client: Client,
    auth: RegistryAuthConfig,
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
    /// tests to point at a wiremock server with
    /// `protocol: ClientProtocol::HttpsExcept(vec![local_addr])`,
    /// and by future production callers that need to thread proxy
    /// or timeout settings through. The supplied config is passed
    /// to `oci_client::Client::new` verbatim — no normalization.
    pub fn with_config(config: ClientConfig) -> Self {
        Self {
            client: Client::new(config),
            auth: RegistryAuthConfig::Anonymous,
        }
    }

    pub fn with_auth(auth: RegistryAuthConfig) -> Self {
        Self::with_config_and_auth(ClientConfig::default(), auth)
    }

    pub fn with_config_and_auth(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self {
            client: Client::new(config),
            auth,
        }
    }

    /// Construct from a pre-built `oci_client::Client`. Useful when
    /// a manifest fetcher and a layer fetcher share one client to
    /// pool connections.
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            auth: RegistryAuthConfig::Anonymous,
        }
    }

    pub fn with_client_and_auth(client: Client, auth: RegistryAuthConfig) -> Self {
        Self { client, auth }
    }

    /// Borrow the underlying client. Layer fetcher consumes this
    /// so the two share a connection pool.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    pub(crate) fn auth(&self) -> &RegistryAuthConfig {
        &self.auth
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
                    p.os.to_string() == "linux"
                        && p.architecture.to_string() == platform.architecture
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
        // Convert mvm's structured reference into the shape
        // `oci_client` consumes. Canonical form is round-tripped
        // through the upstream parser — round-trip failure here
        // would indicate our `canonical()` and oci-client disagree
        // about the same string, which is a bug we want to surface
        // immediately rather than paper over.
        let canonical = reference.canonical();
        let upstream_ref: oci_client::Reference = canonical
            .parse()
            .map_err(|e| OciError::InvalidReference(format!("{canonical}: {e}")))?;

        // Fetch the *raw* wire bytes, not the parsed-then-
        // re-serialized form. JSON re-serialization is not
        // byte-stable (key ordering, whitespace, escape choices),
        // so hashing the re-serialized form mis-computes the
        // digest against what the registry advertised. The
        // content digest is a property of the *wire* bytes;
        // anything else is a bug.
        let auth = self.auth.to_registry_auth();
        let (bytes, advertised_digest) = self
            .client
            .pull_manifest_raw(&upstream_ref, &auth, ACCEPTED_MANIFEST_MEDIA)
            .await
            .map_err(|e| OciError::Registry(e.to_string()))?;

        let computed = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if computed != advertised_digest {
            return Err(OciError::DigestMismatch {
                expected: advertised_digest,
                computed,
            });
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
        let manifest: OciManifest = serde_json::from_slice(&bytes)
            .map_err(|e| OciError::Registry(format!("parse manifest after digest verify: {e}")))?;
        let media_type = manifest_media_type(&manifest).to_string();

        Ok(FetchedManifest {
            reference: reference.clone(),
            digest: computed,
            // `pull_manifest_raw` hands back `bytes::Bytes`; the
            // public `FetchedManifest::bytes` field is `Vec<u8>`
            // so callers don't have to depend on the `bytes`
            // crate. The `.to_vec()` is one copy, which is fine
            // for manifest-sized payloads (single-digit KB).
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
