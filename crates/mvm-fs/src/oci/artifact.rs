//! Push and pull a single-layer artifact through an image registry.
//!
//! An artifact here is one image manifest whose `artifactType` names what it
//! carries, whose config is the empty descriptor, and whose single layer is
//! the payload. That is the shape the image specification recommends for
//! content that is not a container image, so any conforming registry stores
//! it without special support.
//!
//! This module is transport. It proves the bytes it returns are the bytes the
//! manifest names — the manifest against its digest, the layer against its
//! descriptor digest and size, both under size caps — and nothing more. What
//! the payload means, and whether to trust it, is the caller's decision.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oci::OciError;
use crate::oci::layer::{
    LayerDescriptor, LayerFetchOptions, OciLayerFetcher, validate_layer_digest,
};
use crate::oci::manifest::{read_body_capped, verify_manifest_digest};
use crate::oci::reference::ImageReference;
use crate::oci::registry::{ClientConfig, RegistryAuthConfig, RegistryClient};

/// Media type of an image manifest.
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// Media type of the empty descriptor an artifact uses as its config.
pub const OCI_EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// The two bytes the empty descriptor refers to.
const OCI_EMPTY_BLOB: &[u8] = b"{}";

/// An artifact manifest is one descriptor list and a few kilobytes at most.
pub const DEFAULT_MAX_ARTIFACT_MANIFEST_BYTES: u64 = 64 * 1024;

/// Upper bounds on what a pull will buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLimits {
    /// Largest manifest body accepted.
    pub max_manifest_bytes: u64,
    /// Largest layer accepted, checked against the descriptor before the
    /// fetch and against the bytes as they arrive.
    pub max_layer_bytes: u64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: DEFAULT_MAX_ARTIFACT_MANIFEST_BYTES,
            max_layer_bytes: LayerFetchOptions::default().max_size,
        }
    }
}

/// What an artifact is called: the manifest's `artifactType` and the media
/// type of its one layer. Push writes these; pull refuses anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactKind<'a> {
    pub artifact_type: &'a str,
    pub layer_media_type: &'a str,
}

/// The outcome of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedArtifact {
    /// The pushed manifest, pinned by digest with no tag.
    pub reference: ImageReference,
    /// Digest of the manifest bytes that were sent.
    pub manifest_digest: String,
    /// Digest of the layer.
    pub layer_digest: String,
    /// False when the registry already held the layer and it was not sent.
    pub layer_uploaded: bool,
}

/// The outcome of a pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledArtifact {
    /// The pulled manifest, pinned by the digest of the bytes received.
    /// A pull by tag records here which manifest the tag named at the time.
    pub reference: ImageReference,
    /// Digest of the manifest bytes received.
    pub manifest_digest: String,
    /// The layer, already checked against its descriptor.
    pub layer: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactManifest {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
}

/// Registry client for single-layer artifacts.
pub struct OciArtifactClient {
    client: RegistryClient,
    limits: ArtifactLimits,
}

impl OciArtifactClient {
    pub fn new(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self {
            client: RegistryClient::new(config, auth),
            limits: ArtifactLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: ArtifactLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Push `layer` as an artifact of `kind` to `reference`.
    ///
    /// The manifest is stored under the reference's tag, or under its own
    /// digest when the reference has none. A reference that carries a digest
    /// must carry the digest of the manifest being pushed. Blobs the registry
    /// already holds are not sent again.
    pub async fn push(
        &self,
        reference: &ImageReference,
        kind: ArtifactKind<'_>,
        layer: &[u8],
    ) -> Result<PushedArtifact, OciError> {
        let layer_digest = sha256_digest(layer);
        let manifest_bytes = artifact_manifest_bytes(kind, &layer_digest, layer.len() as u64)?;
        let manifest_digest = sha256_digest(&manifest_bytes);
        if let Some(pinned) = &reference.digest {
            if pinned != &manifest_digest {
                return Err(OciError::DigestMismatch {
                    expected: pinned.clone(),
                    computed: manifest_digest,
                });
            }
        }

        self.ensure_blob(reference, &sha256_digest(OCI_EMPTY_BLOB), OCI_EMPTY_BLOB)
            .await?;
        let layer_uploaded = self.ensure_blob(reference, &layer_digest, layer).await?;

        let mut target = reference.clone();
        if target.tag.is_some() {
            target.digest = None;
        } else {
            target.digest = Some(manifest_digest.clone());
        }
        let reported = self
            .client
            .put_manifest(&target, OCI_IMAGE_MANIFEST_MEDIA_TYPE, &manifest_bytes)
            .await?;
        if let Some(reported) = reported {
            if reported != manifest_digest {
                return Err(OciError::DigestMismatch {
                    expected: manifest_digest,
                    computed: reported,
                });
            }
        }

        Ok(PushedArtifact {
            reference: pinned_reference(reference, &manifest_digest),
            manifest_digest,
            layer_digest,
            layer_uploaded,
        })
    }

    /// Pull the artifact of `kind` at `reference` and return its layer.
    ///
    /// Refuses a manifest over the size cap, a manifest whose bytes do not
    /// hash to the pinned or advertised digest, a manifest that is not a
    /// single-layer artifact of `kind`, and a layer over the cap or not
    /// matching its descriptor's digest and size.
    pub async fn pull(
        &self,
        reference: &ImageReference,
        kind: ArtifactKind<'_>,
    ) -> Result<PulledArtifact, OciError> {
        let response = self
            .client
            .get_manifest(reference, &[OCI_IMAGE_MANIFEST_MEDIA_TYPE])
            .await?;
        let manifest_bytes =
            read_body_capped(response.response, self.limits.max_manifest_bytes).await?;
        let manifest_digest = verify_manifest_digest(
            &manifest_bytes,
            reference.digest.as_deref(),
            response.docker_content_digest.as_deref(),
        )?;
        let descriptor = single_layer_of_kind(&manifest_bytes, kind, self.limits)?;

        let fetcher = OciLayerFetcher::from_registry_client(
            self.client.clone(),
            // Capped at the descriptor's size rather than the limit, so a
            // registry cannot stream past what the manifest committed to.
            LayerFetchOptions::builder()
                .max_size(descriptor.size)
                .build(),
        );
        // Grown as bytes arrive rather than reserved from the descriptor, so a
        // manifest cannot make the host commit memory the registry never sends.
        let mut layer = Vec::new();
        let received = fetcher
            .fetch_layer(reference, &descriptor, &mut layer)
            .await?;
        if received != descriptor.size {
            return Err(OciError::Registry(format!(
                "layer {} is {received} bytes but its descriptor says {}",
                descriptor.digest, descriptor.size
            )));
        }

        Ok(PulledArtifact {
            reference: pinned_reference(reference, &manifest_digest),
            manifest_digest,
            layer,
        })
    }

    /// Upload a blob unless the repository already has it. Returns whether
    /// it was uploaded.
    async fn ensure_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
        bytes: &[u8],
    ) -> Result<bool, OciError> {
        if self.client.blob_exists(reference, digest).await? {
            return Ok(false);
        }
        self.client.upload_blob(reference, digest, bytes).await?;
        Ok(true)
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn pinned_reference(reference: &ImageReference, digest: &str) -> ImageReference {
    ImageReference {
        registry: reference.registry.clone(),
        repository: reference.repository.clone(),
        tag: None,
        digest: Some(digest.to_string()),
    }
}

fn artifact_manifest_bytes(
    kind: ArtifactKind<'_>,
    layer_digest: &str,
    layer_size: u64,
) -> Result<Vec<u8>, OciError> {
    let manifest = ArtifactManifest {
        schema_version: 2,
        media_type: Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string()),
        artifact_type: Some(kind.artifact_type.to_string()),
        config: Descriptor {
            media_type: OCI_EMPTY_MEDIA_TYPE.to_string(),
            digest: sha256_digest(OCI_EMPTY_BLOB),
            size: OCI_EMPTY_BLOB.len() as u64,
        },
        layers: vec![Descriptor {
            media_type: kind.layer_media_type.to_string(),
            digest: layer_digest.to_string(),
            size: layer_size,
        }],
        annotations: BTreeMap::new(),
    };
    serde_json::to_vec(&manifest)
        .map_err(|e| OciError::Registry(format!("serialize artifact manifest: {e}")))
}

/// Parse manifest bytes and return the one layer, refusing anything that is
/// not a single-layer artifact of `kind` within the limits.
fn single_layer_of_kind(
    bytes: &[u8],
    kind: ArtifactKind<'_>,
    limits: ArtifactLimits,
) -> Result<LayerDescriptor, OciError> {
    let manifest: ArtifactManifest = serde_json::from_slice(bytes)
        .map_err(|e| OciError::Registry(format!("parse artifact manifest: {e}")))?;
    if manifest.schema_version != 2 {
        return Err(OciError::Registry(format!(
            "artifact manifest has schemaVersion {}, expected 2",
            manifest.schema_version
        )));
    }
    if manifest.media_type.as_deref() != Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE) {
        return Err(OciError::Registry(format!(
            "artifact manifest mediaType is {:?}, expected {OCI_IMAGE_MANIFEST_MEDIA_TYPE}",
            manifest.media_type
        )));
    }
    if manifest.artifact_type.as_deref() != Some(kind.artifact_type) {
        return Err(OciError::Registry(format!(
            "artifactType is {:?}, expected {}",
            manifest.artifact_type, kind.artifact_type
        )));
    }
    let [layer] = manifest.layers.as_slice() else {
        return Err(OciError::Registry(format!(
            "artifact manifest has {} layers, expected exactly 1",
            manifest.layers.len()
        )));
    };
    if layer.media_type != kind.layer_media_type {
        return Err(OciError::Registry(format!(
            "layer mediaType is {}, expected {}",
            layer.media_type, kind.layer_media_type
        )));
    }
    validate_layer_digest(&layer.digest)?;
    if layer.size > limits.max_layer_bytes {
        return Err(OciError::LayerTooLarge {
            declared: layer.size,
            cap: limits.max_layer_bytes,
        });
    }
    Ok(LayerDescriptor {
        digest: layer.digest.clone(),
        size: layer.size,
        media_type: layer.media_type.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::ClientProtocol;
    use crate::oci::test_registry::MemoryRegistry;

    const KIND: ArtifactKind<'static> = ArtifactKind {
        artifact_type: "application/vnd.example.thing.v1",
        layer_media_type: "application/vnd.example.thing.v1.tar",
    };

    fn client() -> OciArtifactClient {
        OciArtifactClient::new(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::Anonymous,
        )
    }

    fn reference(registry: &MemoryRegistry, suffix: &str) -> ImageReference {
        format!("{}/team/thing{suffix}", registry.host())
            .parse()
            .expect("fixture reference parses")
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn push_then_pull_by_tag_and_by_digest_round_trips() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let payload = b"payload bytes".to_vec();

        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, &payload))
            .expect("push");
        assert!(pushed.layer_uploaded);
        assert_eq!(pushed.reference.tag, None);
        assert_eq!(
            pushed.reference.digest.as_deref(),
            Some(pushed.manifest_digest.as_str())
        );

        let by_tag = rt
            .block_on(client().pull(&reference(&registry, ":v1"), KIND))
            .expect("pull by tag");
        assert_eq!(by_tag.layer, payload);
        assert_eq!(by_tag.manifest_digest, pushed.manifest_digest);
        assert_eq!(by_tag.reference, pushed.reference);

        let by_digest = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect("pull by digest");
        assert_eq!(by_digest.layer, payload);
    }

    #[test]
    fn pushed_manifest_is_an_artifact_with_an_empty_config_and_one_layer() {
        let registry = MemoryRegistry::start();
        let pushed = runtime()
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"x"))
            .expect("push");

        let bytes = registry
            .manifest("team/thing", "v1")
            .expect("manifest stored under tag");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["schemaVersion"], 2);
        assert_eq!(json["mediaType"], OCI_IMAGE_MANIFEST_MEDIA_TYPE);
        assert_eq!(json["artifactType"], KIND.artifact_type);
        assert_eq!(json["config"]["mediaType"], OCI_EMPTY_MEDIA_TYPE);
        assert_eq!(json["config"]["size"], 2);
        assert_eq!(json["layers"].as_array().map(Vec::len), Some(1));
        assert_eq!(json["layers"][0]["mediaType"], KIND.layer_media_type);
        assert_eq!(json["layers"][0]["digest"], pushed.layer_digest);
        assert_eq!(
            registry.blob(&sha256_digest(OCI_EMPTY_BLOB)),
            Some(b"{}".to_vec())
        );
    }

    #[test]
    fn a_second_push_of_the_same_layer_skips_the_upload() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        rt.block_on(client().push(&reference(&registry, ":v1"), KIND, b"same"))
            .expect("first push");
        let before = registry.requests().len();

        let again = rt
            .block_on(client().push(&reference(&registry, ":v2"), KIND, b"same"))
            .expect("second push");

        assert!(!again.layer_uploaded);
        let uploads = registry.requests()[before..]
            .iter()
            .filter(|r| r.method == "POST" || r.path.contains("/blobs/uploads/"))
            .count();
        assert_eq!(uploads, 0, "no upload session when both blobs exist");
    }

    #[test]
    fn push_to_a_digest_that_is_not_the_manifest_digest_is_refused_before_upload() {
        let registry = MemoryRegistry::start();
        let wrong = reference(&registry, &format!("@sha256:{}", "0".repeat(64)));

        let err = runtime()
            .block_on(client().push(&wrong, KIND, b"x"))
            .expect_err("mismatched digest must be refused");

        assert!(matches!(err, OciError::DigestMismatch { .. }), "{err}");
        assert!(registry.requests().is_empty());
    }

    #[test]
    fn push_by_digest_stores_the_manifest_under_that_digest() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let probe = rt
            .block_on(client().push(&reference(&registry, ":probe"), KIND, b"d"))
            .expect("probe push");

        let pushed = rt
            .block_on(client().push(&probe.reference, KIND, b"d"))
            .expect("push by digest");

        assert_eq!(pushed.manifest_digest, probe.manifest_digest);
        assert!(
            registry
                .manifest("team/thing", &pushed.manifest_digest)
                .is_some()
        );
    }

    #[test]
    fn push_reuses_a_redeemed_token_and_survives_a_challenge() {
        let registry = MemoryRegistry::start();
        registry.require_token("push-token");

        let pushed = runtime()
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"authed"))
            .expect("push through a bearer challenge");

        let token_fetches = registry
            .requests()
            .iter()
            .filter(|r| r.path == "/token")
            .count();
        assert_eq!(token_fetches, 1, "one challenge, then the token is reused");
        assert!(registry.blob(&pushed.layer_digest).is_some());
    }

    fn authorizations(registry: &MemoryRegistry) -> Vec<String> {
        registry
            .requests()
            .into_iter()
            .filter_map(|r| r.authorization)
            .collect()
    }

    #[test]
    fn a_configured_token_for_one_registry_is_never_sent_to_another() {
        let a = MemoryRegistry::start();
        let b = MemoryRegistry::start();
        a.require_token("token-a");
        let rt = runtime();
        let client = OciArtifactClient::new(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::bearer("token-a"),
        );

        rt.block_on(client.push(&reference(&a, ":v1"), KIND, b"on a"))
            .expect("push to the registry the token is for");
        rt.block_on(client.push(&reference(&b, ":v1"), KIND, b"on b"))
            .expect("push to a second, open registry");

        assert!(authorizations(&a).iter().all(|h| h == "Bearer token-a"));
        assert!(!authorizations(&a).is_empty());
        assert!(
            authorizations(&b).is_empty(),
            "registry B saw credentials: {:?}",
            authorizations(&b)
        );
    }

    #[test]
    fn a_token_issued_by_one_registry_is_never_sent_to_another() {
        let a = MemoryRegistry::start();
        let b = MemoryRegistry::start();
        a.require_token("issued-by-a");
        let rt = runtime();
        let client = client();

        rt.block_on(client.push(&reference(&a, ":v1"), KIND, b"on a"))
            .expect("push through a's challenge");
        rt.block_on(client.push(&reference(&b, ":v1"), KIND, b"on b"))
            .expect("push to b");

        assert!(authorizations(&a).contains(&"Bearer issued-by-a".to_string()));
        assert!(authorizations(&b).is_empty(), "{:?}", authorizations(&b));
    }

    #[test]
    fn a_refused_configured_token_is_reported_not_exchanged() {
        let registry = MemoryRegistry::start();
        registry.require_token("the-right-token");
        let client = OciArtifactClient::new(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::bearer("a-wrong-token"),
        );

        let err = runtime()
            .block_on(client.push(&reference(&registry, ":v1"), KIND, b"x"))
            .expect_err("a refused token must fail the push");

        let message = err.to_string();
        assert!(
            message.contains("refused the configured bearer token"),
            "{message}"
        );
        assert!(
            !registry.requests().iter().any(|r| r.path == "/token"),
            "no anonymous token exchange"
        );
    }

    #[test]
    fn a_blob_redirect_to_another_origin_is_followed_without_credentials() {
        let registry = MemoryRegistry::start();
        let storage = MemoryRegistry::start();
        registry.require_token("pull-token");
        let rt = runtime();
        let client = OciArtifactClient::new(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::bearer("pull-token"),
        );
        let pushed = rt
            .block_on(client.push(&reference(&registry, ":v1"), KIND, b"stored elsewhere"))
            .expect("push");
        let digest = storage.insert_blob(b"stored elsewhere");
        registry.redirect_blob(
            &digest,
            &format!("http://{}/v2/team/thing/blobs/{digest}", storage.host()),
        );

        let pulled = rt
            .block_on(client.pull(&pushed.reference, KIND))
            .expect("pull follows the redirect");

        assert_eq!(pulled.layer, b"stored elsewhere");
        let hops: Vec<_> = storage.requests();
        assert_eq!(hops.len(), 1, "{hops:?}");
        assert_eq!(
            hops[0].authorization, None,
            "no credentials on the redirected hop"
        );
    }

    #[test]
    fn blob_redirects_stop_at_the_cap() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"loop"))
            .expect("push");
        let digest = pushed.layer_digest.clone();
        registry.redirect_blob(
            &digest,
            &format!("http://{}/v2/team/thing/blobs/{digest}", registry.host()),
        );

        let err = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect_err("an endless redirect must stop");

        assert!(err.to_string().contains("5-redirect"), "{err}");
    }

    #[test]
    fn a_layer_over_the_streaming_threshold_round_trips() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let layer: Vec<u8> = (0..3 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();

        let pushed = rt
            .block_on(client().push(&reference(&registry, ":big"), KIND, &layer))
            .expect("streamed push");
        let pulled = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect("pull");

        assert_eq!(pulled.layer, layer);
    }

    #[test]
    fn an_upload_location_on_another_origin_is_refused() {
        let registry = MemoryRegistry::start();
        registry.upload_locations_on("http://127.0.0.2:9");

        let err = runtime()
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"x"))
            .expect_err("cross-origin upload must be refused");

        assert!(err.to_string().contains("another origin"), "{err}");
    }

    #[test]
    fn a_tampered_layer_is_refused() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"genuine"))
            .expect("push");
        registry.serve_blob_as(&pushed.layer_digest, b"swapped");

        let err = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect_err("tampered layer must be refused");

        assert!(matches!(err, OciError::DigestMismatch { .. }), "{err}");
    }

    #[test]
    fn a_tampered_manifest_is_refused_even_when_the_registry_vouches_for_it() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"genuine"))
            .expect("push");
        let original = registry.manifest("team/thing", "v1").expect("stored");
        let tampered = String::from_utf8(original)
            .expect("utf-8")
            .replace(KIND.layer_media_type, "application/vnd.example.other");
        let tampered_digest = sha256_digest(tampered.as_bytes());
        registry.serve_manifest_as("team/thing", &pushed.manifest_digest, tampered.as_bytes());
        registry.advertise_manifest_digest("team/thing", &pushed.manifest_digest, &tampered_digest);

        let err = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect_err("manifest not matching the pinned digest must be refused");

        assert!(
            matches!(&err, OciError::DigestMismatch { computed, .. } if *computed == tampered_digest),
            "{err}"
        );
    }

    #[test]
    fn manifest_bytes_without_a_digest_header_are_still_held_to_the_pinned_digest() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, b"genuine"))
            .expect("push");
        registry.omit_digest_header();
        registry.serve_manifest_as(
            "team/thing",
            &pushed.manifest_digest,
            b"{\"schemaVersion\":2}",
        );

        let err = rt
            .block_on(client().pull(&pushed.reference, KIND))
            .expect_err("bytes not matching the pinned digest must be refused");

        assert!(matches!(err, OciError::DigestMismatch { .. }), "{err}");
    }

    #[test]
    fn manifest_bytes_that_do_not_match_the_advertised_digest_are_refused() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        rt.block_on(client().push(&reference(&registry, ":v1"), KIND, b"genuine"))
            .expect("push");
        registry.advertise_manifest_digest(
            "team/thing",
            "v1",
            &format!("sha256:{}", "1".repeat(64)),
        );

        let err = rt
            .block_on(client().pull(&reference(&registry, ":v1"), KIND))
            .expect_err("advertised digest mismatch must be refused");

        assert!(matches!(err, OciError::DigestMismatch { .. }), "{err}");
    }

    #[test]
    fn a_manifest_of_another_kind_is_refused() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        rt.block_on(client().push(&reference(&registry, ":v1"), KIND, b"x"))
            .expect("push");
        let other = ArtifactKind {
            artifact_type: "application/vnd.example.other.v1",
            ..KIND
        };

        let err = rt
            .block_on(client().pull(&reference(&registry, ":v1"), other))
            .expect_err("wrong artifactType must be refused");

        assert!(err.to_string().contains("artifactType"), "{err}");
    }

    #[test]
    fn an_oversize_manifest_is_refused() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        rt.block_on(client().push(&reference(&registry, ":v1"), KIND, b"x"))
            .expect("push");
        let limits = ArtifactLimits {
            max_manifest_bytes: 32,
            ..ArtifactLimits::default()
        };

        let err = rt
            .block_on(
                client()
                    .with_limits(limits)
                    .pull(&reference(&registry, ":v1"), KIND),
            )
            .expect_err("oversize manifest must be refused");

        assert!(
            matches!(err, OciError::ManifestTooLarge { cap: 32 }),
            "{err}"
        );
    }

    #[test]
    fn an_oversize_layer_is_refused_before_it_is_fetched() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let pushed = rt
            .block_on(client().push(&reference(&registry, ":v1"), KIND, &[7u8; 64]))
            .expect("push");
        let before = registry.requests().len();
        let limits = ArtifactLimits {
            max_layer_bytes: 16,
            ..ArtifactLimits::default()
        };

        let err = rt
            .block_on(client().with_limits(limits).pull(&pushed.reference, KIND))
            .expect_err("oversize layer must be refused");

        assert!(
            matches!(
                err,
                OciError::LayerTooLarge {
                    declared: 64,
                    cap: 16
                }
            ),
            "{err}"
        );
        assert!(
            !registry.requests()[before..]
                .iter()
                .any(|r| r.path.contains("/blobs/")),
            "the layer must not be requested"
        );
    }

    #[test]
    fn a_layer_longer_than_its_descriptor_is_refused_at_the_descriptor_size() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let layer_digest = registry.insert_blob(b"twelve bytes");
        let manifest = artifact_manifest_bytes(KIND, &layer_digest, 4).expect("manifest");
        registry.insert_manifest("team/thing", "v1", OCI_IMAGE_MANIFEST_MEDIA_TYPE, &manifest);

        let err = rt
            .block_on(client().pull(&reference(&registry, ":v1"), KIND))
            .expect_err("a layer past its descriptor size must be refused");

        assert!(
            matches!(err, OciError::LayerTooLarge { cap: 4, .. }),
            "{err}"
        );
    }

    #[test]
    fn a_layer_shorter_than_its_descriptor_is_refused() {
        let registry = MemoryRegistry::start();
        let rt = runtime();
        let layer_digest = registry.insert_blob(b"twelve bytes");
        let manifest = artifact_manifest_bytes(KIND, &layer_digest, 100).expect("manifest");
        registry.insert_manifest("team/thing", "v1", OCI_IMAGE_MANIFEST_MEDIA_TYPE, &manifest);

        let err = rt
            .block_on(client().pull(&reference(&registry, ":v1"), KIND))
            .expect_err("a layer short of its descriptor size must be refused");

        assert!(err.to_string().contains("descriptor says 100"), "{err}");
    }
}
