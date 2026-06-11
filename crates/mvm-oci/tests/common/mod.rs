//! Hermetic OCI registry fixture for integration tests.
//!
//! Spawns a wiremock-backed HTTP server on a random localhost
//! port that speaks just enough of the OCI distribution spec to
//! exercise [`mvm_oci::OciManifestFetcher`] and
//! [`mvm_oci::OciLayerFetcher`] end-to-end:
//!
//! - `GET /v2/` — registry ping (returns 200 + the
//!   `Docker-Distribution-API-Version: registry/2.0` header).
//! - `GET /v2/<repo>/manifests/<reference>` — returns the
//!   pre-registered manifest bytes for a (repository, reference)
//!   pair, with the right `Docker-Content-Digest` header.
//! - `GET /v2/<repo>/blobs/<digest>` — returns the
//!   pre-registered blob bytes for a digest.
//!
//! The fixture is *not* a complete OCI registry. It does the
//! happy path plus a couple of error injections (5xx-then-200 for
//! retry tests, content tamper for digest-mismatch tests). Auth,
//! manifest upload, and the full v2 catalog API are out of scope —
//! the fixture is anonymous-pull-only.

#![allow(dead_code)] // not every helper is used by every test

use mvm_oci::{ClientConfig, ClientProtocol, ImageReference};
use oci_client::client::Client as OciClient;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

/// A running hermetic registry. Drop the value to tear it down.
pub struct HermeticRegistry {
    pub server: MockServer,
}

impl HermeticRegistry {
    /// Spin up a fresh wiremock server on a random localhost port
    /// and register the `/v2/` ping handler.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Docker-Distribution-API-Version", "registry/2.0"),
            )
            .mount(&server)
            .await;
        Self { server }
    }

    /// `host:port` form, suitable for use as the registry portion
    /// of an `ImageReference`.
    pub fn host(&self) -> String {
        // `MockServer::address()` is `127.0.0.1:NNNN`.
        self.server.address().to_string()
    }

    /// An `ImageReference` whose registry points at this fixture
    /// and whose repository / reference are caller-supplied.
    pub fn image_ref(&self, repository: &str, tag: &str) -> ImageReference {
        format!("{}/{repository}:{tag}", self.host())
            .parse()
            .expect("fixture-built reference parses")
    }

    /// An `ImageReference` pinned to the given digest (no tag).
    pub fn image_ref_by_digest(&self, repository: &str, digest: &str) -> ImageReference {
        format!("{}/{repository}@{digest}", self.host())
            .parse()
            .expect("fixture-built digest reference parses")
    }

    /// Serve `bytes` at `/v2/<repository>/manifests/<reference>`
    /// with the right Content-Type and Docker-Content-Digest
    /// headers. Returns the canonical digest of the bytes.
    pub async fn register_manifest(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let path = format!("/v2/{repository}/manifests/{reference}");
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(path))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", media_type)
                    .insert_header("Docker-Content-Digest", digest.as_str())
                    .set_body_bytes(bytes.to_vec()),
            )
            .mount(&self.server)
            .await;
        digest
    }

    /// Same as [`Self::register_manifest`], also exposes the
    /// manifest under its digest at
    /// `/v2/<repository>/manifests/<digest>` (digest-pin
    /// requests).
    pub async fn register_manifest_with_digest_path(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> String {
        let digest = self
            .register_manifest(repository, reference, media_type, bytes)
            .await;
        // also register the by-digest path
        let digest_path = format!("/v2/{repository}/manifests/{digest}");
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(digest_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", media_type)
                    .insert_header("Docker-Content-Digest", digest.as_str())
                    .set_body_bytes(bytes.to_vec()),
            )
            .mount(&self.server)
            .await;
        digest
    }

    /// Serve a manifest only when the request includes the given
    /// bearer token. Also registers the digest path with the same
    /// auth requirement.
    pub async fn register_bearer_manifest_with_digest_path(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
        token: &str,
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        for manifest_ref in [reference, digest.as_str()] {
            let path = format!("/v2/{repository}/manifests/{manifest_ref}");
            Mock::given(method("GET"))
                .and(wiremock::matchers::path(path))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", media_type)
                        .insert_header("Docker-Content-Digest", digest.as_str())
                        .set_body_bytes(bytes.to_vec()),
                )
                .mount(&self.server)
                .await;
        }
        digest
    }

    /// Serve `bytes` at `/v2/<repository>/blobs/<sha256-digest>`.
    /// Returns the digest the bytes hash to (caller can compare
    /// against the manifest's layer descriptor).
    pub async fn register_blob(&self, repository: &str, media_type: &str, bytes: &[u8]) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let path = format!("/v2/{repository}/blobs/{digest}");
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(path))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", media_type)
                    .set_body_bytes(bytes.to_vec()),
            )
            .mount(&self.server)
            .await;
        digest
    }

    /// Serve a blob only when the request includes the given bearer
    /// token.
    pub async fn register_bearer_blob(
        &self,
        repository: &str,
        media_type: &str,
        bytes: &[u8],
        token: &str,
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let path = format!("/v2/{repository}/blobs/{digest}");
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(path))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", media_type)
                    .set_body_bytes(bytes.to_vec()),
            )
            .mount(&self.server)
            .await;
        digest
    }

    /// Serve a *tampered* blob: the path is the legitimate digest
    /// (so the caller's request reaches us) but the response body
    /// is different bytes (so digest verification fails).
    pub async fn register_tampered_blob(
        &self,
        repository: &str,
        claimed_digest: &str,
        actual_bytes: &[u8],
    ) {
        let path = format!("/v2/{repository}/blobs/{claimed_digest}");
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(path))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(actual_bytes.to_vec()),
            )
            .mount(&self.server)
            .await;
    }

    /// Serve a blob that fails `n` times with 503, then succeeds
    /// on attempt `n+1`. Used to exercise the bounded-retry path.
    pub async fn register_flaky_blob(
        &self,
        repository: &str,
        bytes: &[u8],
        fail_first: u32,
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let path = format!("/v2/{repository}/blobs/{digest}");
        let responder = FlakyResponder {
            calls: Arc::new(AtomicU32::new(0)),
            fail_first,
            success_body: bytes.to_vec(),
            success_content_type: "application/octet-stream".to_string(),
        };
        Mock::given(method("GET"))
            .and(wiremock::matchers::path(path))
            .respond_with(responder)
            .mount(&self.server)
            .await;
        digest
    }
}

/// Build an `oci_client::Client` configured to talk plaintext HTTP
/// to the fixture's localhost address. Production callers use
/// `ClientProtocol::Https`; tests need `HttpsExcept` listing the
/// fixture's `host:port` so the same `OciManifestFetcher` /
/// `OciLayerFetcher` code path is exercised against both.
pub fn client_for(registry: &HermeticRegistry) -> OciClient {
    OciClient::new(ClientConfig {
        protocol: ClientProtocol::HttpsExcept(vec![registry.host()]),
        ..ClientConfig::default()
    })
}

/// Builds a minimal OCI image manifest JSON pointing at one layer.
/// The layer's bytes determine the layer descriptor's digest +
/// size. Returns `(manifest_bytes, layer_digest)`.
pub fn minimal_image_manifest(layer_bytes: &[u8], media_type: &str) -> (Vec<u8>, String) {
    let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(layer_bytes)));
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 0
        },
        "layers": [{
            "mediaType": media_type,
            "digest": layer_digest.as_str(),
            "size": layer_bytes.len()
        }]
    });
    (
        serde_json::to_vec(&manifest).expect("manifest serializes"),
        layer_digest,
    )
}

/// Custom responder that fails the first `fail_first` calls with
/// 503 then serves a success body. We track call count via
/// `AtomicU32` because `Respond::respond` takes `&self`.
struct FlakyResponder {
    calls: Arc<AtomicU32>,
    fail_first: u32,
    success_body: Vec<u8>,
    success_content_type: String,
}

impl Respond for FlakyResponder {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
        if attempt < self.fail_first {
            ResponseTemplate::new(503)
                .insert_header("Content-Type", "text/plain")
                .set_body_string("Service Unavailable")
        } else {
            ResponseTemplate::new(200)
                .insert_header("Content-Type", self.success_content_type.as_str())
                .set_body_bytes(self.success_body.clone())
        }
    }
}

/// Unused-but-exposed so the warnings don't fire on shared
/// helpers that not every test exercises.
#[allow(unused_imports)]
pub use wiremock::matchers as wm_matchers;

// Silence dead-code warnings on the helper structs / fields when
// only a subset of tests is built.
#[allow(dead_code)]
fn _silence_unused() {
    let _: HashMap<String, String> = HashMap::new();
    let _ = path_regex(".*");
}
