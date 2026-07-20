//! Hermetic OCI registry fixture for integration tests.
//!
//! Spawns a tiny in-repo HTTP server on a random localhost port
//! that speaks just enough of the OCI distribution spec to
//! exercise [`mvm_fs::oci::OciManifestFetcher`] and
//! [`mvm_fs::oci::OciLayerFetcher`] end-to-end:
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
//! the fixture is anonymous-pull-only unless a test registers a
//! bearer-protected route explicitly.

mod http_fixture;

use base64::Engine as _;
use http_fixture::{FlakyResponder, Responder, Route, TestHttpServer, TestResponse};
use mvm_fs::oci::{ClientConfig, ClientProtocol, ImageReference};
use sha2::{Digest, Sha256};

/// A running hermetic registry. Drop the value to tear it down.
pub struct HermeticRegistry {
    server: TestHttpServer,
}

pub struct BearerChallengeFixture {
    issued_token: String,
    basic_auth: Option<BasicAuthFixture>,
    realm_path: String,
    scope: String,
    service: String,
}

impl BearerChallengeFixture {
    pub fn builder(repository: &str) -> BearerChallengeFixtureBuilder {
        BearerChallengeFixtureBuilder {
            basic_auth: None,
            issued_token: None,
            realm_path: "/token".to_string(),
            scope: format!("repository:{repository}:pull"),
            service: "test-registry".to_string(),
        }
    }
}

pub struct BearerChallengeFixtureBuilder {
    basic_auth: Option<BasicAuthFixture>,
    issued_token: Option<String>,
    realm_path: String,
    scope: String,
    service: String,
}

impl BearerChallengeFixtureBuilder {
    pub fn issued_token(mut self, token: impl Into<String>) -> Self {
        self.issued_token = Some(token.into());
        self
    }

    pub fn basic_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.basic_auth = Some(BasicAuthFixture {
            password: password.into(),
            username: username.into(),
        });
        self
    }

    pub fn build(self) -> BearerChallengeFixture {
        BearerChallengeFixture {
            issued_token: self
                .issued_token
                .expect("bearer challenge fixture must define an issued token"),
            basic_auth: self.basic_auth,
            realm_path: self.realm_path,
            scope: self.scope,
            service: self.service,
        }
    }
}

struct BasicAuthFixture {
    password: String,
    username: String,
}

impl HermeticRegistry {
    /// Spin up a fresh localhost registry fixture and register the
    /// `/v2/` ping handler.
    pub async fn start() -> Self {
        let server = TestHttpServer::start().await;
        server.register(Route::exact(
            "GET",
            "/v2/",
            Responder::Static(
                TestResponse::builder(200)
                    .header("Docker-Distribution-API-Version", "registry/2.0")
                    .build(),
            ),
        ));
        Self { server }
    }

    /// `host:port` form, suitable for use as the registry portion
    /// of an `ImageReference`.
    pub fn host(&self) -> String {
        self.server.addr().to_string()
    }

    /// An `ImageReference` whose registry points at this fixture
    /// and whose repository / reference are caller-supplied.
    pub fn image_ref(&self, repository: &str, tag: &str) -> ImageReference {
        format!("{}/{repository}:{tag}", self.host())
            .parse()
            .expect("fixture-built reference parses")
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
        self.register_manifest_route(
            repository,
            reference,
            media_type,
            bytes,
            digest.as_str(),
            None,
        );
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
        self.register_manifest_route(
            repository,
            digest.as_str(),
            media_type,
            bytes,
            digest.as_str(),
            None,
        );
        digest
    }

    /// Same as [`Self::register_manifest_with_digest_path`], but
    /// deliberately omits the `Docker-Content-Digest` response
    /// header to simulate registries that do not advertise it.
    pub async fn register_manifest_without_digest_header_with_digest_path(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        self.register_manifest_route_without_digest_header(
            repository,
            reference,
            media_type,
            bytes,
            digest.as_str(),
            None,
        );
        self.register_manifest_route_without_digest_header(
            repository,
            digest.as_str(),
            media_type,
            bytes,
            digest.as_str(),
            None,
        );
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
            self.register_manifest_route(
                repository,
                manifest_ref,
                media_type,
                bytes,
                digest.as_str(),
                Some(token),
            );
        }
        digest
    }

    /// Serve a manifest via the bearer-challenge flow: the first
    /// unauthenticated request gets a `WWW-Authenticate` challenge,
    /// the client exchanges it for a token at the fixture token
    /// endpoint, and the retried manifest GET succeeds with the
    /// issued bearer token.
    pub async fn register_challenged_manifest_with_digest_path(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
        challenge: BearerChallengeFixture,
    ) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let challenge_header = format!(
            r#"Bearer realm="http://{}{realm}",service="{service}",scope="{scope}""#,
            self.host(),
            realm = challenge.realm_path,
            service = challenge.service,
            scope = challenge.scope,
        );
        for manifest_ref in [reference, digest.as_str()] {
            self.server.register(Route::exact(
                "GET",
                format!("/v2/{repository}/manifests/{manifest_ref}"),
                Responder::Static(
                    TestResponse::builder(401)
                        .header("WWW-Authenticate", challenge_header.clone())
                        .body_string("auth required")
                        .build(),
                ),
            ));
            if let Some(auth) = &challenge.basic_auth {
                self.server.register(
                    Route::exact(
                        "GET",
                        format!("/v2/{repository}/manifests/{manifest_ref}"),
                        Responder::Static(
                            TestResponse::builder(401)
                                .header("WWW-Authenticate", challenge_header.clone())
                                .body_string("auth required")
                                .build(),
                        ),
                    )
                    .with_authorization(basic_authorization(auth)),
                );
            }
            self.register_manifest_route(
                repository,
                manifest_ref,
                media_type,
                bytes,
                digest.as_str(),
                Some(challenge.issued_token.as_str()),
            );
        }
        self.register_token_route(&challenge);
        digest
    }

    /// Serve `bytes` at `/v2/<repository>/blobs/<sha256-digest>`.
    /// Returns the digest the bytes hash to (caller can compare
    /// against the manifest's layer descriptor).
    pub async fn register_blob(&self, repository: &str, media_type: &str, bytes: &[u8]) -> String {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        self.register_blob_route(repository, media_type, bytes, digest.as_str(), None);
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
        self.register_blob_route(repository, media_type, bytes, digest.as_str(), Some(token));
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
        self.server.register(Route::exact(
            "GET",
            format!("/v2/{repository}/blobs/{claimed_digest}"),
            Responder::Static(
                TestResponse::builder(200)
                    .header("Content-Type", "application/octet-stream")
                    .body_bytes(actual_bytes.to_vec())
                    .build(),
            ),
        ));
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
        let success = TestResponse::builder(200)
            .header("Content-Type", "application/octet-stream")
            .body_bytes(bytes.to_vec())
            .build();
        self.server.register(Route::exact(
            "GET",
            format!("/v2/{repository}/blobs/{digest}"),
            Responder::Flaky(FlakyResponder::new(fail_first, success)),
        ));
        digest
    }

    fn register_manifest_route(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
        digest: &str,
        token: Option<&str>,
    ) {
        let route = Route::exact(
            "GET",
            format!("/v2/{repository}/manifests/{reference}"),
            Responder::Static(
                TestResponse::builder(200)
                    .header("Content-Type", media_type)
                    .header("Docker-Content-Digest", digest)
                    .body_bytes(bytes.to_vec())
                    .build(),
            ),
        );
        self.server.register(match token {
            Some(value) => route.with_bearer_auth(value),
            None => route,
        });
    }

    fn register_manifest_route_without_digest_header(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
        _digest: &str,
        token: Option<&str>,
    ) {
        let route = Route::exact(
            "GET",
            format!("/v2/{repository}/manifests/{reference}"),
            Responder::Static(
                TestResponse::builder(200)
                    .header("Content-Type", media_type)
                    .body_bytes(bytes.to_vec())
                    .build(),
            ),
        );
        self.server.register(match token {
            Some(value) => route.with_bearer_auth(value),
            None => route,
        });
    }

    fn register_blob_route(
        &self,
        repository: &str,
        media_type: &str,
        bytes: &[u8],
        digest: &str,
        token: Option<&str>,
    ) {
        let route = Route::exact(
            "GET",
            format!("/v2/{repository}/blobs/{digest}"),
            Responder::Static(
                TestResponse::builder(200)
                    .header("Content-Type", media_type)
                    .body_bytes(bytes.to_vec())
                    .build(),
            ),
        );
        self.server.register(match token {
            Some(value) => route.with_bearer_auth(value),
            None => route,
        });
    }

    fn register_token_route(&self, challenge: &BearerChallengeFixture) {
        let response = TestResponse::builder(200)
            .header("Content-Type", "application/json")
            .body_string(format!(r#"{{"token":"{}"}}"#, challenge.issued_token))
            .build();
        let token_path = token_path(challenge);
        let route = Route::exact("GET", token_path, Responder::Static(response));
        self.server.register(match &challenge.basic_auth {
            Some(auth) => route.with_authorization(basic_authorization(auth)),
            None => route,
        });
    }
}

fn basic_authorization(auth: &BasicAuthFixture) -> String {
    let credential = format!("{}:{}", auth.username, auth.password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
    format!("Basic {encoded}")
}

fn token_path(challenge: &BearerChallengeFixture) -> String {
    let mut url = reqwest::Url::parse(&format!("http://fixture{}", challenge.realm_path))
        .expect("fixture token URL parses");
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("service", &challenge.service);
        query.append_pair("scope", &challenge.scope);
    }
    let query = url.query().expect("fixture token URL has query");
    format!("{}?{query}", challenge.realm_path)
}

/// Build a fetcher config that talks plaintext HTTP to the fixture's
/// localhost address. Production callers use `ClientProtocol::Https`; tests
/// need `HttpsExcept` listing the fixture's `host:port` so the same
/// `OciManifestFetcher` / `OciLayerFetcher` code path is exercised against
/// both.
pub fn client_config_for(registry: &HermeticRegistry) -> ClientConfig {
    ClientConfig {
        protocol: ClientProtocol::HttpsExcept(vec![registry.host()]),
    }
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
