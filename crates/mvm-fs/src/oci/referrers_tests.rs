use super::test_registry::MemoryRegistry;
use super::{ClientConfig, ClientProtocol, ImageReference, OciManifestFetcher, RegistryAuthConfig};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

fn reference(registry: &MemoryRegistry) -> ImageReference {
    format!("{}/team/image:latest", registry.host())
        .parse()
        .expect("test reference")
}

fn fetcher(auth: RegistryAuthConfig) -> OciManifestFetcher {
    OciManifestFetcher::with_config_and_auth(
        ClientConfig {
            protocol: ClientProtocol::Http,
        },
        auth,
    )
}

#[test]
fn referrers_reuse_the_image_transports_redeemed_token() {
    let registry = MemoryRegistry::start();
    registry.require_token("issued-token");
    let image = reference(&registry);
    let digest = format!("sha256:{}", "a".repeat(64));
    let path = format!("/v2/team/image/referrers/{digest}");
    registry.respond_to_get(&path, 200, b"{\"manifests\":[]}", &[]);
    let fetcher = fetcher(RegistryAuthConfig::Anonymous);
    let runtime = runtime();
    // A missing image still redeems and retains the repository token.
    assert!(
        runtime
            .block_on(fetcher.registry_client().get_optional_manifest(&image, &[]))
            .expect("authenticated 404")
            .is_none()
    );
    let response = runtime
        .block_on(
            fetcher
                .registry_client()
                .get_referrers(&image, &digest, None),
        )
        .expect("referrers")
        .expect("present");
    assert_eq!(response.response.status(), mvm_http::StatusCode::OK);
    let requests = registry.requests();
    assert_eq!(requests.iter().filter(|r| r.path == "/token").count(), 1);
    assert_eq!(
        requests
            .last()
            .expect("referrers request")
            .authorization
            .as_deref(),
        Some("Bearer issued-token")
    );
}

#[test]
fn referrers_and_legacy_metadata_distinguish_missing_from_forbidden() {
    let registry = MemoryRegistry::start();
    let image = reference(&registry);
    let digest = format!("sha256:{}", "a".repeat(64));
    let path = format!("/v2/team/image/referrers/{digest}");
    let fetcher = fetcher(RegistryAuthConfig::Anonymous);
    let runtime = runtime();
    assert!(
        runtime
            .block_on(
                fetcher
                    .registry_client()
                    .get_referrers(&image, &digest, None)
            )
            .expect("404")
            .is_none()
    );
    registry.respond_to_get(&path, 403, b"forbidden", &[]);
    assert!(
        runtime
            .block_on(
                fetcher
                    .registry_client()
                    .get_referrers(&image, &digest, None)
            )
            .err()
            .expect("403 is an error")
            .to_string()
            .contains("403")
    );
    registry.respond_to_get("/v2/team/image/manifests/latest", 403, b"forbidden", &[]);
    assert!(
        runtime
            .block_on(fetcher.registry_client().get_optional_manifest(&image, &[]))
            .is_err()
    );
}

#[test]
fn referrers_refused_configured_credentials_are_never_missing() {
    let registry = MemoryRegistry::start();
    registry.require_token("correct");
    let image = reference(&registry);
    let fetcher = fetcher(RegistryAuthConfig::bearer(registry.host(), "incorrect"));
    let digest = format!("sha256:{}", "a".repeat(64));
    let result = runtime().block_on(
        fetcher
            .registry_client()
            .get_referrers(&image, &digest, None),
    );
    assert!(
        result
            .err()
            .expect("refused credential")
            .to_string()
            .contains("401")
    );
    assert!(registry.requests().iter().all(|r| r.path != "/token"));
}

#[test]
fn referrers_continuations_cannot_redirect_credentials() {
    let registry = MemoryRegistry::start();
    let image = reference(&registry);
    let digest = format!("sha256:{}", "a".repeat(64));
    let fetcher = fetcher(RegistryAuthConfig::bearer(registry.host(), "secret"));
    for next in [
        "http://elsewhere.invalid/referrers",
        "/v2/other/repository/referrers/sha256:bad",
        "?n=10#fragment",
    ] {
        assert!(
            runtime()
                .block_on(
                    fetcher
                        .registry_client()
                        .get_referrers(&image, &digest, Some(next))
                )
                .is_err()
        );
    }
    assert!(registry.requests().is_empty());
}

#[test]
fn referrers_continuation_preserves_endpoint_and_query() {
    let registry = MemoryRegistry::start();
    let image = reference(&registry);
    let digest = format!("sha256:{}", "a".repeat(64));
    registry.respond_to_get(
        &format!("/v2/team/image/referrers/{digest}?last=next"),
        200,
        b"{\"manifests\":[]}",
        &[],
    );
    let fetcher = fetcher(RegistryAuthConfig::Anonymous);
    assert!(
        runtime()
            .block_on(
                fetcher
                    .registry_client()
                    .get_referrers(&image, &digest, Some("?last=next"))
            )
            .expect("second page")
            .is_some()
    );
}
