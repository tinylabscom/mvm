use crate::oci::OciError;
use crate::oci::reference::ImageReference;
use mvm_http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use secrecy::{ExposeSecret, SecretString};

const DOCKER_HUB_REGISTRY: &str = "docker.io";
const DOCKER_HUB_LEGACY_REGISTRY: &str = "index.docker.io";
const DOCKER_HUB_REGISTRY_API_HOST: &str = "registry-1.docker.io";
const DOCKER_HUB_CLOUDFLARE_BLOB_HOST: &str = "production.cloudflare.docker.com";
const DOCKER_HUB_CLOUDFRONT_BLOB_HOST: &str = "production.cloudfront.docker.com";
const MAX_BLOB_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Default)]
pub enum ClientProtocol {
    #[default]
    Https,
    Http,
    HttpsExcept(Vec<String>),
}

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub protocol: ClientProtocol,
}

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
}

#[derive(Clone)]
pub struct RegistryClient {
    http: mvm_http::Client,
    config: ClientConfig,
    auth: RegistryAuthConfig,
}

impl RegistryClient {
    pub fn new(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self {
            http: mvm_http::Client::new(),
            config,
            auth,
        }
    }

    pub fn with_http_client(
        http: mvm_http::Client,
        config: ClientConfig,
        auth: RegistryAuthConfig,
    ) -> Self {
        Self { http, config, auth }
    }

    pub async fn get_manifest(
        &self,
        reference: &ImageReference,
        accept: &[&str],
    ) -> Result<RegistryResponse, OciError> {
        self.get(
            reference,
            &manifest_path(reference),
            Some(accept),
            RedirectPolicy::Refuse,
        )
        .await
    }

    pub async fn get_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<RegistryResponse, OciError> {
        self.get(
            reference,
            &blob_path(reference, digest),
            None,
            RedirectPolicy::Blob,
        )
        .await
    }

    async fn get(
        &self,
        reference: &ImageReference,
        path: &str,
        accept: Option<&[&str]>,
        redirect_policy: RedirectPolicy,
    ) -> Result<RegistryResponse, OciError> {
        let url = self.endpoint(reference, path);
        let request = self.build_request(url.clone(), accept, None);
        let response = request
            .send()
            .await
            .map_err(|e| OciError::Registry(format!("GET {url}: {e}")))?;
        if response.status() != mvm_http::StatusCode::UNAUTHORIZED {
            return self.registry_response(url, response, redirect_policy).await;
        }

        let challenge = parse_auth_challenge(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
        )?;
        let token = self.fetch_bearer_token(&url, &challenge).await?;
        let retry = self
            .build_request(url.clone(), accept, Some(format!("Bearer {token}")))
            .send()
            .await
            .map_err(|e| OciError::Registry(format!("GET {url} after auth: {e}")))?;
        self.registry_response(url, retry, redirect_policy).await
    }

    fn build_request(
        &self,
        url: String,
        accept: Option<&[&str]>,
        authorization: Option<String>,
    ) -> mvm_http::RequestBuilder {
        let mut request = self.http.get(url);
        if let Some(accept_values) = accept {
            request = request.header(ACCEPT, accept_values.join(", "));
        }
        if let Some(authz) = authorization {
            return request.header(AUTHORIZATION, authz);
        }
        match &self.auth {
            RegistryAuthConfig::Anonymous => request,
            RegistryAuthConfig::Bearer { token } => request.bearer_auth(token.expose_secret()),
            RegistryAuthConfig::Basic { username, password } => {
                request.basic_auth(username, Some(password.expose_secret().to_string()))
            }
        }
    }

    async fn registry_response(
        &self,
        url: String,
        response: mvm_http::Response,
        redirect_policy: RedirectPolicy,
    ) -> Result<RegistryResponse, OciError> {
        let mut current_url = mvm_http::Url::parse(&url).map_err(|e| {
            OciError::Registry(format!("registry endpoint is not a valid URL: {e}"))
        })?;
        let mut response = response;
        let mut redirect_count = 0;

        while is_preserving_redirect(response.status()) {
            if redirect_policy == RedirectPolicy::Refuse {
                break;
            }
            if redirect_count == MAX_BLOB_REDIRECTS {
                return Err(OciError::Registry(format!(
                    "GET {} exceeded the {MAX_BLOB_REDIRECTS}-redirect OCI blob limit",
                    display_url(&current_url)
                )));
            }
            let location = response.headers().get(LOCATION).ok_or_else(|| {
                OciError::Registry(format!(
                    "GET {} returned a redirect without Location",
                    display_url(&current_url)
                ))
            })?;
            let next_url = validate_blob_redirect(&current_url, location)?;
            response = self.http.get(next_url.as_str()).send().await.map_err(|e| {
                OciError::Registry(format!(
                    "GET redirected OCI blob from {}: {e}",
                    display_url(&next_url)
                ))
            })?;
            current_url = next_url;
            redirect_count += 1;
        }

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<body unreadable>".to_string());
            return Err(OciError::Registry(format!(
                "GET {} failed with {status}: {body}",
                display_url(&current_url)
            )));
        }
        let headers = response.headers().clone();
        Ok(RegistryResponse {
            content_type: headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            docker_content_digest: headers
                .get("Docker-Content-Digest")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            response,
        })
    }

    async fn fetch_bearer_token(
        &self,
        original_url: &str,
        challenge: &BearerChallenge,
    ) -> Result<String, OciError> {
        let mut token_url = mvm_http::Url::parse(&challenge.realm).map_err(|e| {
            OciError::Registry(format!(
                "bearer auth realm for {original_url} is not a valid URL: {e}"
            ))
        })?;
        {
            let mut query = token_url.query_pairs_mut();
            if let Some(service) = &challenge.service {
                query.append_pair("service", service);
            }
            if let Some(scope) = &challenge.scope {
                query.append_pair("scope", scope);
            }
        }
        let mut request = self.http.get(token_url);
        if let RegistryAuthConfig::Basic { username, password } = &self.auth {
            request = request.basic_auth(username, Some(password.expose_secret().to_string()));
        }
        let response = request.send().await.map_err(|e| {
            OciError::Registry(format!("fetch bearer token for {original_url}: {e}"))
        })?;
        if !response.status().is_success() {
            return Err(OciError::Registry(format!(
                "fetch bearer token for {original_url} failed with {}",
                response.status()
            )));
        }
        let token_response: TokenResponse = response.json().await.map_err(|e| {
            OciError::Registry(format!(
                "parse bearer token response for {original_url}: {e}"
            ))
        })?;
        token_response
            .token
            .or(token_response.access_token)
            .ok_or_else(|| {
                OciError::Registry(format!(
                    "bearer token response for {original_url} had no token field"
                ))
            })
    }

    fn endpoint(&self, reference: &ImageReference, path: &str) -> String {
        let host = registry_api_host(&reference.registry);
        let scheme = match &self.config.protocol {
            ClientProtocol::Https => "https",
            ClientProtocol::Http => "http",
            ClientProtocol::HttpsExcept(exceptions) => {
                if exceptions
                    .iter()
                    .any(|entry| entry == host || entry == &reference.registry)
                {
                    "http"
                } else {
                    "https"
                }
            }
        };
        format!("{scheme}://{host}{path}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectPolicy {
    Refuse,
    Blob,
}

fn is_preserving_redirect(status: mvm_http::StatusCode) -> bool {
    matches!(status.as_u16(), 307 | 308)
}

fn validate_blob_redirect(
    current: &mvm_http::Url,
    location: &mvm_http::header::HeaderValue,
) -> Result<mvm_http::Url, OciError> {
    let location = location
        .to_str()
        .map_err(|_| OciError::Registry("OCI blob redirect Location is not valid text".into()))?;
    let next = current
        .join(location)
        .map_err(|_| OciError::Registry("OCI blob redirect Location is not a valid URL".into()))?;

    if !next.username().is_empty() || next.password().is_some() || next.fragment().is_some() {
        return Err(OciError::Registry(
            "OCI blob redirect URL must not contain credentials or a fragment".into(),
        ));
    }
    if !matches!(next.scheme(), "http" | "https") {
        return Err(OciError::Registry(
            "OCI blob redirect URL must use HTTP or HTTPS".into(),
        ));
    }
    if current.scheme() == "https" && next.scheme() != "https" {
        return Err(OciError::Registry(
            "OCI blob redirect refused an HTTPS downgrade".into(),
        ));
    }
    if same_origin(current, &next) || is_docker_hub_cdn_redirect(current, &next) {
        return Ok(next);
    }

    Err(OciError::Registry(format!(
        "OCI blob redirect from {} to an untrusted origin was refused",
        display_url(current)
    )))
}

fn same_origin(left: &mvm_http::Url, right: &mvm_http::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn is_docker_hub_cdn_redirect(current: &mvm_http::Url, next: &mvm_http::Url) -> bool {
    current.scheme() == "https"
        && current.host_str() == Some(DOCKER_HUB_REGISTRY_API_HOST)
        && current.port_or_known_default() == Some(443)
        && next.scheme() == "https"
        && matches!(
            next.host_str(),
            Some(DOCKER_HUB_CLOUDFLARE_BLOB_HOST | DOCKER_HUB_CLOUDFRONT_BLOB_HOST)
        )
        && next.port_or_known_default() == Some(443)
}

fn display_url(url: &mvm_http::Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

pub struct RegistryResponse {
    pub content_type: Option<String>,
    pub docker_content_digest: Option<String>,
    pub response: mvm_http::Response,
}

fn manifest_path(reference: &ImageReference) -> String {
    let selector = reference
        .digest
        .as_deref()
        .or(reference.tag.as_deref())
        .expect("image reference always has a tag or digest");
    format!("/v2/{}/manifests/{selector}", reference.repository)
}

fn blob_path(reference: &ImageReference, digest: &str) -> String {
    format!("/v2/{}/blobs/{digest}", reference.repository)
}

fn registry_api_host(registry: &str) -> &str {
    match registry {
        DOCKER_HUB_REGISTRY | DOCKER_HUB_LEGACY_REGISTRY => DOCKER_HUB_REGISTRY_API_HOST,
        other => other,
    }
}

#[derive(Debug)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

fn parse_auth_challenge(header: Option<&str>) -> Result<BearerChallenge, OciError> {
    let header = header.ok_or_else(|| {
        OciError::Registry("registry returned 401 without WWW-Authenticate".into())
    })?;
    let challenge = header.strip_prefix("Bearer ").ok_or_else(|| {
        OciError::Registry(format!("unsupported WWW-Authenticate challenge: {header}"))
    })?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in challenge.split(',') {
        let (key, value) = part.trim().split_once('=').ok_or_else(|| {
            OciError::Registry(format!("malformed WWW-Authenticate challenge: {header}"))
        })?;
        let value = value.trim_matches('"').to_string();
        match key {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Ok(BearerChallenge {
        realm: realm.ok_or_else(|| {
            OciError::Registry(format!(
                "WWW-Authenticate challenge missing realm: {header}"
            ))
        })?,
        service,
        scope,
    })
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_endpoint_uses_registry_api_host() {
        let client = RegistryClient::new(ClientConfig::default(), RegistryAuthConfig::Anonymous);
        let reference = "alpine"
            .parse::<ImageReference>()
            .expect("docker hub reference parses");

        let endpoint = client.endpoint(&reference, "/v2/library/alpine/manifests/latest");

        assert_eq!(reference.registry, "docker.io");
        assert_eq!(
            endpoint,
            "https://registry-1.docker.io/v2/library/alpine/manifests/latest"
        );
    }

    #[test]
    fn docker_hub_endpoint_exception_matches_canonical_registry() {
        let client = RegistryClient::new(
            ClientConfig {
                protocol: ClientProtocol::HttpsExcept(vec!["docker.io".to_string()]),
            },
            RegistryAuthConfig::Anonymous,
        );
        let reference = "alpine"
            .parse::<ImageReference>()
            .expect("docker hub reference parses");

        let endpoint = client.endpoint(&reference, "/v2/library/alpine/manifests/latest");

        assert_eq!(
            endpoint,
            "http://registry-1.docker.io/v2/library/alpine/manifests/latest"
        );
    }

    #[test]
    fn parse_bearer_challenge_extracts_realm_service_and_scope() {
        let parsed = parse_auth_challenge(Some(
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:library/alpine:pull""#,
        ))
        .expect("challenge parses");
        assert_eq!(parsed.realm, "https://auth.example/token");
        assert_eq!(parsed.service.as_deref(), Some("registry.example"));
        assert_eq!(
            parsed.scope.as_deref(),
            Some("repository:library/alpine:pull")
        );
    }

    #[test]
    fn docker_hub_canonical_registry_uses_registry_api_host() {
        let reference: ImageReference = "docker.io/library/alpine:latest"
            .parse()
            .expect("reference parses");

        assert_eq!(
            registry_api_host(&reference.registry),
            "registry-1.docker.io"
        );
    }

    #[test]
    fn non_docker_registry_uses_reference_host() {
        let reference: ImageReference = "ghcr.io/example/app:latest"
            .parse()
            .expect("reference parses");

        assert_eq!(registry_api_host(&reference.registry), "ghcr.io");
    }

    #[test]
    fn blob_redirect_accepts_same_origin_relative_location() {
        let current =
            mvm_http::Url::parse("http://127.0.0.1:5000/v2/library/alpine/blobs/sha256:abc")
                .expect("current URL parses");
        let location = mvm_http::header::HeaderValue::from_static("/blob-data/sha256:abc");

        let next = validate_blob_redirect(&current, &location).expect("redirect is accepted");

        assert_eq!(next.as_str(), "http://127.0.0.1:5000/blob-data/sha256:abc");
    }

    #[test]
    fn blob_redirect_accepts_exact_docker_hub_cdn_origin() {
        let current =
            mvm_http::Url::parse("https://registry-1.docker.io/v2/library/alpine/blobs/sha256:abc")
                .expect("current URL parses");
        let location = mvm_http::header::HeaderValue::from_static(
            "https://production.cloudflare.docker.com/registry-v2/blobs/data?verify=secret",
        );

        let next = validate_blob_redirect(&current, &location).expect("redirect is accepted");

        assert_eq!(next.host_str(), Some("production.cloudflare.docker.com"));

        let current_cdn = mvm_http::header::HeaderValue::from_static(
            "https://production.cloudfront.docker.com/registry-v2/blobs/data?verify=secret",
        );
        let next = validate_blob_redirect(&current, &current_cdn).expect("current CDN is accepted");
        assert_eq!(next.host_str(), Some("production.cloudfront.docker.com"));
    }

    #[test]
    fn blob_redirect_rejects_untrusted_cross_origin() {
        let current =
            mvm_http::Url::parse("https://registry-1.docker.io/v2/library/alpine/blobs/sha256:abc")
                .expect("current URL parses");
        let location = mvm_http::header::HeaderValue::from_static("https://example.com/blob");

        let error = validate_blob_redirect(&current, &location).unwrap_err();

        assert!(error.to_string().contains("untrusted origin"));
    }

    #[test]
    fn blob_redirect_rejects_https_downgrade() {
        let current =
            mvm_http::Url::parse("https://registry-1.docker.io/v2/library/alpine/blobs/sha256:abc")
                .expect("current URL parses");
        let location = mvm_http::header::HeaderValue::from_static(
            "http://production.cloudflare.docker.com/blob",
        );

        let error = validate_blob_redirect(&current, &location).unwrap_err();

        assert!(error.to_string().contains("HTTPS downgrade"));
    }

    #[test]
    fn blob_redirect_rejects_credentials_and_fragments() {
        let current = mvm_http::Url::parse("https://registry.example/v2/blobs/sha256:abc")
            .expect("current URL parses");
        for value in [
            "https://user:pass@registry.example/blob",
            "https://registry.example/blob#fragment",
        ] {
            let location = mvm_http::header::HeaderValue::from_str(value)
                .expect("test redirect header is valid");

            let error = validate_blob_redirect(&current, &location).unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("must not contain credentials or a fragment")
            );
        }
    }

    #[test]
    fn display_url_redacts_signed_query() {
        let url =
            mvm_http::Url::parse("https://cdn.example/blob?token=secret").expect("URL parses");

        assert_eq!(display_url(&url), "https://cdn.example/blob");
    }
}
