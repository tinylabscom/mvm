use crate::OciError;
use crate::reference::ImageReference;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use secrecy::{ExposeSecret, SecretString};

const DOCKER_HUB_REGISTRY: &str = "docker.io";
const DOCKER_HUB_LEGACY_REGISTRY: &str = "index.docker.io";
const DOCKER_HUB_REGISTRY_API_HOST: &str = "registry-1.docker.io";

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
    http: reqwest::Client,
    config: ClientConfig,
    auth: RegistryAuthConfig,
}

impl RegistryClient {
    pub fn new(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
            auth,
        }
    }

    pub fn with_http_client(
        http: reqwest::Client,
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
        self.get(reference, &manifest_path(reference), Some(accept))
            .await
    }

    pub async fn get_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<RegistryResponse, OciError> {
        self.get(reference, &blob_path(reference, digest), None)
            .await
    }

    async fn get(
        &self,
        reference: &ImageReference,
        path: &str,
        accept: Option<&[&str]>,
    ) -> Result<RegistryResponse, OciError> {
        let url = self.endpoint(reference, path);
        let request = self.build_request(url.clone(), accept, None);
        let response = request
            .send()
            .await
            .map_err(|e| OciError::Registry(format!("GET {url}: {e}")))?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return self.registry_response(url, response).await;
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
        self.registry_response(url, retry).await
    }

    fn build_request(
        &self,
        url: String,
        accept: Option<&[&str]>,
        authorization: Option<String>,
    ) -> reqwest::RequestBuilder {
        let mut request = self.http.get(url);
        if let Some(accept_values) = accept {
            request = request.header(ACCEPT, accept_values.join(", "));
        }
        if let Some(authz) = authorization {
            return request.header(AUTHORIZATION, authz);
        }
        match &self.auth {
            RegistryAuthConfig::Anonymous => request,
            RegistryAuthConfig::Bearer { token } => {
                request.bearer_auth(token.expose_secret().to_string())
            }
            RegistryAuthConfig::Basic { username, password } => {
                request.basic_auth(username, Some(password.expose_secret().to_string()))
            }
        }
    }

    async fn registry_response(
        &self,
        url: String,
        response: reqwest::Response,
    ) -> Result<RegistryResponse, OciError> {
        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<body unreadable>".to_string());
            return Err(OciError::Registry(format!(
                "GET {url} failed with {status}: {body}"
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
        let mut token_url = reqwest::Url::parse(&challenge.realm).map_err(|e| {
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

pub struct RegistryResponse {
    pub content_type: Option<String>,
    pub docker_content_digest: Option<String>,
    pub response: reqwest::Response,
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

        assert_eq!(registry_api_host(&reference.registry), "registry-1.docker.io");
    }

    #[test]
    fn non_docker_registry_uses_reference_host() {
        let reference: ImageReference = "ghcr.io/example/app:latest"
            .parse()
            .expect("reference parses");

        assert_eq!(registry_api_host(&reference.registry), "ghcr.io");
    }
}
