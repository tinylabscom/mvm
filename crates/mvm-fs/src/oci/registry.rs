use crate::oci::OciError;
use crate::oci::reference::ImageReference;
use mvm_http::Method;
use mvm_http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DOCKER_HUB_REGISTRY: &str = "docker.io";
const DOCKER_HUB_LEGACY_REGISTRY: &str = "index.docker.io";
const DOCKER_HUB_REGISTRY_API_HOST: &str = "registry-1.docker.io";
const MAX_BLOB_REDIRECTS: usize = 5;
/// Request bodies at least this large are streamed in chunks rather than
/// handed to the transport as one more copy of the whole body.
const STREAM_BODY_THRESHOLD: usize = 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

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

/// Scheme, host and port: the unit a credential is issued for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn of(url: &mvm_http::Url) -> Self {
        Self {
            scheme: url.scheme().to_string(),
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            port: url.port_or_known_default(),
        }
    }
}

/// A token a challenge issued is good for one repository on one registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    origin: Origin,
    repository: String,
}

#[derive(Clone)]
pub struct RegistryClient {
    http: mvm_http::Client,
    config: ClientConfig,
    auth: RegistryAuthConfig,
    // The registry the configured credentials belong to: the first origin this
    // client sends a request to. They are never attached to any other origin,
    // so a client handed references on two registries cannot leak one
    // registry's credentials to the other.
    credential_origin: Arc<Mutex<Option<Origin>>>,
    // Tokens redeemed from challenges, reused so a push's several requests are
    // not each refused and replayed — including the upload carrying the blob.
    issued_tokens: Arc<Mutex<HashMap<TokenKey, SecretString>>>,
}

/// What a single request carries besides its method and URL.
#[derive(Default)]
struct RequestParts<'a> {
    accept: Option<&'a [&'a str]>,
    content_type: Option<&'a str>,
    body: Option<&'a [u8]>,
}

/// What to put in a request's `Authorization` header.
enum Authorization {
    None,
    /// A token a challenge issued.
    Bearer(String),
    /// The client's configured credentials.
    Configured,
}

/// The `Authorization` a request went out with, so a refusal can say which
/// credential was refused.
enum SentAuthorization {
    None,
    Issued,
    Configured,
}

impl RegistryClient {
    pub fn new(config: ClientConfig, auth: RegistryAuthConfig) -> Self {
        Self::with_http_client(mvm_http::Client::new(), config, auth)
    }

    pub fn with_http_client(
        http: mvm_http::Client,
        config: ClientConfig,
        auth: RegistryAuthConfig,
    ) -> Self {
        Self {
            http,
            config,
            auth,
            credential_origin: Arc::new(Mutex::new(None)),
            issued_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_manifest(
        &self,
        reference: &ImageReference,
        accept: &[&str],
    ) -> Result<RegistryResponse, OciError> {
        let url = self.endpoint(reference, &manifest_path(reference));
        let parts = RequestParts {
            accept: Some(accept),
            ..RequestParts::default()
        };
        let response = self.send(Method::GET, &url, reference, &parts).await?;
        self.registry_response(url, response, RedirectPolicy::Refuse)
            .await
    }

    pub async fn get_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<RegistryResponse, OciError> {
        let url = self.endpoint(reference, &blob_path(reference, digest));
        let response = self
            .send(Method::GET, &url, reference, &RequestParts::default())
            .await?;
        self.registry_response(url, response, RedirectPolicy::Blob)
            .await
    }

    /// Whether the repository already holds a blob with this digest.
    ///
    /// Only a `200` counts as present. A registry that answers `HEAD` with a
    /// redirect to storage is treated as not having it, which costs a
    /// redundant upload and never a missing blob.
    pub async fn blob_exists(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<bool, OciError> {
        let url = self.endpoint(reference, &blob_path(reference, digest));
        let response = self
            .send(Method::HEAD, &url, reference, &RequestParts::default())
            .await?;
        match response.status().as_u16() {
            200 => Ok(true),
            404 | 307 | 308 => Ok(false),
            _ => Err(unexpected_status("HEAD", &url, response).await),
        }
    }

    /// Upload `bytes` as the blob `digest` with the two-request monolithic
    /// flow: open an upload session, then close it with the whole body.
    ///
    /// The session location must stay on the registry's own origin. The
    /// request that closes the session carries the registry credentials, and
    /// a location elsewhere would hand them to whoever the registry named.
    pub async fn upload_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
        bytes: &[u8],
    ) -> Result<(), OciError> {
        let start_url = self.endpoint(
            reference,
            &format!("/v2/{}/blobs/uploads/", reference.repository),
        );
        let started = self
            .send(
                Method::POST,
                &start_url,
                reference,
                &RequestParts::default(),
            )
            .await?;
        if started.status().as_u16() != 202 {
            return Err(unexpected_status("POST", &start_url, started).await);
        }
        let location = started.headers().get(LOCATION).ok_or_else(|| {
            OciError::Registry(format!(
                "POST {start_url} opened an upload without a Location"
            ))
        })?;
        let upload_url = upload_session_url(&start_url, location, digest)?;
        let parts = RequestParts {
            content_type: Some("application/octet-stream"),
            body: Some(bytes),
            ..RequestParts::default()
        };
        let finished = self
            .send(Method::PUT, upload_url.as_str(), reference, &parts)
            .await?;
        if finished.status().as_u16() != 201 {
            return Err(unexpected_status("PUT", &display_url(&upload_url), finished).await);
        }
        Ok(())
    }

    /// Store `bytes` as the manifest at `reference`'s tag, or at its digest
    /// when it has no tag. Returns the digest the registry reports, if any,
    /// so the caller can check it against the digest of what it sent.
    pub async fn put_manifest(
        &self,
        reference: &ImageReference,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<Option<String>, OciError> {
        let url = self.endpoint(reference, &manifest_path(reference));
        let parts = RequestParts {
            content_type: Some(media_type),
            body: Some(bytes),
            ..RequestParts::default()
        };
        let response = self.send(Method::PUT, &url, reference, &parts).await?;
        if response.status().as_u16() != 201 {
            return Err(unexpected_status("PUT", &url, response).await);
        }
        Ok(response
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string))
    }

    /// Send one request, redeeming a bearer challenge once if the registry
    /// asks for one.
    ///
    /// A configured bearer token is never swapped for a token from the
    /// challenge's realm: that exchange would be anonymous, so a refused
    /// token would silently become a pull-only anonymous one. The refusal is
    /// reported instead.
    async fn send(
        &self,
        method: Method,
        url: &str,
        reference: &ImageReference,
        parts: &RequestParts<'_>,
    ) -> Result<mvm_http::Response, OciError> {
        let parsed = mvm_http::Url::parse(url)
            .map_err(|e| OciError::Registry(format!("registry URL {url} is invalid: {e}")))?;
        let key = TokenKey {
            origin: Origin::of(&parsed),
            repository: reference.repository.clone(),
        };
        let credentials_apply = self.credentials_apply_to(&key.origin);
        let (authorization, sent) = match self.issued_token(&key) {
            Some(token) => (Authorization::Bearer(token), SentAuthorization::Issued),
            None if credentials_apply && self.auth.is_authenticated() => {
                (Authorization::Configured, SentAuthorization::Configured)
            }
            None => (Authorization::None, SentAuthorization::None),
        };
        let response = self
            .dispatch(method.clone(), url, parts, authorization)
            .await
            .map_err(|e| OciError::Registry(format!("{method} {url}: {e}")))?;
        if response.status() != mvm_http::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge = bearer_challenge(&response, url)?;
        if matches!(sent, SentAuthorization::Configured)
            && matches!(self.auth, RegistryAuthConfig::Bearer { .. })
        {
            return Err(OciError::Registry(format!(
                "{method} {url} refused the configured bearer token (HTTP 401). The registry \
                 offered a token from {}, but a configured bearer token is not exchanged for \
                 an anonymous one; check the token's access to {}",
                display_realm(&challenge.realm),
                reference.repository
            )));
        }
        validate_realm(&parsed, &challenge.realm)?;
        // Basic credentials go to the realm even when it is on another host,
        // as a token service conventionally is. They are still only ever
        // offered for requests to the registry they were configured for.
        let basic = if credentials_apply {
            match &self.auth {
                RegistryAuthConfig::Basic { username, password } => Some((username, password)),
                _ => None,
            }
        } else {
            None
        };
        let token = self.fetch_bearer_token(url, &challenge, basic).await?;
        let token_for_retry = token.clone();
        self.remember_token(key, token);
        self.dispatch(
            method.clone(),
            url,
            parts,
            Authorization::Bearer(token_for_retry),
        )
        .await
        .map_err(|e| OciError::Registry(format!("{method} {url} after auth: {e}")))
    }

    /// Whether configured credentials may accompany a request to `origin`.
    /// The first origin asked about claims them.
    fn credentials_apply_to(&self, origin: &Origin) -> bool {
        match self.credential_origin.lock() {
            Ok(mut slot) => slot.get_or_insert_with(|| origin.clone()) == origin,
            Err(_) => false,
        }
    }

    fn issued_token(&self, key: &TokenKey) -> Option<String> {
        self.issued_tokens
            .lock()
            .ok()
            .and_then(|tokens| tokens.get(key).map(|t| t.expose_secret().to_string()))
    }

    fn remember_token(&self, key: TokenKey, token: String) {
        if let Ok(mut tokens) = self.issued_tokens.lock() {
            tokens.insert(key, SecretString::from(token));
        }
    }

    /// Build and send one request. A large body is streamed from the caller's
    /// slice in bounded chunks instead of being copied whole.
    async fn dispatch(
        &self,
        method: Method,
        url: &str,
        parts: &RequestParts<'_>,
        authorization: Authorization,
    ) -> mvm_http::Result<mvm_http::Response> {
        let mut request = self.http.request(method, url);
        if let Some(accept_values) = parts.accept {
            request = request.header(ACCEPT, accept_values.join(", "));
        }
        if let Some(content_type) = parts.content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        request = match (authorization, &self.auth) {
            (Authorization::None, _)
            | (Authorization::Configured, RegistryAuthConfig::Anonymous) => request,
            (Authorization::Bearer(token), _) => {
                request.header(AUTHORIZATION, format!("Bearer {token}"))
            }
            (Authorization::Configured, RegistryAuthConfig::Bearer { token }) => {
                request.bearer_auth(token.expose_secret())
            }
            (Authorization::Configured, RegistryAuthConfig::Basic { username, password }) => {
                request.basic_auth(username, Some(password.expose_secret()))
            }
        };
        match parts.body {
            None => request.send().await,
            Some(body) if body.len() < STREAM_BODY_THRESHOLD => {
                request.body(body.to_vec()).send().await
            }
            Some(body) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
                let request = request.body_stream(body.len() as u64, rx);
                let feed = async move {
                    for chunk in body.chunks(STREAM_CHUNK_BYTES) {
                        if tx.send(chunk.to_vec()).await.is_err() {
                            break;
                        }
                    }
                };
                let (response, ()) = tokio::join!(request.send(), feed);
                response
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
            // No credentials on a redirected hop: the target is often object
            // storage on another origin, and the blob is digest-verified
            // whoever serves it.
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
            return Err(unexpected_status("GET", &display_url(&current_url), response).await);
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
        basic: Option<(&String, &SecretString)>,
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
        if let Some((username, password)) = basic {
            request = request.basic_auth(username, Some(password.expose_secret().to_string()));
        }
        let response = request.send().await.map_err(|e| {
            OciError::Registry(format!("fetch bearer token for {original_url}: {e}"))
        })?;
        if !response.status().is_success() {
            return Err(OciError::Registry(format!(
                "fetch bearer token for {original_url} from {} failed with {} (credentials sent: {})",
                display_realm(&challenge.realm),
                response.status(),
                if basic.is_some() { "basic" } else { "none" }
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

/// Accept a blob redirect to any origin — the blob is digest-verified and the
/// hop carries no credentials — but never one that downgrades HTTPS to HTTP,
/// embeds credentials, or leaves HTTP(S).
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
    Ok(next)
}

fn same_origin(left: &mvm_http::Url, right: &mvm_http::Url) -> bool {
    Origin::of(left) == Origin::of(right)
}

fn display_url(url: &mvm_http::Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn display_realm(realm: &str) -> String {
    mvm_http::Url::parse(realm)
        .map(|url| display_url(&url))
        .unwrap_or_else(|_| "an unparseable realm".to_string())
}

/// A realm receives Basic credentials and hands back the token every later
/// request carries, so it must be HTTPS — or, for a registry reached over
/// plain HTTP by explicit opt-in, that same registry origin.
fn validate_realm(registry: &mvm_http::Url, realm: &str) -> Result<(), OciError> {
    let realm_url = mvm_http::Url::parse(realm).map_err(|e| {
        OciError::Registry(format!(
            "bearer auth realm {realm:?} is not a valid URL: {e}"
        ))
    })?;
    if !realm_url.username().is_empty() || realm_url.password().is_some() {
        return Err(OciError::Registry(
            "bearer auth realm must not contain credentials".into(),
        ));
    }
    match realm_url.scheme() {
        "https" => Ok(()),
        "http" if registry.scheme() == "http" && same_origin(registry, &realm_url) => Ok(()),
        _ => Err(OciError::Registry(format!(
            "bearer auth realm {} for {} is refused: a token realm must use HTTPS, or be the \
             registry's own origin when the registry itself is reached over HTTP",
            display_url(&realm_url),
            display_url(registry)
        ))),
    }
}

/// Resolve an upload session `Location` against the request that opened it,
/// confine it to the registry's origin, and add the `digest` parameter that
/// closes the session.
fn upload_session_url(
    start_url: &str,
    location: &mvm_http::header::HeaderValue,
    digest: &str,
) -> Result<mvm_http::Url, OciError> {
    let start = mvm_http::Url::parse(start_url)
        .map_err(|e| OciError::Registry(format!("registry endpoint is not a valid URL: {e}")))?;
    let location = location
        .to_str()
        .map_err(|_| OciError::Registry("upload Location is not valid text".into()))?;
    let mut next = start
        .join(location)
        .map_err(|_| OciError::Registry("upload Location is not a valid URL".into()))?;
    if !next.username().is_empty() || next.password().is_some() || next.fragment().is_some() {
        return Err(OciError::Registry(
            "upload Location must not contain credentials or a fragment".into(),
        ));
    }
    if !same_origin(&start, &next) {
        return Err(OciError::Registry(format!(
            "upload Location from {} points at another origin; refusing to send credentials there",
            display_url(&start)
        )));
    }
    next.query_pairs_mut().append_pair("digest", digest);
    Ok(next)
}

/// Describe a response the caller did not expect, including a bounded prefix
/// of its body: registries explain refusals there, and an unbounded read would
/// let one choose how much we buffer to print an error.
async fn unexpected_status(method: &str, url: &str, mut response: mvm_http::Response) -> OciError {
    const MAX_ERROR_BODY: usize = 4096;
    let status = response.status();
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            _ => break,
        }
    }
    body.truncate(MAX_ERROR_BODY);
    OciError::Registry(format!(
        "{method} {url} failed with {status}: {}",
        String::from_utf8_lossy(&body)
    ))
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

/// Pick the bearer challenge out of every `WWW-Authenticate` header on a 401.
fn bearer_challenge(response: &mvm_http::Response, url: &str) -> Result<BearerChallenge, OciError> {
    let values: Vec<&str> = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    parse_auth_challenges(&values).map_err(|e| match e {
        OciError::Registry(msg) => OciError::Registry(format!("{url}: {msg}")),
        other => other,
    })
}

fn parse_auth_challenges(values: &[&str]) -> Result<BearerChallenge, OciError> {
    if values.is_empty() {
        return Err(OciError::Registry(
            "registry returned 401 without WWW-Authenticate".into(),
        ));
    }
    let mut offered = Vec::new();
    for value in values {
        for (scheme, params) in split_challenges(value)? {
            if !scheme.eq_ignore_ascii_case("bearer") {
                offered.push(scheme);
                continue;
            }
            let mut challenge = BearerChallenge {
                realm: String::new(),
                service: None,
                scope: None,
            };
            for (key, value) in params {
                match key.to_ascii_lowercase().as_str() {
                    "realm" => challenge.realm = value,
                    "service" => challenge.service = Some(value),
                    "scope" => challenge.scope = Some(value),
                    _ => {}
                }
            }
            if challenge.realm.is_empty() {
                return Err(OciError::Registry(format!(
                    "WWW-Authenticate bearer challenge missing realm: {value}"
                )));
            }
            return Ok(challenge);
        }
    }
    Err(OciError::Registry(format!(
        "registry requires authentication but offered no bearer challenge (offered: {}); \
         only bearer-token challenges are supported",
        offered.join(", ")
    )))
}

type Challenge = (String, Vec<(String, String)>);

/// Tokenize one `WWW-Authenticate` value into challenges. A value may carry
/// several (`Basic realm="a", Bearer realm="b"`), quoted values may contain
/// commas and backslash-escaped quotes, and scheme names are case-insensitive.
fn split_challenges(value: &str) -> Result<Vec<Challenge>, OciError> {
    let malformed = || OciError::Registry(format!("malformed WWW-Authenticate challenge: {value}"));
    let bytes: Vec<char> = value.chars().collect();
    let mut pos = 0;
    let mut challenges: Vec<Challenge> = Vec::new();
    let skip = |pos: &mut usize, extra: char| {
        while *pos < bytes.len() && (bytes[*pos].is_whitespace() || bytes[*pos] == extra) {
            *pos += 1;
        }
    };
    let token = |pos: &mut usize| {
        let start = *pos;
        while *pos < bytes.len()
            && !bytes[*pos].is_whitespace()
            && bytes[*pos] != ','
            && bytes[*pos] != '='
        {
            *pos += 1;
        }
        bytes[start..*pos].iter().collect::<String>()
    };
    loop {
        skip(&mut pos, ',');
        if pos >= bytes.len() {
            break;
        }
        let scheme = token(&mut pos);
        if scheme.is_empty() {
            return Err(malformed());
        }
        let mut params = Vec::new();
        loop {
            skip(&mut pos, ',');
            let name_start = pos;
            let name = token(&mut pos);
            let mut after = pos;
            while after < bytes.len() && bytes[after].is_whitespace() {
                after += 1;
            }
            if name.is_empty() || after >= bytes.len() || bytes[after] != '=' {
                // Not a parameter: either the end, or the next challenge's
                // scheme (or a token68 we have no use for).
                if !name.is_empty() && (after >= bytes.len() || bytes[after] != '=') {
                    pos = name_start;
                }
                break;
            }
            pos = after + 1;
            while pos < bytes.len() && bytes[pos].is_whitespace() {
                pos += 1;
            }
            let mut param_value = String::new();
            if pos < bytes.len() && bytes[pos] == '"' {
                pos += 1;
                let mut closed = false;
                while pos < bytes.len() {
                    match bytes[pos] {
                        '\\' if pos + 1 < bytes.len() => {
                            param_value.push(bytes[pos + 1]);
                            pos += 2;
                        }
                        '"' => {
                            pos += 1;
                            closed = true;
                            break;
                        }
                        other => {
                            param_value.push(other);
                            pos += 1;
                        }
                    }
                }
                if !closed {
                    return Err(malformed());
                }
            } else {
                param_value = token(&mut pos);
                // token68 padding such as `abc==` is not a parameter value.
                while pos < bytes.len() && bytes[pos] == '=' {
                    pos += 1;
                }
            }
            params.push((name, param_value));
        }
        challenges.push((scheme, params));
    }
    Ok(challenges)
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
        let parsed = parse_auth_challenges(&[
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:library/alpine:pull""#,
        ])
        .expect("challenge parses");
        assert_eq!(parsed.realm, "https://auth.example/token");
        assert_eq!(parsed.service.as_deref(), Some("registry.example"));
        assert_eq!(
            parsed.scope.as_deref(),
            Some("repository:library/alpine:pull")
        );
    }

    #[test]
    fn parse_bearer_challenge_keeps_commas_inside_a_quoted_scope() {
        let parsed = parse_auth_challenges(&[
            r#"Bearer realm="https://auth.example/token",scope="repository:team/app:pull,push",service="registry.example""#,
        ])
        .expect("challenge parses");
        assert_eq!(
            parsed.scope.as_deref(),
            Some("repository:team/app:pull,push")
        );
        assert_eq!(parsed.service.as_deref(), Some("registry.example"));
    }

    #[test]
    fn challenge_parsing_handles_escapes_case_and_several_challenges() {
        let parsed = parse_auth_challenges(&[
            r#"Basic realm="registry""#,
            r#"basic realm="x", BEARER realm="https://auth.example/token", service="a \"quoted\" name""#,
        ])
        .expect("the bearer challenge is found");
        assert_eq!(parsed.realm, "https://auth.example/token");
        assert_eq!(parsed.service.as_deref(), Some(r#"a "quoted" name"#));
    }

    #[test]
    fn challenge_parsing_reports_when_no_bearer_challenge_is_offered() {
        let err = parse_auth_challenges(&[r#"Basic realm="registry""#]).unwrap_err();
        assert!(err.to_string().contains("offered: Basic"), "{err}");
        assert!(parse_auth_challenges(&[]).is_err());
        assert!(parse_auth_challenges(&[r#"Bearer realm="unterminated"#]).is_err());
    }

    #[test]
    fn realm_must_be_https_or_the_plain_http_registry_itself() {
        let https_registry = mvm_http::Url::parse("https://registry.example/v2/").unwrap();
        let http_registry = mvm_http::Url::parse("http://127.0.0.1:5000/v2/").unwrap();

        validate_realm(&https_registry, "https://auth.elsewhere.example/token")
            .expect("an HTTPS realm on another host is the usual token service");
        validate_realm(&http_registry, "http://127.0.0.1:5000/token")
            .expect("a plain-HTTP registry may serve its own realm");

        for (registry, realm) in [
            (&https_registry, "http://registry.example/token"),
            (&http_registry, "http://127.0.0.1:6000/token"),
            (&https_registry, "https://user:pw@auth.example/token"),
        ] {
            assert!(
                validate_realm(registry, realm).is_err(),
                "{realm} must be refused for {registry}"
            );
        }
    }

    #[test]
    fn upload_session_url_keeps_the_session_query_and_adds_the_digest() {
        let location = mvm_http::header::HeaderValue::from_static(
            "/v2/team/app/blobs/uploads/abc?_state=opaque",
        );
        let url = upload_session_url(
            "https://registry.example/v2/team/app/blobs/uploads/",
            &location,
            "sha256:00",
        )
        .expect("same-origin location is accepted");
        assert_eq!(
            url.as_str(),
            "https://registry.example/v2/team/app/blobs/uploads/abc?_state=opaque&digest=sha256%3A00"
        );
    }

    #[test]
    fn upload_session_url_refuses_another_origin_and_credentials() {
        for value in [
            "https://storage.example/upload",
            "http://registry.example/v2/team/app/blobs/uploads/abc",
            "https://user:pass@registry.example/upload",
        ] {
            let location = mvm_http::header::HeaderValue::from_str(value).expect("header");
            assert!(
                upload_session_url(
                    "https://registry.example/v2/team/app/blobs/uploads/",
                    &location,
                    "sha256:00",
                )
                .is_err(),
                "{value} must be refused"
            );
        }
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
    fn blob_redirect_accepts_any_https_origin() {
        let current =
            mvm_http::Url::parse("https://registry.example/v2/library/alpine/blobs/sha256:abc")
                .expect("current URL parses");
        let location = mvm_http::header::HeaderValue::from_static(
            "https://storage.example/registry-v2/blobs/data?verify=secret",
        );

        let next = validate_blob_redirect(&current, &location).expect("redirect is accepted");

        assert_eq!(next.host_str(), Some("storage.example"));
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
