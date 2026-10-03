//! Host-side OAuth token exchange and proactive refresh.
//!
//! An OAuth-bound secret's stored value is an [`OAuthTokenSet`]. The machine
//! flow's client secret travels inside that same encrypted store entry, which
//! binds it to the flow by the same (tenant, name) key the egress binding and
//! the resolver share — one confidentiality boundary, one lifecycle, and no
//! second name convention to keep in sync. The host-side refresher is the only
//! component that ever reads it, and it only ever goes out as the HTTP Basic
//! credential of the client-credentials grant.
//!
//! The refresher runs inside the per-VM network endpoint — the one host
//! process that already holds the binding-aware resolver — so a running VM
//! re-arms its own tokens instead of ever tripping
//! [`ResolveError::OAuthRefreshRequired`](super::ResolveError::OAuthRefreshRequired).
//! Scheduling is timer-driven: expiry is a pure time condition, so each loop
//! sleeps until one lead-time before the resolver's refusal skew, exchanges,
//! and re-arms from the freshly stored expiry. The store itself is owned by
//! the operator and the endpoint-capture path, so every pass re-reads the
//! stored set rather than caching it; a token endpoint that stays unreachable
//! leaves the store untouched and the loop gives up, after which resolution
//! fails closed exactly as it does today.
//!
//! The client secret leaves the host only to an `https` token endpoint (checked
//! when the bindings are discovered), only to a destination the VM's network
//! policy admits (checked by the injected destination check before every
//! exchange), and every outcome is reported to the injected
//! [`OAuthRefreshObserver`], which the endpoint backs with its chain-signed
//! audit recorder.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use mvm_core::crypto::secret_binding::{BindingStore, OAuthBindingMeta};
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_http::resolve::Resolve;
use tracing::{info, warn};

use super::resolver::{
    CapturedOAuthToken, OAUTH_REFRESH_SKEW, OAuthSecretString, OAuthTokenSet, SecretResolver,
};

/// JSON pointer of the access token in a token response when the binding does
/// not name one.
const DEFAULT_ACCESS_TOKEN_POINTER: &str = "/access_token";

/// How far ahead of the resolver's refusal skew the proactive exchange fires,
/// leaving room for the retry budget below to run before resolution would
/// start refusing.
const REFRESH_LEAD: Duration = Duration::seconds(60);

/// Ceiling for one token-endpoint round trip.
pub(crate) const EXCHANGE_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Bound on a token response body. Token responses are small JSON documents;
/// anything bigger is not one.
const MAX_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;

/// Backoff between failed exchange attempts, and how many consecutive
/// failures end the loop. Twelve ten-second retries cover the two-minute
/// window between the proactive deadline and expiry; past that the token is
/// gone and resolution failing closed is the correct behavior.
const RETRY_INTERVAL: StdDuration = StdDuration::from_secs(10);
const MAX_CONSECUTIVE_FAILURES: u32 = 12;

/// The stored value for an OAuth binding whose tokens have never been
/// minted: it carries only the client secret the host-side refresher
/// exchanges with. The expiry sits in the past so resolution refuses (and
/// the refresher treats the set as due) until the first real exchange lands.
#[must_use]
pub fn initial_token_set(client_secret: &str) -> OAuthTokenSet {
    OAuthTokenSet {
        access_token: OAuthSecretString::from(String::new()),
        refresh_token: None,
        client_secret: Some(OAuthSecretString::from(client_secret.to_owned())),
        expires_at: DateTime::UNIX_EPOCH,
    }
}

/// Extract the token set a token endpoint (or any captured JSON response)
/// carries, honouring the binding's access-token pointer. Shared by the
/// endpoint's response capture and the refresher's exchange.
pub(crate) fn parse_token_response(
    pointer: Option<&str>,
    json: &serde_json::Value,
) -> Option<CapturedOAuthToken> {
    let pointer = match pointer {
        Some(pointer) if !pointer.is_empty() => pointer,
        _ => DEFAULT_ACCESS_TOKEN_POINTER,
    };
    let access_token = json.pointer(pointer).and_then(serde_json::Value::as_str)?;
    let refresh_token = json
        .pointer("/refresh_token")
        .and_then(serde_json::Value::as_str)
        .map(|value| super::resolver::OAuthSecretString::from(value.to_owned()));
    let expires_at = json
        .pointer("/expires_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .or_else(|| {
            json.pointer("/expires_in")
                .and_then(serde_json::Value::as_i64)
                .and_then(Duration::try_seconds)
                .map(|ttl| Utc::now() + ttl)
        });
    Some(CapturedOAuthToken {
        access_token: super::resolver::OAuthSecretString::from(access_token.to_owned()),
        refresh_token,
        expires_at,
    })
}

/// The form body of the client-credentials grant. Client authentication rides
/// in the HTTP Basic credential, so the body carries only the grant type and
/// the requested scopes.
fn grant_body(scopes: &[String]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", "client_credentials");
    if !scopes.is_empty() {
        serializer.append_pair("scope", &scopes.join(" "));
    }
    serializer.finish()
}

/// Refuse a token endpoint the client secret must not be sent to: anything but
/// an absolute `https` URL naming a host. The grant carries the client secret
/// as an HTTP Basic credential, so a cleartext endpoint would put it on the
/// wire unprotected.
pub(crate) fn require_https_token_url(token_url: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(token_url).context("token_url is not an absolute URL")?;
    if url.scheme() != "https" {
        anyhow::bail!(
            "token_url scheme is `{}`; the client secret is only ever sent over https",
            url.scheme()
        );
    }
    if url.host_str().is_none_or(str::is_empty) {
        anyhow::bail!("token_url names no host");
    }
    Ok(())
}

/// The host of a binding's token endpoint: the destination recorded in audit
/// entries. Never the full URL — a path or query can carry anything.
fn token_endpoint_host(token_url: &str) -> String {
    url::Url::parse(token_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// How long to wait before proactively refreshing a token set with this
/// expiry. Zero or negative means the exchange is already due.
pub(crate) fn refresh_in(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    expires_at - OAUTH_REFRESH_SKEW - REFRESH_LEAD - now
}

/// The token endpoint's destination failed the injected destination check, so
/// nothing was sent to it. Kept as its own type so the refresh loop can tell a
/// policy refusal from a transport failure without reading error text.
// allow(secret-debug): a host name and the destination check's error; never a credential
#[derive(Debug, thiserror::Error)]
#[error("token endpoint `{host}` was not admitted: {source}")]
pub struct TokenEndpointNotAdmitted {
    host: String,
    #[source]
    source: std::io::Error,
}

impl TokenEndpointNotAdmitted {
    /// True when the check refused the destination by policy, as opposed to
    /// failing to reach a decision at all.
    #[must_use]
    pub fn is_policy_denial(&self) -> bool {
        self.source.kind() == std::io::ErrorKind::PermissionDenied
    }
}

/// How the refresher reaches a token endpoint: the HTTP client it sends with,
/// and optionally a check every destination must pass before anything is sent.
///
/// The check is separate from the client's resolver because a client routed
/// through an upstream proxy hands name resolution to the proxy, so its
/// resolver never sees the destination. Running the check first keeps the
/// decision on this host whichever way the connection is made.
#[derive(Clone)]
pub struct TokenEndpointClient {
    http: mvm_http::Client,
    destination_check: Option<Arc<dyn Resolve>>,
}

impl TokenEndpointClient {
    #[must_use]
    pub fn new(http: mvm_http::Client) -> Self {
        Self {
            http,
            destination_check: None,
        }
    }

    /// Require every token endpoint to resolve through `check` before an
    /// exchange is attempted. An error, or an empty answer, refuses it.
    #[must_use]
    pub fn with_destination_check(mut self, check: Arc<dyn Resolve>) -> Self {
        self.destination_check = Some(check);
        self
    }

    async fn admit(&self, token_url: &str) -> Result<(), TokenEndpointNotAdmitted> {
        let Some(check) = &self.destination_check else {
            return Ok(());
        };
        let refused = |host: &str, kind, message: &str| TokenEndpointNotAdmitted {
            host: host.to_owned(),
            source: std::io::Error::new(kind, message.to_owned()),
        };
        let url = url::Url::parse(token_url).map_err(|_| {
            refused(
                "",
                std::io::ErrorKind::InvalidInput,
                "token_url is not a URL",
            )
        })?;
        let host = url.host_str().unwrap_or_default().to_owned();
        let Some(port) = url.port_or_known_default() else {
            return Err(refused(
                &host,
                std::io::ErrorKind::InvalidInput,
                "token_url has no port",
            ));
        };
        match check.resolve(host.clone(), port).await {
            Ok(addrs) if addrs.is_empty() => Err(refused(
                &host,
                std::io::ErrorKind::PermissionDenied,
                "no admitted address",
            )),
            Ok(_) => Ok(()),
            Err(source) => Err(TokenEndpointNotAdmitted { host, source }),
        }
    }
}

impl From<mvm_http::Client> for TokenEndpointClient {
    fn from(http: mvm_http::Client) -> Self {
        Self::new(http)
    }
}

/// POST the client-credentials grant to the binding's token endpoint and
/// parse the token set out of the response. Any failure — a destination the
/// client's check refuses, unreachable endpoint, non-success status,
/// unparseable body, no access token — is an error and writes nothing: the
/// caller's fail-closed behavior is to leave the stored set alone.
pub async fn exchange_client_credentials(
    client: &TokenEndpointClient,
    meta: &OAuthBindingMeta,
    client_secret: &str,
) -> anyhow::Result<CapturedOAuthToken> {
    client.admit(&meta.token_url).await?;
    let response = client
        .http
        .post(&meta.token_url)
        .basic_auth(&meta.client_id, Some(client_secret))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(grant_body(&meta.scopes).into_bytes())
        .timeout(EXCHANGE_TIMEOUT)
        .max_response_bytes(MAX_TOKEN_RESPONSE_BYTES)
        .send()
        .await
        .context("posting the client-credentials grant to the token endpoint")?;
    if !response.status().is_success() {
        // The status is safe to log; the body is not — error pages can echo
        // the submitted credential.
        anyhow::bail!("token endpoint returned {}", response.status());
    }
    let json: serde_json::Value = response
        .json()
        .await
        .context("parsing the token endpoint response body")?;
    parse_token_response(meta.response_access_token_pointer.as_deref(), &json)
        .ok_or_else(|| anyhow::anyhow!("token endpoint response carried no access token"))
}

/// True when `error` is a destination check's policy refusal.
fn is_policy_denial(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<TokenEndpointNotAdmitted>()
            .is_some_and(TokenEndpointNotAdmitted::is_policy_denial)
    })
}

/// How one step of a refresh loop ended. Each variant has a fixed label, so
/// the audit record of a refresh carries no error text — an error from a
/// token endpoint can echo the credential it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthRefreshOutcome {
    /// The exchange succeeded and the fresh token set was stored.
    Refreshed,
    /// An exchange attempt failed; the loop will retry.
    Failed,
    /// The network policy refused the token endpoint; nothing was sent.
    PolicyDenied,
    /// The loop gave up: retries exhausted, the token expired first, the
    /// stored set has no client secret, the store stayed unreadable, or the
    /// policy refused the endpoint.
    Stopped,
}

impl OAuthRefreshOutcome {
    /// The fixed label recorded in the chain.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Refreshed => "refreshed",
            Self::Failed => "failed",
            Self::PolicyDenied => "policy_denied",
            Self::Stopped => "stopped",
        }
    }
}

/// Told how each refresh step ended. The endpoint implements this over its
/// chain-signed audit recorder; a failure to record is the observer's to log,
/// never the loop's to act on.
#[async_trait::async_trait]
pub trait OAuthRefreshObserver: Send + Sync {
    async fn refresh_outcome(
        &self,
        secret_name: &str,
        destination: &str,
        outcome: OAuthRefreshOutcome,
    );
}

/// One OAuth-bound secret the endpoint should keep fresh: its store name and
/// the non-secret flow metadata from its binding.
#[derive(Debug, Clone)]
pub struct OAuthRefreshBinding {
    pub name: String,
    pub meta: OAuthBindingMeta,
}

/// The OAuth-bound secrets of a plan, in plan order. Only `Keystore` sources
/// resolve through the local stores; a `Keystore` secret without a recorded
/// binding is an assembly error, matching `bound_hosts`, and so is an OAuth
/// binding whose token endpoint is not `https`.
pub fn discover_oauth_bindings(
    plan_secrets: &[SecretBinding],
    tenant: &str,
    bindings: &dyn BindingStore,
) -> anyhow::Result<Vec<OAuthRefreshBinding>> {
    let mut out = Vec::new();
    for secret in plan_secrets {
        let SecretSource::Keystore { address } = &secret.source else {
            continue;
        };
        let meta = bindings
            .get(tenant, address)
            .with_context(|| {
                format!(
                    "reading the local binding of secret `{address}` for oauth refresh discovery"
                )
            })?
            .with_context(|| {
                format!("secret `{address}` has no local binding for oauth refresh discovery")
            })?;
        if let Some(oauth) = meta.oauth {
            require_https_token_url(&oauth.token_url).with_context(|| {
                format!("secret `{address}` has an oauth token endpoint the refresher refuses")
            })?;
            out.push(OAuthRefreshBinding {
                name: address.clone(),
                meta: oauth,
            });
        }
    }
    Ok(out)
}

/// Perform one client-credentials exchange for a bound secret and persist
/// the fresh token set through the resolver's capture-persistence path (which
/// preserves the stored client secret). This is the unit the refresh loop
/// schedules; it is also the recovery handle for a secret whose token set is
/// already past the refusal skew.
pub async fn refresh_once(
    resolver: &Arc<dyn SecretResolver>,
    client: &TokenEndpointClient,
    name: &str,
    meta: &OAuthBindingMeta,
) -> anyhow::Result<()> {
    let token_set = resolver
        .oauth_token_set(name)
        .with_context(|| format!("loading stored oauth token set for `{name}`"))?;
    let client_secret = token_set.client_secret.ok_or_else(|| {
        anyhow::anyhow!("stored oauth token set for `{name}` has no client secret; the client-credentials grant cannot be driven")
    })?;
    let captured = exchange_client_credentials(client, meta, client_secret.expose_secret()).await?;
    resolver
        .store_captured_oauth_token(name, captured)
        .with_context(|| format!("persisting refreshed oauth token set for `{name}`"))
}

/// Everything one refresh loop needs besides its binding. Cloned into each
/// spawned loop.
#[derive(Clone)]
struct RefreshSettings {
    resolver: Arc<dyn SecretResolver>,
    client: TokenEndpointClient,
    observer: Option<Arc<dyn OAuthRefreshObserver>>,
    retry_interval: StdDuration,
    max_failures: u32,
}

impl RefreshSettings {
    async fn report(&self, secret_name: &str, destination: &str, outcome: OAuthRefreshOutcome) {
        if let Some(observer) = &self.observer {
            observer
                .refresh_outcome(secret_name, destination, outcome)
                .await;
        }
    }

    /// The loop is ending without a fresh token set; `reason` is for the log
    /// only, the chain records the fixed `stopped` label.
    async fn stopped(&self, secret_name: &str, destination: &str, reason: &str) {
        warn!(secret = %secret_name, reason, "oauth proactive refresh stopped; resolution fails closed once the token expires");
        self.report(secret_name, destination, OAuthRefreshOutcome::Stopped)
            .await;
    }
}

/// Owns the proactive-refresh loops for every OAuth-bound secret of a VM.
/// Built at endpoint assembly over the same resolver the substitution service
/// uses; `start` spawns one timer-driven loop per binding on the current
/// runtime.
pub struct OAuthRefreshDriver {
    settings: RefreshSettings,
    bindings: Vec<OAuthRefreshBinding>,
}

impl OAuthRefreshDriver {
    /// A driver with a default HTTP client, no destination check, and no
    /// observer. The endpoint replaces all three before starting it.
    #[must_use]
    pub fn new(resolver: Arc<dyn SecretResolver>, bindings: Vec<OAuthRefreshBinding>) -> Self {
        Self {
            settings: RefreshSettings {
                resolver,
                client: TokenEndpointClient::new(mvm_http::Client::new()),
                observer: None,
                retry_interval: RETRY_INTERVAL,
                max_failures: MAX_CONSECUTIVE_FAILURES,
            },
            bindings,
        }
    }

    /// Send every exchange through `client`, keeping any destination check
    /// already installed.
    #[must_use]
    pub fn with_http_client(mut self, client: mvm_http::Client) -> Self {
        self.settings.client.http = client;
        self
    }

    /// Refuse any token endpoint `check` does not resolve. See
    /// [`TokenEndpointClient::with_destination_check`].
    #[must_use]
    pub fn with_destination_check(mut self, check: Arc<dyn Resolve>) -> Self {
        self.settings.client = self.settings.client.with_destination_check(check);
        self
    }

    /// Report every refresh outcome to `observer`.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn OAuthRefreshObserver>) -> Self {
        self.settings.observer = Some(observer);
        self
    }

    /// Shrink the retry budget (tests exchange against a mock endpoint and
    /// must not sit through production backoffs).
    #[must_use]
    pub fn with_retry_policy(mut self, retry_interval: StdDuration, max_failures: u32) -> Self {
        self.settings.retry_interval = retry_interval;
        self.settings.max_failures = max_failures;
        self
    }

    #[must_use]
    pub fn bindings(&self) -> &[OAuthRefreshBinding] {
        &self.bindings
    }

    /// Spawn one refresh loop per discovered binding. Loops are detached:
    /// the endpoint process is killed with its VM, which is the shutdown
    /// signal.
    pub fn start(self) {
        for binding in self.bindings {
            tokio::spawn(refresh_loop(self.settings.clone(), binding));
        }
    }

    /// Run every binding's loop in turn until each ends, so a test can
    /// observe what a loop did without the detached tasks of `start`.
    #[cfg(test)]
    pub(crate) async fn run_to_completion(self) {
        for binding in self.bindings {
            refresh_loop(self.settings.clone(), binding).await;
        }
    }
}

/// Keep one secret's token set fresh for as long as the endpoint runs.
///
/// Timer-driven by construction: each pass reads the stored expiry (the store
/// is externally owned, so it is re-read rather than trusted from memory),
/// sleeps until the proactive deadline, exchanges, and re-arms from the new
/// expiry. Any persistent failure leaves the stored set untouched and ends
/// the loop — resolution then fails closed with `OAuthRefreshRequired`,
/// matching a host that never had a refresher. A policy refusal ends it at
/// once: the VM's admitted policy does not change while it runs, so a retry
/// would be refused the same way.
///
/// Every exchange attempt, and the end of the loop, is reported to the
/// observer.
async fn refresh_loop(settings: RefreshSettings, binding: OAuthRefreshBinding) {
    let destination = token_endpoint_host(&binding.meta.token_url);
    let mut failures = 0u32;
    loop {
        let token_set = match settings.resolver.oauth_token_set(&binding.name) {
            Ok(token_set) => token_set,
            Err(error) => {
                failures += 1;
                if failures >= settings.max_failures {
                    warn!(secret = %binding.name, %error, "oauth token set unreadable");
                    settings
                        .stopped(&binding.name, &destination, "token set unreadable")
                        .await;
                    return;
                }
                warn!(secret = %binding.name, %error, "oauth token set unreadable; retrying");
                tokio::time::sleep(settings.retry_interval).await;
                continue;
            }
        };
        if token_set.client_secret.is_none() {
            settings
                .stopped(
                    &binding.name,
                    &destination,
                    "stored token set has no client secret",
                )
                .await;
            return;
        }
        let wait = refresh_in(token_set.expires_at, Utc::now());
        if wait > Duration::zero()
            && let Ok(wait) = wait.to_std()
        {
            tokio::time::sleep(wait).await;
        }
        if Utc::now() >= token_set.expires_at {
            warn!(secret = %binding.name, expires_at = %token_set.expires_at, "oauth token expired before a refresh succeeded");
            settings
                .stopped(
                    &binding.name,
                    &destination,
                    "token expired before a refresh succeeded",
                )
                .await;
            return;
        }
        match refresh_once(
            &settings.resolver,
            &settings.client,
            &binding.name,
            &binding.meta,
        )
        .await
        {
            Ok(()) => {
                info!(secret = %binding.name, expires_at = %token_set.expires_at, "proactively refreshed oauth token set");
                settings
                    .report(&binding.name, &destination, OAuthRefreshOutcome::Refreshed)
                    .await;
                failures = 0;
            }
            Err(error) if is_policy_denial(&error) => {
                warn!(secret = %binding.name, %error, "oauth token endpoint refused by the network policy");
                settings
                    .report(
                        &binding.name,
                        &destination,
                        OAuthRefreshOutcome::PolicyDenied,
                    )
                    .await;
                settings
                    .stopped(
                        &binding.name,
                        &destination,
                        "token endpoint refused by the network policy",
                    )
                    .await;
                return;
            }
            Err(error) => {
                failures += 1;
                settings
                    .report(&binding.name, &destination, OAuthRefreshOutcome::Failed)
                    .await;
                if failures >= settings.max_failures {
                    warn!(secret = %binding.name, %error, "oauth refresh failed");
                    settings
                        .stopped(&binding.name, &destination, "retries exhausted")
                        .await;
                    return;
                }
                warn!(secret = %binding.name, %error, failures, "oauth refresh failed; retrying");
                tokio::time::sleep(settings.retry_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_binding::{FileBindingStore, SecretBindingMeta};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use secrecy::{ExposeSecret, SecretBox};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempfile::tempdir;

    use chrono::Datelike as _;

    use crate::keyholder::resolver::{
        LocalResolver, OAuthSecretString, OAuthTokenSet, ResolveError, SecretResolver,
    };
    use crate::supervisor::audit::CapturingAuditSigner;
    use crate::supervisor::audit_recorder::Recorder;

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env {
                var: "API_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
            inject: Default::default(),
        }
    }

    fn oauth_meta(token_url: &str) -> OAuthBindingMeta {
        OAuthBindingMeta {
            authorization_url: "https://auth.example.com/authorize".into(),
            token_url: token_url.into(),
            client_id: "public-client-id".into(),
            scopes: vec!["scope-a".into(), "scope b".into()],
            response_access_token_pointer: None,
        }
    }

    fn oauth_binding_meta(token_url: &str) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.example.com".into()],
            sigv4: None,
            inject: Default::default(),
            provider: None,
            approve: Default::default(),
            oauth: Some(oauth_meta(token_url)),
        }
    }

    fn expired_token_set(access_token: &str, client_secret: Option<&str>) -> OAuthTokenSet {
        OAuthTokenSet {
            access_token: OAuthSecretString::from(access_token.to_owned()),
            refresh_token: Some(OAuthSecretString::from(String::from("old-refresh-token"))),
            client_secret: client_secret.map(|value| OAuthSecretString::from(value.to_owned())),
            expires_at: Utc::now() + Duration::seconds(30),
        }
    }

    struct StoreFixture {
        _dir: tempfile::TempDir,
        store: Arc<FileSecretStore>,
        bindings: Arc<FileBindingStore>,
    }

    fn fixture(token_set: &OAuthTokenSet, token_url: &str) -> StoreFixture {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "oauth-secret",
                &SecretBox::new(Box::new(serde_json::to_string(token_set).unwrap())),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "oauth-secret", &oauth_binding_meta(token_url))
            .unwrap();
        StoreFixture {
            _dir: dir,
            store: Arc::new(store),
            bindings: Arc::new(bindings),
        }
    }

    fn resolver_over(fixture: &StoreFixture) -> Arc<dyn SecretResolver> {
        Arc::new(LocalResolver::with_bindings(
            "local",
            fixture.store.clone(),
            fixture.bindings.clone(),
        ))
    }

    fn stored_token_set(fixture: &StoreFixture) -> OAuthTokenSet {
        serde_json::from_str(
            fixture
                .store
                .get("local", "oauth-secret")
                .unwrap()
                .expose_secret(),
        )
        .unwrap()
    }

    /// What the mock token endpoint saw on one request.
    #[derive(Debug, Default)]
    struct RecordedRequest {
        request_line: String,
        authorization: Option<String>,
        content_type: Option<String>,
        body: String,
    }

    /// A one-endpoint HTTP mock: accepts on a background thread, records each
    /// request, and answers every one with the same canned response.
    fn spawn_mock_token_server(
        status: &str,
        response_body: &str,
    ) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_owned();
        let response_body = response_body.to_owned();
        let recorded: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let thread_recorded = Arc::clone(&recorded);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                let Ok(request) = read_http_request(&mut stream) else {
                    continue;
                };
                thread_recorded
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                    response_body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://{addr}/token"), recorded)
    }

    /// Read one HTTP/1.1 request: head until the blank line, then the
    /// declared body.
    fn read_http_request(stream: &mut std::net::TcpStream) -> std::io::Result<RecordedRequest> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte)? == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        let mut request_line = String::new();
        let mut authorization = None;
        let mut content_type = None;
        let mut content_length = 0usize;
        for (index, line) in head.split("\r\n").enumerate() {
            if index == 0 {
                request_line = line.to_string();
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.trim().to_string()),
                "content-type" => content_type = Some(value.trim().to_string()),
                "content-length" => {
                    content_length = value.trim().parse().unwrap_or_default();
                }
                _ => {}
            }
        }
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body)?;
        Ok(RecordedRequest {
            request_line,
            authorization,
            content_type,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// A port nothing is listening on.
    fn refused_token_url() -> String {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}/token")
    }

    fn binding_for(token_url: &str) -> OAuthRefreshBinding {
        OAuthRefreshBinding {
            name: "oauth-secret".into(),
            meta: oauth_meta(token_url),
        }
    }

    /// A chain-signing recorder whose entries the test can read back.
    fn capturing_recorder() -> (Arc<Recorder>, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(
            signer.clone(),
            mvm_core::plan::TenantId("local".into()),
        ));
        (recorder, signer)
    }

    /// The `outcome` labels of the `secret.oauth_refresh` entries, in order.
    fn refresh_outcomes(signer: &CapturingAuditSigner) -> Vec<String> {
        signer
            .entries()
            .iter()
            .filter(|entry| entry.event == "secret.oauth_refresh")
            .map(|entry| entry.labels["outcome"].clone())
            .collect()
    }

    /// A loop over `fixture` that reports to `recorder` and retries fast.
    fn audited_driver(fixture: &StoreFixture, recorder: Arc<Recorder>) -> OAuthRefreshDriver {
        OAuthRefreshDriver::new(resolver_over(fixture), vec![])
            .with_retry_policy(StdDuration::from_millis(10), 3)
            .with_observer(recorder)
    }

    /// A destination check that refuses every destination with `kind`.
    #[derive(Debug)]
    struct RefusingCheck(std::io::ErrorKind);

    impl Resolve for RefusingCheck {
        fn resolve(
            &self,
            _host: String,
            _port: u16,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            let kind = self.0;
            Box::pin(async move { Err(std::io::Error::new(kind, "refused by the test check")) })
        }
    }

    // -- pure logic ------------------------------------------------------

    #[test]
    fn initial_token_set_carries_only_the_client_secret() {
        let set = initial_token_set("the-client-secret");
        assert_eq!(
            set.client_secret.unwrap().expose_secret(),
            "the-client-secret"
        );
        assert!(set.access_token.expose_secret().is_empty());
        assert!(set.refresh_token.is_none());
        // An expiry in the past: resolution refuses, the refresher treats
        // the set as due, and any captured merge only moves it forward.
        assert!(set.expires_at < Utc::now());
    }

    #[test]
    fn grant_body_carries_grant_type_and_scopes() {
        // form-urlencoding renders the RFC 6068-style space separator as `+`.
        let body = grant_body(&["scope-a".into(), "scope b".into()]);
        assert_eq!(body, "grant_type=client_credentials&scope=scope-a+scope+b");
        assert_eq!(grant_body(&[]), "grant_type=client_credentials");
    }

    #[test]
    fn refresh_in_leads_the_resolver_skew() {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(10);
        let wait = refresh_in(expires_at, now);
        // 10 minutes to expiry minus the 60 s skew and 60 s lead.
        assert!(wait <= Duration::seconds(480));
        assert!(wait > Duration::seconds(470));
        // Within the lead window the exchange is already due.
        assert!(refresh_in(now + Duration::seconds(90), now) <= Duration::zero());
        // A past expiry is due immediately, not a negative-duration panic.
        assert!(refresh_in(now - Duration::seconds(5), now) <= Duration::zero());
    }

    #[test]
    fn parse_token_response_reads_pointer_tokens_and_expiry() {
        let json = serde_json::json!({
            "access_token": "default-access",
            "nested": {"token": "access-1"},
            "refresh_token": "refresh-1",
            "expires_in": 300,
        });
        let token = parse_token_response(None, &json).unwrap();
        assert_eq!(token.access_token.expose_secret(), "default-access");
        assert_eq!(
            token.refresh_token.as_ref().unwrap().expose_secret(),
            "refresh-1"
        );
        let ttl = token.expires_at.unwrap() - Utc::now();
        assert!(ttl <= Duration::seconds(300));
        assert!(ttl > Duration::seconds(290));

        let custom = parse_token_response(Some("/nested/token"), &json).unwrap();
        assert_eq!(custom.access_token.expose_secret(), "access-1");
        // An empty pointer falls back to the default.
        let defaulted = parse_token_response(Some(""), &serde_json::json!({"access_token": "a"}));
        assert_eq!(defaulted.unwrap().access_token.expose_secret(), "a");
    }

    #[test]
    fn parse_token_response_prefers_absolute_expiry() {
        let json = serde_json::json!({
            "access_token": "access-1",
            "expires_in": 300,
            "expires_at": "2999-01-01T00:00:00Z",
        });
        let token = parse_token_response(None, &json).unwrap();
        assert!(token.expires_at.unwrap().year() > 2500);
    }

    #[test]
    fn parse_token_response_rejects_missing_or_non_string_tokens() {
        assert!(parse_token_response(None, &serde_json::json!({"token": 42})).is_none());
        assert!(parse_token_response(None, &serde_json::json!({"access_token": 7})).is_none());
        assert!(parse_token_response(None, &serde_json::json!({})).is_none());
    }

    #[test]
    fn require_https_token_url_accepts_only_absolute_https_with_a_host() {
        require_https_token_url("https://auth.example.com/token").unwrap();
        require_https_token_url("https://auth.example.com:8443/oauth/token?x=1").unwrap();
        for refused in [
            "http://auth.example.com/token",
            "ftp://auth.example.com/token",
            "/token",
            "auth.example.com/token",
            "",
            "https://",
            "https:",
            "file:///etc/token",
        ] {
            assert!(
                require_https_token_url(refused).is_err(),
                "`{refused}` must be refused"
            );
        }
    }

    #[test]
    fn token_endpoint_host_is_the_host_only() {
        assert_eq!(
            token_endpoint_host("https://auth.example.com:8443/oauth/token?client=x"),
            "auth.example.com"
        );
        assert_eq!(token_endpoint_host("not a url"), "");
    }

    #[test]
    fn discover_refuses_a_cleartext_token_endpoint_and_names_the_secret() {
        let dir = tempdir().unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "cleartext-secret",
                &oauth_binding_meta("http://auth.example.com/token"),
            )
            .unwrap();
        let plan = SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "cleartext-secret".into(),
            },
            destinations: vec![],
        };
        let err = discover_oauth_bindings(&[plan], "local", &bindings).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("cleartext-secret"), "{message}");
        assert!(message.contains("https"), "{message}");
    }

    #[test]
    fn discover_collects_only_keystore_oauth_bindings() {
        let dir = tempdir().unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "oauth-secret",
                &oauth_binding_meta("https://auth.example.com/token"),
            )
            .unwrap();
        let mut plain = oauth_binding_meta("https://auth.example.com/token");
        plain.oauth = None;
        bindings.put("local", "plain-secret", &plain).unwrap();

        let oauth_plan = SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "oauth-secret".into(),
            },
            destinations: vec![],
            approval_required: false,
        };
        let plain_plan = SecretBinding {
            name: "PLAIN".into(),
            source: SecretSource::Keystore {
                address: "plain-secret".into(),
            },
            destinations: vec![],
            approval_required: false,
        };
        let external_plan = SecretBinding {
            name: "EXT".into(),
            source: SecretSource::External {
                provider: "vault".into(),
                path: "secret/x".into(),
            },
            destinations: vec![],
            approval_required: false,
        };

        let found =
            discover_oauth_bindings(&[oauth_plan, plain_plan, external_plan], "local", &bindings)
                .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "oauth-secret");
        assert_eq!(found[0].meta.client_id, "public-client-id");
    }

    #[test]
    fn discover_errors_when_a_keystore_binding_is_missing() {
        let dir = tempdir().unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        let plan = SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "absent".into(),
            },
            destinations: vec![],
            approval_required: false,
        };
        let err = discover_oauth_bindings(&[plan], "local", &bindings).unwrap_err();
        assert!(format!("{err:#}").contains("absent"));
    }

    // -- exchange wiring ---------------------------------------------------

    #[tokio::test]
    async fn refresh_once_exchanges_and_resolution_returns_the_new_token() {
        let (token_url, recorded) = spawn_mock_token_server(
            "200 OK",
            r#"{"access_token":"fresh-access-token","refresh_token":"fresh-refresh-token","expires_in":3600}"#,
        );
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);

        // Precondition: the stale set is inside the refusal skew.
        let err = resolver
            .resolve(&bearer_ref("oauth-secret", &["api.example.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::OAuthRefreshRequired { .. }));

        refresh_once(
            &resolver,
            &TokenEndpointClient::new(mvm_http::Client::new()),
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap();

        // The grant went out as client-credentials with the Basic credential.
        let requests = recorded.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert!(requests[0].request_line.starts_with("POST /token "));
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Basic cHVibGljLWNsaWVudC1pZDp0aGUtY2xpZW50LXNlY3JldA==")
        );
        assert_eq!(
            requests[0].content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            requests[0].body,
            "grant_type=client_credentials&scope=scope-a+scope+b"
        );
        drop(requests);

        // The witness: resolution now returns the new access token, no error.
        let secret = resolver
            .resolve(&bearer_ref("oauth-secret", &["api.example.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"fresh-access-token");

        // The persisted set merged the response and kept the client secret.
        let stored = stored_token_set(&fixture);
        assert_eq!(stored.access_token.expose_secret(), "fresh-access-token");
        assert_eq!(
            stored.refresh_token.unwrap().expose_secret(),
            "fresh-refresh-token"
        );
        assert_eq!(
            stored.client_secret.unwrap().expose_secret(),
            "the-client-secret"
        );
        let ttl = stored.expires_at - Utc::now();
        assert!(ttl <= Duration::seconds(3600));
        assert!(ttl > Duration::seconds(3500));
    }

    #[tokio::test]
    async fn refresh_once_with_unreachable_endpoint_fails_closed() {
        let token_url = refused_token_url();
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        let err = refresh_once(
            &resolver,
            &TokenEndpointClient::new(mvm_http::Client::new()),
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("token endpoint"));

        // Nothing was written: the stale set is intact and still refuses.
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "stale-access-token"
        );
        let err = resolver
            .resolve(&bearer_ref("oauth-secret", &["api.example.com"]))
            .unwrap_err();
        assert!(matches!(err, ResolveError::OAuthRefreshRequired { .. }));
    }

    #[tokio::test]
    async fn refresh_once_with_error_status_writes_nothing() {
        let (token_url, _) =
            spawn_mock_token_server("500 Internal Server Error", r#"{"error":"boom"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        let err = refresh_once(
            &resolver,
            &TokenEndpointClient::new(mvm_http::Client::new()),
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("500"));
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "stale-access-token"
        );
    }

    #[tokio::test]
    async fn refresh_once_rejects_a_response_without_access_token() {
        let (token_url, _) = spawn_mock_token_server("200 OK", r#"{"token":"not-here"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        let err = refresh_once(
            &resolver,
            &TokenEndpointClient::new(mvm_http::Client::new()),
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("no access token"));
    }

    #[tokio::test]
    async fn refresh_once_refuses_to_drive_a_flow_without_client_secret() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let fixture = fixture(&expired_token_set("stale-access-token", None), &token_url);
        let resolver = resolver_over(&fixture);
        let err = refresh_once(
            &resolver,
            &TokenEndpointClient::new(mvm_http::Client::new()),
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("no client secret"));
        // The endpoint was never contacted.
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_refused_destination_is_never_contacted_and_reads_as_a_policy_denial() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        let client = TokenEndpointClient::new(mvm_http::Client::new()).with_destination_check(
            Arc::new(RefusingCheck(std::io::ErrorKind::PermissionDenied)),
        );
        let err = refresh_once(&resolver, &client, "oauth-secret", &oauth_meta(&token_url))
            .await
            .unwrap_err();
        assert!(is_policy_denial(&err), "{err:#}");
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "stale-access-token"
        );
    }

    #[tokio::test]
    async fn a_check_that_cannot_decide_still_blocks_but_is_not_a_policy_denial() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let client = TokenEndpointClient::new(mvm_http::Client::new())
            .with_destination_check(Arc::new(RefusingCheck(std::io::ErrorKind::Other)));
        let err = refresh_once(
            &resolver_over(&fixture),
            &client,
            "oauth-secret",
            &oauth_meta(&token_url),
        )
        .await
        .unwrap_err();
        assert!(!is_policy_denial(&err), "{err:#}");
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn a_transport_failure_is_not_a_policy_denial() {
        let err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "a permission error from somewhere else",
        ));
        assert!(!is_policy_denial(&err));
    }

    // -- the proactive loop ------------------------------------------------

    #[tokio::test]
    async fn refresh_loop_heals_a_stale_set_rearms_and_records_the_refresh() {
        let (token_url, recorded) = spawn_mock_token_server(
            "200 OK",
            r#"{"access_token":"fresh-access-token","expires_in":3600}"#,
        );
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let (recorder, signer) = capturing_recorder();
        let driver = audited_driver(&fixture, recorder);
        // The loop re-arms after the exchange and sleeps toward the new
        // deadline; the timeout cancels that sleep — the assertions below
        // are what matters.
        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            refresh_loop(driver.settings, binding_for(&token_url)),
        )
        .await;
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "fresh-access-token"
        );
        assert_eq!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );
        assert_eq!(refresh_outcomes(&signer), ["refreshed"]);
        let entry = &signer.entries()[0];
        assert_eq!(entry.labels["name"], "oauth-secret");
        assert_eq!(entry.labels["destination"], "127.0.0.1");
        // Metadata only: no credential, token, or URL reaches the chain.
        let chain = serde_json::to_string(&signer.entries()).unwrap();
        for leaked in ["the-client-secret", "fresh-access-token", "/token"] {
            assert!(!chain.contains(leaked), "found `{leaked}` in {chain}");
        }
    }

    #[tokio::test]
    async fn refresh_loop_gives_up_on_an_expired_set_without_exchanging() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let mut token_set = expired_token_set("stale-access-token", Some("the-client-secret"));
        token_set.expires_at = Utc::now() - Duration::seconds(5);
        let fixture = fixture(&token_set, &token_url);
        let (recorder, signer) = capturing_recorder();
        refresh_loop(
            audited_driver(&fixture, recorder).settings,
            binding_for(&token_url),
        )
        .await;
        // Expired is expired: no exchange can help, and none was attempted.
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert_eq!(refresh_outcomes(&signer), ["stopped"]);
    }

    #[tokio::test]
    async fn refresh_loop_retries_a_failing_endpoint_then_gives_up() {
        let (token_url, recorded) =
            spawn_mock_token_server("503 Service Unavailable", r#"{"error":"down"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let (recorder, signer) = capturing_recorder();
        refresh_loop(
            audited_driver(&fixture, recorder).settings,
            binding_for(&token_url),
        )
        .await;
        // Three attempts, then the loop ended fail-closed with the store
        // untouched.
        assert_eq!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            3
        );
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "stale-access-token"
        );
        // Every attempt is recorded, then the loop's end.
        assert_eq!(
            refresh_outcomes(&signer),
            ["failed", "failed", "failed", "stopped"]
        );
    }

    #[tokio::test]
    async fn refresh_loop_stops_at_the_first_policy_denial() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let (recorder, signer) = capturing_recorder();
        let driver = audited_driver(&fixture, recorder).with_destination_check(Arc::new(
            RefusingCheck(std::io::ErrorKind::PermissionDenied),
        ));
        refresh_loop(driver.settings, binding_for(&token_url)).await;
        // The admitted policy does not change while the VM runs, so one
        // refusal ends the loop instead of spending the retry budget.
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert_eq!(refresh_outcomes(&signer), ["policy_denied", "stopped"]);
    }

    #[tokio::test]
    async fn refresh_loop_without_an_observer_records_nothing_and_still_refreshes() {
        let (token_url, _) = spawn_mock_token_server(
            "200 OK",
            r#"{"access_token":"fresh-access-token","expires_in":3600}"#,
        );
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let driver = OAuthRefreshDriver::new(resolver_over(&fixture), vec![])
            .with_retry_policy(StdDuration::from_millis(10), 3);
        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            refresh_loop(driver.settings, binding_for(&token_url)),
        )
        .await;
        assert_eq!(
            stored_token_set(&fixture).access_token.expose_secret(),
            "fresh-access-token"
        );
    }
}
