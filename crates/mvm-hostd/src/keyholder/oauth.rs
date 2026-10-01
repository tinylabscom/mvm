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

use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use mvm_core::crypto::secret_binding::{BindingStore, OAuthBindingMeta};
use mvm_core::plan::{SecretBinding, SecretSource};
use tracing::{info, warn};

use super::resolver::{CapturedOAuthToken, OAUTH_REFRESH_SKEW, SecretResolver};

/// JSON pointer of the access token in a token response when the binding does
/// not name one.
const DEFAULT_ACCESS_TOKEN_POINTER: &str = "/access_token";

/// How far ahead of the resolver's refusal skew the proactive exchange fires,
/// leaving room for the retry budget below to run before resolution would
/// start refusing.
const REFRESH_LEAD: Duration = Duration::seconds(60);

/// Ceiling for one token-endpoint round trip.
const EXCHANGE_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Bound on a token response body. Token responses are small JSON documents;
/// anything bigger is not one.
const MAX_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;

/// Backoff between failed exchange attempts, and how many consecutive
/// failures end the loop. Twelve ten-second retries cover the two-minute
/// window between the proactive deadline and expiry; past that the token is
/// gone and resolution failing closed is the correct behavior.
const RETRY_INTERVAL: StdDuration = StdDuration::from_secs(10);
const MAX_CONSECUTIVE_FAILURES: u32 = 12;

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

/// How long to wait before proactively refreshing a token set with this
/// expiry. Zero or negative means the exchange is already due.
pub(crate) fn refresh_in(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    expires_at - OAUTH_REFRESH_SKEW - REFRESH_LEAD - now
}

/// POST the client-credentials grant to the binding's token endpoint and
/// parse the token set out of the response. Any failure — unreachable
/// endpoint, non-success status, unparseable body, no access token — is an
/// error and writes nothing: the caller's fail-closed behavior is to leave
/// the stored set alone.
pub async fn exchange_client_credentials(
    http: &mvm_http::Client,
    meta: &OAuthBindingMeta,
    client_secret: &str,
) -> anyhow::Result<CapturedOAuthToken> {
    let response = http
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

/// One OAuth-bound secret the endpoint should keep fresh: its store name and
/// the non-secret flow metadata from its binding.
#[derive(Debug, Clone)]
pub struct OAuthRefreshBinding {
    pub name: String,
    pub meta: OAuthBindingMeta,
}

/// The OAuth-bound secrets of a plan, in plan order. Only `Keystore` sources
/// resolve through the local stores; a `Keystore` secret without a recorded
/// binding is an assembly error, matching `bound_hosts`.
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
    http: &mvm_http::Client,
    name: &str,
    meta: &OAuthBindingMeta,
) -> anyhow::Result<()> {
    let token_set = resolver
        .oauth_token_set(name)
        .with_context(|| format!("loading stored oauth token set for `{name}`"))?;
    let client_secret = token_set.client_secret.ok_or_else(|| {
        anyhow::anyhow!("stored oauth token set for `{name}` has no client secret; the client-credentials grant cannot be driven")
    })?;
    let captured = exchange_client_credentials(http, meta, client_secret.expose_secret()).await?;
    resolver
        .store_captured_oauth_token(name, captured)
        .with_context(|| format!("persisting refreshed oauth token set for `{name}`"))
}

/// Owns the proactive-refresh loops for every OAuth-bound secret of a VM.
/// Built at endpoint assembly over the same resolver the substitution service
/// uses; `start` spawns one timer-driven loop per binding on the current
/// runtime.
pub struct OAuthRefreshDriver {
    resolver: Arc<dyn SecretResolver>,
    http: mvm_http::Client,
    bindings: Vec<OAuthRefreshBinding>,
    retry_interval: StdDuration,
    max_failures: u32,
}

impl OAuthRefreshDriver {
    #[must_use]
    pub fn new(resolver: Arc<dyn SecretResolver>, bindings: Vec<OAuthRefreshBinding>) -> Self {
        Self {
            resolver,
            http: mvm_http::Client::new(),
            bindings,
            retry_interval: RETRY_INTERVAL,
            max_failures: MAX_CONSECUTIVE_FAILURES,
        }
    }

    /// Shrink the retry budget (tests exchange against a mock endpoint and
    /// must not sit through production backoffs).
    #[must_use]
    pub fn with_retry_policy(mut self, retry_interval: StdDuration, max_failures: u32) -> Self {
        self.retry_interval = retry_interval;
        self.max_failures = max_failures;
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
            tokio::spawn(refresh_loop(
                Arc::clone(&self.resolver),
                self.http.clone(),
                binding,
                self.retry_interval,
                self.max_failures,
            ));
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
/// matching a host that never had a refresher.
async fn refresh_loop(
    resolver: Arc<dyn SecretResolver>,
    http: mvm_http::Client,
    binding: OAuthRefreshBinding,
    retry_interval: StdDuration,
    max_failures: u32,
) {
    let mut failures = 0u32;
    loop {
        let token_set = match resolver.oauth_token_set(&binding.name) {
            Ok(token_set) => token_set,
            Err(error) => {
                failures += 1;
                if failures >= max_failures {
                    warn!(secret = %binding.name, %error, "oauth token set unreadable; proactive refresh stopped");
                    return;
                }
                warn!(secret = %binding.name, %error, "oauth token set unreadable; retrying");
                tokio::time::sleep(retry_interval).await;
                continue;
            }
        };
        if token_set.client_secret.is_none() {
            warn!(secret = %binding.name, "stored oauth token set has no client secret; proactive refresh stopped");
            return;
        }
        let wait = refresh_in(token_set.expires_at, Utc::now());
        if wait > Duration::zero()
            && let Ok(wait) = wait.to_std()
        {
            tokio::time::sleep(wait).await;
        }
        if Utc::now() >= token_set.expires_at {
            warn!(secret = %binding.name, expires_at = %token_set.expires_at, "oauth token expired before a refresh succeeded; resolution fails closed until an exchange lands");
            return;
        }
        match refresh_once(&resolver, &http, &binding.name, &binding.meta).await {
            Ok(()) => {
                info!(secret = %binding.name, expires_at = %token_set.expires_at, "proactively refreshed oauth token set");
                failures = 0;
            }
            Err(error) => {
                failures += 1;
                if failures >= max_failures {
                    warn!(secret = %binding.name, %error, "oauth refresh failed; giving up, resolution fails closed");
                    return;
                }
                warn!(secret = %binding.name, %error, failures, "oauth refresh failed; retrying");
                tokio::time::sleep(retry_interval).await;
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

    // -- pure logic ------------------------------------------------------

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
        };
        let plain_plan = SecretBinding {
            name: "PLAIN".into(),
            source: SecretSource::Keystore {
                address: "plain-secret".into(),
            },
            destinations: vec![],
        };
        let external_plan = SecretBinding {
            name: "EXT".into(),
            source: SecretSource::External {
                provider: "vault".into(),
                path: "secret/x".into(),
            },
            destinations: vec![],
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
            &mvm_http::Client::new(),
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
            &mvm_http::Client::new(),
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
            &mvm_http::Client::new(),
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
            &mvm_http::Client::new(),
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
            &mvm_http::Client::new(),
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

    // -- the proactive loop ------------------------------------------------

    #[tokio::test]
    async fn refresh_loop_heals_a_stale_set_and_rearms() {
        let (token_url, recorded) = spawn_mock_token_server(
            "200 OK",
            r#"{"access_token":"fresh-access-token","expires_in":3600}"#,
        );
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        let driver = OAuthRefreshDriver::new(resolver, vec![])
            .with_retry_policy(StdDuration::from_millis(10), 3);
        // The loop re-arms after the exchange and sleeps toward the new
        // deadline; the timeout cancels that sleep — the assertions below
        // are what matters.
        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            refresh_loop(
                driver.resolver,
                driver.http,
                OAuthRefreshBinding {
                    name: "oauth-secret".into(),
                    meta: oauth_meta(&token_url),
                },
                driver.retry_interval,
                driver.max_failures,
            ),
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
    }

    #[tokio::test]
    async fn refresh_loop_gives_up_on_an_expired_set_without_exchanging() {
        let (token_url, recorded) =
            spawn_mock_token_server("200 OK", r#"{"access_token":"fresh-access-token"}"#);
        let mut token_set = expired_token_set("stale-access-token", Some("the-client-secret"));
        token_set.expires_at = Utc::now() - Duration::seconds(5);
        let fixture = fixture(&token_set, &token_url);
        let resolver = resolver_over(&fixture);
        refresh_loop(
            resolver,
            mvm_http::Client::new(),
            OAuthRefreshBinding {
                name: "oauth-secret".into(),
                meta: oauth_meta(&token_url),
            },
            StdDuration::from_millis(10),
            3,
        )
        .await;
        // Expired is expired: no exchange can help, and none was attempted.
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refresh_loop_retries_a_failing_endpoint_then_gives_up() {
        let (token_url, recorded) =
            spawn_mock_token_server("503 Service Unavailable", r#"{"error":"down"}"#);
        let fixture = fixture(
            &expired_token_set("stale-access-token", Some("the-client-secret")),
            &token_url,
        );
        let resolver = resolver_over(&fixture);
        refresh_loop(
            resolver,
            mvm_http::Client::new(),
            OAuthRefreshBinding {
                name: "oauth-secret".into(),
                meta: oauth_meta(&token_url),
            },
            StdDuration::from_millis(10),
            3,
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
    }
}
