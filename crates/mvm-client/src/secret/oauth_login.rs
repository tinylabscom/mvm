//! Host-browser OAuth consent for an OAuth-bound secret.
//!
//! The human consents in a browser on this host; the guest is never part of
//! it and never sees the session, the code, or the tokens. The flow is the
//! authorization-code grant of a native public client (RFC 8252):
//!
//! 1. bind a loopback listener on `127.0.0.1` with an ephemeral port;
//! 2. hand the operator an authorization URL carrying a PKCE S256 challenge
//!    and a fresh `state` (`mvm_hostd::keyholder::oauth_consent`);
//! 3. take the redirect on the listener, refusing any whose `state` is not
//!    this login's;
//! 4. redeem the code at the token endpoint with the PKCE verifier, through
//!    the same exchange code the host-side refresher uses.
//!
//! The result is the token set the secret service stores. Nothing here
//! writes it, so every error leaves the store as it was.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Context;
use mvm_core::crypto::secret_binding::OAuthBindingMeta;
use mvm_hostd::keyholder::TokenEndpointClient;
use mvm_hostd::keyholder::oauth::{consented_token_set, exchange_authorization_code};
use mvm_hostd::keyholder::oauth_consent::{ConsentRequest, RedirectRefusal};
use mvm_hostd::keyholder::resolver::{OAuthSecretString, OAuthTokenSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long a login waits for the human to finish consenting.
pub const DEFAULT_CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Bound on one request head reaching the listener. A redirect is a single
/// GET line plus browser headers; anything larger is not one.
const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;

/// How long one connection may take to send its request head before it is
/// dropped. Heads are read concurrently, so this bounds what a stalled client
/// costs, not how long the real callback waits.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections whose request head is still being read. Past this, a new
/// connection is closed at once, so a flood cannot grow without bound.
const MAX_PENDING_CONNECTIONS: usize = 64;

/// Settings for one login. Defaults: a five-minute wait and a plain HTTP
/// client with no destination check — the operator is on the host, choosing
/// to consent, and the binding already restricts the endpoints to https.
#[derive(Clone)]
pub struct OAuthLoginOptions {
    timeout: Duration,
    token_client: TokenEndpointClient,
}

impl Default for OAuthLoginOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_CONSENT_TIMEOUT,
            token_client: TokenEndpointClient::new(mvm_http::Client::new()),
        }
    }
}

impl OAuthLoginOptions {
    /// Give up on the consent after `timeout`.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Redeem the code through `client`.
    #[must_use]
    pub fn with_token_client(mut self, client: TokenEndpointClient) -> Self {
        self.token_client = client;
        self
    }

    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// The loopback listener the authorization server redirects the browser to.
/// Bound to the IPv4 loopback literal only, so nothing off this host can
/// reach it, on a port the kernel picks (RFC 8252 §7.3).
pub(crate) struct LoopbackRedirect {
    listener: TcpListener,
}

impl LoopbackRedirect {
    pub(crate) async fn bind() -> anyhow::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("binding the loopback redirect listener on 127.0.0.1")?;
        Ok(Self { listener })
    }

    pub(crate) fn local_addr(&self) -> anyhow::Result<std::net::SocketAddr> {
        self.listener
            .local_addr()
            .context("reading the loopback redirect listener's address")
    }

    /// Serve the listener until this login's callback arrives.
    ///
    /// The port is on loopback but not private: any local process, or a page
    /// open in the browser, can reach it. So nothing that fails to prove it
    /// belongs to this login ends the wait. A request for another path is
    /// answered 404, and a callback with a missing or wrong `state` is
    /// answered 400; the wait goes on after both. Only a callback carrying
    /// this login's `state` ends it, with the code or with the authorization
    /// server's refusal.
    ///
    /// Each connection's request head is read on its own task, so a client
    /// that connects and stalls cannot keep the real callback waiting behind
    /// it.
    pub(crate) async fn receive_code(
        &self,
        consent: &ConsentRequest,
    ) -> anyhow::Result<OAuthSecretString> {
        let mut pending = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (mut stream, _) =
                        accepted.context("accepting on the loopback redirect listener")?;
                    if pending.len() >= MAX_PENDING_CONNECTIONS {
                        // Dropping the stream closes it; the browser's own
                        // request is retried by the browser, a flood is not.
                        continue;
                    }
                    pending.spawn(async move {
                        let target = tokio::time::timeout(
                            REQUEST_READ_TIMEOUT,
                            read_request_target(&mut stream),
                        )
                        .await;
                        (stream, target)
                    });
                }
                Some(read) = pending.join_next() => {
                    let Ok((mut stream, target)) = read else {
                        continue;
                    };
                    let Ok(Ok(Some(target))) = target else {
                        // A malformed, stalled or non-GET request is not the
                        // callback.
                        respond(&mut stream, "400 Bad Request", "Not an OAuth callback.").await;
                        continue;
                    };
                    if let Some(outcome) = judge_callback(consent, &mut stream, &target).await {
                        return outcome;
                    }
                }
            }
        }
    }
}

/// Answer one request that reached the listener, and return the login's
/// outcome when the request ends it.
async fn judge_callback(
    consent: &ConsentRequest,
    stream: &mut TcpStream,
    target: &str,
) -> Option<anyhow::Result<OAuthSecretString>> {
    match consent.accept_redirect(target) {
        Ok(code) => {
            respond(
                stream,
                "200 OK",
                "Consent received. You can close this window and return to the terminal.",
            )
            .await;
            Some(Ok(code))
        }
        Err(RedirectRefusal::NotTheCallback) => {
            respond(stream, "404 Not Found", "Not found.").await;
            None
        }
        Err(refusal @ (RedirectRefusal::MissingState | RedirectRefusal::StateMismatch)) => {
            tracing::warn!(%refusal, "ignored a callback that does not belong to this login");
            respond(stream, "400 Bad Request", "Not this sign-in's callback.").await;
            None
        }
        Err(refusal @ (RedirectRefusal::Denied(_) | RedirectRefusal::MissingCode)) => {
            respond(
                stream,
                "400 Bad Request",
                "This sign-in was not completed. Return to the terminal for details.",
            )
            .await;
            Some(Err(refusal.into()))
        }
    }
}

/// Read one request head and return its target when it is a `GET`.
async fn read_request_target(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() >= MAX_REQUEST_HEAD_BYTES {
            return Ok(None);
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        head.extend_from_slice(&chunk[..read]);
    }
    let Ok(head) = std::str::from_utf8(&head) else {
        return Ok(None);
    };
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(target), Some(version)) if version.starts_with("HTTP/1.") => {
            Ok(Some(target.to_owned()))
        }
        _ => Ok(None),
    }
}

/// Answer the browser with a short plain-text page. Best effort: the outcome
/// of the login does not depend on the browser reading it.
async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Run one consent end to end and return the token set to store.
///
/// `present` is handed the authorization URL once the listener is ready; it is
/// how the caller gets the URL in front of the human (open a browser, print
/// it). The consent must complete within the options' timeout.
pub(crate) async fn run_consent(
    meta: &OAuthBindingMeta,
    client_secret: Option<OAuthSecretString>,
    options: &OAuthLoginOptions,
    present: &dyn Fn(&str),
) -> anyhow::Result<OAuthTokenSet> {
    let redirect = LoopbackRedirect::bind().await?;
    let consent = ConsentRequest::new(meta, redirect.local_addr()?.port())?;
    present(consent.authorization_url());
    let code = tokio::time::timeout(options.timeout, redirect.receive_code(&consent))
        .await
        .map_err(|_| {
            anyhow::anyhow!("no consent arrived within {}s", options.timeout.as_secs())
        })??;
    drop(redirect);
    let grant = consent.into_grant(code);
    let captured = exchange_authorization_code(
        &options.token_client,
        meta,
        &grant,
        client_secret.as_ref().map(OAuthSecretString::expose_secret),
    )
    .await
    .context("redeeming the authorization code")?;
    consented_token_set(captured, client_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::keyholder::resolver::OAuthGrant;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// What the mock token endpoint saw.
    #[derive(Default)]
    struct Seen {
        authorization: Option<String>,
        body: String,
    }

    /// A one-shot plain-HTTP token endpoint. The https requirement is the
    /// binding's, checked before a login starts; this exercises the exchange.
    fn mock_token_endpoint(status: &str, body: &str) -> (String, Arc<Mutex<Seen>>) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let thread_seen = Arc::clone(&seen);
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    return;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let mut content_length = 0;
            let mut seen = thread_seen.lock().unwrap_or_else(|e| e.into_inner());
            for line in head.lines() {
                if let Some((name, value)) = line.split_once(':') {
                    match name.trim().to_ascii_lowercase().as_str() {
                        "authorization" => seen.authorization = Some(value.trim().to_owned()),
                        "content-length" => content_length = value.trim().parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            let mut body = vec![0u8; content_length];
            let _ = stream.read_exact(&mut body);
            seen.body = String::from_utf8_lossy(&body).into_owned();
            drop(seen);
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{addr}/token"), seen)
    }

    fn meta(token_url: &str) -> OAuthBindingMeta {
        OAuthBindingMeta {
            authorization_url: "https://auth.example.com/authorize".into(),
            token_url: token_url.into(),
            client_id: "public-client-id".into(),
            scopes: vec!["read".into()],
            response_access_token_pointer: None,
        }
    }

    fn query_param(url: &str, key: &str) -> String {
        mvm_http::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .unwrap()
    }

    /// Plays the browser after a consent: follows the redirect with
    /// `callback_query` (where `{state}` is replaced by the request's state)
    /// and returns the status line the listener answered with.
    fn browser(callback_query: &'static str) -> impl Fn(&str) + Send + Sync + 'static {
        move |authorization_url: &str| {
            let redirect = query_param(authorization_url, "redirect_uri");
            let state = query_param(authorization_url, "state");
            let url = mvm_http::Url::parse(&redirect).unwrap();
            let port = url.port().unwrap();
            let target = format!(
                "{}?{}",
                url.path(),
                callback_query.replace("{state}", &state)
            );
            std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                write!(stream, "GET {target} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n").unwrap();
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
            });
        }
    }

    #[tokio::test]
    async fn the_listener_binds_the_ipv4_loopback_literal_on_an_ephemeral_port() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let addr = redirect.local_addr().unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(addr.port(), 0);
        let consent =
            ConsentRequest::new(&meta("https://auth.example.com/token"), addr.port()).unwrap();
        assert_eq!(
            consent.redirect_uri(),
            format!("http://127.0.0.1:{}/callback", addr.port())
        );
    }

    #[tokio::test]
    async fn a_consent_redeems_the_code_with_the_pkce_verifier() {
        let (token_url, seen) = mock_token_endpoint(
            "200 OK",
            r#"{"access_token":"consented-access-token","refresh_token":"consented-refresh-token","expires_in":3600}"#,
        );
        let challenge = Arc::new(Mutex::new(String::new()));
        let browse = browser("code=the-code&state={state}");
        let recorded_challenge = Arc::clone(&challenge);
        let present = move |url: &str| {
            *recorded_challenge.lock().unwrap() = query_param(url, "code_challenge");
            browse(url);
        };
        let set = run_consent(
            &meta(&token_url),
            None,
            &OAuthLoginOptions::default().with_timeout(Duration::from_secs(10)),
            &present,
        )
        .await
        .unwrap();

        assert_eq!(set.grant, OAuthGrant::AuthorizationCode);
        assert_eq!(set.access_token.expose_secret(), "consented-access-token");
        assert_eq!(
            set.refresh_token.as_ref().unwrap().expose_secret(),
            "consented-refresh-token"
        );
        assert!(set.client_secret.is_none());

        let seen = seen.lock().unwrap();
        // A public client: no Basic credential, the client id in the body.
        assert!(seen.authorization.is_none());
        let body: std::collections::BTreeMap<String, String> =
            mvm_http::Url::parse(&format!("http://x/?{}", seen.body))
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect();
        assert_eq!(body["grant_type"], "authorization_code");
        assert_eq!(body["code"], "the-code");
        assert_eq!(body["client_id"], "public-client-id");
        assert!(body["redirect_uri"].starts_with("http://127.0.0.1:"));
        // The verifier sent is the one the authorization request committed to.
        let verifier =
            mvm_hostd::keyholder::oauth_consent::PkceVerifier::from_value(&body["code_verifier"])
                .unwrap();
        assert_eq!(verifier.s256_challenge(), *challenge.lock().unwrap());
    }

    #[tokio::test]
    async fn a_confidential_client_authenticates_the_code_exchange() {
        let (token_url, seen) = mock_token_endpoint(
            "200 OK",
            r#"{"access_token":"a","refresh_token":"r","expires_in":3600}"#,
        );
        let set = run_consent(
            &meta(&token_url),
            Some(OAuthSecretString::from("the-client-secret".to_owned())),
            &OAuthLoginOptions::default().with_timeout(Duration::from_secs(10)),
            &browser("code=the-code&state={state}"),
        )
        .await
        .unwrap();
        assert_eq!(
            seen.lock().unwrap().authorization.as_deref(),
            Some("Basic cHVibGljLWNsaWVudC1pZDp0aGUtY2xpZW50LXNlY3JldA==")
        );
        assert!(!seen.lock().unwrap().body.contains("client_id"));
        assert_eq!(
            set.client_secret.unwrap().expose_secret(),
            "the-client-secret"
        );
    }

    /// One GET to the loopback listener; returns the whole response.
    fn http_get(port: u16, target: &str) -> String {
        let mut stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        write!(stream, "GET {target} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n").unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    #[tokio::test]
    async fn a_forged_callback_is_refused_without_ending_the_wait() {
        let (token_url, seen) = mock_token_endpoint(
            "200 OK",
            r#"{"access_token":"a","refresh_token":"r","expires_in":3600}"#,
        );
        let forged_responses = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&forged_responses);
        let present = move |authorization_url: &str| {
            let redirect =
                mvm_http::Url::parse(&query_param(authorization_url, "redirect_uri")).unwrap();
            let port = redirect.port().unwrap();
            let state = query_param(authorization_url, "state");
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || {
                // Anything on this host can reach the port: a wrong state and
                // a missing one are both answered and ignored...
                for forged in [
                    "/callback?code=forged-code&state=forged".to_owned(),
                    "/callback?code=forged-code".to_owned(),
                    "/callback?error=access_denied&state=forged".to_owned(),
                ] {
                    recorded.lock().unwrap().push(http_get(port, &forged));
                }
                // ...and the real callback still lands afterwards.
                http_get(port, &format!("/callback?code=the-code&state={state}"));
            });
        };
        let set = run_consent(
            &meta(&token_url),
            None,
            &OAuthLoginOptions::default().with_timeout(Duration::from_secs(10)),
            &present,
        )
        .await
        .unwrap();
        assert_eq!(set.access_token.expose_secret(), "a");
        let forged = forged_responses.lock().unwrap();
        assert_eq!(forged.len(), 3);
        for response in forged.iter() {
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        }
        // Only the real code was redeemed.
        let body = seen.lock().unwrap().body.clone();
        assert!(body.contains("code=the-code"), "{body}");
        assert!(!body.contains("forged-code"), "{body}");
    }

    #[tokio::test]
    async fn a_stalled_connection_does_not_hold_up_the_real_callback() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = redirect.local_addr().unwrap().port();
        let consent = ConsentRequest::new(&meta("https://auth.example.com/token"), port).unwrap();
        let state = query_param(consent.authorization_url(), "state");
        let client = std::thread::spawn(move || {
            // Connects first and never sends a byte.
            let stalled = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let response = http_get(port, &format!("/callback?code=c&state={state}"));
            drop(stalled);
            response
        });
        // Well inside the per-connection read timeout: a listener that read
        // heads one at a time would still be waiting on the stalled client.
        let wait = REQUEST_READ_TIMEOUT / 2;
        let code = tokio::time::timeout(wait, redirect.receive_code(&consent))
            .await
            .expect("the real callback must not queue behind a stalled connection")
            .unwrap();
        assert_eq!(code.expose_secret(), "c");
        assert!(client.join().unwrap().starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn a_denied_consent_is_reported_and_nothing_is_exchanged() {
        let (token_url, seen) =
            mock_token_endpoint("200 OK", r#"{"access_token":"a","expires_in":3600}"#);
        let err = run_consent(
            &meta(&token_url),
            None,
            &OAuthLoginOptions::default().with_timeout(Duration::from_secs(10)),
            &browser("error=access_denied&state={state}"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("access_denied"), "{err:#}");
        assert!(seen.lock().unwrap().body.is_empty());
    }

    #[tokio::test]
    async fn a_consent_that_never_arrives_times_out() {
        let err = run_consent(
            &meta("https://auth.example.com/token"),
            None,
            &OAuthLoginOptions::default().with_timeout(Duration::from_millis(100)),
            &|_: &str| {},
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("no consent arrived"), "{err:#}");
    }

    #[tokio::test]
    async fn a_failed_exchange_carries_no_code_or_verifier_in_its_error() {
        let (token_url, _seen) =
            mock_token_endpoint("400 Bad Request", r#"{"error":"invalid_grant"}"#);
        let err = run_consent(
            &meta(&token_url),
            None,
            &OAuthLoginOptions::default().with_timeout(Duration::from_secs(10)),
            &browser("code=the-secret-code&state={state}"),
        )
        .await
        .unwrap_err();
        let rendered = format!("{err:#} {err:?}");
        assert!(rendered.contains("400"), "{rendered}");
        assert!(!rendered.contains("the-secret-code"), "{rendered}");
        assert!(!rendered.contains("code_verifier"), "{rendered}");
    }

    #[tokio::test]
    async fn requests_for_other_paths_do_not_end_the_wait() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = redirect.local_addr().unwrap().port();
        let consent = ConsentRequest::new(&meta("https://auth.example.com/token"), port).unwrap();
        let state = query_param(consent.authorization_url(), "state");
        let client = std::thread::spawn(move || {
            let get = |target: String| {
                let mut stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
                write!(stream, "GET {target} HTTP/1.1\r\n\r\n").unwrap();
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
                response
            };
            let favicon = get("/favicon.ico".into());
            let callback = get(format!("/callback?code=c&state={state}"));
            (favicon, callback)
        });
        let code = tokio::time::timeout(Duration::from_secs(10), redirect.receive_code(&consent))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(code.expose_secret(), "c");
        let (favicon, callback) = client.join().unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");
        assert!(callback.starts_with("HTTP/1.1 200"), "{callback}");
        // The page the browser is left on names no credential.
        assert!(!callback.contains("code=c"), "{callback}");
    }
}
