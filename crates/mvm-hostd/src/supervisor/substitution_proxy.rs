//! Plan 129 / ADR-067 §1 — host substitution endpoint: request preparation.
//!
//! The guest's SDK client routes a secret-bearing request to this host-local
//! endpoint carrying an opaque placeholder. [`prepare_request`] is the
//! security-critical core: it locates the placeholder in each header, resolves
//! it against the session registry, binding-checks the request's destination
//! (claim 12), and substitutes the real credential — yielding a request ready
//! for the host to make the real TLS to the destination (the forward leg,
//! a separate transport step).
//!
//! Substitution happens HERE, on the host, never in the guest: the guest only
//! ever held the opaque placeholder. The prepared request carries the real
//! credential because it must reach the wire — the confinement is that this
//! host component is the only place it exists in the clear.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use url::Url;

use crate::framing::{FrameError, read_json_frame, write_json_frame};
use crate::keyholder::{
    SecretResolver, SubstituteError, SubstitutionEndpoint, SubstitutionRegistry, find_placeholder,
};
use crate::supervisor::tools::http_hardening::hardened_client_builder;

/// 16 MiB cap on a single routed request/response frame.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// A request the guest routed to the substitution endpoint. Header values may
/// carry an opaque placeholder where a credential goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub method: String,
    /// The real destination URL (e.g. `https://api.openai.com/v1/...`).
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A request with every placeholder substituted to its real credential, ready
/// for the forward leg to send to the destination over real TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from preparing a routed request for forwarding.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("request url `{0}` is not a valid absolute URL with a host")]
    BadUrl(String),
    #[error(transparent)]
    Substitute(#[from] SubstituteError),
}

/// Substitute every placeholder in `req`'s headers against `endpoint`,
/// binding-checked to the request's destination host. Returns a request whose
/// headers carry the real credentials, ready to forward.
///
/// Refuses — before the request is forwarded — if a placeholder's destination
/// is not bound for that secret (claim 12) or the placeholder is unknown. The
/// destination host is taken from the request URL, so a guest can't point a
/// secret at `api.openai.com` in the binding but send the bytes elsewhere: the
/// bind-check uses the URL we will actually dial.
pub fn prepare_request(
    endpoint: &SubstitutionEndpoint<'_>,
    req: ProxyRequest,
) -> Result<PreparedRequest, ProxyError> {
    let dest = destination_host(&req.url)?;
    let mut headers = Vec::with_capacity(req.headers.len());
    for (name, value) in req.headers {
        let new_value = match find_placeholder(&value) {
            Some(ph) => {
                let ph = ph.to_string();
                // `substitute` carries the claim-12 bind-check: an unbound
                // destination or unknown token errors here, before forwarding.
                endpoint.substitute(&ph, &dest, &value)?.to_string()
            }
            None => value,
        };
        headers.push((name, new_value));
    }
    Ok(PreparedRequest {
        method: req.method,
        url: req.url,
        headers,
        body: req.body,
    })
}

/// The destination host (no port) from an absolute URL.
fn destination_host(url: &str) -> Result<String, ProxyError> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or_else(|| ProxyError::BadUrl(url.to_string()))
}

// ============================================================================
// Transport — the host-local listener + the real-TLS forward leg (D-T2)
// ============================================================================

/// Wire envelope the guest's SDK sends over the host-local socket:
/// length-prefixed JSON, body base64 so it stays compact and binary-safe.
/// `deny_unknown_fields` fails closed on an unexpected field (W4.1).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    #[serde(default)]
    body_b64: String,
}

/// Reply: the destination's response, or a refusal (unbound destination,
/// unknown placeholder, malformed request, forward failure). A refusal never
/// carries a secret.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum WireResponse {
    Ok {
        status: u16,
        headers: Vec<(String, String)>,
        body_b64: String,
    },
    Refused {
        message: String,
    },
}

/// The response from the real destination.
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from the forward leg.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("forward failed: {0}")]
    Failed(String),
}

/// Forwards a prepared (credential-substituted) request to the real
/// destination and returns its response — the real-TLS leg of the endpoint.
/// A trait so the listener can be tested with a mock that records the
/// credential it received without a network call.
#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError>;
}

/// Production forwarder: a hardened reqwest client (TLS 1.3 min, SSRF-filtered
/// resolver, no redirects — `hardened_client_builder`) makes the real request.
pub struct ReqwestForwarder {
    client: reqwest::Client,
}

impl ReqwestForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        let client = hardened_client_builder(timeout_secs)
            .build()
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Forwarder for ReqwestForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ForwardError::Failed(format!("bad method: {e}")))?;
        let mut rb = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if !req.body.is_empty() {
            rb = rb.body(req.body);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ForwardError::Failed(e.to_string()))?
            .to_vec();
        Ok(ForwardResponse {
            status,
            headers,
            body,
        })
    }
}

/// The running host substitution endpoint: the admission-minted placeholder
/// registry, the secret resolver, and the forward leg. Placeholders are minted
/// at admission (ADR-067 §4), so the registry is read-only while serving.
pub struct SubstitutionService {
    registry: Arc<SubstitutionRegistry>,
    resolver: Arc<dyn SecretResolver>,
    forwarder: Arc<dyn Forwarder>,
}

impl SubstitutionService {
    pub fn new(
        registry: Arc<SubstitutionRegistry>,
        resolver: Arc<dyn SecretResolver>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Self {
        Self {
            registry,
            resolver,
            forwarder,
        }
    }

    /// Accept loop: one routed request per connection, framed JSON, a task per
    /// connection. Runs until the listener errors.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_connection(stream).await {
                            tracing::warn!(error = %e, "substitution endpoint connection failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "substitution endpoint accept failed; stopping");
                    return;
                }
            }
        }
    }

    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), FrameError> {
        let wire: WireRequest = read_json_frame(&mut stream, MAX_FRAME_BYTES).await?;
        let resp = self.process(wire).await;
        write_json_frame(&mut stream, &resp).await
    }

    async fn process(&self, wire: WireRequest) -> WireResponse {
        let body = match B64.decode(wire.body_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                return WireResponse::Refused {
                    message: format!("bad body encoding: {e}"),
                };
            }
        };
        let req = ProxyRequest {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body,
        };
        // Per-request endpoint: two refs, cheap; the registry is read-only
        // after admission minted its placeholders.
        let registry: &SubstitutionRegistry = &self.registry;
        let endpoint = SubstitutionEndpoint::new(registry, self.resolver.as_ref());
        let prepared = match prepare_request(&endpoint, req) {
            Ok(p) => p,
            Err(e) => {
                return WireResponse::Refused {
                    message: e.to_string(),
                };
            }
        };
        match self.forwarder.forward(prepared).await {
            Ok(r) => WireResponse::Ok {
                status: r.status,
                headers: r.headers,
                body_b64: B64.encode(r.body),
            },
            Err(e) => WireResponse::Refused {
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (dir, LocalResolver::new("local", store))
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn prepares_request_with_real_credential_for_a_bound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat".into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {}", ph.as_str())),
                ("content-type".into(), "application/json".into()),
            ],
            body: b"{}".to_vec(),
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        assert_eq!(
            prepared.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // A header without a placeholder is untouched.
        assert_eq!(prepared.headers[1].1, "application/json");
    }

    #[test]
    fn refuses_a_request_to_an_unbound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {}", ph.as_str()))],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(matches!(err, ProxyError::Substitute(_)));
    }

    #[test]
    fn passes_through_a_request_without_a_placeholder() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer ya29.real-token".into())],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req.clone()).unwrap();
        assert_eq!(prepared.headers, req.headers);
    }

    #[test]
    fn rejects_a_url_without_a_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "not a url".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            prepare_request(&endpoint, req).unwrap_err(),
            ProxyError::BadUrl(_)
        ));
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Records the request it was handed so a test can prove the destination
    /// (not the guest) received the real credential — without a network call.
    struct MockForwarder {
        seen: Mutex<Option<PreparedRequest>>,
    }

    #[async_trait]
    impl Forwarder for MockForwarder {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            *self.seen.lock().unwrap() = Some(req);
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("x-mock".into(), "1".into())],
                body: b"pong".to_vec(),
            })
        }
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    /// Build a service over a file store seeded with `openai`=value, a registry
    /// holding one minted placeholder for `hosts`, and a `MockForwarder`.
    /// Returns the service, the minted placeholder string, and the forwarder.
    fn service_with(
        value: &str,
        hosts: &[&str],
    ) -> (
        Arc<SubstitutionService>,
        String,
        Arc<MockForwarder>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(value.to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", hosts)).as_str().to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(reg),
            resolver,
            forwarder.clone(),
        ));
        (service, ph, forwarder, dir)
    }

    #[tokio::test]
    async fn endpoint_substitutes_then_forwards_over_uds() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        // The forwarder (i.e. the destination) saw the REAL credential.
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        match resp {
            WireResponse::Ok {
                status, body_b64, ..
            } => {
                assert_eq!(status, 200);
                assert_eq!(B64.decode(body_b64).unwrap(), b"pong");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn endpoint_refuses_unbound_destination_and_never_forwards() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        assert!(matches!(resp, WireResponse::Refused { .. }));
        // claim 12: an unbound destination never reaches the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }
}
