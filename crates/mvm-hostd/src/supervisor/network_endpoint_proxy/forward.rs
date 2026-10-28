//! The forward leg: the request the host makes to the real destination once
//! a request has been prepared, and the trait test doubles stand in for.

use async_trait::async_trait;
use mvm_contract::substitution::PreparedRequest;

use super::MAX_FRAME_BYTES;
use crate::supervisor::tools::http_hardening::hardened_client_builder_via;

/// The response body must fit inside the bounded guest-facing response frame.
const MAX_FORWARD_RESPONSE_BYTES: usize = MAX_FRAME_BYTES;

/// The response from the real destination.
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A real-destination response whose decoded body is delivered incrementally.
///
/// The bounded receiver makes backpressure part of the type: the upstream
/// reader cannot outrun the FlowMux writer by more than four HTTP chunks.
pub struct ForwardStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: Option<u64>,
    pub body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, ForwardError>>,
}

/// Errors from the forward leg.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("forward failed: {0}")]
    Failed(String),
}

fn check_forward_response_length(length: Option<u64>) -> Result<(), ForwardError> {
    if length.is_some_and(|length| length > MAX_FORWARD_RESPONSE_BYTES as u64) {
        return Err(ForwardError::Failed(format!(
            "response body exceeds the {MAX_FORWARD_RESPONSE_BYTES} byte limit"
        )));
    }
    Ok(())
}

/// Forwards a prepared (credential-substituted) request to the real
/// destination and returns its response — the real-TLS leg of the endpoint.
/// A trait so the listener can be tested with a mock that records the
/// credential it received without a network call.
#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError>;

    /// Forward with a bounded incremental response body.
    ///
    /// Test doubles and compatibility forwarders get a safe buffered adapter;
    /// the production forwarder overrides this and reads the upstream socket
    /// only as the receiver makes room.
    async fn forward_stream(
        &self,
        req: PreparedRequest,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let response = self.forward(req).await?;
        let body_len = Some(response.body.len() as u64);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Ok(response.body))
            .await
            .map_err(|_| ForwardError::Failed("response consumer closed".into()))?;
        Ok(ForwardStreamResponse {
            status: response.status,
            headers: response.headers,
            body_len,
            body: receiver,
        })
    }

    /// Forward a request whose body arrives through a bounded channel.
    ///
    /// The default adapter is for test doubles: it preserves their existing
    /// whole-request assertions while enforcing the production body ceiling.
    /// The production forwarder overrides it and writes chunks directly to the
    /// upstream socket.
    async fn forward_body_stream(
        &self,
        mut req: PreparedRequest,
        mut body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let mut collected = Vec::new();
        while let Some(next) = body.recv().await {
            let chunk = next.map_err(ForwardError::Failed)?;
            if collected.len().saturating_add(chunk.len()) > MAX_FORWARD_RESPONSE_BYTES {
                return Err(ForwardError::Failed(format!(
                    "request body exceeds the {MAX_FORWARD_RESPONSE_BYTES} byte limit"
                )));
            }
            collected.extend_from_slice(&chunk);
        }
        req.body = collected;
        self.forward_stream(req).await
    }
}

/// Flatten an error and its `source()` chain into one message. The client wraps
/// the underlying connect/TLS/resolver cause as a source; the outer
/// `to_string()` alone is just "error sending request for url (...)", which
/// hides whether a forward failed on DNS, the SSRF filter, TLS, or timeout.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Production forwarder: a hardened client (TLS 1.3 floor, no redirects) makes
/// the real request through the shared SSRF-filtering resolver.
///
/// This used to resolve and SSRF-filter the host by hand and pin the safe
/// addresses on the URL's real port, because the shared resolver hardcoded 443
/// — reqwest's `Resolve` never saw the port, and an `http` forward would have
/// gone to the HTTPS port. `mvm_http::Resolve` receives `(host, port)`, so the
/// shared resolver handles it and the hand-rolled path is gone.
pub struct HardenedForwarder {
    timeout_secs: u64,
    proxy: Option<mvm_http::ProxyConfig>,
    /// Resolves only to what the egress gate admitted for the request. See
    /// `pinned_dns`. `None` keeps the SSRF-filtering system resolver.
    gate_resolver: Option<std::sync::Arc<dyn mvm_http::resolve::Resolve>>,
    /// A test's stand-in for the network: where names resolve, and which
    /// anchors the upstream certificate is verified against. Verification
    /// itself is never switched off — a test that wants a failure supplies an
    /// anchor the upstream does not chain to.
    #[cfg(test)]
    test_transport: Option<TestTransport>,
}

/// See [`HardenedForwarder::with_test_transport`].
#[cfg(test)]
pub(crate) struct TestTransport {
    pub(crate) resolver: std::sync::Arc<dyn mvm_http::resolve::Resolve>,
    pub(crate) roots: rustls::RootCertStore,
}

impl HardenedForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        Ok(Self {
            timeout_secs,
            proxy: None,
            gate_resolver: None,
            #[cfg(test)]
            test_transport: None,
        })
    }

    /// Connect only to addresses the VM's egress gate admitted: the answer
    /// it recorded when the request was decided, or a fresh gate decision.
    #[must_use]
    pub(crate) fn with_gate_resolver(
        mut self,
        admitted: std::sync::Arc<super::pinned_dns::AdmittedAddresses>,
        gate: std::sync::Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    ) -> Self {
        self.gate_resolver = Some(std::sync::Arc::new(super::pinned_dns::GateResolver::new(
            admitted, gate,
        )));
        self
    }

    /// Resolve every name through `transport.resolver` and verify upstream
    /// certificates against `transport.roots` instead of the platform store,
    /// so a test can put a real TLS server behind a public name without DNS.
    #[cfg(test)]
    pub(crate) fn with_test_transport(mut self, transport: TestTransport) -> Self {
        self.test_transport = Some(transport);
        self
    }

    fn client_builder(&self) -> mvm_http::ClientBuilder {
        let builder = hardened_client_builder_via(self.timeout_secs, self.proxy.as_ref());
        let builder = match &self.gate_resolver {
            Some(resolver) => builder.resolver(std::sync::Arc::clone(resolver)),
            None => builder,
        };
        #[cfg(test)]
        let builder = match &self.test_transport {
            Some(transport) => builder
                .resolver(std::sync::Arc::clone(&transport.resolver))
                .root_store(transport.roots.clone()),
            None => builder,
        };
        builder
    }

    /// Route the forward leg through an operator-configured upstream proxy.
    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<mvm_http::ProxyConfig>) -> Self {
        self.proxy = proxy;
        self
    }

    async fn send_streaming(
        &self,
        req: PreparedRequest,
        stream_body: Option<tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let method = mvm_http::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ForwardError::Failed(format!("bad method: {e}")))?;
        let client = self
            .client_builder()
            .max_response_bytes(MAX_FORWARD_RESPONSE_BYTES as u64)
            .build()
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        let mut rb = client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        rb = match stream_body {
            Some(receiver) => rb.body_checked_chunked(receiver),
            None if !req.body.is_empty() => rb.body(req.body),
            None => rb,
        };
        let mut resp = rb
            .send()
            .await
            .map_err(|e| ForwardError::Failed(err_chain(&e)))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        check_forward_response_length(resp.content_length())?;
        let body_len = resp.content_length();
        let (sender, body) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if sender.send(Ok(chunk.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = sender
                            .send(Err(ForwardError::Failed(err_chain(&error))))
                            .await;
                        return;
                    }
                }
            }
        });
        Ok(ForwardStreamResponse {
            status,
            headers,
            body_len,
            body,
        })
    }
}

#[async_trait]
impl Forwarder for HardenedForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let mut response = self.forward_stream(req).await?;
        let mut body = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            body.extend_from_slice(&chunk?);
        }
        Ok(ForwardResponse {
            status: response.status,
            headers: response.headers,
            body,
        })
    }

    async fn forward_stream(
        &self,
        req: PreparedRequest,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        self.send_streaming(req, None).await
    }

    async fn forward_body_stream(
        &self,
        req: PreparedRequest,
        body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        self.send_streaming(req, Some(body)).await
    }
}

#[cfg(test)]
mod response_body_tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn declared_response_length_is_checked_before_reading() {
        check_forward_response_length(Some(MAX_FORWARD_RESPONSE_BYTES as u64))
            .expect("a body exactly at the limit is accepted");
        let err = check_forward_response_length(Some((MAX_FORWARD_RESPONSE_BYTES as u64) + 1))
            .expect_err("an oversized declaration must be refused before allocation");
        assert!(err.to_string().contains("response body exceeds"));
        check_forward_response_length(None)
            .expect("chunked or close-delimited bodies are streamed");
    }

    /// A raw loopback upstream: read the request head, answer with `head`,
    /// then write `wire_body_bytes` of payload — however that compares to
    /// what the head declared — and close. A client that hangs up early (as
    /// it does once the cap trips) just ends the reply.
    async fn serve_raw_response(head: String, wire_body_bytes: usize) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the upstream");
        let addr = listener.local_addr().expect("upstream address");
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = socket.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                seen.extend_from_slice(&chunk[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            if socket.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let block = [0u8; 64 * 1024];
            let mut left = wire_body_bytes;
            while left > 0 {
                let n = left.min(block.len());
                if socket.write_all(&block[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
            let _ = socket.shutdown().await;
        });
        addr
    }

    /// The production forwarder with name resolution pinned to `addr`, so a
    /// loopback upstream stands in for the real destination. Certificate
    /// verification itself is untouched; these fixtures speak plain HTTP.
    fn forwarder_to(addr: SocketAddr) -> HardenedForwarder {
        let resolver = mvm_http::PinnedResolver::new().with("upstream.test", vec![addr]);
        HardenedForwarder::new(30)
            .expect("forwarder")
            .with_test_transport(TestTransport {
                resolver: std::sync::Arc::new(resolver),
                roots: rustls::RootCertStore::empty(),
            })
    }

    fn get_request(addr: SocketAddr) -> PreparedRequest {
        PreparedRequest {
            method: "GET".into(),
            url: format!("http://upstream.test:{}/", addr.port()),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_lying_content_length_does_not_defeat_the_forward_response_cap() {
        // The head declares 10 bytes while the wire carries more than the
        // cap. The declaration frames the body, so the forwarder reads
        // exactly what was declared and the oversized remainder never becomes
        // response body.
        let addr = serve_raw_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".to_string(),
            MAX_FORWARD_RESPONSE_BYTES + 1,
        )
        .await;
        let response = forwarder_to(addr)
            .forward(get_request(addr))
            .await
            .expect("the declared 10 bytes are a complete response");
        assert_eq!(response.body, vec![0u8; 10]);
    }

    #[tokio::test]
    async fn an_absent_content_length_does_not_defeat_the_forward_response_cap() {
        // With no declared length the body is read until close, so the
        // reader's cumulative cap is the only bound: the forwarder must
        // refuse rather than accumulate and deliver the stream.
        let addr = serve_raw_response(
            "HTTP/1.1 200 OK\r\n\r\n".to_string(),
            MAX_FORWARD_RESPONSE_BYTES + 1,
        )
        .await;
        let err = forwarder_to(addr)
            .forward(get_request(addr))
            .await
            .err()
            .expect("a body past the cap must be refused, not delivered");
        assert!(
            err.to_string().contains(&format!(
                "exceeded the {} byte limit",
                MAX_FORWARD_RESPONSE_BYTES
            )),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_declared_length_past_the_cap_is_refused_before_the_body_is_read() {
        // The declaration alone convicts the body, and the refusal must come
        // from the pre-read check: the upstream closes without sending one
        // body byte, so a read-time failure would surface as an incomplete
        // body instead.
        let declared = MAX_FORWARD_RESPONSE_BYTES as u64 + 1;
        let addr = serve_raw_response(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n"),
            0,
        )
        .await;
        let err = forwarder_to(addr)
            .forward(get_request(addr))
            .await
            .err()
            .expect("an oversized declaration must be refused before reading");
        assert!(
            err.to_string().contains(&format!(
                "exceeds the {} byte limit",
                MAX_FORWARD_RESPONSE_BYTES
            )),
            "{err}"
        );
    }
}
