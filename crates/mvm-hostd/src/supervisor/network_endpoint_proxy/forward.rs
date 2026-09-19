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
}

impl HardenedForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        Ok(Self {
            timeout_secs,
            proxy: None,
        })
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
        let client = hardened_client_builder_via(self.timeout_secs, self.proxy.as_ref())
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
}
