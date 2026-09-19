//! The request paths: buffered, streamed response, and streamed body. Each
//! runs the shared preparation, the AI budget check, the forward leg, and
//! the response transform.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::ir::AuthType;
use mvm_contract::substitution::SubstitutionDriver;
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use zeroize::Zeroizing;

use super::SubstitutionService;
use super::ai_budget::AiRequestMeta;
use super::forward::{ForwardError, ForwardResponse, ForwardStreamResponse};
use super::prepare::{PreparedFlow, destination_host};
use crate::keyholder::{NetworkEndpoint, find_placeholder};
use crate::supervisor::ai_meter;
use crate::supervisor::redactor::{RedactionHits, SensitiveDetectionError, StreamingRedactor};
use crate::supervisor::reversible_replacement::StreamingReinjector;
use crate::supervisor::secret_audit::ForwardOutcome;

/// Typed FlowMux request ceiling, independent of transport frame size.
const MAX_HTTP_STREAM_BODY_BYTES: usize = 32 * 1024 * 1024;
const HTTP_REQUEST_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on how much of a streaming AI response body we retain for trailing
/// usage extraction. SSE usage blocks are small and appear at the end of the
/// stream; this buffer only keeps the tail so guest bandwidth is unaffected.
const MAX_AI_STREAM_BUFFER_BYTES: usize = 256 * 1024;

impl SubstitutionService {
    /// Substitute, gate, forward, and audit one request.
    ///
    /// `pub(crate)` so the FlowMux `Http` arm can call it. That arm frames the
    /// request and the reply; everything this does — placeholder resolution,
    /// destination binding, the claim-10 gate, payload-free audit — happens
    /// here and only here, on every transport.
    pub(crate) async fn process(&self, wire: WireRequest) -> WireResponse {
        let mut flow = match self.prepare_flow(wire).await {
            Ok(flow) => flow,
            Err(refusal) => return refusal,
        };
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            };
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        self.audit_handoff(&flow).await;
        match self.forwarder.forward(request).await {
            Ok(mut response) => {
                let reinject_proofs = flow.replacement_flow.reinject_response(&mut response);
                self.audit_completed_flow(&flow, &reinject_proofs).await;
                self.audit_forward_outcome(&flow, ForwardOutcome::Completed)
                    .await;
                if let Some(meta) = ai_meta {
                    self.record_ai_usage(&meta, response.status, &response.body)
                        .await;
                }
                WireResponse::Ok {
                    status: response.status,
                    headers: response.headers,
                    body_b64: B64.encode(response.body),
                }
            }
            Err(error) => {
                self.audit_forward_outcome(&flow, ForwardOutcome::UpstreamFailed)
                    .await;
                WireResponse::Refused {
                    message: error.to_string(),
                }
            }
        }
    }

    /// Substitute and forward one FlowMux request while keeping the upstream
    /// response body incremental and bounded.
    pub(crate) async fn process_stream(
        self: &Arc<Self>,
        wire: WireRequest,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        let mut flow = self.prepare_flow(wire).await?;
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return Err(WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            });
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        self.audit_handoff(&flow).await;
        let upstream = match self.forwarder.forward_stream(request).await {
            Ok(upstream) => upstream,
            Err(error) => {
                self.audit_forward_outcome(&flow, ForwardOutcome::UpstreamFailed)
                    .await;
                return Err(WireResponse::Refused {
                    message: error.to_string(),
                });
            }
        };

        self.transform_response_stream(flow, upstream, ai_meta)
            .await
    }

    /// Process a FlowMux request body as bounded chunks. Signing and
    /// reversible request-body replacement need replay after seeing the full
    /// payload, so those explicit classes retain a bounded zeroizing replay
    /// buffer; every other typed request streams through the inspector.
    pub(crate) async fn process_body_stream(
        self: &Arc<Self>,
        head: mvm_core::substitution_wire::HttpFlowHead,
        mut body: tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        let destination = destination_host(&head.url).ok();
        let replacement_action = destination
            .as_deref()
            .map(|dest| {
                crate::supervisor::reversible_replacement_resolve::resolve(
                    &self.reversible_replacement_policy,
                    dest,
                )
            })
            .cloned()
            .unwrap_or_default();
        let endpoint = NetworkEndpoint::new(&self.registry, self.resolver.as_ref());
        let signs_body = head.headers.iter().any(|(_, value)| {
            find_placeholder(value).is_some_and(|placeholder| {
                matches!(
                    endpoint.auth_type(placeholder),
                    Some(AuthType::Sigv4 | AuthType::Hmac)
                )
            })
        });
        let replaces_body =
            replacement_action.replaces_on(mvm_core::policy::RewriteSurface::RequestBody);

        if signs_body || replaces_body {
            let mut replay = Zeroizing::new(Vec::new());
            loop {
                let next = match tokio::time::timeout(HTTP_REQUEST_IDLE_TIMEOUT, body.recv()).await
                {
                    Ok(next) => next,
                    Err(_) => {
                        self.audit_fail_closed(destination.as_deref(), "request_body_idle_timeout")
                            .await;
                        return Err(WireResponse::Refused {
                            message: "request body idle timeout".into(),
                        });
                    }
                };
                let Some(chunk) = next else {
                    break;
                };
                if replay.len().saturating_add(chunk.len()) > MAX_HTTP_STREAM_BODY_BYTES {
                    self.audit_fail_closed(destination.as_deref(), "request_body_limit_exceeded")
                        .await;
                    return Err(WireResponse::Refused {
                        message: format!(
                            "request body exceeds the {MAX_HTTP_STREAM_BODY_BYTES} byte limit"
                        ),
                    });
                }
                replay.extend_from_slice(&chunk);
            }
            if replay.len() as u64 != head.body_len {
                self.audit_fail_closed(destination.as_deref(), "request_body_truncated")
                    .await;
                return Err(WireResponse::Refused {
                    message: "request body ended before its declared length".into(),
                });
            }
            return self
                .process_stream(WireRequest {
                    method: head.method,
                    url: head.url,
                    headers: head.headers,
                    body_b64: B64.encode(&*replay),
                })
                .await;
        }

        let wire = WireRequest {
            method: head.method,
            url: head.url,
            headers: head.headers,
            body_b64: String::new(),
        };
        let mut flow = self.prepare_flow(wire).await?;
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return Err(WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            });
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        let expected_len = head.body_len;
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let service = Arc::clone(self);
        let action = flow.redaction_action.clone();
        let producer_destination = destination.clone();
        let producer = tokio::spawn(async move {
            let mut redactor = StreamingRedactor::new();
            let mut hits = RedactionHits::default();
            let mut received = 0_u64;
            loop {
                let next = match tokio::time::timeout(HTTP_REQUEST_IDLE_TIMEOUT, body.recv()).await
                {
                    Ok(next) => next,
                    Err(_) => {
                        service
                            .audit_fail_closed(
                                producer_destination.as_deref(),
                                "request_body_idle_timeout",
                            )
                            .await;
                        let _ = sender.send(Err("request body idle timeout".into())).await;
                        return Err(SensitiveDetectionError);
                    }
                };
                let Some(chunk) = next else {
                    break;
                };
                received = received.saturating_add(chunk.len() as u64);
                if received > expected_len {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_length_exceeded",
                        )
                        .await;
                    let _ = sender
                        .send(Err("request body exceeded its declared length".into()))
                        .await;
                    return Err(SensitiveDetectionError);
                }
                let (ready, chunk_hits) = match redactor.push(&service.redactor, &action, &chunk) {
                    Ok(result) => result,
                    Err(error) => {
                        service
                            .audit_fail_closed(
                                producer_destination.as_deref(),
                                "request_body_detector_failed",
                            )
                            .await;
                        let _ = sender
                            .send(Err("sensitive-data detector failed closed".into()))
                            .await;
                        return Err(error);
                    }
                };
                hits.merge(chunk_hits);
                if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_stream_canceled",
                        )
                        .await;
                    return Err(SensitiveDetectionError);
                }
            }
            if received != expected_len {
                service
                    .audit_fail_closed(producer_destination.as_deref(), "request_body_truncated")
                    .await;
                let _ = sender
                    .send(Err("request body ended before its declared length".into()))
                    .await;
                return Err(SensitiveDetectionError);
            }
            let (tail, tail_hits) = match redactor.finish(&service.redactor, &action) {
                Ok(result) => result,
                Err(error) => {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_detector_failed",
                        )
                        .await;
                    return Err(error);
                }
            };
            hits.merge(tail_hits);
            if !tail.is_empty() && sender.send(Ok(tail)).await.is_err() {
                service
                    .audit_fail_closed(
                        producer_destination.as_deref(),
                        "request_body_stream_canceled",
                    )
                    .await;
                return Err(SensitiveDetectionError);
            }
            Ok(hits)
        });
        self.audit_handoff(&flow).await;
        let upstream = match self.forwarder.forward_body_stream(request, receiver).await {
            Ok(upstream) => upstream,
            Err(error) => {
                self.audit_forward_outcome(&flow, ForwardOutcome::UpstreamFailed)
                    .await;
                return Err(WireResponse::Refused {
                    message: error.to_string(),
                });
            }
        };
        let request_hits = match producer.await {
            Ok(Ok(hits)) => hits,
            Ok(Err(_)) => {
                self.audit_forward_outcome(&flow, ForwardOutcome::RequestFailed)
                    .await;
                return Err(WireResponse::Refused {
                    message: "request transform failed closed".into(),
                });
            }
            Err(_) => {
                self.audit_forward_outcome(&flow, ForwardOutcome::RequestFailed)
                    .await;
                return Err(WireResponse::Refused {
                    message: "request transform task failed closed".into(),
                });
            }
        };
        flow.redaction_hits.merge(request_hits);
        self.transform_response_stream(flow, upstream, ai_meta)
            .await
    }

    async fn transform_response_stream(
        self: &Arc<Self>,
        mut flow: PreparedFlow,
        mut upstream: ForwardStreamResponse,
        ai_meta: Option<AiRequestMeta>,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        // Reinject and redact response headers before any body byte can cross
        // to the guest. HTTP transfer framing belongs to the upstream leg, not
        // FlowMux; remove it because transforms may change decoded length.
        let mut head = ForwardResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: Vec::new(),
        };
        let mut reinject_proofs = flow.replacement_flow.reinject_response(&mut head);
        head.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
        });
        for (_, value) in &mut head.headers {
            if let Some((redacted, hits)) = self
                .redactor
                .redact_bytes_for(value.as_bytes(), &flow.redaction_action)
            {
                if hits.detector_failures > 0 {
                    self.audit_fail_closed(
                        flow.destination.as_deref(),
                        "response_header_detector_failed",
                    )
                    .await;
                    self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                        .await;
                    return Err(WireResponse::Refused {
                        message: "sensitive-data detector failed closed; refusing response".into(),
                    });
                }
                *value = String::from_utf8_lossy(&redacted).into_owned();
                flow.redaction_hits.merge(hits);
            }
        }

        let response_status = head.status;
        let response_headers = std::mem::take(&mut head.headers);
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let service = Arc::clone(self);
        let response_destination = flow.destination.clone();
        let meter_streaming = ai_meta.is_some();
        tokio::spawn(async move {
            // Every exit below yields how the forward ended, and the outcome is
            // recorded once, after the block, whichever exit was taken.
            let outcome = async {
                let mut redactor = StreamingRedactor::new();
                let mut ai_body_buffer = if meter_streaming {
                    Some(Vec::with_capacity(0))
                } else {
                    None
                };
                let mut reinjector = StreamingReinjector::new();
                while let Some(next) = upstream.body.recv().await {
                    let chunk = match next {
                        Ok(chunk) => chunk,
                        Err(error) => {
                            let _ = sender.send(Err(error)).await;
                            return ForwardOutcome::ResponseFailed;
                        }
                    };
                    if let Some(buf) = ai_body_buffer.as_mut().filter(|buf| {
                        buf.len().saturating_add(chunk.len()) <= MAX_AI_STREAM_BUFFER_BYTES
                    }) {
                        buf.extend_from_slice(&chunk);
                    }
                    let (reintroduced, proofs) =
                        reinjector.push(&mut flow.replacement_flow, &chunk);
                    reinject_proofs.extend(proofs);
                    let (ready, hits) = match redactor.push(
                        &service.redactor,
                        &flow.redaction_action,
                        &reintroduced,
                    ) {
                        Ok(result) => result,
                        Err(_) => {
                            service
                                .audit_fail_closed(
                                    response_destination.as_deref(),
                                    "response_body_detector_failed",
                                )
                                .await;
                            let _ = sender
                                .send(Err(ForwardError::Failed(
                                    "sensitive-data detector failed closed".into(),
                                )))
                                .await;
                            return ForwardOutcome::ResponseRefused;
                        }
                    };
                    flow.redaction_hits.merge(hits);
                    if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                        service
                            .audit_fail_closed(
                                response_destination.as_deref(),
                                "response_body_stream_canceled",
                            )
                            .await;
                        return ForwardOutcome::Canceled;
                    }
                }
                let (reintroduced_tail, proofs) = reinjector.finish(&mut flow.replacement_flow);
                reinject_proofs.extend(proofs);
                let (ready, hits) = match redactor.push(
                    &service.redactor,
                    &flow.redaction_action,
                    &reintroduced_tail,
                ) {
                    Ok(result) => result,
                    Err(_) => {
                        service
                            .audit_fail_closed(
                                response_destination.as_deref(),
                                "response_body_detector_failed",
                            )
                            .await;
                        let _ = sender
                            .send(Err(ForwardError::Failed(
                                "sensitive-data detector failed closed".into(),
                            )))
                            .await;
                        return ForwardOutcome::ResponseRefused;
                    }
                };
                flow.redaction_hits.merge(hits);
                if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                    service
                        .audit_fail_closed(
                            response_destination.as_deref(),
                            "response_body_stream_canceled",
                        )
                        .await;
                    return ForwardOutcome::Canceled;
                }
                let (tail, hits) = match redactor.finish(&service.redactor, &flow.redaction_action)
                {
                    Ok(result) => result,
                    Err(_) => {
                        service
                            .audit_fail_closed(
                                response_destination.as_deref(),
                                "response_body_detector_failed",
                            )
                            .await;
                        let _ = sender
                            .send(Err(ForwardError::Failed(
                                "sensitive-data detector failed closed".into(),
                            )))
                            .await;
                        return ForwardOutcome::ResponseRefused;
                    }
                };
                flow.redaction_hits.merge(hits);
                if !tail.is_empty() && sender.send(Ok(tail)).await.is_err() {
                    service
                        .audit_fail_closed(
                            response_destination.as_deref(),
                            "response_body_stream_canceled",
                        )
                        .await;
                    return ForwardOutcome::Canceled;
                }
                service.audit_completed_flow(&flow, &reinject_proofs).await;
                if let (Some(meta), Some(body)) = (ai_meta, ai_body_buffer) {
                    service
                        .record_streaming_ai_usage(&meta, response_status, &body)
                        .await;
                }
                ForwardOutcome::Completed
            }
            .await;
            service.audit_forward_outcome(&flow, outcome).await;
        });

        Ok(ForwardStreamResponse {
            status: response_status,
            headers: response_headers,
            // Header/body transforms can change decoded length. Completion is
            // explicit and the guest applies an independent hard cap.
            body_len: None,
            body: receiver,
        })
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SecretResolver, SubstitutionRegistry};
    use crate::supervisor::network_endpoint_proxy::SubstitutionService;
    use crate::supervisor::network_endpoint_proxy::test_support::{
        MockForwarder, RedirectForwarder, bearer_ref, gate_admitting, service_with,
    };
    use crate::supervisor::redactor::STREAM_TRANSFORM_OVERLAP;
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::substitution_wire::WireResponse;
    use secrecy::SecretBox;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn flowmux_request_body_streams_through_split_token_redaction() {
        let (service, placeholder, forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let split = 13;
        let mut first = vec![b'x'; STREAM_TRANSFORM_OVERLAP - split];
        first.extend_from_slice(&secret[..split]);
        let second = secret[split..].to_vec();
        let body_len = (first.len() + second.len()) as u64;
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        sender.send(Zeroizing::new(first)).await.unwrap();
        sender.send(Zeroizing::new(second)).await.unwrap();
        drop(sender);

        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "POST".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
                    body_len,
                },
                receiver,
            )
            .await
            .expect("streamed request");
        let mut response_body = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            response_body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(response_body, b"pong");

        let seen = forwarder.seen.lock().unwrap();
        let request = seen.as_ref().expect("forwarded request");
        assert!(
            !request
                .body
                .windows(secret.len())
                .any(|window| window == secret),
            "split secret crossed the request inspector"
        );
        assert_eq!(request.headers[0].1, "Bearer sk-live-zzz");
    }

    #[tokio::test]
    async fn signing_flow_uses_the_bounded_replay_buffer_before_forwarding() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "hook",
                &SecretBox::new(Box::new("Jefe".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(SecretRef {
                name: "hook".into(),
                mount: SecretMount::Env { var: "K".into() },
                auth_type: AuthType::Hmac,
                allowed_hosts: vec!["hooks.example.com".into()],
                sigv4: None,
            })
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(registry),
            resolver,
            forwarder.clone(),
            gate_admitting(&[("hooks.example.com", 443)]),
        ));
        let body = b"what do ya want for nothing?";
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(Zeroizing::new(body[..10].to_vec()))
            .await
            .unwrap();
        sender
            .send(Zeroizing::new(body[10..].to_vec()))
            .await
            .unwrap();
        drop(sender);
        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "POST".into(),
                    url: "https://hooks.example.com/event".into(),
                    headers: vec![("x-sig".into(), placeholder)],
                    body_len: body.len() as u64,
                },
                receiver,
            )
            .await
            .expect("signed request");
        while response.body.recv().await.is_some() {}

        let seen = forwarder.seen.lock().unwrap();
        let request = seen.as_ref().expect("forwarded request");
        assert_eq!(request.body, body);
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-mvm-signature")
                && value == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        }));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_streaming_request_hits_the_idle_deadline_without_forwarding() {
        let (service, _placeholder, forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let task_service = Arc::clone(&service);
        let request = tokio::spawn(async move {
            task_service
                .process_body_stream(
                    mvm_core::substitution_wire::HttpFlowHead {
                        method: "POST".into(),
                        url: "https://api.openai.com/v1".into(),
                        headers: Vec::new(),
                        body_len: 1,
                    },
                    receiver,
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(HTTP_REQUEST_IDLE_TIMEOUT + std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        drop(sender);
        let refusal = match request.await.expect("request task") {
            Ok(_) => panic!("idle request must refuse"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(
                refusal,
                WireResponse::Refused { ref message }
                    if message.contains("idle timeout") || message.contains("failed closed")
            ),
            "unexpected refusal: {refusal:?}"
        );
        assert!(
            forwarder.seen.lock().unwrap().is_none(),
            "an incomplete request must never reach the destination"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_returned_without_following_or_rebinding_substitution() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(RedirectForwarder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(registry),
            resolver,
            forwarder.clone(),
            gate_admitting(&[("api.openai.com", 443)]),
        ));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(sender);
        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "GET".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
                    body_len: 0,
                },
                receiver,
            )
            .await
            .expect("redirect response");
        while response.body.recv().await.is_some() {}

        assert_eq!(response.status, 302);
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("location") && value == "https://unbound.example/steal"
        }));
        assert_eq!(
            forwarder.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the endpoint must surface a redirect, never follow it with the bound credential"
        );
    }
}
