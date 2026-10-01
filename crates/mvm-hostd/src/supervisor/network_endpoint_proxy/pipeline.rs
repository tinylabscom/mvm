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
use super::prepare::{
    BodyPlaceholderScan, PLACEHOLDER_IN_BODY_MESSAGE, PreparedFlow, REASON_PLACEHOLDER_IN_BODY,
    UNPARSEABLE_DESTINATION, destination_host,
};
use super::reflection::{ScrubCounts, StreamingScrubber, body_is_readable, merge_counts};
use crate::keyholder::resolver::CapturedOAuthToken;
use crate::keyholder::{NetworkEndpoint, find_placeholder};
use crate::supervisor::ai_meter;
use crate::supervisor::redactor::{RedactionHits, SensitiveDetectionError, StreamingRedactor};
use crate::supervisor::reversible_replacement::StreamingReinjector;
use crate::supervisor::secret_audit::ForwardOutcome;

/// Why a response was refused because its encoding hid it from the scrub.
const REASON_RESPONSE_ENCODED: &str = "response_encoded_unscannable";

/// Typed FlowMux request ceiling, independent of transport frame size.
const MAX_HTTP_STREAM_BODY_BYTES: usize = 32 * 1024 * 1024;
const HTTP_REQUEST_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on how much of a streaming AI response body we retain for trailing
/// usage extraction. SSE usage blocks are small and appear at the end of the
/// stream; this buffer only keeps the tail so guest bandwidth is unaffected.
const MAX_AI_STREAM_BUFFER_BYTES: usize = 256 * 1024;

impl SubstitutionService {
    fn flow_has_oauth_capture(&self, flow: &PreparedFlow) -> bool {
        flow.substituted
            .iter()
            .any(|substituted| self.oauth_capture_by_secret.contains_key(&substituted.name))
    }

    fn captured_oauth_token(
        &self,
        rule: &super::OAuthCaptureRule,
        json: &serde_json::Value,
    ) -> Option<CapturedOAuthToken> {
        crate::keyholder::oauth::parse_token_response(
            Some(rule.response_access_token_pointer()),
            json,
        )
    }

    /// Capture OAuth tokens (access and refresh) returned in a JSON response
    /// body and teach the reflection scrubber to replace them with the
    /// binding's placeholder before any bytes reach the guest.
    async fn capture_oauth_response_tokens(
        &self,
        flow: &PreparedFlow,
        body: &[u8],
    ) -> Result<(), WireResponse> {
        if flow.substituted.is_empty() || self.oauth_capture_by_secret.is_empty() {
            return Ok(());
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Ok(());
        };
        for substituted in &flow.substituted {
            let Some(rule) = self.oauth_capture_by_secret.get(&substituted.name) else {
                continue;
            };
            let Some(token) = self.captured_oauth_token(rule, &json) else {
                continue;
            };
            let mut learned_values = vec![token.access_token.expose_secret().as_bytes().to_vec()];
            if let Some(refresh_token) = &token.refresh_token {
                learned_values.push(refresh_token.expose_secret().as_bytes().to_vec());
            }
            if let Err(error) = self
                .resolver
                .store_captured_oauth_token(&substituted.name, token)
            {
                self.audit_fail_closed(flow.destination.as_deref(), "oauth_capture_store_failed")
                    .await;
                return Err(WireResponse::Refused {
                    message: format!(
                        "captured oauth token for `{}` could not be stored: {error}",
                        substituted.name
                    ),
                });
            }
            for learned_value in learned_values {
                // A zero-length needle would match at every scrub position.
                if learned_value.is_empty() {
                    continue;
                }
                self.reflection.learn_captured_token(
                    &substituted.name,
                    &substituted.placeholder,
                    &learned_value,
                );
            }
        }
        Ok(())
    }

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
                if let Err(refusal) = self.scrub_buffered_response(&flow, &mut response).await {
                    self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                        .await;
                    return refusal;
                }
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
            let mut placeholders = BodyPlaceholderScan::new();
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
                if placeholders.found_in(&chunk) {
                    service
                        .audit_flow_refused(
                            producer_destination
                                .as_deref()
                                .unwrap_or(UNPARSEABLE_DESTINATION),
                            REASON_PLACEHOLDER_IN_BODY,
                        )
                        .await;
                    let _ = sender.send(Err(PLACEHOLDER_IN_BODY_MESSAGE.into())).await;
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

    /// Refuse a response the endpoint cannot read while it holds a value that
    /// could be in it. `Err` carries the refusal for the workload; the chain
    /// entry is written here.
    async fn refuse_unreadable_response(
        &self,
        flow: &PreparedFlow,
        headers: &[(String, String)],
    ) -> Result<(), WireResponse> {
        if body_is_readable(headers) {
            return Ok(());
        }
        self.audit_fail_closed(flow.destination.as_deref(), REASON_RESPONSE_ENCODED)
            .await;
        Err(WireResponse::Refused {
            message: "response is content-encoded and cannot be checked for a reflected \
                      credential; refusing (fail-closed)"
                .into(),
        })
    }

    /// Scrub a whole buffered response of every value substituted so far.
    async fn scrub_buffered_response(
        &self,
        flow: &PreparedFlow,
        response: &mut ForwardResponse,
    ) -> Result<(), WireResponse> {
        self.capture_oauth_response_tokens(flow, &response.body)
            .await?;
        let Some(set) = self.reflection.snapshot() else {
            return Ok(());
        };
        self.refuse_unreadable_response(flow, &response.headers)
            .await?;
        let mut counts = ScrubCounts::new();
        for (_, value) in &mut response.headers {
            *value = set.scrub_str(value, &mut counts);
        }
        let body_counts_before: u64 = counts.values().sum();
        response.body = set.scrub(&response.body, &mut counts);
        if counts.values().sum::<u64>() != body_counts_before {
            // The body changed length; a declared length would now be wrong.
            let len = response.body.len().to_string();
            for (name, value) in &mut response.headers {
                if name.eq_ignore_ascii_case("content-length") {
                    value.clone_from(&len);
                }
            }
        }
        self.audit_reflection_scrubbed(&counts, flow.destination.as_deref())
            .await;
        Ok(())
    }

    async fn transform_captured_oauth_stream(
        &self,
        mut flow: PreparedFlow,
        mut upstream: ForwardStreamResponse,
        ai_meta: Option<AiRequestMeta>,
        mut head: ForwardResponse,
        mut scrub_counts: ScrubCounts,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        if let Err(refusal) = self.refuse_unreadable_response(&flow, &head.headers).await {
            self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                .await;
            return Err(refusal);
        }
        let mut body = Vec::new();
        while let Some(next) = upstream.body.recv().await {
            let chunk = match next {
                Ok(chunk) => chunk,
                Err(error) => {
                    self.audit_forward_outcome(&flow, ForwardOutcome::ResponseFailed)
                        .await;
                    return Err(WireResponse::Refused {
                        message: error.to_string(),
                    });
                }
            };
            if body.len().saturating_add(chunk.len()) > MAX_HTTP_STREAM_BODY_BYTES {
                self.audit_fail_closed(flow.destination.as_deref(), "response_body_limit_exceeded")
                    .await;
                self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                    .await;
                return Err(WireResponse::Refused {
                    message: format!(
                        "response body exceeds the {MAX_HTTP_STREAM_BODY_BYTES} byte limit"
                    ),
                });
            }
            body.extend_from_slice(&chunk);
        }
        if let Err(refusal) = self.capture_oauth_response_tokens(&flow, &body).await {
            self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                .await;
            return Err(refusal);
        }
        if let Some(set) = self.reflection.snapshot() {
            for (_, value) in &mut head.headers {
                *value = set.scrub_str(value, &mut scrub_counts);
            }
            body = set.scrub(&body, &mut scrub_counts);
        }
        head.body = body;
        let reinject_proofs = flow.replacement_flow.reinject_response(&mut head);
        if let Some((redacted, hits)) = self
            .redactor
            .redact_bytes_for(&head.body, &flow.redaction_action)
        {
            if hits.detector_failures > 0 {
                self.audit_fail_closed(
                    flow.destination.as_deref(),
                    "response_body_detector_failed",
                )
                .await;
                self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                    .await;
                return Err(WireResponse::Refused {
                    message: "sensitive-data detector failed closed; refusing response".into(),
                });
            }
            head.body = redacted;
            flow.redaction_hits.merge(hits);
        }

        self.audit_completed_flow(&flow, &reinject_proofs).await;
        if let Some(meta) = ai_meta {
            self.record_streaming_ai_usage(&meta, head.status, &head.body)
                .await;
        }
        self.audit_reflection_scrubbed(&scrub_counts, flow.destination.as_deref())
            .await;
        self.audit_forward_outcome(&flow, ForwardOutcome::Completed)
            .await;

        let status = head.status;
        let headers = head.headers;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        if !head.body.is_empty() {
            sender
                .try_send(Ok(head.body))
                .map_err(|_| WireResponse::Refused {
                    message: "response consumer closed".into(),
                })?;
        }
        drop(sender);
        Ok(ForwardStreamResponse {
            status,
            headers,
            body_len: None,
            body: receiver,
        })
    }

    async fn transform_response_stream(
        self: &Arc<Self>,
        mut flow: PreparedFlow,
        mut upstream: ForwardStreamResponse,
        ai_meta: Option<AiRequestMeta>,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        // A reflected credential is scrubbed before any other transform sees
        // the response, headers first, so nothing downstream ever holds it.
        let scrub_set = self.reflection.snapshot();
        let mut scrub_counts = ScrubCounts::new();
        if let Some(set) = &scrub_set {
            if let Err(refusal) = self
                .refuse_unreadable_response(&flow, &upstream.headers)
                .await
            {
                self.audit_forward_outcome(&flow, ForwardOutcome::ResponseRefused)
                    .await;
                return Err(refusal);
            }
            for (_, value) in &mut upstream.headers {
                *value = set.scrub_str(value, &mut scrub_counts);
            }
        }
        // Reinject and redact response headers before any body byte can cross
        // to the guest. HTTP transfer framing belongs to the upstream leg, not
        // FlowMux; remove it because transforms may change decoded length.
        let status = upstream.status;
        let headers = std::mem::take(&mut upstream.headers);
        let mut head = ForwardResponse {
            status,
            headers,
            body: Vec::new(),
        };
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
        if self.flow_has_oauth_capture(&flow) {
            return self
                .transform_captured_oauth_stream(flow, upstream, ai_meta, head, scrub_counts)
                .await;
        }
        let mut reinject_proofs = flow.replacement_flow.reinject_response(&mut head);

        let response_status = head.status;
        let response_headers = std::mem::take(&mut head.headers);
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let service = Arc::clone(self);
        let response_destination = flow.destination.clone();
        let meter_streaming = ai_meta.is_some();
        tokio::spawn(async move {
            // Every exit below yields how the forward ended, and the outcome is
            // recorded once, after the block, whichever exit was taken.
            let mut scrubber = scrub_set.map(StreamingScrubber::new);
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
                    let chunk = match scrubber.as_mut() {
                        Some(scrubber) => scrubber.push(&chunk),
                        None => chunk,
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
                // What the scrubber held back for a value that might have
                // continued is decided now, and goes through the same
                // transforms as every other byte.
                let held_back = scrubber
                    .as_mut()
                    .map(StreamingScrubber::finish)
                    .unwrap_or_default();
                let (mut reintroduced_tail, proofs) =
                    reinjector.push(&mut flow.replacement_flow, &held_back);
                reinject_proofs.extend(proofs);
                let (tail, proofs) = reinjector.finish(&mut flow.replacement_flow);
                reintroduced_tail.extend(tail);
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
            // Scrubbed occurrences are recorded on every exit, a failed or
            // canceled body included: what matters is that the destination
            // sent the value back, not whether the guest read to the end.
            if let Some(scrubber) = &scrubber {
                merge_counts(&mut scrub_counts, scrubber.counts().clone());
            }
            service
                .audit_reflection_scrubbed(&scrub_counts, response_destination.as_deref())
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
    use crate::keyholder::resolver::OAuthTokenSet;
    use crate::keyholder::{
        FileBindingStore, LocalResolver, SecretBindingMeta, SecretResolver, SubstitutionRegistry,
    };
    use crate::supervisor::network_endpoint_proxy::test_support::{
        MockForwarder, RedirectForwarder, bearer_ref, gate_admitting, service_with,
    };
    use crate::supervisor::network_endpoint_proxy::{
        ForwardError, ForwardResponse, Forwarder, SubstitutionService,
    };
    use crate::supervisor::redactor::STREAM_TRANSFORM_OVERLAP;
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_binding::{BindingStore, OAuthBindingMeta};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::substitution_wire::WireResponse;
    use secrecy::{ExposeSecret, SecretBox};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use crate::keyholder::resolver::OAuthSecretString;

    fn oauth_binding_meta(pointer: &str) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into()],
            sigv4: None,
            inject: Default::default(),
            provider: None,
            approve: Default::default(),
            oauth: Some(OAuthBindingMeta {
                authorization_url: "https://auth.example.com/authorize".into(),
                token_url: "https://auth.example.com/token".into(),
                client_id: "public-client-id".into(),
                scopes: vec!["scope-a".into()],
                response_access_token_pointer: Some(pointer.into()),
            }),
        }
    }

    fn oauth_token_set(access_token: &str) -> OAuthTokenSet {
        OAuthTokenSet {
            access_token: OAuthSecretString::from(access_token.to_owned()),
            refresh_token: Some(OAuthSecretString::from(String::from("oauth-refresh-token"))),
            client_secret: None,
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

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
                inject: Default::default(),
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

    struct OAuthTokenForwarder;

    #[async_trait]
    impl Forwarder for OAuthTokenForwarder {
        async fn forward(
            &self,
            _req: mvm_contract::substitution::PreparedRequest,
        ) -> Result<ForwardResponse, ForwardError> {
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"access_token":"fresh-oauth-token","token_type":"Bearer"}"#.to_vec(),
            })
        }
    }

    struct FullOAuthTokenForwarder;

    #[async_trait]
    impl Forwarder for FullOAuthTokenForwarder {
        async fn forward(
            &self,
            _req: mvm_contract::substitution::PreparedRequest,
        ) -> Result<ForwardResponse, ForwardError> {
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"access_token":"fresh-oauth-token","refresh_token":"fresh-refresh-token","expires_in":3600,"token_type":"Bearer"}"#
                    .to_vec(),
            })
        }
    }

    struct ShortOAuthTokenForwarder;

    #[async_trait]
    impl Forwarder for ShortOAuthTokenForwarder {
        async fn forward(
            &self,
            _req: mvm_contract::substitution::PreparedRequest,
        ) -> Result<ForwardResponse, ForwardError> {
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"access_token":"tok123","token_type":"Bearer"}"#.to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn oauth_token_substituted_at_endpoint_never_reaches_guest() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(
                    serde_json::to_string(&oauth_token_set("placeholder-seeded-value")).unwrap(),
                )),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "openai", &oauth_binding_meta("/access_token"))
            .unwrap();
        let resolver = Arc::new(LocalResolver::with_bindings(
            "local",
            Arc::new(store),
            Arc::new(bindings),
        ));
        let resolver_dyn: Arc<dyn SecretResolver> = resolver.clone();
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(registry),
                resolver_dyn,
                Arc::new(OAuthTokenForwarder),
                gate_admitting(&[("api.openai.com", 443)]),
            )
            .with_oauth_capture_rule("openai", "/access_token"),
        );
        let response = service
            .process(mvm_core::substitution_wire::WireRequest {
                method: "GET".into(),
                url: "https://api.openai.com/token".into(),
                headers: vec![("authorization".into(), placeholder.clone())],
                body_b64: String::new(),
            })
            .await;
        let mvm_core::substitution_wire::WireResponse::Ok { body_b64, .. } = response else {
            panic!("request must succeed");
        };
        let body = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(
            body.contains(&placeholder),
            "captured token must be replaced with the minted placeholder: {body}"
        );
        assert!(
            !body.contains("fresh-oauth-token"),
            "captured token must never be exposed to the guest: {body}"
        );
        let secret = resolver
            .resolve(&bearer_ref("openai", &["api.openai.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"fresh-oauth-token");
    }

    #[tokio::test]
    async fn echoed_oauth_refresh_token_is_scrubbed_and_persisted() {
        let dir = tempdir().unwrap();
        let store = Arc::new(FileSecretStore::with_dir(dir.path()));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(
                    serde_json::to_string(&oauth_token_set("seed-token")).unwrap(),
                )),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "openai", &oauth_binding_meta("/access_token"))
            .unwrap();
        let resolver = Arc::new(LocalResolver::with_bindings(
            "local",
            store.clone(),
            Arc::new(bindings),
        ));
        let resolver_dyn: Arc<dyn SecretResolver> = resolver.clone();
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(registry),
                resolver_dyn,
                Arc::new(FullOAuthTokenForwarder),
                gate_admitting(&[("api.openai.com", 443)]),
            )
            .with_oauth_capture_rule("openai", "/access_token"),
        );
        let response = service
            .process(mvm_core::substitution_wire::WireRequest {
                method: "GET".into(),
                url: "https://api.openai.com/token".into(),
                headers: vec![("authorization".into(), placeholder.clone())],
                body_b64: String::new(),
            })
            .await;
        let mvm_core::substitution_wire::WireResponse::Ok { body_b64, .. } = response else {
            panic!("request must succeed");
        };
        let body = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(
            body.matches(&placeholder).count() >= 2,
            "access and refresh token must both be replaced with the minted placeholder: {body}"
        );
        assert!(
            !body.contains("fresh-oauth-token"),
            "captured access token must never be exposed to the guest: {body}"
        );
        assert!(
            !body.contains("fresh-refresh-token"),
            "captured refresh token must never be exposed to the guest: {body}"
        );
        let secret = resolver
            .resolve(&bearer_ref("openai", &["api.openai.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"fresh-oauth-token");
        let stored: OAuthTokenSet =
            serde_json::from_str(store.get("local", "openai").unwrap().expose_secret()).unwrap();
        assert_eq!(
            stored.refresh_token.as_ref().unwrap().expose_secret(),
            "fresh-refresh-token"
        );
        assert!(stored.expires_at > Utc::now());
    }

    #[tokio::test]
    async fn short_oauth_tokens_are_scrubbed_and_persisted() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(
                    serde_json::to_string(&oauth_token_set("seed-token")).unwrap(),
                )),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "openai", &oauth_binding_meta("/access_token"))
            .unwrap();
        let resolver = Arc::new(LocalResolver::with_bindings(
            "local",
            Arc::new(store),
            Arc::new(bindings),
        ));
        let resolver_dyn: Arc<dyn SecretResolver> = resolver.clone();
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(registry),
                resolver_dyn,
                Arc::new(ShortOAuthTokenForwarder),
                gate_admitting(&[("api.openai.com", 443)]),
            )
            .with_oauth_capture_rule("openai", "/access_token"),
        );
        let response = service
            .process(mvm_core::substitution_wire::WireRequest {
                method: "GET".into(),
                url: "https://api.openai.com/token".into(),
                headers: vec![("authorization".into(), placeholder.clone())],
                body_b64: String::new(),
            })
            .await;
        let mvm_core::substitution_wire::WireResponse::Ok { body_b64, .. } = response else {
            panic!("request must succeed");
        };
        let body = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(body.contains(&placeholder));
        assert!(!body.contains("tok123"));
        let secret = resolver
            .resolve(&bearer_ref("openai", &["api.openai.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"tok123");
    }

    #[tokio::test]
    async fn flowmux_response_token_capture_updates_streamed_oauth_responses() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(
                    serde_json::to_string(&oauth_token_set("seed-token")).unwrap(),
                )),
            )
            .unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put("local", "openai", &oauth_binding_meta("/access_token"))
            .unwrap();
        let resolver = Arc::new(LocalResolver::with_bindings(
            "local",
            Arc::new(store),
            Arc::new(bindings),
        ));
        let resolver_dyn: Arc<dyn SecretResolver> = resolver.clone();
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(registry),
                resolver_dyn,
                Arc::new(OAuthTokenForwarder),
                gate_admitting(&[("api.openai.com", 443)]),
            )
            .with_oauth_capture_rule("openai", "/access_token"),
        );
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(sender);
        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "GET".into(),
                    url: "https://api.openai.com/token".into(),
                    headers: vec![("authorization".into(), placeholder.clone())],
                    body_len: 0,
                },
                receiver,
            )
            .await
            .expect("streamed oauth response");
        let mut body = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains(&placeholder));
        assert!(!body.contains("fresh-oauth-token"));
        let secret = resolver
            .resolve(&bearer_ref("openai", &["api.openai.com"]))
            .unwrap();
        assert_eq!(secret.expose_secret().as_slice(), b"fresh-oauth-token");
    }
}
