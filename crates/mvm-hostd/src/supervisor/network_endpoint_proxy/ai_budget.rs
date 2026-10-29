//! AI egress metering and the per-VM token budget: usage extraction from
//! provider responses, the budget refusal, and the metrics and audit records
//! they produce.

use mvm_core::observability::instance_metrics::{
    InstanceLabels, InstanceMetricsRegistry, global as instance_metrics_global,
};
use mvm_core::policy::audit::ai_usage::AiUsageRecord;
use url::Url;

use super::SubstitutionService;
use super::prepare::PreparedFlow;
use crate::supervisor::ai_meter;
use crate::supervisor::audit_recorder::Recorder;
use mvm_contract::substitution::PreparedRequest;
use mvm_core::substitution_wire::WireResponse;

/// Minimal request metadata captured for AI metering so the streaming path
/// doesn't need to own the whole prepared request after it has been handed
/// to the forwarder.
#[derive(Debug, Clone)]
pub(super) struct AiRequestMeta {
    pub(super) method: String,
    pub(super) url: String,
}

impl SubstitutionService {
    pub(super) fn ai_tracker(&self) -> Option<&std::sync::Arc<ai_meter::AiBudgetTracker>> {
        self.ai_tracker.as_ref()
    }

    pub(super) fn ai_budget_exceeded(&self) -> bool {
        self.ai_tracker().map(|t| t.is_exceeded()).unwrap_or(false)
    }

    pub(super) fn ai_request_budget_enabled(&self) -> bool {
        self.ai_tracker()
            .is_some_and(|tracker| tracker.request_budget.is_some())
    }

    pub(super) async fn admit_ai_request(
        &self,
        flow: &PreparedFlow,
        request: &mut PreparedRequest,
    ) -> Result<(), WireResponse> {
        let checked = (|| {
            if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
                return Err("ai_token_budget_exhausted");
            }
            let Some(tracker) = self
                .ai_tracker()
                .and_then(|tracker| tracker.request_budget.as_ref())
            else {
                return Ok(None);
            };
            if self.recorder.is_none() || self.instance_id.is_none() {
                return Err("ai_budget_audit_identity_unavailable");
            }
            let (canonical, cost) = tracker.inspect(
                &request.method,
                &request.url,
                &request.headers,
                &request.body,
            )?;
            let reserved = tracker.reserve(cost)?;
            request.body = canonical;
            request.headers.retain(|(name, _)| {
                !name.eq_ignore_ascii_case("content-length")
                    && !name.eq_ignore_ascii_case("transfer-encoding")
            });
            Ok(Some(tracker.audit_labels(reserved)?))
        })();
        match checked {
            Ok(reserved) => {
                if let (Some(mut labels), Some(recorder)) = (reserved, &self.recorder) {
                    labels.push(("vm".into(), self.instance_id.clone().unwrap_or_default()));
                    let bindings: Vec<_> = flow
                        .substituted
                        .iter()
                        .map(|binding| binding.name.as_str())
                        .collect();
                    let bindings =
                        serde_json::to_string(&bindings).map_err(|_| WireResponse::Refused {
                            message: "AI egress binding metadata encoding failed".into(),
                        })?;
                    labels.push(("secret_bindings".into(), bindings));
                    if recorder
                        .record_unbound(
                            crate::supervisor::audit_recorder::EventCategory::Host,
                            "host.ai.budget_reserved",
                            labels,
                        )
                        .await
                        .is_err()
                    {
                        return Err(WireResponse::Refused {
                            message: "AI egress budget reservation audit failed".into(),
                        });
                    }
                }
                Ok(())
            }
            Err(reason) => {
                self.audit_fail_closed(flow.destination.as_deref(), reason)
                    .await;
                self.audit_ai_budget_exceeded(flow, &request.url).await;
                Err(WireResponse::Refused {
                    message: format!("AI egress budget refused: {reason}"),
                })
            }
        }
    }

    pub(super) async fn record_ai_usage(&self, meta: &AiRequestMeta, status: u16, body: &[u8]) {
        if !self
            .ai_policy
            .as_ref()
            .is_some_and(|policy| policy.metering)
        {
            return;
        }
        let Some(tracker) = self.ai_tracker() else {
            return;
        };
        let Some(usage) = ai_meter::extract_usage(&meta.url, body) else {
            return;
        };
        let totals = tracker.record(&usage);
        self.update_ai_metrics(totals);
        if let Some(recorder) = &self.recorder {
            let record = self.build_ai_usage_record(meta, status, &usage, totals.exceeded);
            if let Err(e) = self.record_ai_sample(recorder, &record).await {
                tracing::warn!(error = %e, "ai.usage audit emit failed");
            }
            if totals.exceeded {
                emit_ai_budget_exceeded(recorder, &record).await;
            }
        }
    }

    pub(super) async fn record_streaming_ai_usage(
        &self,
        meta: &AiRequestMeta,
        status: u16,
        body: &[u8],
    ) {
        if !self
            .ai_policy
            .as_ref()
            .is_some_and(|policy| policy.metering)
        {
            return;
        }
        let Some(tracker) = self.ai_tracker() else {
            return;
        };
        let Some(usage) = ai_meter::extract_streaming_usage(&meta.url, body) else {
            return;
        };
        let totals = tracker.record(&usage);
        self.update_ai_metrics(totals);
        if let Some(recorder) = &self.recorder {
            let record = self.build_ai_usage_record(meta, status, &usage, totals.exceeded);
            if let Err(e) = self.record_ai_sample(recorder, &record).await {
                tracing::warn!(error = %e, "ai.usage audit emit failed");
            }
            if totals.exceeded {
                emit_ai_budget_exceeded(recorder, &record).await;
            }
        }
    }

    async fn record_ai_sample(
        &self,
        recorder: &Recorder,
        record: &AiUsageRecord,
    ) -> Result<(), crate::supervisor::audit_recorder::RecorderError> {
        let mut labels = record.to_labels();
        if let Some(vm) = &self.instance_id {
            labels.push(("vm".into(), vm.clone()));
        }
        if let Some(budget) = self
            .ai_tracker()
            .and_then(|tracker| tracker.request_budget.as_ref())
        {
            labels.push(("budget_id".into(), budget.lifetime_id().to_owned()));
        }
        recorder
            .record_unbound(
                crate::supervisor::audit_recorder::EventCategory::Host,
                "host.ai.usage",
                labels,
            )
            .await
    }

    pub(super) async fn audit_ai_budget_exceeded(&self, flow: &PreparedFlow, url: &str) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        let (host, port, path) = parse_url_parts(url);
        let destination = flow.destination.as_deref().unwrap_or(&host);
        let record = AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host: destination.to_string(),
            port,
            method: String::new(),
            path,
            provider: String::new(),
            model: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            status: 0,
            budget_exceeded: true,
        };
        if let Err(e) = recorder.record_ai_budget_exceeded(&record).await {
            tracing::warn!(error = %e, destination, "ai.budget_exceeded audit emit failed");
        }
    }

    fn update_ai_metrics(&self, totals: ai_meter::UsageTotals) {
        let Some(instance_id) = self.instance_id.as_deref() else {
            return;
        };
        let registry: &InstanceMetricsRegistry = match &self.instance_metrics {
            Some(r) => r.as_ref(),
            None => instance_metrics_global(),
        };
        if !registry.update_ai_counters(
            instance_id,
            totals.requests,
            totals.input_tokens,
            totals.output_tokens,
            totals.total_tokens,
        ) {
            let labels = InstanceLabels {
                instance_id: instance_id.to_string(),
                tenant: self.tenant.clone(),
                template: String::new(),
            };
            registry.register(labels);
            let _ = registry.update_ai_counters(
                instance_id,
                totals.requests,
                totals.input_tokens,
                totals.output_tokens,
                totals.total_tokens,
            );
        }
    }

    fn build_ai_usage_record(
        &self,
        meta: &AiRequestMeta,
        status: u16,
        usage: &ai_meter::ExtractedUsage,
        budget_exceeded: bool,
    ) -> AiUsageRecord {
        let (host, port, path) = parse_url_parts(&meta.url);
        AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host,
            port,
            method: meta.method.clone(),
            path,
            provider: usage.provider.to_string(),
            model: usage.model.clone(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            status,
            budget_exceeded,
        }
    }
}

async fn emit_ai_budget_exceeded(recorder: &Recorder, record: &AiUsageRecord) {
    if let Err(e) = recorder.record_ai_budget_exceeded(record).await {
        tracing::warn!(error = %e, "ai.budget_exceeded audit emit failed");
    }
}

fn parse_url_parts(url: &str) -> (String, u16, String) {
    let Some(u) = Url::parse(url).ok() else {
        return (String::new(), 0, String::new());
    };
    let host = u.host_str().unwrap_or("").to_string();
    let port = u.port_or_known_default().unwrap_or(0);
    let path = u.path().to_string();
    (host, port, path)
}

#[cfg(test)]
mod ai_metering_tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    use super::*;
    use crate::keyholder::SubstitutionRegistry;
    use crate::supervisor::network_endpoint_proxy::test_support::gate_admitting;
    use crate::supervisor::network_endpoint_proxy::{
        ForwardError, ForwardResponse, ForwardStreamResponse, Forwarder, PreparedRequest,
    };
    use mvm_contract::policy::network_policy::AiPolicy;
    use mvm_core::observability::instance_metrics::InstanceMetricsRegistry;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use secrecy::SecretBox;

    struct NullResolver;

    impl crate::keyholder::SecretResolver for NullResolver {
        fn resolve(
            &self,
            _r: &crate::keyholder::SecretRef,
        ) -> Result<SecretBox<Vec<u8>>, crate::keyholder::ResolveError> {
            Err(crate::keyholder::ResolveError::Unbound {
                name: String::new(),
            })
        }
    }

    struct TestForwarder {
        status: u16,
        body: Vec<u8>,
    }

    impl TestForwarder {
        fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                body: body.into(),
            }
        }
    }

    #[async_trait]
    impl Forwarder for TestForwarder {
        async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            Ok(ForwardResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }

        async fn forward_stream(
            &self,
            _req: PreparedRequest,
        ) -> Result<ForwardStreamResponse, ForwardError> {
            let (sender, receiver) = tokio::sync::mpsc::channel(2);
            for chunk in self.body.chunks(64) {
                sender
                    .send(Ok(chunk.to_vec()))
                    .await
                    .map_err(|_| ForwardError::Failed("consumer closed".into()))?;
            }
            Ok(ForwardStreamResponse {
                status: self.status,
                headers: Vec::new(),
                body_len: Some(self.body.len() as u64),
                body: receiver,
            })
        }
    }

    fn openai_response() -> Vec<u8> {
        br#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#
            .to_vec()
    }

    fn openai_stream() -> Vec<u8> {
        b"data: {\"choices\":[]}\n\ndata: {\"model\":\"gpt-4\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n".to_vec()
    }

    fn wire_to(url: &str) -> WireRequest {
        WireRequest {
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body_b64: B64.encode(b""),
        }
    }

    fn metered_service(
        forwarder: Arc<dyn Forwarder>,
        policy: AiPolicy,
    ) -> (Arc<SubstitutionService>, Arc<InstanceMetricsRegistry>) {
        let metrics = Arc::new(InstanceMetricsRegistry::new());
        let strict = policy.request_budget.is_some();
        let mut service = SubstitutionService::new(
            Arc::new(SubstitutionRegistry::default()),
            Arc::new(NullResolver),
            forwarder,
            // Every destination these tests send to, so a budget refusal
            // can only be the budget's.
            gate_admitting(&[
                ("api.openai.com", 443),
                ("example.com", 443),
                ("api.anthropic.com", 443),
            ]),
        )
        .with_instance_id("vm-1")
        .with_ai_policy(policy)
        .with_instance_metrics(Arc::clone(&metrics));
        if strict {
            service = service.with_recorder(Recorder::new(
                Arc::new(crate::supervisor::audit::CapturingAuditSigner::new()),
                mvm_core::plan::TenantId("local".into()),
            ));
        }
        (Arc::new(service), metrics)
    }

    #[tokio::test]
    async fn process_records_openai_usage_in_tracker_and_metrics() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered(),
        );
        let resp = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().requests, 1);
        assert_eq!(tracker.totals().input_tokens, 10);
        assert_eq!(tracker.totals().output_tokens, 5);
        assert_eq!(tracker.totals().total_tokens, 15);

        let (_, values) = metrics.get("vm-1").expect("instance registered");
        assert_eq!(values.ai_requests_total, 1);
        assert_eq!(values.ai_tokens_input_total, 10);
        assert_eq!(values.ai_tokens_output_total, 5);
        assert_eq!(values.ai_tokens_total_total, 15);
    }

    #[tokio::test]
    async fn process_allows_request_that_exceeds_budget_then_refuses_the_next() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered().with_total_budget(5),
        );

        let first = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(first, WireResponse::Ok { status: 200, .. }));

        let second = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(
            matches!(second, WireResponse::Refused { ref message, .. } if message.contains("AI egress budget")),
            "expected budget refusal, got {second:?}"
        );
    }

    #[tokio::test]
    async fn process_stream_records_openai_streaming_usage() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_stream())),
            AiPolicy::metered(),
        );
        let stream = service
            .process_stream(
                wire_to("https://api.openai.com/v1/chat/completions"),
                &Default::default(),
            )
            .await
            .expect("stream request succeeded");
        assert_eq!(stream.status, 200);

        // Drain the body so the spawned transform task finishes and records usage.
        let mut receiver = stream.body;
        let mut received = 0;
        while let Some(chunk) = receiver.recv().await {
            let chunk = chunk.expect("chunk ok");
            received += chunk.len();
        }
        assert!(received > 0);

        // Give the spawned task a moment to record usage.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().input_tokens, 3);
        assert_eq!(tracker.totals().output_tokens, 2);
        assert_eq!(tracker.totals().total_tokens, 5);

        let (_, values) = metrics.get("vm-1").expect("instance registered");
        assert_eq!(values.ai_tokens_total_total, 5);
    }

    #[tokio::test]
    async fn unknown_provider_is_not_metered() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered(),
        );
        let resp = service.process(wire_to("https://example.com/v1")).await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().requests, 0);
        assert!(metrics.get("vm-1").is_none());
    }

    #[tokio::test]
    async fn budget_refusal_only_blocks_known_ai_providers() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered().with_total_budget(5),
        );

        // First OpenAI call pushes the VM over budget.
        let first = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(first, WireResponse::Ok { status: 200, .. }));

        // A non-AI destination is still allowed after the budget is exhausted.
        let other = service.process(wire_to("https://example.com/v1")).await;
        assert!(matches!(other, WireResponse::Ok { status: 200, .. }));

        // Another OpenAI call is refused.
        let second = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(
            matches!(second, WireResponse::Refused { ref message, .. } if message.contains("AI egress budget")),
        );
    }

    #[tokio::test]
    async fn disabled_policy_skips_metering() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::disabled(),
        );
        let resp = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));
        assert!(service.ai_tracker().is_none());
    }

    #[tokio::test]
    async fn strict_budget_refuses_missing_audit_before_forwarding() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let mut service = Arc::try_unwrap(service).ok().unwrap();
        service.recorder = None;
        let response = service.process(strict_request()).await;
        assert!(matches!(response, WireResponse::Refused { message }
            if message.contains("ai_budget_audit_identity_unavailable")));
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_usage_and_reservation_share_the_endpoint_lifetime() {
        let mut policy = strict_policy();
        policy.metering = true;
        let (service, _) = metered_service(Arc::new(TestForwarder::ok(
            br#"{"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":1,"output_tokens":5}}"#.to_vec()
        )), policy);
        let signer = Arc::new(crate::supervisor::audit::CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), mvm_core::plan::TenantId("local".into()));
        let service = Arc::try_unwrap(service)
            .ok()
            .unwrap()
            .with_recorder(recorder);
        assert!(matches!(
            service.process(strict_request()).await,
            WireResponse::Ok { .. }
        ));
        let entries = signer.entries();
        let reservation = entries
            .iter()
            .find(|e| e.event == "host.ai.budget_reserved")
            .unwrap();
        let usage = entries.iter().find(|e| e.event == "host.ai.usage").unwrap();
        assert_eq!(reservation.labels["budget_id"], usage.labels["budget_id"]);
        assert_eq!(reservation.labels["vm"], usage.labels["vm"]);
        assert_eq!(reservation.labels["secret_bindings"], "[]");
        assert_eq!(usage.labels["output_tokens"], "5");
    }

    struct CountForwarder {
        calls: std::sync::atomic::AtomicU64,
        fail: bool,
    }

    #[async_trait]
    impl Forwarder for CountForwarder {
        async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail {
                return Err(ForwardError::Failed("synthetic failure".into()));
            }
            Ok(ForwardResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            })
        }
    }

    fn strict_request() -> WireRequest {
        let mut wire = wire_to("https://api.anthropic.com/v1/messages");
        wire.body_b64 = B64
            .encode(br#"{"model":"claude-haiku-4-5-20251001","max_tokens":20000,"messages":[]}"#);
        wire
    }

    fn strict_policy() -> AiPolicy {
        let mut policy = AiPolicy::disabled();
        policy.request_budget = Some(mvm_contract::policy::network_policy::AiRequestBudget {
            max_requests: 1,
            max_spend_microusd: 500_000,
            model: mvm_contract::policy::network_policy::AiBudgetModel::ClaudeHaiku45,
        });
        policy
    }

    #[tokio::test]
    async fn strict_budget_is_shared_by_buffered_and_streaming_and_survives_failure() {
        for fail in [false, true] {
            let forwarder = Arc::new(CountForwarder {
                calls: std::sync::atomic::AtomicU64::new(0),
                fail,
            });
            let (service, _) = metered_service(forwarder.clone(), strict_policy());
            let first = service.process(strict_request()).await;
            assert_eq!(matches!(first, WireResponse::Ok { .. }), !fail);
            assert!(
                service
                    .process_stream(strict_request(), &Default::default())
                    .await
                    .is_err()
            );
            assert!(matches!(
                service.process(strict_request()).await,
                WireResponse::Refused { .. }
            ));
            assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn streaming_reserves_before_the_forwarder_and_refuses_aliases() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let mut alias = strict_request();
        alias.body_b64 =
            B64.encode(br#"{"model":"claude-haiku-4-5","max_tokens":1,"messages":[]}"#);
        assert!(
            service
                .process_stream(alias, &Default::default())
                .await
                .is_err()
        );
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            service
                .process_stream(strict_request(), &Default::default())
                .await
                .is_ok()
        );
        assert!(matches!(
            service.process(strict_request()).await,
            WireResponse::Refused { .. }
        ));
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn streamed_request_body_cannot_bypass_the_shared_reservation() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        for expected_success in [true, false] {
            let wire = strict_request();
            let bytes = B64.decode(wire.body_b64).unwrap();
            let head = mvm_core::substitution_wire::HttpFlowHead {
                method: wire.method,
                url: wire.url,
                headers: wire.headers,
                body_len: bytes.len() as u64,
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            sender.send(zeroize::Zeroizing::new(bytes)).await.unwrap();
            drop(sender);
            let result = service
                .process_body_stream(head, receiver, &Default::default())
                .await;
            assert_eq!(result.is_ok(), expected_success);
        }
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn strict_stream_declared_size_is_refused_before_reading_a_body() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let wire = strict_request();
        let head = mvm_core::substitution_wire::HttpFlowHead {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body_len: 1024 * 1024 + 1,
        };
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            service.process_body_stream(head, receiver, &Default::default()),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(WireResponse::Refused { .. }))),
            "oversized declaration must be refused without waiting for body bytes"
        );
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn strict_stream_fragment_overflow_is_refused_before_eof() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let wire = strict_request();
        let head = mvm_core::substitution_wire::HttpFlowHead {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body_len: 1024 * 1024,
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(17);
        for _ in 0..16 {
            sender
                .send(zeroize::Zeroizing::new(vec![b' '; 65536]))
                .await
                .unwrap();
        }
        sender
            .send(zeroize::Zeroizing::new(vec![b' ']))
            .await
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            service.process_body_stream(head, receiver, &Default::default()),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(WireResponse::Refused { .. }))),
            "fragment accumulation must stop at the strict limit, without waiting for EOF"
        );
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(sender);
    }

    #[tokio::test]
    async fn strict_stream_accepts_the_exact_size_boundary() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let wire = strict_request();
        let mut bytes = B64.decode(wire.body_b64).unwrap();
        bytes.resize(1024 * 1024, b' ');
        let head = mvm_core::substitution_wire::HttpFlowHead {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body_len: 1024 * 1024,
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        for chunk in bytes.chunks(65536) {
            sender
                .send(zeroize::Zeroizing::new(chunk.to_vec()))
                .await
                .unwrap();
        }
        drop(sender);
        assert!(
            service
                .process_body_stream(head, receiver, &Default::default())
                .await
                .is_ok()
        );
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct PendingForwarder {
        entered: tokio::sync::Notify,
    }

    #[async_trait]
    impl Forwarder for PendingForwarder {
        async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelled_upstream_attempt_does_not_refund_the_reservation() {
        let forwarder = Arc::new(PendingForwarder {
            entered: tokio::sync::Notify::new(),
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let owner = Arc::clone(&service);
        let call = tokio::spawn(async move { owner.process(strict_request()).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            forwarder.entered.notified(),
        )
        .await
        .unwrap();
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert!(matches!(
            service.process(strict_request()).await,
            WireResponse::Refused { .. }
        ));
    }

    #[tokio::test]
    async fn reservation_audit_carries_only_identity_and_counters() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder, strict_policy());
        let signer = Arc::new(crate::supervisor::audit::CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), mvm_core::plan::TenantId("local".into()));
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .unwrap()
                .with_recorder(recorder),
        );
        assert!(matches!(
            service.process(strict_request()).await,
            WireResponse::Ok { .. }
        ));
        let entries = signer.entries();
        let reservation = entries
            .iter()
            .find(|entry| entry.event == "host.ai.budget_reserved")
            .unwrap();
        assert_eq!(reservation.labels["vm"], "vm-1");
        assert_eq!(reservation.labels["reserved_requests"], "1");
        assert_eq!(reservation.labels["reserved_spend_microusd"], "500000");
        assert!(
            !serde_json::to_string(reservation)
                .unwrap()
                .contains("messages")
        );
    }

    #[tokio::test]
    async fn reservation_audit_failure_refuses_forwarding_without_a_refund() {
        let forwarder = Arc::new(CountForwarder {
            calls: std::sync::atomic::AtomicU64::new(0),
            fail: false,
        });
        let (service, _) = metered_service(forwarder.clone(), strict_policy());
        let recorder = Recorder::new(
            Arc::new(crate::supervisor::audit::NoopAuditSigner),
            mvm_core::plan::TenantId("local".into()),
        );
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .unwrap()
                .with_recorder(recorder),
        );
        assert!(matches!(service.process(strict_request()).await,
            WireResponse::Refused { message } if message.contains("reservation audit failed")));
        assert!(matches!(service.process(strict_request()).await,
            WireResponse::Refused { message } if message.contains("ai_request_budget_exhausted")));
        assert_eq!(forwarder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
