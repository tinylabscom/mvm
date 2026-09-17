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

    pub(super) async fn record_ai_usage(&self, meta: &AiRequestMeta, status: u16, body: &[u8]) {
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
            if let Err(e) = recorder.record_ai_usage(&record).await {
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
            if let Err(e) = recorder.record_ai_usage(&record).await {
                tracing::warn!(error = %e, "ai.usage audit emit failed");
            }
            if totals.exceeded {
                emit_ai_budget_exceeded(recorder, &record).await;
            }
        }
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
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(SubstitutionRegistry::default()),
                Arc::new(NullResolver),
                forwarder,
            )
            .with_instance_id("vm-1")
            .with_ai_policy(policy)
            .with_instance_metrics(Arc::clone(&metrics)),
        );
        (service, metrics)
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
            AiPolicy::metered_with_total_budget(5),
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
            .process_stream(wire_to("https://api.openai.com/v1/chat/completions"))
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
            AiPolicy::metered_with_total_budget(5),
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
}
