//! `host.audit.v1` — workload-emitted audit entries.
//!
//! Workloads call `emit` or `emit_batch` over the broker's vsock UDS;
//! this handler forwards each accepted entry to `mvm-audit-signer`
//! over its own UDS, forcing the chain entry's `category` to
//! `workload_audit` and stamping the supervisor-authoritative
//! `workload_id` / `tenant_id` / `session_id` / `correlation_id`.
//!
//! Limits:
//!
//! - Per-record cap: 4 KiB (`BROKER_AUDIT_RECORD_BYTES`).
//! - Batch size: 100 entries / 256 KiB total
//!   (`BROKER_AUDIT_BATCH_MAX` / `BROKER_AUDIT_BATCH_BYTES`).
//! - Rate limit: 20 tokens/sec/workload (`BROKER_AUDIT_TOKENS_PER_SEC`).
//! - Audit durability: `PerCall` — the audit-signer fsyncs before
//!   returning, so the broker's response carries an already-durable
//!   `chain_head`.
//!
//! Refusal semantics:
//!
//! - Unknown verb → `ServiceErrorCode::NotImplemented`.
//! - Payload too large (single `emit`) → `ServiceErrorCode::BadRequest`
//!   with an explicit `"record exceeds 4 KiB"` message (no payload
//!   bytes embedded).
//! - Batch oversize (count or total bytes) →
//!   `ServiceErrorCode::BadRequest`.
//! - Rate limit exceeded → `ServiceErrorCode::RateLimitExceeded`.
//! - Audit-signer transport error → `ServiceErrorCode::Unavailable`.
//! - Audit-signer protocol error → `ServiceErrorCode::InternalError`
//!   with the typed audit-signer code embedded for forensics.

use std::pin::Pin;
use std::time::{Duration, Instant};

use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::audit_signer::{AppendEntryRequest, AppendEntryResponse};
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_audit::{
    BROKER_AUDIT_BATCH_BYTES, BROKER_AUDIT_BATCH_MAX, BROKER_AUDIT_RECORD_BYTES,
    BROKER_AUDIT_TOKENS_PER_SEC, EmitBatchEntryStatus, EmitBatchRequest, EmitBatchResponse,
    EmitErrorCode, EmitRequest, EmitResponse,
};
use tokio::sync::Mutex;

use crate::broker::audit_client::{AuditClient, AuditClientError};

/// The category every workload-emitted entry is forced to. Distinct
/// from the system categories so the chain verifier can compute
/// workload-asserted vs system-asserted entry rates separately.
const WORKLOAD_AUDIT_CATEGORY: &str = "workload_audit";

/// Per-workload token bucket. Cheap (couple of words) so per-call lock
/// acquisition isn't a hot path.
// allow(secret-debug): rate-limit state (token count + refill rate +
// capacity + last-refill instant) is not secret material. Debug
// printing is helpful for diagnosing rate-limit behaviour in logs.
#[derive(Debug)]
struct TokenBucket {
    /// Current token count (floating-point so a partial refill at the
    /// sub-millisecond level doesn't quantise away).
    tokens: f64,
    /// Capacity (max burst) — equals `tokens_per_sec` in this v1
    /// implementation (one-second burst).
    capacity: f64,
    /// Refill rate, tokens per second.
    refill_per_sec: f64,
    /// Last instant we refilled. Refills happen lazily on `try_take`.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(tokens_per_sec: u32) -> Self {
        let cap = tokens_per_sec as f64;
        Self {
            tokens: cap,
            capacity: cap,
            refill_per_sec: cap,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `true` if there was a token to
    /// take, `false` otherwise.
    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * self.refill_per_sec;
        if refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The handler itself.
///
/// Holds the `AuditClient` it forwards to + a per-workload token
/// bucket. Built by the broker's `main` at startup with the
/// audit-signer's UDS path from `SubprocessConfig`.
pub struct HostAuditV1Handler {
    audit_client: AuditClient,
    rate_limiter: Mutex<TokenBucket>,
    call_timeout: Duration,
}

impl HostAuditV1Handler {
    /// New handler with the default rate (`BROKER_AUDIT_TOKENS_PER_SEC`)
    /// and a 5-second call timeout (fsync on the audit-signer side is
    /// typically <50ms but pathological disks can stall longer).
    pub fn new(audit_client: AuditClient) -> Self {
        Self {
            audit_client,
            rate_limiter: Mutex::new(TokenBucket::new(BROKER_AUDIT_TOKENS_PER_SEC)),
            call_timeout: Duration::from_secs(5),
        }
    }

    /// Test/override hook for the bucket rate. Production uses
    /// `BROKER_AUDIT_TOKENS_PER_SEC` via [`Self::new`].
    pub fn with_rate(audit_client: AuditClient, tokens_per_sec: u32) -> Self {
        Self {
            audit_client,
            rate_limiter: Mutex::new(TokenBucket::new(tokens_per_sec)),
            call_timeout: Duration::from_secs(5),
        }
    }

    async fn handle_emit(
        &self,
        ctx: &ServiceCallCtx,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let req: EmitRequest = serde_json::from_value(payload).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("emit payload parse failed: {e}"),
            )
        })?;
        check_record_size(&req)?;
        self.consume_token().await?;
        let append = build_append_entry(ctx, &req, &short_request_id(ctx, 0));
        let chain_head = self.dispatch_one(append).await?;
        let resp = EmitResponse { chain_head };
        serde_json::to_value(resp).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("emit response encode failed: {e}"),
            )
        })
    }

    async fn handle_emit_batch(
        &self,
        ctx: &ServiceCallCtx,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let req: EmitBatchRequest = serde_json::from_value(payload).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("emit_batch payload parse failed: {e}"),
            )
        })?;
        if req.entries.len() > BROKER_AUDIT_BATCH_MAX {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!(
                    "emit_batch entries={} exceeds max={}",
                    req.entries.len(),
                    BROKER_AUDIT_BATCH_MAX
                ),
            ));
        }
        let total_bytes: usize = req.entries.iter().map(record_byte_estimate).sum();
        if total_bytes > BROKER_AUDIT_BATCH_BYTES {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!(
                    "emit_batch total_bytes={} exceeds cap={}",
                    total_bytes, BROKER_AUDIT_BATCH_BYTES
                ),
            ));
        }

        let mut statuses = Vec::with_capacity(req.entries.len());
        let mut last_head = String::new();
        let mut stop_remaining = false;

        for (idx, entry) in req.entries.iter().enumerate() {
            if stop_remaining {
                statuses.push(EmitBatchEntryStatus::Skipped);
                continue;
            }
            if let Err(err) = check_record_size(entry) {
                statuses.push(EmitBatchEntryStatus::Err {
                    code: EmitErrorCode::RecordTooLarge,
                    message: err.message,
                });
                stop_remaining = true;
                continue;
            }
            // Each entry consumes a token. If the bucket runs dry mid-batch
            // the remaining entries are Skipped.
            if !self.try_take_token().await {
                statuses.push(EmitBatchEntryStatus::Err {
                    code: EmitErrorCode::AuditSignerError,
                    message: "per-workload rate limit exhausted mid-batch".into(),
                });
                stop_remaining = true;
                continue;
            }
            let append = build_append_entry(ctx, entry, &short_request_id(ctx, idx));
            match self.dispatch_one(append).await {
                Ok(new_head) => {
                    last_head = new_head.clone();
                    statuses.push(EmitBatchEntryStatus::Ok {
                        chain_head: new_head,
                    });
                }
                Err(err) => {
                    statuses.push(EmitBatchEntryStatus::Err {
                        code: EmitErrorCode::AuditSignerError,
                        message: err.message,
                    });
                    stop_remaining = true;
                }
            }
        }

        let resp = EmitBatchResponse {
            chain_head: last_head,
            statuses,
        };
        serde_json::to_value(resp).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("emit_batch response encode failed: {e}"),
            )
        })
    }

    async fn consume_token(&self) -> Result<(), ServiceError> {
        if self.try_take_token().await {
            Ok(())
        } else {
            Err(ServiceError::new(
                ServiceErrorCode::RateLimitExceeded,
                "per-workload audit emit rate limit exceeded",
            ))
        }
    }

    async fn try_take_token(&self) -> bool {
        self.rate_limiter.lock().await.try_take()
    }

    async fn dispatch_one(&self, append: AppendEntryRequest) -> Result<String, ServiceError> {
        let resp = self
            .audit_client
            .append(&append)
            .await
            .map_err(|e| match e {
                AuditClientError::Connect { .. } | AuditClientError::Io { .. } => {
                    ServiceError::new(
                        ServiceErrorCode::Unavailable,
                        "audit-signer transport failed",
                    )
                }
                AuditClientError::ResponseTooLarge { .. }
                | AuditClientError::Decode { .. }
                | AuditClientError::Encode { .. }
                | AuditClientError::Protocol { .. } => ServiceError::new(
                    ServiceErrorCode::InternalError,
                    "audit-signer protocol violation",
                ),
            })?;
        match resp {
            AppendEntryResponse::Ok { chain_head, .. } => Ok(chain_head),
            AppendEntryResponse::Pong { .. } => Err(ServiceError::new(
                ServiceErrorCode::InternalError,
                "audit-signer responded Pong to AppendEntry",
            )),
            AppendEntryResponse::Err { code, .. } => Err(ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("audit-signer rejected entry: {:?}", code),
            )),
        }
    }
}

impl ServiceHandler for HostAuditV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse("host.audit.v1").expect("host.audit.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        // Every profile may emit audit entries — there's no profile
        // that has audit-emission turned off. Workloads decide whether
        // they want their entries on the chain.
        &[
            AgentProfile::SealedProd,
            AgentProfile::Dev,
            AgentProfile::Builder,
        ]
    }

    fn audit_durability(&self) -> AuditDurability {
        // PerCall — every workload-emitted entry fsyncs through the
        // audit-signer before the broker returns. The handler does
        // *not* emit a *separate* audit entry per call (the entry IS
        // the audit emission); the broker's per-call audit hook can
        // be configured to also emit a `service_call` entry on top,
        // but the handler itself produces one workload_audit entry
        // per `emit` and N per `emit_batch`.
        AuditDurability::PerCall
    }

    fn idempotency(&self) -> Idempotency {
        // Each call mints a fresh entry. The workload's ergonomic for
        // dedup is "supply a deterministic field in your payload"; the
        // chain itself doesn't dedup.
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    fn response_size_cap(&self) -> usize {
        // Single emit returns ~80 bytes; batch returns ~80 bytes
        // per entry. 32 KiB is plenty for a 100-entry batch.
        32 * 1024
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            match verb {
                "emit" => self.handle_emit(ctx, payload).await,
                "emit_batch" => self.handle_emit_batch(ctx, payload).await,
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("host.audit.v1: unknown verb `{other}`"),
                )),
            }
        })
    }
}

/// Estimate the JSON-encoded byte size of one entry. Used for both the
/// per-record cap and the per-batch total. Encoding is deliberately
/// pre-canonicalisation since the cap is a workload-input gate, not a
/// chain-cost gate.
fn record_byte_estimate(req: &EmitRequest) -> usize {
    serde_json::to_vec(req)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
}

fn check_record_size(req: &EmitRequest) -> Result<(), ServiceError> {
    let size = record_byte_estimate(req);
    if size > BROKER_AUDIT_RECORD_BYTES {
        return Err(ServiceError::new(
            ServiceErrorCode::BadRequest,
            format!(
                "record {} bytes exceeds cap {}",
                size, BROKER_AUDIT_RECORD_BYTES
            ),
        ));
    }
    Ok(())
}

/// Stamp the supervisor-authoritative identifiers into an
/// `AppendEntryRequest::AppendEntry` envelope. The workload-supplied
/// `ts` and `fields` ride through; everything else comes from `ctx`.
fn build_append_entry(
    ctx: &ServiceCallCtx,
    req: &EmitRequest,
    request_id: &str,
) -> AppendEntryRequest {
    AppendEntryRequest::AppendEntry {
        request_id: request_id.to_string(),
        category: WORKLOAD_AUDIT_CATEGORY.into(),
        ts: req.ts.clone(),
        workload_id: ctx.workload_id.clone(),
        tenant_id: ctx.tenant_id.clone(),
        session_id: ctx.session_id.clone(),
        correlation_id: ctx.correlation_id.as_str().to_string(),
        fields: req.fields.clone(),
    }
}

/// Compose a per-entry request id from the context's correlation id +
/// an offset. The audit-signer logs `request_id` for diagnostics; this
/// makes batch entries individually addressable in those logs.
fn short_request_id(ctx: &ServiceCallCtx, idx: usize) -> String {
    format!("{}-{}", ctx.correlation_id.as_str(), idx)
}

// Force-cite the const so a future maintainer can grep for the cap
// constant without chasing the const usage through serde.
const _: usize = BROKER_AUDIT_RECORD_BYTES;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
    use mvm_core::protocol::broker::CorrelationId;
    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex as TokioMutex;

    use super::*;

    fn ctx() -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            correlation_id: CorrelationId::new("01HCORR0000000000000000"),
            session_id: "sess-001".into(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    /// Spin a minimal mock audit-signer that records the requests it
    /// receives + responds with `responder(req)`.
    async fn spawn_mock<F>(
        path: std::path::PathBuf,
        captured: Arc<TokioMutex<Vec<AppendEntryRequest>>>,
        responder: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(&AppendEntryRequest) -> AppendEntryResponse + Send + Sync + 'static,
    {
        let listener = UnixListener::bind(&path).unwrap();
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let captured = captured.clone();
                let responder = responder.clone();
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let req: AppendEntryRequest = serde_json::from_slice(&body).unwrap();
                    captured.lock().await.push(req.clone());
                    let resp = responder(&req);
                    let resp_bytes = serde_json::to_vec(&resp).unwrap();
                    let resp_len: u32 = resp_bytes.len().try_into().unwrap();
                    let _ = stream.write_all(&resp_len.to_be_bytes()).await;
                    let _ = stream.write_all(&resp_bytes).await;
                    let _ = stream.shutdown().await;
                });
            }
        })
    }

    fn ok_response(req: &AppendEntryRequest) -> AppendEntryResponse {
        AppendEntryResponse::Ok {
            request_id: req.request_id().to_string(),
            chain_head: "head-".to_string() + req.request_id(),
            entry_hash: "head-".to_string() + req.request_id(),
            sig_alg: SIG_ALG_ED25519,
        }
    }

    #[tokio::test]
    async fn emit_forwards_entry_with_workload_audit_category_and_ctx_ids() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), ok_response).await;
        tokio::task::yield_now().await;

        let handler = HostAuditV1Handler::new(AuditClient::new(&path));
        let payload = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {"action": "rate_limit_breach"},
        });
        let resp = handler
            .dispatch(&ctx(), "emit", payload)
            .await
            .expect("emit must succeed");
        let parsed: EmitResponse = serde_json::from_value(resp).unwrap();
        assert!(parsed.chain_head.starts_with("head-"));

        let req = captured.lock().await[0].clone();
        match req {
            AppendEntryRequest::AppendEntry {
                category,
                workload_id,
                tenant_id,
                session_id,
                correlation_id,
                fields,
                ..
            } => {
                // The handler MUST force the category to workload_audit,
                // ignoring any caller-supplied value.
                assert_eq!(category, "workload_audit");
                // Supervisor-authoritative ids must come from ctx.
                assert_eq!(workload_id, "wl-001");
                assert_eq!(tenant_id, "t-001");
                assert_eq!(session_id, "sess-001");
                assert_eq!(correlation_id, "01HCORR0000000000000000");
                // Workload fields ride through verbatim.
                assert_eq!(fields["action"], "rate_limit_breach");
            }
            other => panic!("expected AppendEntry, got {:?}", other),
        }
        mock.abort();
    }

    #[tokio::test]
    async fn emit_rejects_record_above_4kib() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), ok_response).await;
        tokio::task::yield_now().await;

        let handler = HostAuditV1Handler::new(AuditClient::new(&path));
        // 5 KiB filler — well past the 4 KiB cap.
        let big = "a".repeat(5 * 1024);
        let payload = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {"blob": big},
        });
        let err = handler.dispatch(&ctx(), "emit", payload).await.unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::BadRequest);
        assert!(err.message.contains("exceeds cap"));
        // No append attempted.
        assert!(captured.lock().await.is_empty());
        mock.abort();
    }

    #[tokio::test]
    async fn emit_returns_rate_limit_when_bucket_drained() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), ok_response).await;
        tokio::task::yield_now().await;

        // Bucket sized to 2 tokens; 3rd call must hit the limit.
        let handler = HostAuditV1Handler::with_rate(AuditClient::new(&path), 2);
        let payload = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {"i": 1},
        });
        handler
            .dispatch(&ctx(), "emit", payload.clone())
            .await
            .expect("first call ok");
        handler
            .dispatch(&ctx(), "emit", payload.clone())
            .await
            .expect("second call ok");
        let err = handler.dispatch(&ctx(), "emit", payload).await.unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::RateLimitExceeded);
        assert_eq!(captured.lock().await.len(), 2);
        mock.abort();
    }

    #[tokio::test]
    async fn unknown_verb_returns_not_implemented() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        // No mock spawned — the handler shouldn't reach the network.
        let handler = HostAuditV1Handler::new(AuditClient::new(&path));
        let err = handler
            .dispatch(&ctx(), "delete_chain", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn emit_batch_succeeds_with_per_entry_status() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), ok_response).await;
        tokio::task::yield_now().await;

        let handler = HostAuditV1Handler::with_rate(AuditClient::new(&path), 100);
        let payload = serde_json::json!({
            "entries": [
                {"ts": "2026-05-28T00:00:00Z", "fields": {"i": 1}},
                {"ts": "2026-05-28T00:00:01Z", "fields": {"i": 2}},
                {"ts": "2026-05-28T00:00:02Z", "fields": {"i": 3}},
            ]
        });
        let resp = handler
            .dispatch(&ctx(), "emit_batch", payload)
            .await
            .expect("batch must succeed");
        let parsed: EmitBatchResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.statuses.len(), 3);
        for s in &parsed.statuses {
            assert!(matches!(s, EmitBatchEntryStatus::Ok { .. }));
        }
        assert!(!parsed.chain_head.is_empty());
        assert_eq!(captured.lock().await.len(), 3);
        mock.abort();
    }

    #[tokio::test]
    async fn emit_batch_stops_after_oversize_entry_marks_subsequent_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), ok_response).await;
        tokio::task::yield_now().await;

        let handler = HostAuditV1Handler::with_rate(AuditClient::new(&path), 100);
        let big = "a".repeat(5 * 1024);
        let payload = serde_json::json!({
            "entries": [
                {"ts": "2026-05-28T00:00:00Z", "fields": {"i": 1}},
                {"ts": "2026-05-28T00:00:01Z", "fields": {"blob": big}},
                {"ts": "2026-05-28T00:00:02Z", "fields": {"i": 3}},
            ]
        });
        let resp = handler
            .dispatch(&ctx(), "emit_batch", payload)
            .await
            .expect("batch shape is valid");
        let parsed: EmitBatchResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.statuses.len(), 3);
        match &parsed.statuses[0] {
            EmitBatchEntryStatus::Ok { .. } => {}
            other => panic!("entry 0 expected Ok, got {:?}", other),
        }
        match &parsed.statuses[1] {
            EmitBatchEntryStatus::Err { code, .. } => {
                assert_eq!(*code, EmitErrorCode::RecordTooLarge);
            }
            other => panic!("entry 1 expected RecordTooLarge, got {:?}", other),
        }
        assert!(matches!(parsed.statuses[2], EmitBatchEntryStatus::Skipped));
        // Only the first entry got appended.
        assert_eq!(captured.lock().await.len(), 1);
        mock.abort();
    }

    #[tokio::test]
    async fn emit_batch_rejects_more_than_max_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        // No mock — the handler rejects at the count gate before any
        // network attempt.
        let handler = HostAuditV1Handler::with_rate(AuditClient::new(&path), 1000);
        let mut entries = Vec::new();
        for i in 0..(BROKER_AUDIT_BATCH_MAX + 1) {
            entries.push(serde_json::json!({
                "ts": "2026-05-28T00:00:00Z",
                "fields": {"i": i},
            }));
        }
        let payload = serde_json::json!({"entries": entries});
        let err = handler
            .dispatch(&ctx(), "emit_batch", payload)
            .await
            .unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::BadRequest);
        assert!(err.message.contains("exceeds max"));
    }

    #[tokio::test]
    async fn dispatch_one_maps_audit_signer_typed_err_to_internal_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock(path.clone(), captured.clone(), |req| {
            AppendEntryResponse::Err {
                request_id: req.request_id().to_string(),
                code: AuditSignerErrorCode::ChainDriftDetected,
                message: "chain drift".into(),
            }
        })
        .await;
        tokio::task::yield_now().await;

        let handler = HostAuditV1Handler::new(AuditClient::new(&path));
        let payload = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {},
        });
        let err = handler.dispatch(&ctx(), "emit", payload).await.unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::InternalError);
        assert!(err.message.contains("ChainDriftDetected"));
        mock.abort();
    }

    #[tokio::test]
    async fn dispatch_returns_unavailable_when_audit_signer_socket_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.sock");
        let handler = HostAuditV1Handler::new(AuditClient::new(&path));
        let payload = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {},
        });
        let err = handler.dispatch(&ctx(), "emit", payload).await.unwrap_err();
        assert_eq!(err.code, ServiceErrorCode::Unavailable);
    }

    #[test]
    fn token_bucket_starts_at_capacity() {
        let mut b = TokenBucket::new(5);
        assert_eq!(b.tokens, 5.0);
        for _ in 0..5 {
            assert!(b.try_take());
        }
        assert!(!b.try_take());
    }

    #[test]
    fn handler_id_is_host_audit_v1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.sock");
        let h = HostAuditV1Handler::new(AuditClient::new(&path));
        assert_eq!(h.id().as_str(), "host.audit.v1");
        assert_eq!(h.audit_durability(), AuditDurability::PerCall);
    }
}
