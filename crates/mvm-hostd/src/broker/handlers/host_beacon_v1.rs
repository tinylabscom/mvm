//! `host.beacon.v1` — guest-agent boot beacon.
//!
//! The platform's own guest agent calls `report` once at boot; this
//! handler forwards one chain-signed entry to `mvm-audit-signer` in the
//! system `lifecycle` category under the `lifecycle.beacon_reported`
//! event name. The entry is host-authoritative in its identity binding
//! (`workload_id` / `tenant_id` / `session_id` / `correlation_id` all
//! come from the supervisor's `ServiceCallCtx`) and guest-asserted only
//! in its data fields (`agent_version`, `boot_unix_ms`).
//!
//! This is the deployment-evidence counterpart to `plan.launched`: that
//! entry proves the supervisor started a backend for the plan; this one
//! proves the admitted workload's agent actually came alive inside it —
//! the "is my code actually running in production?" signal, recorded on
//! the same tamper-evident chain.
//!
//! Limits:
//!
//! - Rate limit: 1 token/sec/workload (`BEACON_TOKENS_PER_SEC`) with a
//!   one-second burst — a boot beacon needs exactly one token; a
//!   compromised guest looping `report` can bloat the chain by at most
//!   one entry per second.
//! - Payload cap: 4 KiB (`BEACON_REPORT_BYTES`) on the serialized
//!   report, enforced before parse effects.
//!
//! Refusal semantics:
//!
//! - Unknown verb → `ServiceErrorCode::NotImplemented`.
//! - Oversize payload → `ServiceErrorCode::BadRequest`.
//! - Rate limit exceeded → `ServiceErrorCode::RateLimitExceeded`.
//! - Audit-signer transport error → `ServiceErrorCode::Unavailable`.

use std::pin::Pin;
use std::time::Duration;

use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::audit_signer::AppendEntryRequest;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_beacon::{BEACON_REPORTED_EVENT, BeaconAck, BeaconReport};
use mvm_core::rate_limit::TokenBucket;
use tokio::sync::Mutex;

use crate::broker::audit_client::{AuditClient, AuditClientError};

/// The audit category the beacon entry is recorded under. Chosen from
/// the audit-signer's existing allow-list: the beacon marks a workload
/// lifecycle fact (agent came alive), not a new evidence class.
const BEACON_CATEGORY: &str = "lifecycle";

/// Serialized-payload cap for one `report` call.
const BEACON_REPORT_BYTES: usize = 4096;

/// Per-workload report rate: one beacon per second bounds chain bloat
/// under a hostile guest while leaving boot-time retries (agent may
/// fire before the host broker is fully up) cheap.
const BEACON_TOKENS_PER_SEC: u32 = 1;

/// The handler. Holds the `AuditClient` it forwards to and a
/// per-workload token bucket.
pub struct HostBeaconV1Handler {
    audit_client: AuditClient,
    rate_limiter: Mutex<TokenBucket>,
    call_timeout: Duration,
}

impl HostBeaconV1Handler {
    /// New handler with the default rate ([`BEACON_TOKENS_PER_SEC`]) and
    /// a 5-second call timeout (fsync on the audit-signer side is
    /// typically <50ms but pathological disks can stall longer).
    pub fn new(audit_client: AuditClient) -> Self {
        Self {
            audit_client,
            rate_limiter: Mutex::new(TokenBucket::new(BEACON_TOKENS_PER_SEC)),
            call_timeout: Duration::from_secs(5),
        }
    }

    /// Test/override hook for the bucket rate. Production uses
    /// [`BEACON_TOKENS_PER_SEC`] via [`Self::new`].
    pub fn with_rate(audit_client: AuditClient, tokens_per_sec: u32) -> Self {
        Self {
            audit_client,
            rate_limiter: Mutex::new(TokenBucket::new(tokens_per_sec)),
            call_timeout: Duration::from_secs(5),
        }
    }

    async fn handle_report(
        &self,
        ctx: &ServiceCallCtx,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let size = serde_json::to_vec(&payload)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size > BEACON_REPORT_BYTES {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("report {size} bytes exceeds cap {BEACON_REPORT_BYTES}"),
            ));
        }
        let report: BeaconReport = serde_json::from_value(payload).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("report payload parse failed: {e}"),
            )
        })?;
        if !self.rate_limiter.lock().await.try_take() {
            return Err(ServiceError::new(
                ServiceErrorCode::RateLimitExceeded,
                "beacon report rate limit exceeded",
            ));
        }
        let chain_head = self.dispatch_one(build_append_entry(ctx, &report)).await?;
        let ack = BeaconAck { chain_head };
        serde_json::to_value(ack).map_err(|e| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("report response encode failed: {e}"),
            )
        })
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
            mvm_core::protocol::audit_signer::AppendEntryResponse::Ok { chain_head, .. } => {
                Ok(chain_head)
            }
            mvm_core::protocol::audit_signer::AppendEntryResponse::Pong { .. } => {
                Err(ServiceError::new(
                    ServiceErrorCode::InternalError,
                    "audit-signer responded Pong to AppendEntry",
                ))
            }
            mvm_core::protocol::audit_signer::AppendEntryResponse::Err { code, .. } => {
                Err(ServiceError::new(
                    ServiceErrorCode::InternalError,
                    format!("audit-signer rejected entry: {code:?}"),
                ))
            }
        }
    }
}

impl ServiceHandler for HostBeaconV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse(mvm_core::protocol::host_beacon::HOST_BEACON_SERVICE)
            .expect("host.beacon.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        // Every profile runs the platform agent; the beacon carries no
        // authority, only liveness evidence.
        &[
            AgentProfile::SealedProd,
            AgentProfile::Dev,
            AgentProfile::Builder,
        ]
    }

    fn audit_durability(&self) -> AuditDurability {
        // PerCall — the beacon entry fsyncs through the audit-signer
        // before the broker returns, so the ack's `chain_head` is
        // durable. The handler does not emit a separate per-call entry:
        // the beacon entry IS the audit emission.
        AuditDurability::PerCall
    }

    fn idempotency(&self) -> Idempotency {
        // Each boot mints a fresh entry; retries after a host-broker
        // race legitimately produce a second entry, and the rate limit
        // bounds the total.
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            match verb {
                "report" => self.handle_report(ctx, payload).await,
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("host.beacon.v1: unknown verb `{other}`"),
                )),
            }
        })
    }
}

/// Stamp the supervisor-authoritative identifiers and the host-authored
/// event into an `AppendEntryRequest::AppendEntry`. The guest-supplied
/// `agent_version` / `boot_unix_ms` ride through as data fields only.
fn build_append_entry(ctx: &ServiceCallCtx, report: &BeaconReport) -> AppendEntryRequest {
    AppendEntryRequest::AppendEntry {
        request_id: format!("{}-beacon", ctx.correlation_id.as_str()),
        category: BEACON_CATEGORY.into(),
        ts: chrono::Utc::now().to_rfc3339(),
        workload_id: ctx.workload_id.clone(),
        tenant_id: ctx.tenant_id.clone(),
        session_id: ctx.session_id.clone(),
        correlation_id: ctx.correlation_id.as_str().to_string(),
        fields: serde_json::json!({
            "event": BEACON_REPORTED_EVENT,
            "agent_version": report.agent_version,
            "boot_unix_ms": report.boot_unix_ms,
        }),
    }
}

// Force-cite the cap constant so a future maintainer can grep for it
// without chasing serde.
const _: usize = BEACON_REPORT_BYTES;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::{AppendEntryResponse, AuditSignerErrorCode};
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

    fn sample_report() -> BeaconReport {
        BeaconReport {
            agent_version: "0.17.0".into(),
            boot_unix_ms: 1_787_181_844_000,
        }
    }

    /// Spin a minimal mock audit-signer that records the requests it
    /// receives and replies with a canned `Ok` head.
    async fn spawn_mock_signer(
        path: std::path::PathBuf,
        captured: Arc<TokioMutex<Vec<AppendEntryRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await.unwrap();
                let req: AppendEntryRequest = serde_json::from_slice(&body).unwrap();
                let request_id = req.request_id().to_string();
                captured.lock().await.push(req);
                let resp = AppendEntryResponse::Ok {
                    request_id,
                    chain_head: "head-mock".into(),
                    entry_hash: "head-mock".into(),
                    sig_alg: SIG_ALG_ED25519,
                };
                let resp_bytes = serde_json::to_vec(&resp).unwrap();
                let resp_len: u32 = resp_bytes.len().try_into().unwrap();
                stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
                stream.write_all(&resp_bytes).await.unwrap();
                let _ = stream.shutdown().await;
            }
        })
    }

    #[tokio::test]
    async fn report_appends_lifecycle_beacon_entry_with_authoritative_identity() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock_signer(sock.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let handler = HostBeaconV1Handler::new(AuditClient::new(&sock));
        let ack = handler
            .handle_report(&ctx(), serde_json::to_value(sample_report()).unwrap())
            .await
            .expect("report must succeed");
        assert_eq!(ack["chain_head"], "head-mock");

        let entries = captured.lock().await;
        assert_eq!(entries.len(), 1);
        let AppendEntryRequest::AppendEntry {
            category,
            workload_id,
            tenant_id,
            session_id,
            fields,
            ..
        } = &entries[0]
        else {
            panic!("expected AppendEntry");
        };
        assert_eq!(category, "lifecycle");
        assert_eq!(workload_id, "wl-001");
        assert_eq!(tenant_id, "t-001");
        assert_eq!(session_id, "sess-001");
        assert_eq!(fields["event"], BEACON_REPORTED_EVENT);
        assert_eq!(fields["agent_version"], "0.17.0");
        assert_eq!(fields["boot_unix_ms"], 1_787_181_844_000_u64);
        mock.abort();
    }

    #[tokio::test]
    async fn report_refuses_guest_supplied_identity() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock_signer(sock.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let handler = HostBeaconV1Handler::new(AuditClient::new(&sock));
        // `deny_unknown_fields` makes the identity unexpressible: the
        // parse itself must fail before any rate token is consumed.
        let err = handler
            .handle_report(
                &ctx(),
                serde_json::json!({
                    "agent_version": "0.17.0",
                    "boot_unix_ms": 0,
                    "workload_id": "wl-spoof",
                }),
            )
            .await
            .expect_err("guest-supplied identity must be refused");
        assert_eq!(err.code, ServiceErrorCode::BadRequest);

        assert!(
            captured.lock().await.is_empty(),
            "no chain entry may be written for a refused report"
        );
        mock.abort();
    }

    #[tokio::test]
    async fn report_enforces_rate_limit() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let captured = Arc::new(TokioMutex::new(Vec::new()));
        let mock = spawn_mock_signer(sock.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        // Bucket capacity equals the rate: the first report takes the
        // one burst token, the immediate second report is refused.
        let handler = HostBeaconV1Handler::with_rate(AuditClient::new(&sock), 1);
        handler
            .handle_report(&ctx(), serde_json::to_value(sample_report()).unwrap())
            .await
            .expect("first report succeeds");
        let err = handler
            .handle_report(&ctx(), serde_json::to_value(sample_report()).unwrap())
            .await
            .expect_err("second immediate report exceeds burst");
        assert_eq!(err.code, ServiceErrorCode::RateLimitExceeded);
        assert_eq!(captured.lock().await.len(), 1);
        mock.abort();
    }

    #[tokio::test]
    async fn report_maps_signer_rejection_to_internal_error() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let signer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let resp = AppendEntryResponse::Err {
                request_id: "req-1".into(),
                code: AuditSignerErrorCode::InvalidRequest,
                message: "category not in allow-list".into(),
            };
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            let resp_len: u32 = resp_bytes.len().try_into().unwrap();
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
        });

        let handler = HostBeaconV1Handler::new(AuditClient::new(&sock));
        let err = handler
            .handle_report(&ctx(), serde_json::to_value(sample_report()).unwrap())
            .await
            .expect_err("signer rejection must surface");
        assert_eq!(err.code, ServiceErrorCode::InternalError);
        signer.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_verb_is_not_implemented() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let handler = HostBeaconV1Handler::new(AuditClient::new(&sock));
        let outcome = handler
            .dispatch(&ctx(), "bogus", serde_json::json!({}))
            .await;
        let err = outcome.expect_err("unknown verb must be refused");
        assert_eq!(err.code, ServiceErrorCode::NotImplemented);
    }
}
