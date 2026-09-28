//! The approver the endpoint runs: ledger, broker, timeout, grants, audit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use mvm_contract::policy::approval::{
    ApprovalLedger, ApprovalOutcome, ApprovalReason, ApprovalRequest, ApprovalRequestId,
    ApprovalResponse, OperatorId, PolicyCapability, PolicyDecision, PolicyEvaluation, PolicyReason,
};
use mvm_contract::policy::approval_prompt::{
    ApprovalAnswer, ApprovalPrompt, ApprovalScope, ApprovalSubject, MAX_SUBJECT_FIELD_CHARS,
};
use mvm_contract::protocol::agent_session::{
    AgentSessionId, AgentSessionJournal, IdempotencyKey, RetentionPolicy,
};
use sha2::{Digest, Sha256};

use super::broker::ApprovalBroker;
use super::limiter::PromptLimiter;
use super::{ApprovalVerdict, REASON_APPROVAL_UNAVAILABLE, RuntimeApprover};
use crate::supervisor::audit_recorder::{EventCategory, Recorder};

/// How long a held flow waits for an answer before it is denied.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a session-scoped approval lasts.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(15 * 60);
/// Prompts one VM may raise per minute before the rest are denied unasked.
pub const DEFAULT_PROMPTS_PER_MINUTE: usize = 10;

/// The one operator identity the ledger authorises: the broker. Which backend
/// behind it answered is recorded as the answer's reason.
const BROKER_OPERATOR: &str = "approval-broker";

const REASON_TIMED_OUT: &str = "timed_out";
const REASON_RATE_LIMITED: &str = "rate_limited";
const REASON_ANSWER_MISMATCH: &str = "answer_mismatch";
const REASON_LEDGER_REFUSED: &str = "ledger_refused";

/// A millisecond wall clock; a seam so tests can move time.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    })
}

/// A remembered session-scoped approval.
struct SessionGrant {
    key: [u8; 32],
    expires_at_ms: u64,
}

/// The ledger and the journal that hosts it, locked together.
struct Ledger {
    ledger: ApprovalLedger,
    journal: AgentSessionJournal,
}

/// Records every runtime approval in the contract's [`ApprovalLedger`], asks
/// a broker, and fails closed.
pub struct ApprovalSupervisor {
    ledger: Mutex<Ledger>,
    session_id: AgentSessionId,
    broker: Option<Arc<dyn ApprovalBroker>>,
    grants: Mutex<Vec<SessionGrant>>,
    limiter: Mutex<PromptLimiter>,
    recorder: Option<Arc<Recorder>>,
    timeout: Duration,
    session_ttl: Duration,
    clock: Clock,
    sequence: AtomicU64,
    nonce: AtomicU64,
    instance_digest: [u8; 32],
}

/// Builds an [`ApprovalSupervisor`].
pub struct ApprovalSupervisorBuilder {
    instance: String,
    broker: Option<Arc<dyn ApprovalBroker>>,
    recorder: Option<Arc<Recorder>>,
    timeout: Duration,
    session_ttl: Duration,
    prompts_per_minute: usize,
    clock: Clock,
}

impl ApprovalSupervisorBuilder {
    /// Ask `broker`. Without one every question is denied.
    #[must_use]
    pub fn broker(mut self, broker: Arc<dyn ApprovalBroker>) -> Self {
        self.broker = Some(broker);
        self
    }

    /// Chain-sign every step to `recorder`.
    #[must_use]
    pub fn recorder(mut self, recorder: Option<Arc<Recorder>>) -> Self {
        self.recorder = recorder;
        self
    }

    /// Wait at most `timeout` for an answer.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Remember a session-scoped approval for `ttl`.
    #[must_use]
    pub fn session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = ttl;
        self
    }

    /// Put at most `max` questions to the broker per minute.
    #[must_use]
    pub fn prompts_per_minute(mut self, max: usize) -> Self {
        self.prompts_per_minute = max;
        self
    }

    /// Read time from `clock` (milliseconds since the epoch).
    #[must_use]
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Open the ledger's journal and build the supervisor.
    ///
    /// # Errors
    ///
    /// The journal could not be opened — an id the contract refuses.
    pub fn build(self) -> anyhow::Result<ApprovalSupervisor> {
        let session_id = AgentSessionId::parse(session_id_for(&self.instance))
            .map_err(|e| anyhow::anyhow!("approval session id: {e}"))?;
        let instance_digest: [u8; 32] = Sha256::digest(self.instance.as_bytes()).into();
        let retention = RetentionPolicy {
            max_events: 4_096,
            max_bytes: 4 * 1024 * 1024,
            max_age_ms: Some(24 * 60 * 60 * 1000),
        };
        let (journal, _) = AgentSessionJournal::open(
            session_id.clone(),
            instance_digest,
            (self.clock)(),
            retention,
        )
        .map_err(|e| anyhow::anyhow!("opening the approval journal: {e:?}"))?;
        Ok(ApprovalSupervisor {
            ledger: Mutex::new(Ledger {
                ledger: ApprovalLedger::new(session_id.clone()),
                journal,
            }),
            session_id,
            broker: self.broker,
            grants: Mutex::new(Vec::new()),
            limiter: Mutex::new(PromptLimiter::new(
                self.prompts_per_minute,
                Duration::from_secs(60),
            )),
            recorder: self.recorder,
            timeout: self.timeout,
            session_ttl: self.session_ttl,
            clock: self.clock,
            sequence: AtomicU64::new(1),
            nonce: AtomicU64::new(1),
            instance_digest,
        })
    }
}

/// A contract-legal session id for an instance: lower-case, `[a-z0-9._-]`.
fn session_id_for(instance: &str) -> String {
    let cleaned: String = instance
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(96)
        .collect();
    format!("approvals-{}", cleaned.trim_matches('-'))
        .trim_end_matches('-')
        .to_string()
}

impl ApprovalSupervisor {
    /// Start building a supervisor for the VM `instance`.
    #[must_use]
    pub fn builder(instance: &str) -> ApprovalSupervisorBuilder {
        ApprovalSupervisorBuilder {
            instance: instance.to_string(),
            broker: None,
            recorder: None,
            timeout: DEFAULT_APPROVAL_TIMEOUT,
            session_ttl: DEFAULT_SESSION_TTL,
            prompts_per_minute: DEFAULT_PROMPTS_PER_MINUTE,
            clock: system_clock(),
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Whether `key` has a live session grant; drops expired ones.
    fn session_granted(&self, key: &[u8; 32], now: u64) -> bool {
        let mut grants = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        grants.retain(|grant| grant.expires_at_ms > now);
        grants.iter().any(|grant| &grant.key == key)
    }

    fn remember(&self, key: [u8; 32], now: u64) {
        let ttl = u64::try_from(self.session_ttl.as_millis()).unwrap_or(u64::MAX);
        let mut grants = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        grants.retain(|grant| grant.key != key);
        grants.push(SessionGrant {
            key,
            expires_at_ms: now.saturating_add(ttl),
        });
    }

    fn next_request_id(&self) -> ApprovalRequestId {
        let n = self.sequence.fetch_add(1, Ordering::Relaxed);
        let salt = &hex::encode(&self.instance_digest[..4]);
        ApprovalRequestId::parse(format!("appr-{salt}-{n}"))
            .expect("request id is built from contract-legal characters")
    }

    /// Record the request in the ledger. `Err` means the ledger refused it,
    /// which is itself a denial.
    fn open_request(
        &self,
        request_id: &ApprovalRequestId,
        subject: &ApprovalSubject,
        key: [u8; 32],
        now: u64,
    ) -> Result<(), ()> {
        let capability = match subject {
            ApprovalSubject::ToolCall { .. } => PolicyCapability::AgentInvoke,
            ApprovalSubject::Egress { .. } | ApprovalSubject::SecretUse { .. } => {
                PolicyCapability::NetworkConnect
            }
        };
        let request_digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(subject).unwrap_or_default()).into();
        let policy_digest: [u8; 32] = Sha256::digest(b"mvm-runtime-approval-v1").into();
        let evaluation = PolicyEvaluation {
            capability,
            resource_digest: key,
            request_digest,
            admission_plan_digest: Some(self.instance_digest),
            policy_digest,
            matched_rule: None,
            decision: PolicyDecision::Ask(PolicyReason::ApprovalRequired),
        };
        let timeout = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
        let request = ApprovalRequest {
            approval_id: request_id.clone(),
            session_id: self.session_id.clone(),
            idempotency_key: IdempotencyKey::parse(request_id.as_str()).map_err(|_| ())?,
            capability,
            resource_digest: key,
            request_digest,
            policy_digest,
            admission_plan_digest: self.instance_digest,
            reason: ApprovalReason::PolicyRule,
            authorized_operators: vec![OperatorId::parse(BROKER_OPERATOR).map_err(|_| ())?],
            expires_at_unix_ms: now.saturating_add(timeout.max(1)),
        };
        let mut state = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
        let Ledger { ledger, journal } = &mut *state;
        ledger
            .request(journal, &evaluation, request, now)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn respond(&self, request_id: &ApprovalRequestId, outcome: ApprovalOutcome, now: u64) {
        let response = ApprovalResponse {
            approval_id: request_id.clone(),
            operator_id: OperatorId::parse(BROKER_OPERATOR).expect("constant operator id"),
            outcome,
            response_nonce: self.nonce.fetch_add(1, Ordering::Relaxed),
            reason: None,
            ticket_ref: None,
        };
        let mut state = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
        let Ledger { ledger, journal } = &mut *state;
        let _ = ledger.respond(journal, response, now);
    }

    /// Close a request nobody answered: expired when its deadline has
    /// passed, canceled otherwise.
    fn close_unanswered(&self, request_id: &ApprovalRequestId, now: u64) {
        let mut state = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
        let Ledger { ledger, journal } = &mut *state;
        if ledger.expire(journal, request_id, now).is_err() {
            let _ = ledger.cancel(journal, request_id, now);
        }
    }

    async fn audit(&self, event: &str, labels: Vec<(String, String)>) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        if let Err(e) = recorder
            .record_unbound(EventCategory::Approval, event, labels)
            .await
        {
            tracing::warn!(error = %e, event, "approval audit emit failed");
        }
    }

    async fn deny(
        &self,
        request_id: Option<&ApprovalRequestId>,
        subject: &ApprovalSubject,
        event: &str,
        reason: &'static str,
    ) -> ApprovalVerdict {
        let mut labels = subject_labels(subject);
        if let Some(id) = request_id {
            labels.push(("request_id".into(), id.to_string()));
        }
        labels.push(("reason".into(), reason.to_string()));
        self.audit(event, labels).await;
        ApprovalVerdict::Denied { reason }
    }
}

/// The question's identity for a session grant: what the operator approved,
/// not the particular request. Guest-derived values that vary per request —
/// an egress path — are left out, so a session approval covers the rule.
fn question_key(subject: &ApprovalSubject) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match subject {
        ApprovalSubject::Egress {
            route_id,
            rule,
            destination,
            method,
            ..
        } => {
            for part in ["egress", route_id, rule, destination, method] {
                hasher.update(part.as_bytes());
                hasher.update([0]);
            }
        }
        ApprovalSubject::SecretUse {
            secret,
            destination,
        } => {
            for part in ["secret", secret, destination] {
                hasher.update(part.as_bytes());
                hasher.update([0]);
            }
        }
        ApprovalSubject::ToolCall { tool } => {
            hasher.update(b"tool\0");
            hasher.update(tool.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// The labels a chain entry carries for a subject: host-chosen names and the
/// destination, and a guest-supplied method only as a fixed-set label. No
/// path, and no tool name — both come from the workload.
fn subject_labels(subject: &ApprovalSubject) -> Vec<(String, String)> {
    let mut labels = vec![("kind".to_string(), subject.kind_label().to_string())];
    match subject {
        ApprovalSubject::Egress {
            route_id,
            rule,
            destination,
            method,
            ..
        } => {
            labels.push(("route".into(), route_id.clone()));
            labels.push(("rule".into(), rule.clone()));
            labels.push(("destination".into(), destination.clone()));
            labels.push((
                "method".into(),
                crate::supervisor::network_endpoint_proxy::method_label(method).to_string(),
            ));
        }
        ApprovalSubject::SecretUse {
            secret,
            destination,
        } => {
            labels.push(("secret".into(), secret.clone()));
            labels.push(("destination".into(), destination.clone()));
        }
        ApprovalSubject::ToolCall { .. } => {}
    }
    labels
}

/// Bound every guest-derived field before it leaves the endpoint.
fn bounded(subject: &ApprovalSubject) -> ApprovalSubject {
    let cut = |s: &str| s.chars().take(MAX_SUBJECT_FIELD_CHARS).collect::<String>();
    match subject {
        ApprovalSubject::Egress {
            route_id,
            rule,
            destination,
            method,
            path,
        } => ApprovalSubject::Egress {
            route_id: route_id.clone(),
            rule: rule.clone(),
            destination: destination.clone(),
            method: cut(method),
            path: cut(path),
        },
        ApprovalSubject::SecretUse { .. } => subject.clone(),
        ApprovalSubject::ToolCall { tool } => ApprovalSubject::ToolCall { tool: cut(tool) },
    }
}

#[async_trait]
impl RuntimeApprover for ApprovalSupervisor {
    async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict {
        let now = self.now();
        let key = question_key(subject);
        if self.session_granted(&key, now) {
            let mut labels = subject_labels(subject);
            labels.push(("scope".into(), "session".into()));
            labels.push(("reason".into(), "session_grant".into()));
            self.audit("approval.granted", labels).await;
            return ApprovalVerdict::Approved;
        }
        let Some(broker) = &self.broker else {
            return self
                .deny(
                    None,
                    subject,
                    "approval.denied",
                    REASON_APPROVAL_UNAVAILABLE,
                )
                .await;
        };
        let admitted = self
            .limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .try_take(now);
        if !admitted {
            return self
                .deny(None, subject, "approval.denied", REASON_RATE_LIMITED)
                .await;
        }

        let request_id = self.next_request_id();
        if self.open_request(&request_id, subject, key, now).is_err() {
            return self
                .deny(
                    Some(&request_id),
                    subject,
                    "approval.denied",
                    REASON_LEDGER_REFUSED,
                )
                .await;
        }
        let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
        let mut labels = subject_labels(subject);
        labels.push(("request_id".into(), request_id.to_string()));
        labels.push(("expires_in_ms".into(), timeout_ms.to_string()));
        self.audit("approval.requested", labels).await;

        let prompt = ApprovalPrompt {
            request_id: request_id.clone(),
            subject: bounded(subject),
            expires_in_ms: timeout_ms,
        };
        let answer = tokio::time::timeout(self.timeout, broker.ask(&prompt)).await;
        let now = self.now();
        match answer {
            Err(_elapsed) => {
                self.close_unanswered(&request_id, now);
                self.deny(
                    Some(&request_id),
                    subject,
                    "approval.timed_out",
                    REASON_TIMED_OUT,
                )
                .await
            }
            Ok(Err(error)) => {
                self.close_unanswered(&request_id, now);
                self.deny(Some(&request_id), subject, "approval.denied", error.label())
                    .await
            }
            Ok(Ok(answer)) if answer.request_id != request_id => {
                self.close_unanswered(&request_id, now);
                self.deny(
                    Some(&request_id),
                    subject,
                    "approval.denied",
                    REASON_ANSWER_MISMATCH,
                )
                .await
            }
            Ok(Ok(answer)) => self.settle(&request_id, subject, key, &answer, now).await,
        }
    }
}

impl ApprovalSupervisor {
    async fn settle(
        &self,
        request_id: &ApprovalRequestId,
        subject: &ApprovalSubject,
        key: [u8; 32],
        answer: &ApprovalAnswer,
        now: u64,
    ) -> ApprovalVerdict {
        self.respond(request_id, answer.outcome, now);
        let mut labels = subject_labels(subject);
        labels.push(("request_id".into(), request_id.to_string()));
        labels.push(("reason".into(), answer.reason_label().to_string()));
        match answer.outcome {
            ApprovalOutcome::Approved => {
                labels.push(("scope".into(), answer.scope.label().to_string()));
                if answer.scope == ApprovalScope::Session {
                    self.remember(key, now);
                }
                self.audit("approval.granted", labels).await;
                ApprovalVerdict::Approved
            }
            ApprovalOutcome::Denied => {
                self.audit("approval.denied", labels).await;
                ApprovalVerdict::Denied {
                    reason: "approval_denied",
                }
            }
        }
    }

    /// The ledger's state for `request_id`, for tests and diagnostics.
    #[must_use]
    pub fn ledger_state(
        &self,
        request_id: &ApprovalRequestId,
    ) -> Option<mvm_contract::policy::approval::ApprovalState> {
        self.ledger
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ledger
            .state(request_id)
            .ok()
    }
}

#[cfg(test)]
mod tests;
