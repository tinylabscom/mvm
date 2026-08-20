//! Typed DTOs for the verified local audit read contract.
//!
//! Everything a UI consumer receives is defined here: the normalized
//! [`VerifiedAuditEvent`], its stable [`AuditEventId`] identity, the typed
//! per-source refusal, and the bounded newest-first read request/response
//! pair with its typed cursor. Serialization shapes are pinned with
//! `deny_unknown_fields` so drift fails loudly on both ends.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Which local chain format an event or refusal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSourceKind {
    /// Per-tenant host-lifecycle chain (`<tenant>.jsonl`, signed envelopes).
    Lifecycle,
    /// Per-VM workload-emitted chain (`<tenant>.<vm>.workload.jsonl`, JCS).
    Workload,
}

/// Identity of one local audit source: a chain kind plus its scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSourceId {
    /// Chain format of the source.
    pub kind: AuditSourceKind,
    /// Tenant the chain file is scoped to.
    pub tenant: String,
    /// VM name for per-VM workload chains; `None` for lifecycle chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// Stable identity of one verified event: its source plus the entry's
/// zero-based position in the verified chain. Chains are append-only and
/// only verified prefixes are ever exposed, so `(source, seq)` names the
/// same entry on every read without rewriting the underlying chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventId {
    /// The source chain this event was read from.
    pub source: AuditSourceId,
    /// Zero-based position in the verified chain order.
    pub seq: u64,
}

/// Normalized category of audit activity, mapped from raw event names and
/// workload categories at the service boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEventKind {
    /// Plan/bundle/image admission and provenance decisions.
    Admission,
    /// A workload being launched or running.
    Launch,
    /// Machine/tenant lifecycle transitions (created, exited, destroyed…).
    Lifecycle,
    /// Readiness/health signals.
    Readiness,
    /// Volume and application-dependency activity.
    Volume,
    /// Secret-reference activity (metadata only, never values).
    SecretReference,
    /// Policy resolution and network-policy activity.
    Policy,
    /// An explicit denial, rejection, or failure.
    Refusal,
    /// Anything not covered by a dedicated category.
    Other,
}

/// One normalized audit event, returned only after its source chain passed
/// signature, link, and scope verification. All free text is sanitized and
/// capped; secret values, credentials, raw payloads, and host paths never
/// appear in any field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAuditEvent {
    /// Stable identity (source + position in the verified chain).
    pub id: AuditEventId,
    /// Normalized activity category.
    pub kind: AuditEventKind,
    /// RFC 3339 timestamp carried by the signed entry.
    pub timestamp: String,
    /// Tenant the event belongs to (matches the source scope).
    pub tenant: String,
    /// Machine/VM the event concerns, when one is identifiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Sanitized raw event name (lifecycle chains) or category (workload
    /// chains) for display alongside the normalized kind.
    pub event: String,
    /// Plan content-address the event is bound to, when bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    /// Sanitized, capped human-readable detail. Sensitive labels are
    /// dropped and path-like values redacted before rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Principal that authorized the decision, when the event records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizer_principal: Option<String>,
    /// Free-form rationale for the authorization decision, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_reason: Option<String>,
    /// Optional ticket / incident / change-request reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ticket_ref: Option<String>,
}

/// Why events from a source were withheld. Withheld means withheld: a
/// refused source contributes zero events, never a partial prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditRefusalKind {
    /// The chain file could not be read.
    Io,
    /// A line failed to parse or decode.
    Malformed,
    /// A chain link (prev-hash / entry-hash) did not hold.
    ChainBroken,
    /// A signature did not verify under the trusted host key.
    SignatureInvalid,
    /// A verified entry claimed a scope other than the source's.
    ScopeMismatch,
    /// The chain ends mid-record: a writer died between the record and its
    /// terminator. Deliberately not folded into [`Self::Malformed`] — an
    /// operator needs to tell an interrupted write from an edited log, and on
    /// disk the two are otherwise the same thing.
    Truncated,
}

/// Typed refusal for one source that failed verification. Returned
/// alongside (never mixed into) verified events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSourceRefusal {
    /// The source that was refused.
    pub source: AuditSourceId,
    /// Failure category.
    pub kind: AuditRefusalKind,
    /// Zero-based line/entry index of the first failure, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Sanitized human-readable reason.
    pub detail: String,
}

/// Per-source verification summary for sources that verified clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSourceSummary {
    /// The verified source.
    pub source: AuditSourceId,
    /// Number of authenticated entries in the chain.
    pub entries: u64,
}

/// Typed pagination cursor: the ordering key of the last event of the
/// previous page. The next page contains strictly older events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCursor {
    /// RFC 3339 timestamp of the last returned event.
    pub timestamp: String,
    /// Source of the last returned event.
    pub source: AuditSourceId,
    /// Chain position of the last returned event.
    pub seq: u64,
}

impl AuditCursor {
    /// Cursor pointing at `event`, for requesting the page after it.
    pub fn after(event: &VerifiedAuditEvent) -> Self {
        Self {
            timestamp: event.timestamp.clone(),
            source: event.id.source.clone(),
            seq: event.id.seq,
        }
    }
}

/// Default page size when the request does not name one.
pub const DEFAULT_READ_LIMIT: usize = 100;

/// Hard upper bound on a single page. Requests above it are clamped.
pub const MAX_READ_LIMIT: usize = 1000;

/// Bounded, filtered read request. Build via [`AuditReadRequest::builder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReadRequest {
    pub(crate) tenant: Option<String>,
    pub(crate) machine: Option<String>,
    pub(crate) kinds: Vec<AuditEventKind>,
    pub(crate) since: Option<DateTime<Utc>>,
    pub(crate) until: Option<DateTime<Utc>>,
    pub(crate) limit: Option<usize>,
    pub(crate) cursor: Option<AuditCursor>,
}

impl AuditReadRequest {
    /// Start building a request. An empty request reads the newest
    /// [`DEFAULT_READ_LIMIT`] events across every local source.
    pub fn builder() -> AuditReadRequestBuilder {
        AuditReadRequestBuilder::default()
    }

    /// Effective page size: default when unset, clamped to
    /// `1..=`[`MAX_READ_LIMIT`].
    pub(crate) fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_READ_LIMIT)
            .clamp(1, MAX_READ_LIMIT)
    }
}

/// Builder for [`AuditReadRequest`].
#[derive(Debug, Clone, Default)]
pub struct AuditReadRequestBuilder {
    request: AuditReadRequest,
}

impl AuditReadRequestBuilder {
    /// Only events from this tenant's chains.
    #[must_use]
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.request.tenant = Some(tenant.into());
        self
    }

    /// Only events whose machine matches.
    #[must_use]
    pub fn machine(mut self, machine: impl Into<String>) -> Self {
        self.request.machine = Some(machine.into());
        self
    }

    /// Restrict to one normalized kind (repeatable).
    #[must_use]
    pub fn kind(mut self, kind: AuditEventKind) -> Self {
        self.request.kinds.push(kind);
        self
    }

    /// Only events at or after this instant.
    #[must_use]
    pub fn since(mut self, since: DateTime<Utc>) -> Self {
        self.request.since = Some(since);
        self
    }

    /// Only events at or before this instant.
    #[must_use]
    pub fn until(mut self, until: DateTime<Utc>) -> Self {
        self.request.until = Some(until);
        self
    }

    /// Page size (clamped to `1..=`[`MAX_READ_LIMIT`]).
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.request.limit = Some(limit);
        self
    }

    /// Resume strictly after this cursor.
    #[must_use]
    pub fn cursor(mut self, cursor: AuditCursor) -> Self {
        self.request.cursor = Some(cursor);
        self
    }

    /// Finish the request.
    pub fn build(self) -> AuditReadRequest {
        self.request
    }
}

/// Result of a bounded verified read: newest-first events, per-source
/// summaries, typed refusals, and the continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReadResponse {
    /// Verified events, newest first.
    pub events: Vec<VerifiedAuditEvent>,
    /// Sources that verified clean (whether or not they contributed
    /// events to this page).
    pub sources: Vec<VerifiedSourceSummary>,
    /// Sources withheld because verification failed.
    pub refusals: Vec<AuditSourceRefusal>,
    /// Cursor for the next (older) page; `None` when exhausted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<AuditCursor>,
}

/// Total ordering key for merged events. Newest-first output sorts by this
/// key descending: timestamp first, then a deterministic source rank
/// (kind, tenant, machine) as tie-break, then chain position. The rule is
/// stable across reads because it depends only on signed entry content and
/// source identity — never on file mtimes or read order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OrderKey {
    ts_ms: i64,
    kind: AuditSourceKind,
    tenant: String,
    machine: Option<String>,
    seq: u64,
}

impl OrderKey {
    fn new(timestamp: &str, source: &AuditSourceId, seq: u64) -> Self {
        Self {
            ts_ms: parse_ts_millis(timestamp),
            kind: source.kind,
            tenant: source.tenant.clone(),
            machine: source.machine.clone(),
            seq,
        }
    }

    pub(crate) fn of_event(event: &VerifiedAuditEvent) -> Self {
        Self::new(&event.timestamp, &event.id.source, event.id.seq)
    }

    pub(crate) fn of_cursor(cursor: &AuditCursor) -> Self {
        Self::new(&cursor.timestamp, &cursor.source, cursor.seq)
    }
}

/// Epoch milliseconds of an RFC 3339 timestamp; unparseable timestamps
/// sort oldest so they can never jump the queue.
pub(crate) fn parse_ts_millis(timestamp: &str) -> i64 {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|t| t.timestamp_millis())
        .unwrap_or(i64::MIN)
}

/// Map a lifecycle-chain event name onto the normalized kind.
pub(crate) fn classify_lifecycle_event(event: &str) -> AuditEventKind {
    if event == "plan.failed"
        || event.contains(".rejected")
        || event.contains(".denied")
        || event.contains(".refused")
        || event.ends_with(".grant_required")
    {
        return AuditEventKind::Refusal;
    }
    match event {
        "plan.launched" | "plan.running" => AuditEventKind::Launch,
        "plan.admitted"
        | "plan.verified"
        | "plan.boot_posture"
        | "plan.shares_admitted"
        | "plan.grants_enforced"
        | "plan.oci_provenance" => AuditEventKind::Admission,
        "plan.policy_resolved" => AuditEventKind::Policy,
        "plan.exited" => AuditEventKind::Lifecycle,
        _ => classify_lifecycle_prefix(event),
    }
}

fn classify_lifecycle_prefix(event: &str) -> AuditEventKind {
    if event.starts_with("lifecycle.")
        || event.starts_with("checkpoint.")
        || event.starts_with("session.")
        || event.starts_with("cmd.")
    {
        AuditEventKind::Lifecycle
    } else if event.starts_with("readiness.") || event.contains("readiness") {
        AuditEventKind::Readiness
    } else if event.starts_with("volume.") || event.starts_with("deps.") {
        AuditEventKind::Volume
    } else if event.starts_with("secret") || event.starts_with("host.secrets") {
        AuditEventKind::SecretReference
    } else if event.starts_with("policy.")
        || event.starts_with("network.")
        || event.starts_with("service.")
        || event.starts_with("flow.")
    {
        AuditEventKind::Policy
    } else {
        AuditEventKind::Other
    }
}

/// Map a workload-chain category onto the normalized kind.
pub(crate) fn classify_workload_category(category: &str) -> AuditEventKind {
    match category {
        "plan" => AuditEventKind::Admission,
        "lifecycle" | "cmd" => AuditEventKind::Lifecycle,
        "secret" | "key" => AuditEventKind::SecretReference,
        "policy" | "flow" | "dns" => AuditEventKind::Policy,
        _ => AuditEventKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> VerifiedAuditEvent {
        VerifiedAuditEvent {
            id: AuditEventId {
                source: AuditSourceId {
                    kind: AuditSourceKind::Lifecycle,
                    tenant: "local".into(),
                    machine: None,
                },
                seq: 3,
            },
            kind: AuditEventKind::Launch,
            timestamp: "2026-08-01T10:00:00+00:00".into(),
            tenant: "local".into(),
            machine: Some("worker".into()),
            event: "plan.launched".into(),
            plan_id: Some("sha256:abc".into()),
            detail: Some("verb=up".into()),
            authorizer_principal: Some("host:builder".into()),
            authorization_reason: Some("scheduled rollout".into()),
            authorization_ticket_ref: Some("CHG-12345".into()),
        }
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: VerifiedAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn event_rejects_unknown_fields() {
        let mut value = serde_json::to_value(sample_event()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!("x"));
        let err = serde_json::from_value::<VerifiedAuditEvent>(value).unwrap_err();
        assert!(err.to_string().contains("smuggled"), "{err}");
    }

    #[test]
    fn optional_fields_are_omitted_when_absent() {
        let mut event = sample_event();
        event.machine = None;
        event.plan_id = None;
        event.detail = None;
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("machine"));
        assert!(!json.contains("plan_id"));
        assert!(!json.contains("detail"));
        let back: VerifiedAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn kind_serde_roundtrip_all_variants() {
        for kind in [
            AuditEventKind::Admission,
            AuditEventKind::Launch,
            AuditEventKind::Lifecycle,
            AuditEventKind::Readiness,
            AuditEventKind::Volume,
            AuditEventKind::SecretReference,
            AuditEventKind::Policy,
            AuditEventKind::Refusal,
            AuditEventKind::Other,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: AuditEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
        assert_eq!(
            serde_json::to_string(&AuditEventKind::SecretReference).unwrap(),
            "\"secret_reference\""
        );
    }

    #[test]
    fn refusal_and_response_serde_roundtrip() {
        let response = AuditReadResponse {
            events: vec![sample_event()],
            sources: vec![VerifiedSourceSummary {
                source: sample_event().id.source,
                entries: 4,
            }],
            refusals: vec![AuditSourceRefusal {
                source: AuditSourceId {
                    kind: AuditSourceKind::Workload,
                    tenant: "local".into(),
                    machine: Some("vm1".into()),
                },
                kind: AuditRefusalKind::SignatureInvalid,
                line: Some(2),
                detail: "signature invalid at line 2".into(),
            }],
            next_cursor: Some(AuditCursor::after(&sample_event())),
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: AuditReadResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, back);
    }

    #[test]
    fn cursor_rejects_unknown_fields() {
        let err = serde_json::from_str::<AuditCursor>(
            r#"{"timestamp":"2026-08-01T10:00:00Z","source":{"kind":"lifecycle","tenant":"local"},"seq":0,"extra":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("extra"), "{err}");
    }

    #[test]
    fn effective_limit_defaults_and_clamps() {
        assert_eq!(
            AuditReadRequest::builder().build().effective_limit(),
            DEFAULT_READ_LIMIT
        );
        assert_eq!(
            AuditReadRequest::builder()
                .limit(0)
                .build()
                .effective_limit(),
            1
        );
        assert_eq!(
            AuditReadRequest::builder()
                .limit(10_000)
                .build()
                .effective_limit(),
            MAX_READ_LIMIT
        );
        assert_eq!(
            AuditReadRequest::builder()
                .limit(7)
                .build()
                .effective_limit(),
            7
        );
    }

    #[test]
    fn order_key_sorts_by_time_then_source_then_seq() {
        let lifecycle = AuditSourceId {
            kind: AuditSourceKind::Lifecycle,
            tenant: "local".into(),
            machine: None,
        };
        let workload = AuditSourceId {
            kind: AuditSourceKind::Workload,
            tenant: "local".into(),
            machine: Some("vm1".into()),
        };
        let older = OrderKey::new("2026-08-01T09:00:00Z", &lifecycle, 5);
        let newer = OrderKey::new("2026-08-01T10:00:00Z", &lifecycle, 0);
        assert!(newer > older, "later timestamp wins regardless of seq");

        // Equal timestamps: deterministic source rank breaks the tie.
        let a = OrderKey::new("2026-08-01T10:00:00Z", &lifecycle, 1);
        let b = OrderKey::new("2026-08-01T10:00:00Z", &workload, 1);
        assert!(a < b, "lifecycle ranks before workload at equal instants");

        // Same source, equal timestamps: chain position decides.
        let s0 = OrderKey::new("2026-08-01T10:00:00Z", &lifecycle, 0);
        let s1 = OrderKey::new("2026-08-01T10:00:00Z", &lifecycle, 1);
        assert!(s1 > s0);
    }

    #[test]
    fn unparseable_timestamp_sorts_oldest() {
        let src = AuditSourceId {
            kind: AuditSourceKind::Lifecycle,
            tenant: "local".into(),
            machine: None,
        };
        let bad = OrderKey::new("not-a-time", &src, 99);
        let good = OrderKey::new("1970-01-01T00:00:01Z", &src, 0);
        assert!(bad < good);
    }

    #[test]
    fn lifecycle_event_classification() {
        use AuditEventKind::*;
        let cases = [
            ("plan.launched", Launch),
            ("plan.running", Launch),
            ("plan.admitted", Admission),
            ("plan.verified", Admission),
            ("plan.oci_provenance", Admission),
            ("plan.boot_posture", Admission),
            ("plan.shares_admitted", Admission),
            ("plan.grants_enforced", Admission),
            ("plan.policy_resolved", Policy),
            ("plan.failed", Refusal),
            ("plan.rejected.nonce_replay", Refusal),
            ("service.call.denied", Refusal),
            ("plan.grant_required", Refusal),
            ("plan.exited", Lifecycle),
            ("lifecycle.tenant.destroyed", Lifecycle),
            ("checkpoint.forked", Lifecycle),
            ("session.parked", Lifecycle),
            ("session.resumed", Lifecycle),
            ("cmd.up.completed", Lifecycle),
            ("readiness.probe", Readiness),
            ("volume.sealed", Volume),
            ("deps.installed", Volume),
            ("secret.put", SecretReference),
            ("host.secrets.v1", SecretReference),
            ("policy.resolved", Policy),
            ("network.flow", Policy),
            ("service.call", Policy),
            ("totally.unknown", Other),
        ];
        for (name, want) in cases {
            assert_eq!(classify_lifecycle_event(name), want, "{name}");
        }
    }

    #[test]
    fn workload_category_classification() {
        use AuditEventKind::*;
        let cases = [
            ("plan", Admission),
            ("lifecycle", Lifecycle),
            ("cmd", Lifecycle),
            ("secret", SecretReference),
            ("key", SecretReference),
            ("policy", Policy),
            ("flow", Policy),
            ("dns", Policy),
            ("workload_audit", Other),
            ("host", Other),
            ("audit", Other),
        ];
        for (category, want) in cases {
            assert_eq!(classify_workload_category(category), want, "{category}");
        }
    }
}
