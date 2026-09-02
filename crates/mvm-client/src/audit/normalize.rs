//! Normalization from verified chain entries to [`VerifiedAuditEvent`]s
//! and from verifier errors to typed [`AuditSourceRefusal`]s.
//!
//! Only already-verified entries reach the normalizers here — the service
//! never normalizes an entry whose source failed verification. Refusal
//! mapping keeps the verifier taxonomy (malformed / broken link / bad
//! signature) without leaking raw error payloads.

use std::collections::BTreeMap;

use mvm_hostd::audit_signer::canonical::CanonicalEntry;
use mvm_hostd::audit_signer::verify::WorkloadVerifyError;
use mvm_hostd::supervisor::{
    PlanAuditEntry, UNBOUND_IMAGE_NAME, UNBOUND_PLAN_ID, VerifyError as LifecycleVerifyError,
};

use super::event::{
    AuditEventId, AuditRefusalKind, AuditSourceId, AuditSourceRefusal, VerifiedAuditEvent,
    classify_lifecycle_event, classify_workload_category,
};
use super::sanitize::{
    MAX_DETAIL_LEN, MAX_FIELD_LEN, is_sensitive_label_key, sanitize_free_text, sanitize_label_value,
};

/// Label keys inspected (in order) when deriving the machine name of a
/// lifecycle event.
const MACHINE_LABEL_KEYS: &[&str] = &["vm", "vm_name", "machine", "workload"];

/// Normalize one verified lifecycle-chain entry.
pub(crate) fn normalize_lifecycle_entry(
    source: &AuditSourceId,
    seq: u64,
    entry: &PlanAuditEntry,
) -> VerifiedAuditEvent {
    const SURFACED_LABELS: &[&str] = &[
        "authorizer_principal",
        "authorization_reason",
        "authorization_ticket_ref",
    ];

    VerifiedAuditEvent {
        id: AuditEventId {
            source: source.clone(),
            seq,
        },
        kind: classify_lifecycle_event(&entry.event),
        timestamp: entry.timestamp.to_rfc3339(),
        tenant: entry.tenant.0.clone(),
        machine: lifecycle_machine(entry),
        event: sanitize_free_text(&entry.event, MAX_FIELD_LEN),
        plan_id: lifecycle_plan_id(entry),
        detail: render_labels(&entry.labels, SURFACED_LABELS),
        authorizer_principal: entry
            .labels
            .get("authorizer_principal")
            .map(|v| sanitize_free_text(v, MAX_FIELD_LEN)),
        authorization_reason: entry
            .labels
            .get("authorization_reason")
            .map(|v| sanitize_free_text(v, MAX_FIELD_LEN)),
        authorization_ticket_ref: entry
            .labels
            .get("authorization_ticket_ref")
            .map(|v| sanitize_free_text(v, MAX_FIELD_LEN)),
    }
}

/// Normalize one verified workload-chain entry. The entry's free-form
/// `fields` payload is deliberately never rendered — it can carry raw
/// policy payloads and guest-influenced bytes.
pub(crate) fn normalize_workload_entry(
    source: &AuditSourceId,
    seq: u64,
    entry: &CanonicalEntry,
) -> VerifiedAuditEvent {
    let detail = format!(
        "correlation_id={} session_id={} workload_id={}",
        sanitize_free_text(&entry.correlation_id, MAX_FIELD_LEN),
        sanitize_free_text(&entry.session_id, MAX_FIELD_LEN),
        sanitize_free_text(&entry.workload_id, MAX_FIELD_LEN),
    );
    VerifiedAuditEvent {
        id: AuditEventId {
            source: source.clone(),
            seq,
        },
        kind: classify_workload_category(&entry.category),
        timestamp: sanitize_free_text(&entry.ts, MAX_FIELD_LEN),
        tenant: entry.tenant_id.clone(),
        machine: source.machine.clone(),
        event: sanitize_free_text(&entry.category, MAX_FIELD_LEN),
        plan_id: None,
        detail: Some(sanitize_free_text(&detail, MAX_DETAIL_LEN)),
        authorizer_principal: None,
        authorization_reason: None,
        authorization_ticket_ref: None,
    }
}

/// Machine name of a lifecycle event: an explicit machine-ish label wins,
/// then the image name unless it is the unbound placeholder.
fn lifecycle_machine(entry: &PlanAuditEntry) -> Option<String> {
    for key in MACHINE_LABEL_KEYS {
        if let Some(value) = entry.labels.get(*key) {
            return Some(sanitize_free_text(value, MAX_FIELD_LEN));
        }
    }
    if entry.image_name == UNBOUND_IMAGE_NAME {
        None
    } else {
        Some(sanitize_free_text(&entry.image_name, MAX_FIELD_LEN))
    }
}

/// Plan id unless the entry is the unbound placeholder.
fn lifecycle_plan_id(entry: &PlanAuditEntry) -> Option<String> {
    if entry.plan_id.0 == UNBOUND_PLAN_ID {
        None
    } else {
        Some(sanitize_free_text(&entry.plan_id.0, MAX_FIELD_LEN))
    }
}

/// Render labels as sorted `k=v` pairs, dropping sensitive keys,
/// path-like values, and any keys that are surfaced as dedicated fields.
/// The result is capped at the detail limit.
fn render_labels(labels: &BTreeMap<String, String>, exclude_keys: &[&str]) -> Option<String> {
    let pairs: Vec<String> = labels
        .iter()
        .filter(|(key, _)| !is_sensitive_label_key(key) && !exclude_keys.contains(&key.as_str()))
        .map(|(key, value)| {
            format!(
                "{}={}",
                sanitize_free_text(key, MAX_FIELD_LEN),
                sanitize_label_value(value)
            )
        })
        .collect();
    if pairs.is_empty() {
        None
    } else {
        Some(sanitize_free_text(&pairs.join(" "), MAX_DETAIL_LEN))
    }
}

/// Map a lifecycle-chain verification failure to a typed refusal.
pub(crate) fn refusal_from_lifecycle(
    source: &AuditSourceId,
    err: &LifecycleVerifyError,
) -> AuditSourceRefusal {
    let (kind, line) = match err {
        LifecycleVerifyError::Io(_) => (AuditRefusalKind::Io, None),
        LifecycleVerifyError::Malformed { line, .. } => {
            (AuditRefusalKind::Malformed, Some(*line as u64))
        }
        LifecycleVerifyError::PrevHashMismatch { line } => {
            (AuditRefusalKind::ChainBroken, Some(*line as u64))
        }
        LifecycleVerifyError::SignatureInvalid { line } => {
            (AuditRefusalKind::SignatureInvalid, Some(*line as u64))
        }
        // The readable entry disagrees with the bytes the signature covers, so
        // what the line displays is not what was attested. That is an
        // authenticity failure, not a parse failure — the caller must treat it
        // exactly as it treats a bad signature. The distinct cause survives in
        // the refusal's message.
        LifecycleVerifyError::EntryCanonicalMismatch { line } => {
            (AuditRefusalKind::SignatureInvalid, Some(*line as u64))
        }
        LifecycleVerifyError::TruncatedTail { line } => {
            (AuditRefusalKind::Truncated, Some(*line as u64))
        }
    };
    refusal(source, kind, line, &err.to_string())
}

/// Map a segment-set verification failure to a typed refusal.
///
/// A set failure is a statement about the chain as a whole rather than about
/// one line, so most variants carry no line number. They are still
/// [`AuditRefusalKind::ChainBroken`]: to a reader, a segment that has been
/// removed and a link that does not join up are the same fact — the chronology
/// cannot be trusted. A reader that filed a missing segment under "I/O
/// problem" would carry on displaying the survivors as though they were the
/// whole history, which is the one outcome rotation must never produce.
pub(crate) fn refusal_from_segment_set(
    source: &AuditSourceId,
    err: &mvm_hostd::supervisor::SegmentSetError,
) -> AuditSourceRefusal {
    use mvm_hostd::supervisor::SegmentSetError as E;
    // A per-segment failure keeps the precision the single-file verifier had:
    // the line index is within that segment, and the set error's own message
    // names which one.
    if let E::Segment { source: inner, .. } = err {
        let mapped = refusal_from_lifecycle(source, inner);
        return refusal(source, mapped.kind, mapped.line, &err.to_string());
    }
    let kind = match err {
        E::Io(_) | E::NoChain { .. } => AuditRefusalKind::Io,
        _ => AuditRefusalKind::ChainBroken,
    };
    refusal(source, kind, None, &err.to_string())
}

/// Map a workload-chain verification failure to a typed refusal.
pub(crate) fn refusal_from_workload(
    source: &AuditSourceId,
    err: &WorkloadVerifyError,
) -> AuditSourceRefusal {
    let (kind, line) = match err {
        WorkloadVerifyError::Io(_) => (AuditRefusalKind::Io, None),
        WorkloadVerifyError::Malformed { line, .. }
        | WorkloadVerifyError::NonCanonical { line }
        | WorkloadVerifyError::DisallowedCategory { line, .. }
        | WorkloadVerifyError::UnsupportedSigAlg { line, .. } => {
            (AuditRefusalKind::Malformed, Some(*line as u64))
        }
        WorkloadVerifyError::PrevHashMismatch { line }
        | WorkloadVerifyError::EntryHashMismatch { line } => {
            (AuditRefusalKind::ChainBroken, Some(*line as u64))
        }
        WorkloadVerifyError::SignatureInvalid { line } => {
            (AuditRefusalKind::SignatureInvalid, Some(*line as u64))
        }
    };
    refusal(source, kind, line, &err.to_string())
}

/// Typed refusal for a verified entry that claims a scope other than its
/// source's (e.g. a foreign tenant's entry spliced into this tenant's file
/// by a signer confusion).
pub(crate) fn scope_mismatch_refusal(
    source: &AuditSourceId,
    line: u64,
    found_tenant: &str,
) -> AuditSourceRefusal {
    refusal(
        source,
        AuditRefusalKind::ScopeMismatch,
        Some(line),
        &format!(
            "entry at line {line} claims tenant '{}' but the source is scoped to tenant '{}'",
            sanitize_free_text(found_tenant, MAX_FIELD_LEN),
            source.tenant
        ),
    )
}

fn refusal(
    source: &AuditSourceId,
    kind: AuditRefusalKind,
    line: Option<u64>,
    detail: &str,
) -> AuditSourceRefusal {
    AuditSourceRefusal {
        source: source.clone(),
        kind,
        line,
        detail: sanitize_free_text(detail, MAX_DETAIL_LEN),
    }
}

#[cfg(test)]
mod tests {
    use super::super::event::AuditEventKind;
    use super::*;
    use chrono::Utc;
    use mvm_core::plan::{PlanId, TenantId};

    fn lifecycle_source() -> AuditSourceId {
        AuditSourceId {
            kind: super::super::event::AuditSourceKind::Lifecycle,
            tenant: "local".into(),
            machine: None,
        }
    }

    fn workload_source() -> AuditSourceId {
        AuditSourceId {
            kind: super::super::event::AuditSourceKind::Workload,
            tenant: "local".into(),
            machine: Some("vm1".into()),
        }
    }

    fn entry(event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId("local".into()),
            plan_id: PlanId("sha256:abc".into()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "worker-img".into(),
            image_sha256: "abc123".into(),
            caller_commitment: None,
            event: event.into(),
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn lifecycle_entry_normalizes_core_fields() {
        let e = entry("plan.launched");
        let out = normalize_lifecycle_entry(&lifecycle_source(), 4, &e);
        assert_eq!(out.kind, AuditEventKind::Launch);
        assert_eq!(out.tenant, "local");
        assert_eq!(out.id.seq, 4);
        assert_eq!(out.event, "plan.launched");
        assert_eq!(out.plan_id.as_deref(), Some("sha256:abc"));
        assert_eq!(out.machine.as_deref(), Some("worker-img"));
        assert!(out.detail.is_none(), "no labels ⇒ no detail");
    }

    #[test]
    fn machine_label_outranks_image_name() {
        let mut e = entry("plan.launched");
        e.labels.insert("vm".into(), "my-vm".into());
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        assert_eq!(out.machine.as_deref(), Some("my-vm"));
    }

    #[test]
    fn unbound_placeholders_map_to_none() {
        let mut e = entry("lifecycle.tenant.destroyed");
        e.plan_id = PlanId(UNBOUND_PLAN_ID.into());
        e.image_name = UNBOUND_IMAGE_NAME.into();
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        assert!(out.plan_id.is_none());
        assert!(out.machine.is_none());
    }

    #[test]
    fn sensitive_labels_are_dropped_from_detail() {
        let mut e = entry("plan.admitted");
        e.labels.insert("verb".into(), "up".into());
        e.labels.insert("api_token".into(), "sk-live-123".into());
        e.labels.insert("env_home".into(), "/Users/alice".into());
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        let detail = out.detail.unwrap();
        assert!(detail.contains("verb=up"));
        assert!(!detail.contains("sk-live-123"), "{detail}");
        assert!(!detail.contains("alice"), "{detail}");
    }

    #[test]
    fn path_values_are_redacted_in_detail() {
        let mut e = entry("plan.admitted");
        e.labels.insert(
            "rootfs".into(),
            "/Users/alice/.mvm/cache/rootfs.ext4".into(),
        );
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        let detail = out.detail.unwrap();
        assert!(detail.contains("rootfs=[redacted-path]"), "{detail}");
        assert!(!detail.contains(".mvm"), "{detail}");
    }

    #[test]
    fn control_sequences_are_stripped_from_event_and_detail() {
        let mut e = entry("plan.\u{1b}[31madmitted");
        e.labels
            .insert("note".into(), "line1\nline2\u{1b}]0;t\u{07}".into());
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        assert_eq!(out.event, "plan.admitted");
        let detail = out.detail.unwrap();
        assert!(!detail.contains('\n'), "{detail:?}");
        assert!(!detail.contains('\u{1b}'), "{detail:?}");
    }

    #[test]
    fn oversized_labels_are_capped() {
        let mut e = entry("plan.admitted");
        e.labels.insert("big".into(), "z".repeat(4000));
        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        let detail = out.detail.unwrap();
        assert!(detail.chars().count() <= MAX_DETAIL_LEN, "{}", detail.len());
    }

    #[test]
    fn authorizer_labels_are_surfaced_as_dedicated_fields_and_omitted_from_detail() {
        let mut e = entry("plan.admitted");
        e.labels
            .insert("authorizer_principal".into(), "host:builder".into());
        e.labels
            .insert("authorization_reason".into(), "scheduled rollout".into());
        e.labels
            .insert("authorization_ticket_ref".into(), "CHG-12345".into());
        e.labels.insert("verb".into(), "up".into());

        let out = normalize_lifecycle_entry(&lifecycle_source(), 0, &e);
        assert_eq!(out.authorizer_principal.as_deref(), Some("host:builder"));
        assert_eq!(
            out.authorization_reason.as_deref(),
            Some("scheduled rollout")
        );
        assert_eq!(out.authorization_ticket_ref.as_deref(), Some("CHG-12345"));

        let detail = out.detail.expect("detail exists");
        assert!(detail.contains("verb=up"), "{detail}");
        assert!(!detail.contains("authorizer_principal"), "{detail}");
        assert!(!detail.contains("authorization_reason"), "{detail}");
        assert!(!detail.contains("authorization_ticket_ref"), "{detail}");
    }

    #[test]
    fn workload_entry_normalizes_without_fields_payload() {
        let e = CanonicalEntry {
            category: "policy".into(),
            correlation_id: "corr-1".into(),
            fields: serde_json::json!({"raw_policy": "SUPER-SENSITIVE"}),
            prev_hash: "0".repeat(64),
            session_id: "sess-9".into(),
            tenant_id: "local".into(),
            ts: "2026-08-01T10:00:00Z".into(),
            workload_id: "wl-7".into(),
        };
        let out = normalize_workload_entry(&workload_source(), 2, &e);
        assert_eq!(out.kind, AuditEventKind::Policy);
        assert_eq!(out.tenant, "local");
        assert_eq!(out.machine.as_deref(), Some("vm1"));
        assert_eq!(out.event, "policy");
        let detail = out.detail.unwrap();
        assert!(detail.contains("corr-1"));
        assert!(
            !detail.contains("SUPER-SENSITIVE"),
            "raw fields payload must never be rendered: {detail}"
        );
    }

    #[test]
    fn lifecycle_refusals_map_to_typed_kinds() {
        let src = lifecycle_source();
        let cases = [
            (
                LifecycleVerifyError::Io("nope".into()),
                AuditRefusalKind::Io,
                None,
            ),
            (
                LifecycleVerifyError::Malformed {
                    line: 3,
                    reason: "bad".into(),
                },
                AuditRefusalKind::Malformed,
                Some(3),
            ),
            (
                LifecycleVerifyError::PrevHashMismatch { line: 1 },
                AuditRefusalKind::ChainBroken,
                Some(1),
            ),
            (
                LifecycleVerifyError::SignatureInvalid { line: 0 },
                AuditRefusalKind::SignatureInvalid,
                Some(0),
            ),
        ];
        for (err, want_kind, want_line) in cases {
            let r = refusal_from_lifecycle(&src, &err);
            assert_eq!(r.kind, want_kind);
            assert_eq!(r.line, want_line);
            assert_eq!(r.source, src);
        }
    }

    #[test]
    fn workload_refusals_map_to_typed_kinds() {
        let src = workload_source();
        let cases = [
            (
                WorkloadVerifyError::NonCanonical { line: 2 },
                AuditRefusalKind::Malformed,
            ),
            (
                WorkloadVerifyError::EntryHashMismatch { line: 5 },
                AuditRefusalKind::ChainBroken,
            ),
            (
                WorkloadVerifyError::SignatureInvalid { line: 4 },
                AuditRefusalKind::SignatureInvalid,
            ),
            (
                WorkloadVerifyError::UnsupportedSigAlg {
                    line: 0,
                    sig_alg: 9,
                },
                AuditRefusalKind::Malformed,
            ),
        ];
        for (err, want_kind) in cases {
            assert_eq!(refusal_from_workload(&src, &err).kind, want_kind);
        }
    }

    #[test]
    fn scope_mismatch_refusal_names_both_tenants_sanitized() {
        let r = scope_mismatch_refusal(&lifecycle_source(), 7, "evil\u{1b}[2Jtenant");
        assert_eq!(r.kind, AuditRefusalKind::ScopeMismatch);
        assert_eq!(r.line, Some(7));
        assert!(r.detail.contains("eviltenant"), "{}", r.detail);
        assert!(r.detail.contains("local"));
        assert!(!r.detail.contains('\u{1b}'));
    }
}
