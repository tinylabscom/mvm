//! Fire-and-forget tracing mirror for chain-signed audit appends.
//!
//! Every successful chain append also emits one diagnostic `tracing` event at
//! the dedicated target `mvm::audit`. The mirror carries only the fixed,
//! non-sensitive envelope fields of the audit entry; the free-form `labels`
//! map is deliberately omitted because it may contain secrets, environment
//! values, credentials, host paths, or raw policy payloads.
//!
//! The mirror is isolated from the chain write: a missing, slow, or panicking
//! subscriber cannot block, reorder, or fail a chain append, and cannot
//! change what is signed.

use crate::supervisor::audit::PlanAuditEntry;

/// Tracing target used for all audit-mirror events.
pub const TARGET: &str = "mvm::audit";

/// Emit a single diagnostic tracing event for `entry`.
///
/// This function is intentionally isolated from chain signing. It catches any
/// subscriber panic so that a misbehaving observability layer can never
/// propagate into the audit path.
pub fn emit_mirror_event(entry: &PlanAuditEntry) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tracing::info!(
            target: TARGET,
            tenant = %entry.tenant.0,
            plan_id = %entry.plan_id.0,
            plan_version = %entry.plan_version,
            image_name = %entry.image_name,
            image_sha256 = %entry.image_sha256,
            event = %entry.event,
            timestamp = %entry.timestamp,
            "audit entry appended to chain",
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;

    #[derive(Default)]
    struct FieldCapture(BTreeMap<String, String>);

    impl Visit for FieldCapture {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{:?}", value));
        }
    }

    type CapturedEvents = Arc<Mutex<Vec<(String, BTreeMap<String, String>)>>>;

    struct CaptureLayer {
        events: CapturedEvents,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut capture = FieldCapture::default();
            event.record(&mut capture);
            self.events
                .lock()
                .expect("capture mutex poisoned")
                .push((event.metadata().target().to_string(), capture.0));
        }
    }

    fn sample_entry(event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: mvm_contract::plan::TenantId("tenant-a".to_string()),
            plan_id: mvm_contract::plan::PlanId("plan-123".to_string()),
            plan_version: 7,
            bundle_id: None,
            bundle_version: None,
            image_name: "alpine".into(),
            image_sha256: "deadbeef".into(),
            event: event.into(),
            caller_commitment: None,
            labels: BTreeMap::from([("secret_key".into(), "secret_value".into())]),
        }
    }

    #[test]
    fn mirror_event_carries_non_sensitive_envelope_fields() {
        let events: CapturedEvents = Arc::new(Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);

        let entry = sample_entry("plan.admitted");
        tracing::subscriber::with_default(subscriber, || {
            emit_mirror_event(&entry);
        });

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (target, fields) = &captured[0];
        assert_eq!(target, TARGET);
        assert_eq!(fields.get("tenant"), Some(&"tenant-a".to_string()));
        assert_eq!(fields.get("plan_id"), Some(&"plan-123".to_string()));
        assert_eq!(fields.get("plan_version"), Some(&"7".to_string()));
        assert_eq!(fields.get("image_name"), Some(&"alpine".to_string()));
        assert_eq!(fields.get("image_sha256"), Some(&"deadbeef".to_string()));
        assert_eq!(fields.get("event"), Some(&"plan.admitted".to_string()));
        assert!(fields.contains_key("timestamp"));
        assert!(
            !fields.contains_key("labels"),
            "free-form labels must not appear in the mirror"
        );
        assert!(
            !fields.values().any(|v| v.contains("secret_value")),
            "mirror must not leak sensitive label values"
        );
    }

    /// The mirror must be invisible to the chain. It runs after the write and
    /// touches nothing that gets signed, so this holds by construction — but
    /// nothing pinned it, and "obviously can't differ" is how a byte-identity
    /// property stops being true.
    ///
    /// A fixed key and a fixed timestamp make the two runs comparable: a fresh
    /// key would change every signature and make the comparison vacuous. The
    /// observed-count assertion stops the test passing by mirroring nothing.
    #[tokio::test]
    async fn chain_bytes_are_identical_with_and_without_a_mirror_subscriber() {
        use crate::supervisor::audit::AuditSigner;
        use crate::supervisor::audit_file::FileAuditSigner;

        async fn chain_bytes(observe: bool) -> (String, usize) {
            let dir = tempfile::tempdir().unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let signer = FileAuditSigner::open(key, dir.path()).unwrap();
            let mut entry = sample_entry("plan.admitted");
            entry.timestamp = chrono::DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc);

            let seen = if observe {
                let events: CapturedEvents = Arc::new(Mutex::new(Vec::new()));
                let layer = CaptureLayer {
                    events: events.clone(),
                };
                let subscriber = tracing_subscriber::registry().with(layer);
                let guard = tracing::subscriber::set_default(subscriber);
                signer.sign_and_emit(&entry).await.unwrap();
                emit_mirror_event(&entry);
                drop(guard);
                events.lock().unwrap().len()
            } else {
                signer.sign_and_emit(&entry).await.unwrap();
                emit_mirror_event(&entry);
                0
            };

            let path = dir.path().join("tenant-a.jsonl");
            (std::fs::read_to_string(path).unwrap(), seen)
        }

        let (without, none_seen) = chain_bytes(false).await;
        let (with, some_seen) = chain_bytes(true).await;

        assert_eq!(none_seen, 0, "no subscriber installed, so nothing observed");
        assert!(
            some_seen >= 1,
            "the mirror emitted nothing, so this proves nothing"
        );
        assert_eq!(
            without, with,
            "installing a mirror subscriber changed the signed chain bytes"
        );
    }

    /// A mirrored event is only usable as a signal if it never describes an
    /// append that did not happen.
    ///
    /// Both production call sites `?` on `sign_and_emit` before mirroring, so
    /// this holds today. Nothing pinned the ordering, though: a refactor that
    /// hoisted the mirror above the `?` would start reporting appends that
    /// failed, and no test would notice.
    #[tokio::test]
    async fn a_failed_append_emits_no_mirrored_event() {
        use crate::supervisor::audit::AuditSigner;
        use crate::supervisor::audit_file::FileAuditSigner;

        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();

        // A directory where the chain file must be: the append's `open` fails.
        std::fs::create_dir_all(dir.path().join("tenant-a.jsonl")).unwrap();

        let events: CapturedEvents = Arc::new(Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);

        // Mirrors the production shape: `?` on the append, mirror only after.
        let entry = sample_entry("plan.admitted");
        let appended = signer.sign_and_emit(&entry).await;
        if appended.is_ok() {
            emit_mirror_event(&entry);
        }
        drop(guard);

        assert!(
            appended.is_err(),
            "append should fail when the chain path is a directory"
        );
        assert_eq!(
            events.lock().unwrap().len(),
            0,
            "a failed append must not produce a mirrored event"
        );
    }

    #[test]
    fn panicking_subscriber_does_not_block_chain_write() {
        struct PanicLayer;
        impl<S> Layer<S> for PanicLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                panic!("hostile subscriber");
            }
        }

        let signer: Arc<crate::supervisor::audit::CapturingAuditSigner> =
            Arc::new(crate::supervisor::audit::CapturingAuditSigner::new());
        let recorder = crate::supervisor::audit_recorder::Recorder::new(
            signer.clone(),
            mvm_contract::plan::TenantId("tenant-a".to_string()),
        );

        let subscriber = tracing_subscriber::registry().with(PanicLayer);
        let result = tracing::subscriber::with_default(subscriber, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(recorder.record_plan_bound(
                        crate::supervisor::audit_recorder::EventCategory::Plan,
                        "plan.launched",
                        &crate::supervisor::audit::tests::sample_plan(),
                        None,
                        [],
                    ))
            }))
        });

        // The chain write itself must succeed; only the mirror may panic.
        assert!(
            result.is_ok(),
            "chain append must survive a panicking subscriber"
        );
        assert_eq!(signer.entries().len(), 1);
    }
}
