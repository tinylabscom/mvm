use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::supervisor::audit::audit_file::FileAuditSigner;
use crate::supervisor::audit::signer::{
    AuditError, AuditSigner, CapturingAuditSigner, PlanAuditEntry,
};

fn context(mode: AuditFailureMode) -> AuditContext {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.execution_epoch = 7;
    AuditContext::Workload {
        plan: Box::new(plan),
        mode,
    }
}

fn recorder(signer: Arc<dyn AuditSigner>) -> Arc<Recorder> {
    Arc::new(Recorder::new(
        signer,
        mvm_core::plan::TenantId("local".into()),
    ))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

#[test]
fn binding_overwrites_forged_identity_labels_with_the_admitted_plan() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(CapturingAuditSigner::new());
    let mut context = context(AuditFailureMode::Development);
    if let AuditContext::Workload { plan, .. } = &mut context {
        plan.audit_labels
            .insert("builder".into(), "forged-builder".into());
        plan.audit_labels
            .insert("vm_name".into(), "forged-instance".into());
        plan.audit_labels
            .insert("workload".into(), "forged-workload".into());
    }
    let plan = context.plan().unwrap().clone();
    let recorder = Arc::new(
        Recorder::new(signer.clone(), mvm_core::plan::TenantId("local".into()))
            .with_vm_name("physical-instance"),
    );
    let sink = BoundRecorder::builder(recorder, runtime.handle().clone(), context)
        .health_file(dir.path().join("health.json"))
        .build()
        .unwrap();
    sink.record(
        "host.flow.denied",
        BTreeMap::from([
            ("workload".into(), "another-workload".into()),
            ("execution_epoch".into(), "99".into()),
            ("category".into(), "secret".into()),
            ("audit_scope".into(), "builder".into()),
        ]),
    )
    .unwrap();
    let entries = signer.entries();
    let entry = entries.last().unwrap();
    assert_eq!(entry.plan_id, plan.plan_id);
    assert_eq!(entry.plan_version, plan.plan_version);
    assert_eq!(entry.tenant, plan.tenant);
    assert_eq!(entry.labels["workload"], plan.workload.0);
    assert_eq!(entry.labels["execution_epoch"], "7");
    assert_eq!(entry.labels["category"], "host");
    assert_eq!(entry.labels["audit_scope"], "workload");
    assert_eq!(entry.labels["vm_name"], "physical-instance");
    assert!(!entry.labels.contains_key("builder"));
}

#[test]
fn assembled_async_consumers_share_binding_and_never_fall_back_after_sink_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(CapturingAuditSigner::new());
    let recorder = recorder(signer.clone());
    let assembled_consumer = recorder.as_ref().clone();
    let sink = Arc::new(
        BoundRecorder::builder(
            Arc::clone(&recorder),
            runtime.handle().clone(),
            context(AuditFailureMode::Development),
        )
        .health_file(dir.path().join("health.json"))
        .build()
        .unwrap(),
    );
    let shared: Arc<dyn AuditSink> = sink.clone();
    recorder.bind_audit_sink(&shared).unwrap();
    assert!(recorder.bind_audit_sink(&shared).is_err());
    runtime
        .block_on(assembled_consumer.record_unbound(
            EventCategory::Secret,
            "secret.substituted",
            BTreeMap::new(),
        ))
        .unwrap();
    let entries = signer.entries();
    assert_eq!(entries.last().unwrap().labels["execution_epoch"], "7");
    assert_eq!(entries.last().unwrap().labels["category"], "secret");
    let count = entries.len();
    drop(shared);
    drop(sink);
    assert!(
        runtime
            .block_on(assembled_consumer.record_unbound(
                EventCategory::Secret,
                "secret.substituted",
                BTreeMap::new(),
            ))
            .is_err()
    );
    assert_eq!(
        signer.entries().len(),
        count,
        "expired binding must not emit unbound"
    );
}

#[test]
fn bound_builder_async_audit_does_not_recurse_into_its_own_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(CapturingAuditSigner::new());
    let recorder = recorder(signer.clone());
    let sink: Arc<dyn AuditSink> = Arc::new(
        BoundRecorder::builder(
            Arc::clone(&recorder),
            runtime.handle().clone(),
            AuditContext::Builder {
                tenant: mvm_core::plan::TenantId("local".into()),
                name: "builder-one".into(),
            },
        )
        .health_file(dir.path().join("health.json"))
        .build()
        .unwrap(),
    );
    recorder.bind_audit_sink(&sink).unwrap();
    runtime
        .block_on(recorder.record_unbound(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::new(),
        ))
        .unwrap();
    assert_eq!(
        signer.entries().last().unwrap().labels["builder"],
        "builder-one"
    );
}

#[test]
fn builders_record_their_own_identity_without_a_fabricated_workload_plan() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(CapturingAuditSigner::new());
    let sink = BoundRecorder::builder(
        recorder(signer.clone()),
        runtime.handle().clone(),
        AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("local".into()),
            name: "builder-one".into(),
        },
    )
    .health_file(dir.path().join("health.json"))
    .build()
    .unwrap();
    sink.record("host.flow.denied", BTreeMap::new()).unwrap();
    let entries = signer.entries();
    let entry = entries.last().unwrap();
    assert_eq!(entry.labels["audit_scope"], "builder");
    assert_eq!(entry.labels["builder"], "builder-one");
    assert!(!entry.labels.contains_key("workload"));
    assert!(!entry.labels.contains_key("execution_epoch"));
}

#[test]
fn builder_reboots_keep_distinct_health_records_while_workload_binding_is_stable() {
    let root = std::path::Path::new("/tmp/audit-health-test");
    let builder = AuditContext::Builder {
        tenant: mvm_core::plan::TenantId("builder".into()),
        name: "persistent-builder".into(),
    };
    assert_ne!(
        BoundRecorder::health_path(root, &builder).unwrap(),
        BoundRecorder::health_path(root, &builder).unwrap(),
    );
    let workload = context(AuditFailureMode::Development);
    assert_eq!(
        BoundRecorder::health_path(root, &workload).unwrap(),
        BoundRecorder::health_path(root, &workload).unwrap(),
    );
}

struct SwitchableSigner {
    fail: AtomicBool,
}

#[async_trait::async_trait]
impl AuditSigner for SwitchableSigner {
    async fn sign_and_emit(&self, _entry: &PlanAuditEntry) -> Result<(), AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(AuditError::Io("injected write failure".into()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn flow_and_async_service_failures_share_one_production_streak() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(SwitchableSigner {
        fail: AtomicBool::new(false),
    });
    let recorder = recorder(signer.clone());
    let stops = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&stops);
    let sink = Arc::new(
        BoundRecorder::builder(
            Arc::clone(&recorder),
            runtime.handle().clone(),
            context(AuditFailureMode::Production),
        )
        .health_file(dir.path().join("health.json"))
        .on_stop(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }))
        .build()
        .unwrap(),
    );
    let shared: Arc<dyn AuditSink> = sink.clone();
    recorder.bind_audit_sink(&shared).unwrap();
    signer.fail.store(true, Ordering::SeqCst);
    assert!(sink.record("host.flow.denied", BTreeMap::new()).is_err());
    assert!(
        runtime
            .block_on(recorder.record_unbound(
                EventCategory::Secret,
                "secret.substituted",
                BTreeMap::new(),
            ))
            .is_err()
    );
    sink.suppress_denial();
    assert_eq!(sink.health().consecutive_write_failures, 2);
    assert_eq!(stops.load(Ordering::SeqCst), 0);
    assert!(shared.record("dns.refused", BTreeMap::new()).is_err());
    assert_eq!(stops.load(Ordering::SeqCst), 1);
    assert_eq!(sink.health().write_failures, 3);
}

#[test]
fn a_production_sink_requires_a_real_stop_notifier_before_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let result = BoundRecorder::builder(
        recorder(Arc::new(CapturingAuditSigner::new())),
        runtime.handle().clone(),
        context(AuditFailureMode::Production),
    )
    .health_file(dir.path().join("health.json"))
    .build();
    assert!(result.is_err());
    assert!(!dir.path().join("health.json").exists());
}

#[test]
fn third_failed_write_notifies_once_and_latches_production_closed() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(SwitchableSigner {
        fail: AtomicBool::new(false),
    });
    let stopped = Arc::new(AtomicUsize::new(0));
    let stop_count = Arc::clone(&stopped);
    let sink = BoundRecorder::builder(
        recorder(signer.clone()),
        runtime.handle().clone(),
        context(AuditFailureMode::Production),
    )
    .health_file(dir.path().join("health.json"))
    .on_stop(Arc::new(move || {
        stop_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }))
    .build()
    .unwrap();
    signer.fail.store(true, Ordering::SeqCst);
    for n in 1..=3 {
        assert!(sink.record("host.flow.allowed", BTreeMap::new()).is_err());
        assert_eq!(stopped.load(Ordering::SeqCst), usize::from(n == 3));
    }
    signer.fail.store(false, Ordering::SeqCst);
    assert!(sink.record("host.flow.allowed", BTreeMap::new()).is_err());
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
    assert!(sink.health().host_record_incomplete());
}

#[test]
fn development_keeps_running_but_success_does_not_erase_the_incomplete_mark() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let signer = Arc::new(SwitchableSigner {
        fail: AtomicBool::new(false),
    });
    let sink = BoundRecorder::builder(
        recorder(signer.clone()),
        runtime.handle().clone(),
        context(AuditFailureMode::Development),
    )
    .health_file(dir.path().join("health.json"))
    .build()
    .unwrap();
    signer.fail.store(true, Ordering::SeqCst);
    for _ in 0..4 {
        assert!(sink.record("host.flow.denied", BTreeMap::new()).is_err());
    }
    signer.fail.store(false, Ordering::SeqCst);
    sink.record("host.flow.allowed", BTreeMap::new()).unwrap();
    assert_eq!(sink.health().consecutive_write_failures, 0);
    assert_eq!(sink.health().write_failures, 4);
    sink.suppress_denial();
    sink.suppress_denial();
    sink.flush_health().unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("health.json")).unwrap()).unwrap();
    assert_eq!(saved["completeness"], "host_record_incomplete");
    assert_eq!(saved["health"]["denials_suppressed"], 2);
}

#[test]
fn an_unwritable_journal_marks_the_epoch_before_returning_the_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let journal = dir.path().join("audit.jsonl");
    let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let signer = FileAuditSigner::open_file(key, &journal).unwrap();
    let health = dir.path().join("health.json");
    let sink = BoundRecorder::builder(
        recorder(Arc::new(signer)),
        runtime.handle().clone(),
        context(AuditFailureMode::Development),
    )
    .health_file(health.clone())
    .build()
    .unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(sink.record("host.flow.allowed", BTreeMap::new()).is_err());
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(health).unwrap()).unwrap();
    assert_eq!(saved["completeness"], "host_record_incomplete");
    assert_eq!(saved["binding"]["execution_epoch"], 7);
}
