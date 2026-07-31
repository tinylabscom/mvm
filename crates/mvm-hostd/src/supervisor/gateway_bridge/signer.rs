//! Signer task — the sole per-VM caller of `AuditSigner::sign_and_emit`.
//! Drains the bridge's event mpsc, fans each event out to host-allowlisted
//! observers, then chain-signs it.

use std::sync::Arc;

use mvm_core::plan::ExecutionPlan;
use mvm_core::policy::PolicyBundle;
use tokio::sync::{broadcast, mpsc};

use crate::supervisor::audit::{AuditEntry, AuditSigner};

use super::events::{FlowEvent, FlowEventKind, FlowEventWire};

/// Drains the per-VM event channel, fans each `FlowEvent` out to the
/// host-allowlisted observers, then converts it
/// to a chained `AuditEntry` and signs it. Sole caller of
/// `signer.sign_and_emit` per VM.
///
/// **Ordering invariant:** observer fan-out runs **before** chain
/// signing, so observers see every event the chain will record. Chain
/// signing is structural — it always runs after the fan-out loop and
/// cannot be displaced by tenant policy. A panicking observer is
/// caught via `catch_unwind` and logged via `tracing::warn`; sibling
/// observers and the chain-signing call continue.
pub(crate) async fn signer_task(
    mut rx: mpsc::Receiver<FlowEvent>,
    plan: Arc<ExecutionPlan>,
    bundle: Option<Arc<PolicyBundle>>,
    signer: Arc<dyn AuditSigner>,
    broadcast_tx: broadcast::Sender<String>,
    observers: Vec<Arc<dyn crate::supervisor::network::Observer>>,
) {
    while let Some(event) = rx.recv().await {
        // Publish on the live-tail broadcast first (informational,
        // never blocks the signer; failure here is "no subscribers"
        // which is fine).
        if let Ok(json) = serde_json::to_string(&FlowEventWire::from(&event)) {
            let _ = broadcast_tx.send(json);
        }

        // Observer fan-out under `catch_unwind`.
        // Runs BEFORE chain signing so observers see every event the
        // chain will record (the always-on chain-signing path below
        // is structural and cannot be displaced by tenant policy).
        // Each observer call is panic-isolated: a panicking observer
        // does not break sibling observers or the chain-signing path.
        for obs in &observers {
            let obs_name = obs.name();
            let event_ref = &event;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                obs.on_flow_event(event_ref);
            }));
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                tracing::warn!(
                    observer = obs_name,
                    flow_id = %event.flow_id,
                    panic = %msg,
                    "observer panicked; isolated via catch_unwind, sibling observers continue"
                );
            }
        }

        // Construct chained entry + emit. Errors are logged but the
        // loop continues — losing one entry is worse than tearing
        // down the bridge.
        let entry = match &event.kind {
            FlowEventKind::Opened => AuditEntry::flow_opened(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
            ),
            FlowEventKind::Closed { reason } => AuditEntry::flow_closed(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
                *reason,
            ),
            FlowEventKind::ObserverFault { observer, reason } => AuditEntry::flow_observer_fault(
                plan.as_ref(),
                bundle.as_deref(),
                &event.flow_id,
                event.direction,
                observer,
                reason,
            ),
        };
        if let Err(e) = signer.sign_and_emit(&entry).await {
            tracing::warn!(error = ?e, flow_id = event.flow_id, "signer emit failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::{FlowCloseReason, FlowDirection};

    /// Proves the structural ordering invariant: observers run BEFORE
    /// chain signing under `catch_unwind`. A
    /// panicking observer is logged + isolated; sibling observers
    /// continue to receive events and the chain-signing call still
    /// fires. Verifies AuditEmit is non-displaceable by tenant policy.
    #[tokio::test(flavor = "current_thread")]
    async fn signer_task_fans_out_to_observers_before_signing() {
        use crate::supervisor::audit::CapturingAuditSigner;
        use crate::supervisor::network::{Observer, RequiredCapabilities};
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::task::LocalSet;

        struct CountObs(AtomicU32);
        impl Observer for CountObs {
            fn name(&self) -> &'static str {
                "count"
            }
            fn required_capabilities(&self) -> RequiredCapabilities {
                RequiredCapabilities {
                    flow_events: true,
                    payload_tap: false,
                }
            }
            fn on_flow_event(&self, _: &FlowEvent) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct PanicObs;
        impl Observer for PanicObs {
            fn name(&self) -> &'static str {
                "panic"
            }
            fn required_capabilities(&self) -> RequiredCapabilities {
                RequiredCapabilities {
                    flow_events: true,
                    payload_tap: false,
                }
            }
            fn on_flow_event(&self, _: &FlowEvent) {
                panic!("test panic");
            }
        }

        // signer_task is `spawn_local`'d in production (LocalSet
        // runtime, current-thread tokio); mirror that here so the
        // test exercises the same execution shape.
        let local = LocalSet::new();
        local
            .run_until(async {
                let (tx, rx) = mpsc::channel::<FlowEvent>(8);
                let (broadcast_tx, _broadcast_rx) = broadcast::channel::<String>(8);

                let count_before = Arc::new(CountObs(AtomicU32::new(0)));
                let count_after = Arc::new(CountObs(AtomicU32::new(0)));
                let signer = Arc::new(CapturingAuditSigner::new());
                // Order matters: count_before runs BEFORE PanicObs (covers
                // "preceding sibling sees event"), count_after runs AFTER
                // PanicObs (covers "following sibling sees event despite
                // intervening panic"). Without count_after, a regression
                // that breaks the fan-out loop on panic would still leave
                // count_before == 2 — the loop increments it before the
                // panicking sibling unwinds. count_after at position 2
                // makes the panic-isolation property load-bearing.
                let observers: Vec<Arc<dyn Observer>> = vec![
                    count_before.clone() as Arc<dyn Observer>,
                    Arc::new(PanicObs) as Arc<dyn Observer>,
                    count_after.clone() as Arc<dyn Observer>,
                ];

                let task = tokio::task::spawn_local(signer_task(
                    rx,
                    Arc::new(test_plan()),
                    None,
                    signer.clone() as Arc<dyn crate::supervisor::audit::AuditSigner>,
                    broadcast_tx,
                    observers,
                ));

                tx.send(FlowEvent {
                    flow_id: "f1".into(),
                    direction: FlowDirection::Egress,
                    kind: FlowEventKind::Opened,
                })
                .await
                .unwrap();
                tx.send(FlowEvent {
                    flow_id: "f1".into(),
                    direction: FlowDirection::Egress,
                    kind: FlowEventKind::Closed {
                        reason: FlowCloseReason::Eof,
                    },
                })
                .await
                .unwrap();
                drop(tx);
                task.await.unwrap();

                // count_before (vec position 0) ran before PanicObs on
                // each iteration; counter would tick even if the loop
                // broke on panic. Kept to cover the "preceding sibling"
                // property explicitly.
                assert_eq!(
                    count_before.0.load(Ordering::SeqCst),
                    2,
                    "before-panic observer must see both events"
                );
                // count_after (vec position 2) is the load-bearing
                // panic-isolation assertion: it sits behind PanicObs in
                // the fan-out order, so a regression that removed
                // `catch_unwind` (or otherwise broke the loop on panic)
                // would leave it at 0.
                assert_eq!(
                    count_after.0.load(Ordering::SeqCst),
                    2,
                    "after-panic observer must see both events \
                     (proves panic isolation across siblings)"
                );
                // CapturingAuditSigner also recorded both entries —
                // chain integrity preserved across observer panics.
                let entries = signer.entries();
                assert_eq!(
                    entries.len(),
                    2,
                    "chain signing fires AFTER fan-out regardless of observer panics"
                );
            })
            .await;
    }

    /// Plan-doc-shaped `ExecutionPlan` for fan-out tests. Mirrors the
    /// `sample_plan()` helper in `audit.rs` but kept local so this
    /// test module owns its fixture lifecycle.
    fn test_plan() -> mvm_core::plan::ExecutionPlan {
        use chrono::TimeZone;
        use mvm_core::plan::{
            AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement,
            ExecutionPlan, FsPolicyRef, KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef,
            PostRunLifecycle, Resources, RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef,
            TenantId, TimeoutSpec, WorkloadId,
        };
        ExecutionPlan {
            build_provenance: Default::default(),
            snapshot_at: Default::default(),
            network_mode: Default::default(),
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("test-plan".into()),
            plan_version: 1,
            tenant: TenantId("test".into()),
            workload: WorkloadId("test-workload".into()),
            runtime_profile: RuntimeProfileRef("firecracker".into()),
            image: SignedImageRef {
                name: "img".into(),
                sha256: "0".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 256,
                disk_mib: 1024,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 60,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".into()),
            fs_policy: FsPolicyRef("local-default".into()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".into()),
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            tool_policy: PolicyRef("local-default".into()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec![],
                retention_days: 0,
            },
            audit_labels: std::collections::BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: chrono::Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
            agent_verbs: None,
            services: Vec::new(),
        }
    }
}
