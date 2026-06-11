//! `LifecycleHooks` convenience layer.
//!
//! Three composable pieces sit underneath: the unified audit
//! [`Recorder`](crate::supervisor::Recorder), the per-category metrics on
//! [`Metrics`](mvm_core::observability::metrics::Metrics), and the
//! live [`EventBus`](crate::supervisor::EventBus). Each one stands on its own.
//! In practice, callers that want one usually want all three at
//! once — every state-machine transition emits a durable audit
//! record + bumps a counter + notifies live subscribers.
//!
//! `LifecycleHooks` is the convenience wrapper that calls them
//! together so consumers (instance_snapshot, mvm-hostd, future
//! BackendLauncher) write one call site, not three.
//!
//! ## Shape
//!
//! - Both fields are `Option<...>`. A `LifecycleHooks::none()`
//!   value is a Send/Sync no-op suitable for tests and for
//!   "consumer doesn't care about live emit" paths.
//! - Helpers are sync where possible. The Recorder's `record_*`
//!   methods are async (the underlying signer's `sign_and_emit`
//!   is async), so the helpers stay async on that axis — but the
//!   EventBus.publish call is sync, so a hooks-with-only-bus
//!   helper would be sync if we needed it. Today every helper is
//!   async to keep the interface uniform.
//! - Errors propagate from the Recorder (audit signer failures are
//!   load-bearing). EventBus publish failures are absorbed silently
//!   per the "best-effort notification" framing in [`EventBus`].
//!
//! ## What this module does NOT do
//!
//! - **Construct the substrate.** Callers build a `Recorder` and
//!   `EventBus` at process start; `LifecycleHooks` just wraps
//!   them.
//! - **Define new categories or events.** Helpers are thin layers
//!   over the existing `Recorder::record_*` + `EventBus::publish`
//!   APIs. Adding a new event means adding a [`LifecycleEvent`]
//!   variant + a helper here.
//! - **Replace direct Recorder / EventBus use.** Consumers that
//!   want only one half (e.g., emit audit but not publish, or
//!   vice versa) call the underlying APIs directly. `LifecycleHooks`
//!   exists for the common case where both fire together.

use std::sync::Arc;

use mvm_core::plan::{ExecutionPlan, TenantId};

use crate::supervisor::audit_recorder::{EventCategory, Recorder, RecorderError};
use crate::supervisor::event_bus::{EventBus, LifecycleEvent};

/// Bundles a [`Recorder`] + an [`EventBus`] so consumers can wire
/// both with a single argument.
///
/// Both fields are `Option<...>` so test paths (and consumers that
/// don't care about one half) can use [`LifecycleHooks::none`] or
/// build with only one of the two.
#[derive(Clone)]
pub struct LifecycleHooks {
    pub recorder: Option<Recorder>,
    pub event_bus: Option<EventBus>,
}

impl LifecycleHooks {
    /// Build with both halves wired.
    pub fn new(recorder: Recorder, event_bus: EventBus) -> Self {
        Self {
            recorder: Some(recorder),
            event_bus: Some(event_bus),
        }
    }

    /// All-`None` no-op handle. Helpers called on this value
    /// short-circuit without emitting anywhere. Useful as the
    /// default for legacy callers that haven't adopted the
    /// audit/event substrate yet.
    pub fn none() -> Self {
        Self {
            recorder: None,
            event_bus: None,
        }
    }

    /// Build with only an audit Recorder; no live event bus.
    pub fn audit_only(recorder: Recorder) -> Self {
        Self {
            recorder: Some(recorder),
            event_bus: None,
        }
    }

    /// Build with only an event bus; no durable audit.
    pub fn bus_only(event_bus: EventBus) -> Self {
        Self {
            recorder: None,
            event_bus: Some(event_bus),
        }
    }

    /// Emit "instance started" — audit record + live event in one
    /// call. Audit-side errors propagate; event-bus errors are
    /// absorbed (best-effort).
    pub async fn record_instance_started(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
    ) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_plan_bound(
                    EventCategory::Lifecycle,
                    "lifecycle.instance.started",
                    plan,
                    None,
                    [("vm_name".to_string(), vm_name.to_string())],
                )
                .await?;
        }
        if let Some(ref bus) = self.event_bus {
            let _ = bus.publish(LifecycleEvent::InstanceStarted {
                tenant: plan.tenant.clone(),
                plan_id: plan.plan_id.clone(),
                vm_name: vm_name.to_string(),
            });
        }
        Ok(())
    }

    /// Emit "instance stopped".
    pub async fn record_instance_stopped(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
    ) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_plan_bound(
                    EventCategory::Lifecycle,
                    "lifecycle.instance.stopped",
                    plan,
                    None,
                    [("vm_name".to_string(), vm_name.to_string())],
                )
                .await?;
        }
        if let Some(ref bus) = self.event_bus {
            let _ = bus.publish(LifecycleEvent::InstanceStopped {
                tenant: plan.tenant.clone(),
                plan_id: plan.plan_id.clone(),
                vm_name: vm_name.to_string(),
            });
        }
        Ok(())
    }

    /// Emit "instance paused".
    pub async fn record_instance_paused(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
    ) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_plan_bound(
                    EventCategory::Lifecycle,
                    "lifecycle.instance.paused",
                    plan,
                    None,
                    [("vm_name".to_string(), vm_name.to_string())],
                )
                .await?;
        }
        if let Some(ref bus) = self.event_bus {
            let _ = bus.publish(LifecycleEvent::InstancePaused {
                tenant: plan.tenant.clone(),
                plan_id: plan.plan_id.clone(),
                vm_name: vm_name.to_string(),
            });
        }
        Ok(())
    }

    /// Emit "instance resumed".
    pub async fn record_instance_resumed(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
    ) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_plan_bound(
                    EventCategory::Lifecycle,
                    "lifecycle.instance.resumed",
                    plan,
                    None,
                    [("vm_name".to_string(), vm_name.to_string())],
                )
                .await?;
        }
        if let Some(ref bus) = self.event_bus {
            let _ = bus.publish(LifecycleEvent::InstanceResumed {
                tenant: plan.tenant.clone(),
                plan_id: plan.plan_id.clone(),
                vm_name: vm_name.to_string(),
            });
        }
        Ok(())
    }

    /// Emit "instance destroyed".
    pub async fn record_instance_destroyed(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
    ) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_plan_bound(
                    EventCategory::Lifecycle,
                    "lifecycle.instance.destroyed",
                    plan,
                    None,
                    [("vm_name".to_string(), vm_name.to_string())],
                )
                .await?;
        }
        if let Some(ref bus) = self.event_bus {
            let _ = bus.publish(LifecycleEvent::InstanceDestroyed {
                tenant: plan.tenant.clone(),
                plan_id: plan.plan_id.clone(),
                vm_name: vm_name.to_string(),
            });
        }
        Ok(())
    }

    /// Emit "host started" — unbound event, used at supervisor /
    /// mvm-hostd boot. No plan context.
    pub async fn record_host_started(&self, version: &str) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_unbound(
                    EventCategory::Host,
                    "host.started",
                    [("version".to_string(), version.to_string())],
                )
                .await?;
        }
        // No EventBus variant for host events — operators query
        // host state via `mvmctl doctor` rather than subscribing
        // to a stream. If a future use case wants host events on
        // the bus, add `LifecycleEvent::HostStarted`.
        Ok(())
    }

    /// Emit "host shutdown" — unbound event, used at supervisor /
    /// mvm-hostd shutdown.
    pub async fn record_host_shutdown(&self) -> Result<(), RecorderError> {
        if let Some(ref recorder) = self.recorder {
            recorder
                .record_unbound(EventCategory::Host, "host.shutdown", [])
                .await?;
        }
        Ok(())
    }
}

/// Builder helper that wires a Recorder backed by a chain-signed
/// FileAuditSigner + an EventBus with the default capacity. The
/// common "one of each at process boot" shape. Returns the bus
/// separately so callers can clone it into subscribers.
pub fn standard_hooks(
    signer: Arc<dyn crate::supervisor::AuditSigner>,
    default_tenant: TenantId,
    metrics: Option<Arc<mvm_core::observability::metrics::Metrics>>,
) -> (LifecycleHooks, EventBus) {
    let bus = EventBus::new();
    let mut recorder = Recorder::new(signer, default_tenant);
    if let Some(m) = metrics {
        recorder = recorder.with_metrics(m);
    }
    let hooks = LifecycleHooks::new(recorder, bus.clone());
    (hooks, bus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::CapturingAuditSigner;
    use mvm_core::observability::metrics::Metrics;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TimeoutSpec, WorkloadId,
    };
    use std::collections::BTreeMap;

    fn fixture_plan() -> ExecutionPlan {
        let now = chrono::Utc::now();
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("plan-test".to_string()),
            plan_version: 1,
            tenant: TenantId("local".to_string()),
            workload: WorkloadId("vm-test".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".to_string()),
            fs_policy: FsPolicyRef("local-default".to_string()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".to_string()),
            tool_policy: PolicyRef("local-default".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            audit_labels: BTreeMap::new(),
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
            valid_from: now,
            valid_until: now + chrono::Duration::minutes(10),
            nonce: Nonce::from_bytes([0u8; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        }
    }

    fn build_hooks() -> (LifecycleHooks, Arc<CapturingAuditSigner>, EventBus) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".to_string()));
        let bus = EventBus::new();
        let hooks = LifecycleHooks::new(recorder, bus.clone());
        (hooks, signer, bus)
    }

    // ──────────────────────────────────────────────────────────────
    // Constructors
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn none_constructor_yields_both_none() {
        let h = LifecycleHooks::none();
        assert!(h.recorder.is_none());
        assert!(h.event_bus.is_none());
    }

    #[test]
    fn audit_only_constructor_skips_event_bus() {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer, TenantId("local".to_string()));
        let h = LifecycleHooks::audit_only(recorder);
        assert!(h.recorder.is_some());
        assert!(h.event_bus.is_none());
    }

    #[test]
    fn bus_only_constructor_skips_recorder() {
        let h = LifecycleHooks::bus_only(EventBus::new());
        assert!(h.recorder.is_none());
        assert!(h.event_bus.is_some());
    }

    // ──────────────────────────────────────────────────────────────
    // record_instance_* helpers — dual-emit invariants
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn record_instance_started_fires_both_sinks() {
        let (hooks, signer, bus) = build_hooks();
        let mut rx = bus.subscribe();
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks
                .record_instance_started(&plan, "vm-alpha")
                .await
                .unwrap();
            // Audit side — entry captured with the right event name.
            let entries = signer.entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].event, "lifecycle.instance.started");
            assert_eq!(
                entries[0].labels.get("vm_name"),
                Some(&"vm-alpha".to_string())
            );
            // Bus side — subscriber sees the event.
            let event = rx.recv().await.unwrap();
            assert_eq!(
                event,
                LifecycleEvent::InstanceStarted {
                    tenant: TenantId("local".to_string()),
                    plan_id: PlanId("plan-test".to_string()),
                    vm_name: "vm-alpha".to_string(),
                }
            );
        });
    }

    #[test]
    fn all_five_lifecycle_helpers_emit_distinct_event_names() {
        let (hooks, signer, _bus) = build_hooks();
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_instance_started(&plan, "v").await.unwrap();
            hooks.record_instance_stopped(&plan, "v").await.unwrap();
            hooks.record_instance_paused(&plan, "v").await.unwrap();
            hooks.record_instance_resumed(&plan, "v").await.unwrap();
            hooks.record_instance_destroyed(&plan, "v").await.unwrap();
        });
        let events: Vec<String> = signer.entries().iter().map(|e| e.event.clone()).collect();
        assert_eq!(
            events,
            vec![
                "lifecycle.instance.started",
                "lifecycle.instance.stopped",
                "lifecycle.instance.paused",
                "lifecycle.instance.resumed",
                "lifecycle.instance.destroyed",
            ]
        );
    }

    #[test]
    fn none_hooks_swallow_emits_silently() {
        // LifecycleHooks::none() is the legacy/test path —
        // helpers return Ok(()) without panicking, no audit
        // entry, no bus publish.
        let h = LifecycleHooks::none();
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            h.record_instance_started(&plan, "v").await.unwrap();
            h.record_instance_stopped(&plan, "v").await.unwrap();
            h.record_host_started("0.14.0").await.unwrap();
            h.record_host_shutdown().await.unwrap();
        });
        // Nothing to assert beyond "no panic, all Ok" — the
        // bus + recorder are None so there's nowhere for the
        // emits to land.
    }

    #[test]
    fn audit_only_hooks_skip_bus_publish() {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".to_string()));
        let hooks = LifecycleHooks::audit_only(recorder);
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_instance_started(&plan, "v").await.unwrap();
        });
        assert_eq!(signer.entries().len(), 1);
        // No bus assertion needed — there's no bus to subscribe
        // to. The pin here is that the audit-only path still
        // emits the audit entry.
    }

    #[test]
    fn bus_only_hooks_skip_audit_record() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let hooks = LifecycleHooks::bus_only(bus);
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_instance_started(&plan, "v").await.unwrap();
            let event = rx.recv().await.unwrap();
            assert!(matches!(event, LifecycleEvent::InstanceStarted { .. }));
        });
    }

    // ──────────────────────────────────────────────────────────────
    // Host events (unbound)
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn host_started_emits_unbound_audit_with_version_label() {
        let (hooks, signer, _bus) = build_hooks();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_host_started("0.14.0").await.unwrap();
        });
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "host.started");
        assert_eq!(
            entries[0].labels.get("version"),
            Some(&"0.14.0".to_string())
        );
    }

    #[test]
    fn host_shutdown_emits_unbound_audit() {
        let (hooks, signer, _bus) = build_hooks();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_host_shutdown().await.unwrap();
        });
        assert_eq!(signer.entries()[0].event, "host.shutdown");
    }

    // ──────────────────────────────────────────────────────────────
    // standard_hooks builder
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn standard_hooks_wires_recorder_and_bus_together() {
        let signer = Arc::new(CapturingAuditSigner::new());
        let metrics = Arc::new(Metrics::new());
        let (hooks, bus) = standard_hooks(
            signer.clone(),
            TenantId("local".to_string()),
            Some(metrics.clone()),
        );
        let mut rx = bus.subscribe();
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_instance_started(&plan, "vm-x").await.unwrap();
            let _ = rx.recv().await.unwrap();
        });
        // All three sinks fired.
        assert_eq!(signer.entries().len(), 1);
        assert_eq!(metrics.snapshot().audit_lifecycle_total, 1);
    }

    #[test]
    fn standard_hooks_works_without_metrics() {
        // Operators who don't wire metrics still get audit + bus.
        let signer = Arc::new(CapturingAuditSigner::new());
        let (hooks, _bus) = standard_hooks(signer.clone(), TenantId("local".to_string()), None);
        let plan = fixture_plan();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            hooks.record_instance_stopped(&plan, "vm-x").await.unwrap();
        });
        assert_eq!(signer.entries().len(), 1);
    }

    #[test]
    fn hooks_are_clone_for_multi_threaded_emit() {
        // LifecycleHooks must be Clone so multiple threads /
        // tokio tasks can share without Arc<Mutex<...>> games.
        let (hooks, _signer, _bus) = build_hooks();
        let cloned = hooks.clone();
        let _ = cloned; // compile-check
    }
}
