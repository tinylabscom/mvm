//! Plan 60 Phase 4 piece 3 — host-side lifecycle event bus.
//!
//! `tokio::sync::broadcast`-based pub/sub channel that carries
//! every VM/instance state transition. The supervisor publishes
//! [`LifecycleEvent`] values on every state-machine edge; live
//! consumers (the future `mvmctl events --follow` watch path,
//! mvmd's reconcile loop, the audit Recorder when wired through)
//! subscribe and get backfilled by the broadcast channel's
//! per-subscriber ring buffer.
//!
//! ## Channel semantics
//!
//! Per `tokio::sync::broadcast`:
//! - Every subscriber sees every event published AFTER they
//!   subscribe (no replay of pre-subscribe events).
//! - A subscriber that falls behind by `capacity` events sees
//!   `RecvError::Lagged(n)` once and then resumes; older events
//!   are dropped.
//! - Publishing with no subscribers is a no-op — the channel
//!   doesn't buffer between zero and one subscriber.
//! - The bus is `Clone` because the underlying `Sender` is.
//!
//! ## Cross-process delivery
//!
//! In-process only — `broadcast::Sender` is `tokio`-local. Cross-
//! process subscribers (mvmd in a different binary, an external
//! `mvmctl events` invocation) need a forwarder: a long-lived task
//! that subscribes to the bus + serialises events out a Unix
//! socket or HTTP SSE endpoint. That forwarder is Phase 4
//! follow-up work; this module is the in-process substrate.
//!
//! ## Relationship to the audit Recorder
//!
//! The event bus and the audit Recorder serve overlapping but
//! distinct purposes:
//!
//! - **Audit Recorder** writes durable, chain-signed records to
//!   `~/.mvm/audit/<tenant>.jsonl`. Synchronous: every emit
//!   round-trips through the signer. Mandatory for compliance.
//! - **Event bus** publishes ephemeral notifications to live
//!   subscribers. Best-effort: a slow subscriber drops events
//!   rather than blocking publishers. Optional for compliance,
//!   load-bearing for UX.
//!
//! Both can coexist on a single state transition: the supervisor
//! emits an audit record AND publishes a lifecycle event. A future
//! wiring slice routes them through one call site.

use tokio::sync::broadcast;

use mvm_core::plan::{PlanId, TenantId};

/// Default channel capacity. Sized for bursty lifecycle events
/// (e.g., 100-instance reconcile cycle) without surprising
/// subscribers with `Lagged` warnings under normal operation.
/// Operators tuning a fleet at scale can construct an `EventBus`
/// with `with_capacity` and pick a different number.
pub const DEFAULT_CAPACITY: usize = 256;

/// One lifecycle event the supervisor publishes. The enum is
/// intentionally narrow — every variant maps to one state-machine
/// edge in `crate::supervisor::state::PlanStateMachine` or
/// `mvm::vm::instance_snapshot`'s pause/resume pipeline. New
/// variants are wire-stable additions when consumers run a binary
/// older than the publisher; `#[serde(deny_unknown_fields)]` on
/// any future on-wire form will require a `PROTOCOL_VERSION` bump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// `mvmctl up` admitted a plan and the backend.start() returned
    /// Ok. The audit Recorder emits a `plan.launched` at the same
    /// time; the event bus surfaces the same fact for live
    /// consumers.
    InstanceStarted {
        tenant: TenantId,
        plan_id: PlanId,
        vm_name: String,
    },
    /// The instance reached its terminal state and the supervisor
    /// has finished teardown. Symmetric to `InstanceStarted`.
    InstanceStopped {
        tenant: TenantId,
        plan_id: PlanId,
        vm_name: String,
    },
    /// `mvmctl pause` quiesced the VM and the snapshot HMAC sealed.
    InstancePaused {
        tenant: TenantId,
        plan_id: PlanId,
        vm_name: String,
    },
    /// `mvmctl resume` verified the snapshot and Firecracker loaded
    /// it. The instance is running again.
    InstanceResumed {
        tenant: TenantId,
        plan_id: PlanId,
        vm_name: String,
    },
    /// The instance was destroyed and its directory swept.
    /// `vm_name` is included for retrospective audit; subscribers
    /// can no longer query the instance after this event.
    InstanceDestroyed {
        tenant: TenantId,
        plan_id: PlanId,
        vm_name: String,
    },
}

impl LifecycleEvent {
    /// Wire-stable string tag — the same string the audit
    /// Recorder uses as `event_name` for the matching emit. Lets
    /// consumers filter by event without matching on the variant.
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::InstanceStarted { .. } => "lifecycle.instance.started",
            Self::InstanceStopped { .. } => "lifecycle.instance.stopped",
            Self::InstancePaused { .. } => "lifecycle.instance.paused",
            Self::InstanceResumed { .. } => "lifecycle.instance.resumed",
            Self::InstanceDestroyed { .. } => "lifecycle.instance.destroyed",
        }
    }
}

/// Pub/sub bus over a `tokio::sync::broadcast` channel. Cheap to
/// clone (sender is internally `Arc`); share one instance across
/// every supervisor subcomponent that emits lifecycle events.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<LifecycleEvent>,
}

impl EventBus {
    /// Build a bus with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Build a bus with operator-supplied capacity. Higher capacity
    /// reduces `Lagged` errors for slow subscribers at the cost of
    /// memory.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event. Returns the count of subscribers that
    /// received it (zero is a valid outcome — no subscribers
    /// listening). Wire-level errors are not exposed; the
    /// broadcast channel doesn't fail per-event.
    pub fn publish(&self, event: LifecycleEvent) -> usize {
        // broadcast::Sender::send returns Err only when there are
        // no active receivers, which is not an error in our model
        // — events with no subscribers are dropped silently. Map
        // both branches to a subscriber count.
        self.tx.send(event).unwrap_or_default()
    }

    /// Subscribe to the bus. New subscribers see every event
    /// published AFTER they call `subscribe`; pre-subscribe events
    /// are not replayed.
    pub fn subscribe(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.tx.subscribe()
    }

    /// Active-subscriber count. Useful for the `mvmctl events
    /// --watch-count` probe and for tests that need to assert
    /// "the bus has the expected fan-out."
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_event(name: &str) -> LifecycleEvent {
        LifecycleEvent::InstanceStarted {
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("plan-test".to_string()),
            vm_name: name.to_string(),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // event_name() taxonomy
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn event_name_strings_are_stable() {
        // Pin the wire-stable strings the audit Recorder + log
        // aggregators grep against. A refactor that renames a
        // variant must update consumers OR keep the wire string.
        assert_eq!(
            fixture_event("vm1").event_name(),
            "lifecycle.instance.started"
        );
        let stopped = LifecycleEvent::InstanceStopped {
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("p".to_string()),
            vm_name: "vm1".to_string(),
        };
        assert_eq!(stopped.event_name(), "lifecycle.instance.stopped");
        let paused = LifecycleEvent::InstancePaused {
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("p".to_string()),
            vm_name: "vm1".to_string(),
        };
        assert_eq!(paused.event_name(), "lifecycle.instance.paused");
        let resumed = LifecycleEvent::InstanceResumed {
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("p".to_string()),
            vm_name: "vm1".to_string(),
        };
        assert_eq!(resumed.event_name(), "lifecycle.instance.resumed");
        let destroyed = LifecycleEvent::InstanceDestroyed {
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("p".to_string()),
            vm_name: "vm1".to_string(),
        };
        assert_eq!(destroyed.event_name(), "lifecycle.instance.destroyed");
    }

    #[test]
    fn every_event_name_starts_with_lifecycle_prefix() {
        // The audit Recorder's prefix-validation requires every
        // emitted event_name to start with `lifecycle.` — pin
        // that invariant here so a new LifecycleEvent variant
        // can't slip through with a different prefix.
        let all = [
            LifecycleEvent::InstanceStarted {
                tenant: TenantId("t".to_string()),
                plan_id: PlanId("p".to_string()),
                vm_name: "v".to_string(),
            },
            LifecycleEvent::InstanceStopped {
                tenant: TenantId("t".to_string()),
                plan_id: PlanId("p".to_string()),
                vm_name: "v".to_string(),
            },
            LifecycleEvent::InstancePaused {
                tenant: TenantId("t".to_string()),
                plan_id: PlanId("p".to_string()),
                vm_name: "v".to_string(),
            },
            LifecycleEvent::InstanceResumed {
                tenant: TenantId("t".to_string()),
                plan_id: PlanId("p".to_string()),
                vm_name: "v".to_string(),
            },
            LifecycleEvent::InstanceDestroyed {
                tenant: TenantId("t".to_string()),
                plan_id: PlanId("p".to_string()),
                vm_name: "v".to_string(),
            },
        ];
        for evt in &all {
            assert!(
                evt.event_name().starts_with("lifecycle."),
                "event name {:?} missing lifecycle. prefix",
                evt.event_name()
            );
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Pub/sub round-trip
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn publish_with_no_subscribers_is_a_noop() {
        let bus = EventBus::new();
        let count = bus.publish(fixture_event("vm1"));
        assert_eq!(
            count, 0,
            "publish with no subscribers should report 0 deliveries"
        );
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn single_subscriber_receives_published_event() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let bus = EventBus::new();
            let mut rx = bus.subscribe();
            assert_eq!(bus.subscriber_count(), 1);
            let delivered = bus.publish(fixture_event("vm1"));
            assert_eq!(delivered, 1);
            let received = rx.recv().await.unwrap();
            assert_eq!(received, fixture_event("vm1"));
        });
    }

    #[test]
    fn multiple_subscribers_each_receive_every_event() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let bus = EventBus::new();
            let mut rx1 = bus.subscribe();
            let mut rx2 = bus.subscribe();
            let mut rx3 = bus.subscribe();
            assert_eq!(bus.subscriber_count(), 3);
            assert_eq!(bus.publish(fixture_event("vm1")), 3);
            assert_eq!(rx1.recv().await.unwrap(), fixture_event("vm1"));
            assert_eq!(rx2.recv().await.unwrap(), fixture_event("vm1"));
            assert_eq!(rx3.recv().await.unwrap(), fixture_event("vm1"));
        });
    }

    #[test]
    fn late_subscriber_does_not_see_pre_subscribe_events() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let bus = EventBus::new();
            bus.publish(fixture_event("pre-subscribe"));
            let mut rx = bus.subscribe();
            // Send a fresh event so we have something to receive.
            bus.publish(fixture_event("post-subscribe"));
            // First recv should yield the post-subscribe event,
            // NOT a backfill of pre-subscribe.
            let received = rx.recv().await.unwrap();
            assert_eq!(received, fixture_event("post-subscribe"));
        });
    }

    #[test]
    fn subscriber_count_drops_when_receiver_drops() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);
        drop(rx);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn slow_subscriber_lags_rather_than_blocks_publisher() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // capacity=2 → publish 5 events without recv → subscriber
            // misses 3, sees `Lagged(3)` on first recv, then resumes.
            let bus = EventBus::with_capacity(2);
            let mut rx = bus.subscribe();
            for i in 0..5 {
                bus.publish(fixture_event(&format!("vm{i}")));
            }
            let first = rx.recv().await;
            assert!(
                matches!(first, Err(broadcast::error::RecvError::Lagged(_))),
                "expected Lagged, got {first:?}"
            );
            // Subsequent recvs should yield the events still in the
            // ring buffer.
            let next = rx.recv().await.unwrap();
            // capacity=2 means the ring holds the most recent 2; the
            // next recv yields vm3 (oldest still in ring).
            assert_eq!(next, fixture_event("vm3"));
        });
    }

    #[test]
    fn bus_is_clone_for_multi_publisher_sharing() {
        // The Sender is internally Arc; clones share the channel.
        // Compile-check + a small functional pin via subscriber count.
        let bus = EventBus::new();
        let bus2 = bus.clone();
        let _rx = bus.subscribe();
        // Both clones see the same subscriber count.
        assert_eq!(bus.subscriber_count(), 1);
        assert_eq!(bus2.subscriber_count(), 1);
    }

    #[test]
    fn default_capacity_constant_is_documented_value() {
        // Pin the documented default so a "let's bump this to 1024
        // because" PR has to update the comment too.
        assert_eq!(DEFAULT_CAPACITY, 256);
    }
}
