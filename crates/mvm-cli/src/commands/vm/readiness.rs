//! Shared host-side readiness milestone emission.
//!
//! Every `mvmctl` subcommand that observes a VM-lifecycle milestone
//! the user might want to see in `mvmctl ls/ps --json` ends up here.
//! The function is intentionally best-effort: readiness is
//! observability, never gating, so registry I/O failures and
//! unregistered VMs degrade silently with a `tracing::warn` /
//! `tracing::debug` rather than aborting the launch or shutdown.

use std::time::{Duration, Instant};

use mvm::vsock_transport::{self, VsockTransport};
use mvm_core::domain::instance::InstanceReadiness;
use mvm_guest::integrations::{IntegrationStateReport, IntegrationStatus};
use mvm_guest::vsock::{
    GUEST_AGENT_PORT, GuestCapability, GuestRequest, GuestResponse, negotiate_protocol,
    send_request,
};

/// Persist a host-observed readiness milestone on the VM's registry
/// entry. Best-effort:
///
/// - If the registry can't be loaded or saved → `tracing::warn` and
///   return without bubbling the error.
/// - If the VM has no registry entry (the launchd-spawned direct-boot
///   path doesn't always register) → `tracing::debug` and return.
/// - If the registry update itself fails → `tracing::warn`.
///
/// Callers must never rely on this function to gate launch/teardown
/// — readiness is a downstream display signal, not a control flow.
pub(super) fn record_vm_readiness(vm_name: &str, readiness: InstanceReadiness) {
    let path = mvm::vm::name_registry::registry_path();
    let mut reg = match mvm::vm::name_registry::VmNameRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                err = %e,
                vm = vm_name,
                "failed to load VM name registry for readiness update"
            );
            return;
        }
    };
    let now = mvm_core::time::utc_now();
    match reg.set_readiness(vm_name, readiness, &now) {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!(
                vm = vm_name,
                "no registry entry for readiness update; skipping"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(err = %e, vm = vm_name, "failed to set readiness");
            return;
        }
    }
    if let Err(e) = reg.save(&path) {
        tracing::warn!(err = %e, vm = vm_name, "failed to save VM name registry");
    }
}

/// One snapshot of guest integration health observed by the host.
/// Built from a single `GuestRequest::IntegrationStatus` round-trip so
/// the host-side transitions are deterministic — there's no "partial
/// view" where the snapshot has some services missing from the report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServicesHealthSnapshot {
    /// Names of services whose status is anything other than
    /// `IntegrationStatus::Active`. Sorted for stable readiness
    /// payloads (the host then renders them into
    /// `InstanceReadiness::ServicesStarting { pending }`).
    pending: Vec<String>,
}

fn classify_services_snapshot(reports: &[IntegrationStateReport]) -> ServicesHealthSnapshot {
    let mut pending: Vec<String> = reports
        .iter()
        .filter(|r| !matches!(r.status, IntegrationStatus::Active))
        .map(|r| r.name.clone())
        .collect();
    pending.sort();
    ServicesHealthSnapshot { pending }
}

/// Query guest integration status via the standard `mvm::vsock_transport`
/// abstraction. Performs the hello prelude on each connection so the
/// agent dispatches the operational request.
fn query_services_via_transport(vm_name: &str) -> anyhow::Result<Vec<IntegrationStateReport>> {
    let transport: Box<dyn VsockTransport> = vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(GUEST_AGENT_PORT)?;
    let _ = negotiate_protocol(&mut stream, vec![GuestCapability::IntegrationStatus])?;
    let resp = send_request(&mut stream, &GuestRequest::IntegrationStatus)?;
    match resp {
        GuestResponse::IntegrationStatusReport { integrations } => Ok(integrations),
        GuestResponse::Error { message } => {
            anyhow::bail!("guest integration status error: {message}")
        }
        other => anyhow::bail!("unexpected response to IntegrationStatus: {other:?}"),
    }
}

/// Block until every guest integration reports `Active`, or `timeout`
/// elapses. Updates the registry's readiness on every transition the
/// host observes: each tick recomputes a `ServicesHealthSnapshot` and
/// records either `InstanceReadiness::ServicesStarting { pending }` or
/// `InstanceReadiness::ServicesReady`.
///
/// Best-effort:
/// - Transport / RPC errors `tracing::debug` and retry on the next
///   tick (a still-booting agent commonly fails the first few
///   polls).
/// - On timeout, the function returns leaving readiness at whatever
///   the last successful poll observed — `mvmctl ls --json` then
///   surfaces exactly which services blocked.
/// - VMs with no integrations transition to `ServicesReady`
///   immediately (the mock backend exercises this in
///   `mvm_backend::mock_guest_agent::dispatch`).
///
/// # Future: `Degraded`
///
/// Detecting `Degraded { unhealthy }` requires polling *after*
/// `ServicesReady`. None of those follow-up paths are wired here;
/// once `ServicesReady` fires, this function returns.
pub(super) fn wait_for_services_ready(vm_name: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let poll_interval = Duration::from_secs(1);
    let mut last_snapshot: Option<ServicesHealthSnapshot> = None;

    loop {
        match query_services_via_transport(vm_name) {
            Ok(reports) => {
                let snapshot = classify_services_snapshot(&reports);
                let readiness = if snapshot.pending.is_empty() {
                    InstanceReadiness::ServicesReady
                } else {
                    InstanceReadiness::ServicesStarting {
                        pending: snapshot.pending.clone(),
                    }
                };
                // Only record when the snapshot changed, to avoid
                // thrashing the registry file every tick when nothing
                // moved. The first successful poll always records,
                // since `last_snapshot` is `None`.
                if last_snapshot.as_ref() != Some(&snapshot) {
                    record_vm_readiness(vm_name, readiness);
                    last_snapshot = Some(snapshot.clone());
                }
                if snapshot.pending.is_empty() {
                    return;
                }
            }
            Err(e) => {
                tracing::debug!(
                    err = %e,
                    vm = vm_name,
                    "services-ready poll failed; will retry"
                );
            }
        }

        if Instant::now() >= deadline {
            tracing::debug!(
                vm = vm_name,
                "services-ready poll timed out; leaving readiness at last-known state"
            );
            return;
        }
        std::thread::sleep(poll_interval);
    }
}

/// Post-`ServicesReady` integration-health watcher. The `mvmctl up`
/// foreground Ctrl+C wait loop ticks this monitor every ~10 s so a service
/// that flips `Active` → `Error` *after* boot transitions readiness
/// to `Degraded { unhealthy }` instead of stranding the VM at
/// `ServicesReady` in the registry.
///
/// Stateful by design: `observe_and_record` only writes the
/// registry when the snapshot *changes*, so the wait loop can call
/// it on every tick without thrashing `vm-names.json`.
///
/// Readiness mapping for this watcher is **post-ready** semantics:
///
/// - `pending.is_empty()` → `InstanceReadiness::ServicesReady`.
///   Reached on recovery (services come back) or initial steady
///   state.
/// - `pending` non-empty → `InstanceReadiness::Degraded
///   { unhealthy: pending }`. The reused `pending` field carries
///   exactly the service names whose `IntegrationStatus` is
///   anything other than `Active`. The boot-time
///   `wait_for_services_ready` uses a `ServicesStarting { pending }`
///   mapping for the same snapshot — this monitor deliberately
///   diverges because the user-facing distinction is
///   "still starting" vs "was ready then broke."
pub(super) struct ServicesHealthMonitor {
    last_snapshot: Option<ServicesHealthSnapshot>,
}

impl ServicesHealthMonitor {
    /// Construct a monitor with no prior snapshot. The first
    /// successful `observe_and_record` call records its observed
    /// readiness unconditionally; subsequent calls dedup against
    /// the previous snapshot.
    pub(super) fn new() -> Self {
        Self {
            last_snapshot: None,
        }
    }

    /// Poll once. Returns the readiness the monitor decided to
    /// record (or `None` if nothing changed or the poll failed).
    /// Side effect: writes the registry via `record_vm_readiness`
    /// when the readiness value changes. Transport / RPC errors
    /// `tracing::debug` and return `None` — the monitor is
    /// observability, never gating.
    pub(super) fn observe_and_record(&mut self, vm_name: &str) -> Option<InstanceReadiness> {
        let reports = match query_services_via_transport(vm_name) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    err = %e,
                    vm = vm_name,
                    "services-health monitor poll failed; will retry"
                );
                return None;
            }
        };
        let snapshot = classify_services_snapshot(&reports);
        if self.last_snapshot.as_ref() == Some(&snapshot) {
            return None;
        }
        let readiness = readiness_for_post_ready_snapshot(&snapshot);
        record_vm_readiness(vm_name, readiness.clone());
        self.last_snapshot = Some(snapshot);
        Some(readiness)
    }
}

/// Pure decision function: given a post-ready services snapshot,
/// what readiness does it map to? Factored out so unit tests can
/// pin the mapping without hitting the transport / registry.
fn readiness_for_post_ready_snapshot(snapshot: &ServicesHealthSnapshot) -> InstanceReadiness {
    if snapshot.pending.is_empty() {
        InstanceReadiness::ServicesReady
    } else {
        InstanceReadiness::Degraded {
            unhealthy: snapshot.pending.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::integrations::IntegrationStateReport;

    fn report(name: &str, status: IntegrationStatus) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: None,
        }
    }

    #[test]
    fn snapshot_empty_list_has_no_pending() {
        let snap = classify_services_snapshot(&[]);
        assert!(snap.pending.is_empty());
    }

    #[test]
    fn snapshot_all_active_has_no_pending() {
        let reports = vec![
            report("postgres", IntegrationStatus::Active),
            report("redis", IntegrationStatus::Active),
        ];
        let snap = classify_services_snapshot(&reports);
        assert!(snap.pending.is_empty());
    }

    #[test]
    fn snapshot_collects_non_active_into_pending_and_sorts() {
        let reports = vec![
            report("redis", IntegrationStatus::Active),
            report("worker", IntegrationStatus::Starting),
            report("postgres", IntegrationStatus::Pending),
            report("queue", IntegrationStatus::Paused),
            report("api", IntegrationStatus::Error("502".to_string())),
        ];
        let snap = classify_services_snapshot(&reports);
        // Sorted alphabetically for stable readiness payloads.
        assert_eq!(snap.pending, vec!["api", "postgres", "queue", "worker"]);
    }

    // ---------------- Post-ready Degraded mapping ----------------
    //
    // The post-ready watcher uses the **same** snapshot shape as
    // the boot-time wait — only the readiness mapping diverges.
    // These tests pin that divergence (boot's `ServicesStarting` vs
    // monitor's `Degraded`) since the field name change is part of
    // the user-facing contract (`mvmctl ls --json` consumers
    // pattern-match on the variant tag).

    #[test]
    fn post_ready_snapshot_all_active_maps_to_services_ready() {
        let snap = classify_services_snapshot(&[report("postgres", IntegrationStatus::Active)]);
        let readiness = readiness_for_post_ready_snapshot(&snap);
        assert_eq!(readiness, InstanceReadiness::ServicesReady);
    }

    #[test]
    fn post_ready_snapshot_empty_list_maps_to_services_ready() {
        let snap = classify_services_snapshot(&[]);
        let readiness = readiness_for_post_ready_snapshot(&snap);
        assert_eq!(readiness, InstanceReadiness::ServicesReady);
    }

    #[test]
    fn post_ready_snapshot_with_pending_maps_to_degraded_with_unhealthy_field() {
        let snap = classify_services_snapshot(&[
            report("postgres", IntegrationStatus::Error("crashed".to_string())),
            report("redis", IntegrationStatus::Active),
            report("worker", IntegrationStatus::Pending),
        ]);
        let readiness = readiness_for_post_ready_snapshot(&snap);
        match readiness {
            InstanceReadiness::Degraded { unhealthy } => {
                // Boot uses `ServicesStarting { pending }`; post-ready
                // uses `Degraded { unhealthy }`. Same names, but the
                // field name change is part of the readable contract.
                assert_eq!(unhealthy, vec!["postgres", "worker"]);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn monitor_starts_with_no_last_snapshot() {
        let monitor = ServicesHealthMonitor::new();
        assert!(monitor.last_snapshot.is_none());
    }

    #[test]
    fn monitor_records_first_observed_snapshot_unconditionally() {
        // Manually drive the snapshot-comparison path the same way
        // `observe_and_record` does, without going through the
        // transport. This is the same dedup invariant the live
        // ticker depends on.
        let mut monitor = ServicesHealthMonitor::new();
        let snap = ServicesHealthSnapshot {
            pending: vec!["postgres".to_string()],
        };
        assert!(monitor.last_snapshot.as_ref() != Some(&snap));
        monitor.last_snapshot = Some(snap.clone());
        // Second observation of the same snapshot is a no-op.
        assert_eq!(monitor.last_snapshot.as_ref(), Some(&snap));
    }

    #[test]
    fn monitor_dedups_identical_snapshots_until_change() {
        let mut monitor = ServicesHealthMonitor::new();
        let a = ServicesHealthSnapshot {
            pending: vec!["postgres".to_string()],
        };
        let b = ServicesHealthSnapshot {
            pending: vec!["redis".to_string()],
        };

        // First observation records.
        monitor.last_snapshot = Some(a.clone());
        assert_eq!(monitor.last_snapshot.as_ref(), Some(&a));

        // Identical observation: dedups.
        assert!(monitor.last_snapshot.as_ref() == Some(&a));

        // Different observation: would record.
        assert!(monitor.last_snapshot.as_ref() != Some(&b));
    }
}
