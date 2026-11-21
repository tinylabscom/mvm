//! The epoch gate on the endpoint's egress decisions.
//!
//! A workload endpoint serves one admitted plan. Before it serves anything it
//! asks the epoch gate whether the plan's execution epoch may act for its unit,
//! and it asks again on every egress decision, reading the workload ledger
//! each time. Replacing or quarantining a unit does not stop the VM that ran
//! at the old epoch, so a decision taken once at start would leave that VM
//! reaching out under an epoch the ledger has already superseded.
//!
//! A decision taken when a flow opens is not taken again while it relays, so
//! a serving workload endpoint also asks the ledger on a fixed interval
//! ([`REVOCATION_CHECK_INTERVAL`]) from one thread. The first refusal is handed
//! to the caller once, and the thread ends: the endpoint binary records it and
//! exits, which closes every flow, the session and the listeners together.
//!
//! A builder endpoint runs under no plan and has no epoch to gate.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::{
    HostInterfaceError,
    epoch_gate::CommandGate,
    workload::{canonical_dir_at, legacy_path_at},
};
use mvm_runtime::vmm::egress_gate::AdmissionCheck;
use tracing::warn;

use super::network_endpoint::EndpointConfig;
use crate::supervisor::audit::audit_recorder::{EventCategory, Recorder};

/// How often a serving workload endpoint asks the ledger again.
///
/// This is the bound on how long a flow opened before a replacement or a
/// quarantine keeps relaying after the commit lands. Each tick is one wakeup
/// and one read of a small ledger file per endpoint, so one second keeps the
/// idle cost to a single wakeup per second per unit while leaving a revoked
/// epoch at most about a second of egress it was already holding.
pub const REVOCATION_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// The chain entry recorded when a serving endpoint closes everything because
/// its epoch stopped being admitted.
pub const REVOKED_EVENT: &str = "host.flow.revoked";

/// A workload endpoint's unit and epoch, and the mvm home whose workload
/// ledger decides them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointEpochGate {
    home: PathBuf,
    unit: String,
    epoch: ExecutionEpoch,
}

impl EndpointEpochGate {
    #[must_use]
    pub fn new(home: PathBuf, unit: String, epoch: ExecutionEpoch) -> Self {
        Self { home, unit, epoch }
    }

    /// The gate for the plan the endpoint was configured with. `None` for an
    /// endpoint with no plan: a builder, or a config the audit preflight has
    /// already refused.
    pub fn for_config(cfg: &EndpointConfig) -> Result<Option<Self>> {
        let Some(plan) = cfg.audit.as_ref().and_then(|audit| audit.plan()) else {
            return Ok(None);
        };
        let epoch = ExecutionEpoch::new(plan.execution_epoch)
            .context("the admitted plan carries a zero execution epoch")?;
        let home = mvm_core::config::mvm_home_strict()
            .context("resolve the mvm home the epoch gate reads")?;
        Ok(Some(Self::new(home, plan.workload.0.clone(), epoch)))
    }

    /// Read the ledger now and admit the plan's epoch. An unreadable or
    /// malformed ledger refuses like a denial does.
    pub fn admit(&self) -> Result<(), HostInterfaceError> {
        CommandGate::load_at(&self.home)?.admit(&self.unit, self.epoch)?;
        Ok(())
    }

    /// What the endpoint's confinement must leave readable for [`Self::admit`]
    /// to keep working: the canonical ledger directory, created now if no
    /// commit has made it yet so a later first commit lands inside the grant,
    /// and the legacy ledger file when one still exists. Read-only.
    pub fn readable_ledger_paths(&self) -> Result<Vec<PathBuf>> {
        let canonical = canonical_dir_at(&self.home);
        for dir in [
            self.home.clone(),
            mvm_core::config::policy_generations_dir_at(&self.home),
            canonical.clone(),
        ] {
            mvm_core::private_fs::create_owned_private_dir(&dir)
                .with_context(|| format!("securing {}", dir.display()))?;
        }
        let mut paths = vec![canonical];
        let legacy = legacy_path_at(&self.home);
        if std::fs::symlink_metadata(&legacy).is_ok_and(|meta| meta.is_file()) {
            paths.push(legacy);
        }
        Ok(paths)
    }

    /// The check the egress gate asks before every decision. A refusal is
    /// logged with the unit, epoch and reason; the decision it refuses is
    /// audited like any other egress denial.
    #[must_use]
    pub fn into_check(self) -> AdmissionCheck {
        AdmissionCheck::new(move || match self.admit() {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    unit = %self.unit,
                    epoch = self.epoch.get(),
                    reason = %error,
                    "egress refused: execution epoch not admitted"
                );
                false
            }
        })
    }
}

/// Watch `cfg`'s epoch while the endpoint serves. `None` for an endpoint with
/// no plan to gate, which gets no thread.
pub fn watch_config(
    cfg: &EndpointConfig,
    interval: Duration,
    on_revoked: impl FnOnce(EndpointEpochGate, HostInterfaceError) + Send + 'static,
) -> Result<Option<RevocationWatch>> {
    EndpointEpochGate::for_config(cfg)?
        .map(|gate| gate.watch(interval, on_revoked))
        .transpose()
}

impl EndpointEpochGate {
    /// Ask the ledger every `interval` on one thread, and hand the first
    /// refusal to `on_revoked`, once. The thread blocks on its stop channel
    /// between checks, so dropping the returned watch ends it at once.
    pub fn watch(
        self,
        interval: Duration,
        on_revoked: impl FnOnce(EndpointEpochGate, HostInterfaceError) + Send + 'static,
    ) -> Result<RevocationWatch> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("mvm-epoch-watch".into())
            .spawn(move || {
                if let Some(refusal) = self.wait_for_refusal(interval, &stopped) {
                    on_revoked(self, refusal);
                }
            })
            .context("spawn the execution-epoch watch")?;
        Ok(RevocationWatch {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// `None` when `stop` fires or its sender is dropped first.
    fn wait_for_refusal(
        &self,
        interval: Duration,
        stop: &mpsc::Receiver<()>,
    ) -> Option<HostInterfaceError> {
        loop {
            match stop.recv_timeout(interval) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
            if let Err(refusal) = self.admit() {
                return Some(refusal);
            }
        }
    }

    /// Record that this endpoint is closing every flow and its session
    /// because the ledger refused its epoch. Through a bound sink the entry
    /// carries the plan; a failure is logged, and the caller closes anyway.
    pub fn record_revocation(
        &self,
        recorder: Option<&Recorder>,
        runtime: &tokio::runtime::Handle,
        refusal: &HostInterfaceError,
    ) {
        warn!(
            unit = %self.unit,
            epoch = self.epoch.get(),
            reason = %refusal,
            "execution epoch no longer admitted; closing every flow and the session"
        );
        let Some(recorder) = recorder else {
            warn!("no audit recorder; the revocation is not in the chain");
            return;
        };
        let labels = [
            ("class".to_string(), "session".to_string()),
            ("reason".to_string(), "execution_not_admitted".to_string()),
            ("detail".to_string(), refusal.to_string()),
        ];
        if let Err(error) =
            runtime.block_on(recorder.record_unbound(EventCategory::Host, REVOKED_EVENT, labels))
        {
            warn!(%error, "recording the epoch revocation failed");
        }
    }
}

/// The running epoch watch. Dropping it stops and joins the thread.
#[derive(Debug)]
pub struct RevocationWatch {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for RevocationWatch {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_generation::workload_store::OwnedWorkloadStore;
    use mvm_core::host_interface::{error::Denial, workload::WorkloadChange};
    use mvm_core::policy::network_policy::NetworkPolicy;
    use mvm_runtime::vmm::egress_gate::{DenyReason, EgressVerdict};

    fn epoch(n: u64) -> ExecutionEpoch {
        ExecutionEpoch::new(n).unwrap()
    }

    fn gate_at(home: &std::path::Path, n: u64) -> EndpointEpochGate {
        EndpointEpochGate::new(home.to_path_buf(), "unit".into(), epoch(n))
    }

    fn commit(home: &std::path::Path, change: WorkloadChange) {
        OwnedWorkloadStore::open(home)
            .unwrap()
            .commit(&change)
            .unwrap();
    }

    fn replace(home: &std::path::Path) {
        commit(
            home,
            WorkloadChange::Replace {
                workload: "unit".into(),
                from_epoch: ExecutionEpoch::FIRST,
            },
        );
    }

    /// An egress call through the endpoint's gate for an unrestricted policy,
    /// so only the epoch can refuse it.
    fn egress(gate: &EndpointEpochGate) -> EgressVerdict {
        super::super::network_endpoint::build_egress_gate(&NetworkPolicy::unrestricted())
            .with_admission(gate.clone().into_check())
            .decide_request("93.184.216.34:443")
    }

    fn refused_by_epoch(verdict: EgressVerdict) -> bool {
        verdict == EgressVerdict::Deny(DenyReason::ExecutionNotAdmitted)
    }

    fn denial(result: Result<(), HostInterfaceError>) -> Denial {
        match result {
            Err(HostInterfaceError::Denied(denial)) => denial,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn the_current_epoch_starts_and_reaches_out() {
        let home = tempfile::tempdir().unwrap();
        let gate = gate_at(home.path(), 1);
        assert!(gate.admit().is_ok());
        assert!(matches!(egress(&gate), EgressVerdict::Allow { .. }));
    }

    #[test]
    fn a_replacement_after_start_refuses_the_next_egress_call() {
        let home = tempfile::tempdir().unwrap();
        let gate = gate_at(home.path(), 1);
        assert!(matches!(egress(&gate), EgressVerdict::Allow { .. }));
        replace(home.path());
        assert!(refused_by_epoch(egress(&gate)));
        assert_eq!(
            denial(gate.admit()),
            Denial::StaleEpoch { got: 1, current: 2 }
        );
        assert!(matches!(
            egress(&gate_at(home.path(), 2)),
            EgressVerdict::Allow { .. }
        ));
    }

    #[test]
    fn an_epoch_not_yet_promoted_neither_starts_nor_reaches_out() {
        let home = tempfile::tempdir().unwrap();
        let gate = gate_at(home.path(), 2);
        assert_eq!(
            denial(gate.admit()),
            Denial::EpochNotPromoted { got: 2, current: 1 }
        );
        assert!(refused_by_epoch(egress(&gate)));
    }

    #[test]
    fn a_quarantined_unit_neither_starts_nor_reaches_out() {
        let home = tempfile::tempdir().unwrap();
        commit(
            home.path(),
            WorkloadChange::Quarantine {
                workload: "unit".into(),
            },
        );
        let gate = gate_at(home.path(), 1);
        assert_eq!(
            denial(gate.admit()),
            Denial::WorkloadQuarantined("unit".into())
        );
        assert!(refused_by_epoch(egress(&gate)));
    }

    #[test]
    fn the_readable_ledger_paths_exist_before_the_first_commit() {
        let home = tempfile::tempdir().unwrap();
        let paths = gate_at(home.path(), 1).readable_ledger_paths().unwrap();
        assert_eq!(paths, vec![canonical_dir_at(home.path())]);
        assert!(paths[0].is_dir());
        // A commit after the grant lands inside the granted directory.
        replace(home.path());
        assert!(canonical_dir_at(home.path()).join("ledger.json").is_file());
        assert!(gate_at(home.path(), 2).admit().is_ok());
    }

    fn config(audit: Option<mvm_core::audit_sink::AuditContext>) -> EndpointConfig {
        serde_json::from_value(serde_json::json!({
            "tenant_id": "local",
            "instance_id": "vm",
            "secrets": [],
            "transport": { "kind": "uds", "path": "unused-network.sock" },
            "egress_mode": "flow_mux",
            "audit": audit,
        }))
        .unwrap()
    }

    #[test]
    fn a_workload_endpoint_is_gated_by_its_plans_workload_and_epoch() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("unit-a")
            .build();
        plan.execution_epoch = 3;
        let cfg = config(Some(mvm_core::audit_sink::AuditContext::Workload {
            plan: Box::new(plan),
        }));
        assert_eq!(
            EndpointEpochGate::for_config(&cfg).unwrap(),
            Some(EndpointEpochGate::new(
                home.path().to_path_buf(),
                "unit-a".into(),
                epoch(3)
            ))
        );
    }

    const TICK: Duration = Duration::from_millis(2);
    /// Far longer than any tick, so a slow test host cannot flake it; the
    /// waits below return as soon as the watch reports.
    const BOUND: Duration = Duration::from_secs(5);

    /// Watch `gate` every [`TICK`], reporting each refusal handed over.
    fn watching(gate: EndpointEpochGate) -> (RevocationWatch, mpsc::Receiver<HostInterfaceError>) {
        let (revoked, refusals) = mpsc::channel();
        let watch = gate
            .watch(TICK, move |_, refusal| revoked.send(refusal).unwrap())
            .unwrap();
        (watch, refusals)
    }

    #[test]
    fn a_replacement_while_serving_is_reported_once() {
        let home = tempfile::tempdir().unwrap();
        let (watch, refusals) = watching(gate_at(home.path(), 1));
        replace(home.path());
        assert_eq!(
            denial(Err(refusals.recv_timeout(BOUND).unwrap())),
            Denial::StaleEpoch { got: 1, current: 2 }
        );
        // The thread has ended: nothing else arrives and the sender is gone.
        drop(watch);
        assert!(matches!(
            refusals.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn a_quarantine_while_serving_is_reported() {
        let home = tempfile::tempdir().unwrap();
        let (_watch, refusals) = watching(gate_at(home.path(), 1));
        commit(
            home.path(),
            WorkloadChange::Quarantine {
                workload: "unit".into(),
            },
        );
        assert_eq!(
            denial(Err(refusals.recv_timeout(BOUND).unwrap())),
            Denial::WorkloadQuarantined("unit".into())
        );
    }

    #[test]
    fn an_admitted_epoch_is_left_alone_across_many_ticks() {
        let home = tempfile::tempdir().unwrap();
        let (_watch, refusals) = watching(gate_at(home.path(), 1));
        // About a hundred ticks against a ledger that admits the epoch.
        assert!(matches!(
            refusals.recv_timeout(TICK * 100),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        // Still watching: a replacement now is reported.
        replace(home.path());
        assert!(refusals.recv_timeout(BOUND).is_ok());
    }

    #[test]
    fn dropping_the_watch_stops_it_without_a_report() {
        let home = tempfile::tempdir().unwrap();
        let (watch, refusals) = watching(gate_at(home.path(), 1));
        drop(watch);
        replace(home.path());
        assert!(matches!(
            refusals.recv_timeout(TICK * 10),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn a_revocation_is_recorded_in_the_chain_exactly_once() {
        let (_env, home) = crate::test_fixtures::isolated_mvm_home();
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), [7u8; 32]).unwrap();
        let recorder = super::super::network_endpoint::build_audit_recorder("local")
            .expect("signer key present");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let (done, finished) = mpsc::channel();
        let watch = gate_at(home.path(), 1)
            .watch(TICK, move |gate, refusal| {
                gate.record_revocation(Some(&recorder), &handle, &refusal);
                done.send(()).unwrap();
            })
            .unwrap();
        replace(home.path());
        finished.recv_timeout(BOUND).unwrap();
        // Many more ticks' worth of a ledger that still refuses.
        assert!(finished.recv_timeout(TICK * 20).is_err());
        drop(watch);
        let chain =
            std::fs::read_to_string(mvm_core::config::mvm_audit_dir().join("local.jsonl")).unwrap();
        let revoked: Vec<&str> = chain
            .lines()
            .filter(|line| line.contains(REVOKED_EVENT))
            .collect();
        assert_eq!(revoked.len(), 1, "{chain}");
        assert!(revoked[0].contains("execution_not_admitted"), "{chain}");
    }

    #[test]
    fn a_builder_endpoint_starts_no_watch() {
        let cfg = config(Some(mvm_core::audit_sink::AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("local".into()),
            name: "builder".into(),
        }));
        let watch = watch_config(&cfg, TICK, |_, _| panic!("a builder has no epoch")).unwrap();
        assert!(watch.is_none());
    }

    #[test]
    fn a_builder_endpoint_is_not_gated() {
        let cfg = config(Some(mvm_core::audit_sink::AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("local".into()),
            name: "builder".into(),
        }));
        assert!(EndpointEpochGate::for_config(&cfg).unwrap().is_none());
        assert!(
            EndpointEpochGate::for_config(&config(None))
                .unwrap()
                .is_none()
        );
    }
}
