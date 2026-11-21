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
//! ([`REVOCATION_CHECK_INTERVAL`]) from one thread. The first definitive
//! denial (stale, not yet promoted, quarantined) is handed to the caller once,
//! and the thread ends: the endpoint binary records it and exits, which closes
//! every flow, the session and the listeners together.
//!
//! An unreadable ledger is not a denial at first. One bad read or a briefly
//! interrupted commit says nothing about whether the unit was replaced, and
//! exiting on it would end egress for good on every running workload. The
//! watch keeps asking; meanwhile flows already open keep relaying, and new
//! ones are still refused by the per-decision check, which treats an
//! unreadable ledger as a refusal. A ledger that stays unreadable for
//! [`UNREADABLE_LEDGER_GRACE`] revokes the endpoint as a denial would.
//!
//! A builder endpoint runs under no plan and has no epoch to gate.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::{
    HostInterfaceError,
    epoch_gate::CommandGate,
    error::Denial,
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

/// How long the ledger may stay unreadable, on every check, before a serving
/// endpoint revokes as if it had been denied.
///
/// Long enough for the policy coordinator to restart and resolve an
/// interrupted commit; a ledger unreadable for longer cannot vouch for any
/// epoch. A commit that crashed after its rename landed may itself be the
/// replacement or quarantine, so tolerance cannot be unbounded. Nothing
/// clears a stale commit marker on a timer: the coordinator resolves it when
/// it starts, or when the next launch or containment command asks it to.
pub const UNREADABLE_LEDGER_GRACE: Duration = Duration::from_secs(30);

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
    grace: Duration,
    on_revoked: impl FnOnce(EndpointEpochGate, HostInterfaceError) + Send + 'static,
) -> Result<Option<RevocationWatch>> {
    EndpointEpochGate::for_config(cfg)?
        .map(|gate| gate.watch(interval, grace, on_revoked))
        .transpose()
}

impl EndpointEpochGate {
    /// Ask the ledger every `interval` on one thread, and hand the refusal
    /// that ends the endpoint to `on_revoked`, once: a definitive denial, or
    /// a ledger that has stayed unreadable for `grace`. The thread blocks on
    /// its stop channel between checks, so dropping the returned watch ends
    /// it at once.
    pub fn watch(
        self,
        interval: Duration,
        grace: Duration,
        on_revoked: impl FnOnce(EndpointEpochGate, HostInterfaceError) + Send + 'static,
    ) -> Result<RevocationWatch> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("mvm-epoch-watch".into())
            .spawn(move || {
                if let Some(refusal) = self.wait_for_refusal(interval, grace, &stopped) {
                    on_revoked(self, refusal);
                }
            })
            .context("spawn the execution-epoch watch")?;
        Ok(RevocationWatch {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The refusal that ends the endpoint; `None` when `stop` fires or its
    /// sender is dropped first.
    fn wait_for_refusal(
        &self,
        interval: Duration,
        grace: Duration,
        stop: &mpsc::Receiver<()>,
    ) -> Option<HostInterfaceError> {
        let mut unreadable = UnreadableLedger::new(grace);
        loop {
            match stop.recv_timeout(interval) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
            let checked_at = Instant::now();
            if let Some(refusal) = unreadable.observe(self, checked_at, self.admit()) {
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
            ("reason".to_string(), revocation_reason(refusal).to_string()),
            ("detail".to_string(), refusal.to_string()),
        ];
        if let Err(error) =
            runtime.block_on(recorder.record_unbound(EventCategory::Host, REVOKED_EVENT, labels))
        {
            warn!(%error, "recording the epoch revocation failed");
        }
    }
}

/// The `reason` label on a revocation entry.
fn revocation_reason(refusal: &HostInterfaceError) -> &'static str {
    if is_definitive(refusal) {
        "execution_not_admitted"
    } else {
        "ledger_unreadable"
    }
}

/// How long the ledger has been unreadable, across the watch's checks.
struct UnreadableLedger {
    grace: Duration,
    since: Option<Instant>,
}

impl UnreadableLedger {
    fn new(grace: Duration) -> Self {
        Self { grace, since: None }
    }

    /// One check, taken at `checked_at`. Returns the refusal that ends the
    /// endpoint: a definitive denial at once, or the read error once the
    /// ledger has been unreadable on every check for `grace`. A read that
    /// admits the epoch resets the clock. Entering and leaving the unreadable
    /// state are each logged once.
    fn observe(
        &mut self,
        gate: &EndpointEpochGate,
        checked_at: Instant,
        result: Result<(), HostInterfaceError>,
    ) -> Option<HostInterfaceError> {
        match result {
            Ok(()) => {
                if self.since.take().is_some() {
                    warn!(
                        unit = %gate.unit,
                        epoch = gate.epoch.get(),
                        "workload ledger readable again and admits this epoch"
                    );
                }
                None
            }
            Err(refusal) if is_definitive(&refusal) => Some(refusal),
            Err(error) => {
                let since = *self.since.get_or_insert_with(|| {
                    warn!(
                        unit = %gate.unit,
                        epoch = gate.epoch.get(),
                        %error,
                        grace_secs = self.grace.as_secs(),
                        "workload ledger unreadable; open flows keep relaying until a read \
                         decides or the grace runs out"
                    );
                    checked_at
                });
                (checked_at.saturating_duration_since(since) >= self.grace).then_some(error)
            }
        }
    }
}

/// Whether `refusal` is the ledger's answer about this epoch rather than a
/// failure to read the ledger.
fn is_definitive(refusal: &HostInterfaceError) -> bool {
    matches!(
        refusal,
        HostInterfaceError::Denied(
            Denial::StaleEpoch { .. }
                | Denial::EpochNotPromoted { .. }
                | Denial::WorkloadQuarantined(_)
        )
    )
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
    use mvm_core::host_interface::workload::WorkloadChange;
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
    /// A grace no test outlasts, for tests about something else.
    const NO_GRACE_LIMIT: Duration = Duration::from_secs(3600);

    /// Watch `gate` every [`TICK`], reporting each refusal handed over.
    fn watching(gate: EndpointEpochGate) -> (RevocationWatch, mpsc::Receiver<HostInterfaceError>) {
        let (revoked, refusals) = mpsc::channel();
        let watch = gate
            .watch(TICK, NO_GRACE_LIMIT, move |_, refusal| {
                revoked.send(refusal).unwrap()
            })
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

    /// A watch that records its revocation through a real chain recorder, as
    /// the endpoint binary does, and reports each time it did.
    struct RecordedWatch {
        _env: mvm_core::util::test_env::TestEnv,
        home: tempfile::TempDir,
        _runtime: tokio::runtime::Runtime,
        watch: Option<RevocationWatch>,
        recorded: mpsc::Receiver<()>,
    }

    impl RecordedWatch {
        fn start() -> Self {
            Self::with_grace(NO_GRACE_LIMIT)
        }

        fn with_grace(grace: Duration) -> Self {
            let (env, home) = crate::test_fixtures::isolated_mvm_home();
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
            let (done, recorded) = mpsc::channel();
            let watch = gate_at(home.path(), 1)
                .watch(TICK, grace, move |gate, refusal| {
                    gate.record_revocation(Some(&recorder), &handle, &refusal);
                    done.send(()).unwrap();
                })
                .unwrap();
            Self {
                _env: env,
                home,
                _runtime: runtime,
                watch: Some(watch),
                recorded,
            }
        }

        fn home(&self) -> &std::path::Path {
            self.home.path()
        }

        /// About `ticks` checks pass with nothing recorded.
        fn quiet_for(&self, ticks: u32) {
            assert!(matches!(
                self.recorded.recv_timeout(TICK * ticks),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
        }

        /// The watch has ended: no further report can arrive.
        fn ended(&self) {
            assert!(matches!(
                self.recorded.recv_timeout(BOUND),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ));
        }

        /// Stop the watch and return the revocation entries in the chain.
        fn finish(mut self) -> Vec<String> {
            drop(self.watch.take());
            let chain =
                std::fs::read_to_string(mvm_core::config::mvm_audit_dir().join("local.jsonl"))
                    .unwrap_or_default();
            chain
                .lines()
                .filter(|line| line.contains(REVOKED_EVENT))
                .map(str::to_owned)
                .collect()
        }
    }

    /// Replace the ledger file by rename, as a commit does.
    fn write_ledger(home: &std::path::Path, contents: &str) {
        let dir = canonical_dir_at(home);
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("ledger.json.staged");
        std::fs::write(&staged, contents).unwrap();
        std::fs::rename(staged, dir.join("ledger.json")).unwrap();
    }

    fn ledger_at_epoch(home: &std::path::Path, epoch: u64) {
        write_ledger(
            home,
            &serde_json::json!({
                "sequence": 1,
                "workloads": { "unit": { "epoch": epoch, "quarantined": false } },
            })
            .to_string(),
        );
    }

    fn unreadable_ledger(home: &std::path::Path) {
        write_ledger(home, "{ not a ledger");
        assert!(matches!(
            gate_at(home, 1).admit(),
            Err(HostInterfaceError::Denied(Denial::StateUnreadable(_)))
        ));
    }

    #[test]
    fn a_revocation_is_recorded_in_the_chain_exactly_once() {
        let watched = RecordedWatch::start();
        replace(watched.home());
        watched.recorded.recv_timeout(BOUND).unwrap();
        // The ledger still refuses, but the watch reported once and ended.
        watched.ended();
        let revoked = watched.finish();
        assert_eq!(revoked.len(), 1, "{revoked:?}");
        assert!(revoked[0].contains("execution_not_admitted"), "{revoked:?}");
    }

    #[test]
    fn an_unreadable_ledger_neither_revokes_nor_records() {
        let watched = RecordedWatch::start();
        unreadable_ledger(watched.home());
        watched.quiet_for(100);
        assert!(watched.finish().is_empty());
    }

    #[test]
    fn a_denial_after_an_unreadable_ledger_revokes_once() {
        let watched = RecordedWatch::start();
        unreadable_ledger(watched.home());
        watched.quiet_for(20);
        ledger_at_epoch(watched.home(), 2);
        watched.recorded.recv_timeout(BOUND).unwrap();
        watched.ended();
        let revoked = watched.finish();
        assert_eq!(revoked.len(), 1, "{revoked:?}");
        assert!(revoked[0].contains("stale execution epoch"), "{revoked:?}");
    }

    #[test]
    fn an_unreadable_ledger_that_recovers_inside_the_grace_carries_on() {
        // About 20 unreadable ticks, well inside a two-second grace.
        let watched = RecordedWatch::with_grace(Duration::from_secs(2));
        unreadable_ledger(watched.home());
        watched.quiet_for(20);
        ledger_at_epoch(watched.home(), 1);
        watched.quiet_for(50);
        // Still watching: a replacement now is revoked.
        ledger_at_epoch(watched.home(), 2);
        watched.recorded.recv_timeout(BOUND).unwrap();
        assert_eq!(watched.finish().len(), 1);
    }

    /// Leave the commit marker in place, as a commit that crashed between
    /// its rename and clearing the marker does.
    fn commit_marker(home: &std::path::Path) -> std::path::PathBuf {
        let marker = canonical_dir_at(home).join(mvm_core::host_interface::workload::PENDING_FILE);
        std::fs::write(&marker, "{}").unwrap();
        marker
    }

    fn unreadable() -> Result<(), HostInterfaceError> {
        Err(HostInterfaceError::Denied(Denial::StateUnreadable(
            "ledger.json: corrupt".into(),
        )))
    }

    fn stale() -> Result<(), HostInterfaceError> {
        Err(HostInterfaceError::Denied(Denial::StaleEpoch {
            got: 1,
            current: 2,
        }))
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_grace_counts_only_continuous_unreadability() {
        let gate = gate_at(std::path::Path::new("/unused"), 1);
        let mut clock = UnreadableLedger::new(UNREADABLE_LEDGER_GRACE);
        let t0 = Instant::now();
        assert!(clock.observe(&gate, t0, unreadable()).is_none());
        assert!(clock.observe(&gate, t0 + secs(29), unreadable()).is_none());
        // An admitting read resets the clock.
        assert!(clock.observe(&gate, t0 + secs(30), Ok(())).is_none());
        assert!(clock.observe(&gate, t0 + secs(40), unreadable()).is_none());
        assert!(clock.observe(&gate, t0 + secs(69), unreadable()).is_none());
        let refusal = clock.observe(&gate, t0 + secs(70), unreadable()).unwrap();
        assert_eq!(revocation_reason(&refusal), "ledger_unreadable");
    }

    #[test]
    fn a_denial_ends_the_endpoint_at_once_even_inside_the_grace() {
        let gate = gate_at(std::path::Path::new("/unused"), 1);
        let mut clock = UnreadableLedger::new(UNREADABLE_LEDGER_GRACE);
        let t0 = Instant::now();
        assert!(clock.observe(&gate, t0, unreadable()).is_none());
        let refusal = clock.observe(&gate, t0 + secs(1), stale()).unwrap();
        assert_eq!(revocation_reason(&refusal), "execution_not_admitted");
    }

    #[test]
    fn an_unreadable_ledger_past_the_grace_revokes_once_as_unreadable() {
        let watched = RecordedWatch::with_grace(TICK * 25);
        unreadable_ledger(watched.home());
        watched.recorded.recv_timeout(BOUND).unwrap();
        watched.ended();
        let revoked = watched.finish();
        assert_eq!(revoked.len(), 1, "{revoked:?}");
        assert!(revoked[0].contains("ledger_unreadable"), "{revoked:?}");
    }

    #[test]
    fn a_landed_replacement_behind_its_commit_marker_revokes_within_the_grace() {
        let watched = RecordedWatch::with_grace(Duration::from_millis(300));
        ledger_at_epoch(watched.home(), 2);
        commit_marker(watched.home());
        // Each read waits out the marker before calling the ledger unreadable.
        watched.recorded.recv_timeout(BOUND).unwrap();
        let revoked = watched.finish();
        assert_eq!(revoked.len(), 1, "{revoked:?}");
        assert!(revoked[0].contains("ledger_unreadable"), "{revoked:?}");
    }

    #[test]
    fn a_landed_quarantine_revokes_as_soon_as_its_commit_marker_clears() {
        let watched = RecordedWatch::start();
        write_ledger(
            watched.home(),
            &serde_json::json!({
                "sequence": 1,
                "workloads": { "unit": { "epoch": 1, "quarantined": true } },
            })
            .to_string(),
        );
        let marker = commit_marker(watched.home());
        assert!(matches!(
            watched.recorded.recv_timeout(Duration::from_millis(1500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        std::fs::remove_file(marker).unwrap();
        watched.recorded.recv_timeout(BOUND).unwrap();
        let revoked = watched.finish();
        assert_eq!(revoked.len(), 1, "{revoked:?}");
        assert!(revoked[0].contains("execution_not_admitted"), "{revoked:?}");
        assert!(revoked[0].contains("quarantined"), "{revoked:?}");
    }

    #[test]
    fn a_builder_endpoint_starts_no_watch() {
        let cfg = config(Some(mvm_core::audit_sink::AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("local".into()),
            name: "builder".into(),
        }));
        let watch = watch_config(&cfg, TICK, NO_GRACE_LIMIT, |_, _| {
            panic!("a builder has no epoch")
        })
        .unwrap();
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
