//! Periodic-tick driver for [`BalloonController`].
//!
//! `BalloonController::tick` is a pure-logic decision function.
//! Production callers want it called on a
//! schedule against the live `VmBackend`. This module is the
//! adapter: it queries the backend for running VMs, reads each
//! one's `BalloonState`, hands the snapshot to the controller, and
//! wires the apply closure to `VmBackend::balloon_set_target`.
//!
//! The supervisor's eventual daemon binary spawns
//! [`run_balloon_loop`] at boot; library consumers can also spawn
//! it directly. The loop honours a `tokio::sync::watch` shutdown
//! signal so callers can stop it cleanly.
//!
//! Why an async function and not a struct: the tick logic itself
//! is fully synchronous (sysinfo reads + backend RPCs); the only
//! reason for async at this level is the periodic sleep + the
//! shutdown select. A free async function pushes the entire shape
//! into one `tokio::spawn`-able awaitable without inventing a
//! ContextManager.
//!
//! Tests cover both the pure-helper tick (`run_one_tick`) and the
//! loop driver (with `tokio::time::pause` so the suite doesn't
//! sleep for real).

use std::sync::Arc;
use std::time::Duration;

use mvm_core::vm_backend::{VmBackend, VmStatus};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::watch;

use crate::supervisor::balloon::{BalloonController, HostPressureSource, TickOutcome};
use crate::supervisor::reaper::jittered_interval;

/// Tuning for the periodic balloon tick loop.
#[derive(Debug, Clone)]
pub struct BalloonRuntimeConfig {
    /// Nominal interval between ticks.
    pub base_interval: Duration,
    /// Maximum +/- jitter applied to each interval. Zero disables
    /// jitter and produces deterministic ticking — useful for
    /// tests, suboptimal in production where coordinated ticking
    /// across many supervisors would amplify host pressure.
    pub jitter: Duration,
}

impl Default for BalloonRuntimeConfig {
    fn default() -> Self {
        // 10 s base + ±2 s jitter: responsive enough that a
        // pressure spike doesn't sit unresolved for long, slow
        // enough that `sysinfo::refresh_memory` (the current default
        // pressure source) doesn't dominate the supervisor's CPU
        // budget. Step-aligned with `BalloonPolicy::step_mib = 64`.
        Self {
            base_interval: Duration::from_secs(10),
            jitter: Duration::from_secs(2),
        }
    }
}

/// Run a single tick against `backend`: list running VMs that
/// advertise balloon support, read each one's state, run the
/// controller, apply the resulting targets.
///
/// Pure-async-free synchronous helper so callers (and tests) can
/// drive a single tick without a tokio runtime. Returns the empty
/// outcome set when the backend doesn't advertise balloon support
/// — no point in reading state from a backend that can't apply
/// the result anyway.
pub fn run_one_tick<P>(
    backend: &dyn VmBackend,
    controller: &BalloonController<P>,
) -> anyhow::Result<Vec<TickOutcome>>
where
    P: HostPressureSource,
{
    if !backend.capabilities().balloon {
        // Honest no-op: a balloon-less backend can't act on
        // decisions, so skip the pressure read + state scan
        // entirely. Empty outcome set is the natural return.
        return Ok(Vec::new());
    }

    let infos = backend.list()?;
    let mut states = Vec::new();
    for info in infos {
        if info.status != VmStatus::Running {
            continue;
        }
        match backend.balloon_state(&info.id) {
            Ok(state) => states.push((info.id, state)),
            Err(e) => {
                // A single VM's state-read failure doesn't sink
                // the whole tick — record at warn and skip the VM
                // so the others still get evaluated. A backend
                // that hasn't created a balloon device for this
                // particular VM (mem_initial wasn't set) hits this
                // path with the per-backend "no balloon device"
                // error.
                tracing::warn!(
                    vm = %info.name,
                    "balloon_state read failed; skipping VM in this tick: {e:#}",
                );
            }
        }
    }

    controller.tick(&states, |vm, target| backend.balloon_set_target(vm, target))
}

/// Async loop: every `config.base_interval` (± `config.jitter`),
/// run a tick. Exits cleanly when `shutdown` flips to `true`.
///
/// Errors from `run_one_tick` are logged at `error!` and the loop
/// continues — a transient backend failure shouldn't kill the
/// supervisor's reclaim machinery. Non-`Hold` outcomes are logged
/// at `info!` so an operator tailing the supervisor's logs sees
/// "inflate vm-a to 256 MiB" lines while pressure is high.
///
/// The first tick fires after one interval, not immediately, so a
/// freshly-spawned supervisor doesn't ballon-thrash on a still-
/// settling pressure reading. Pass a [`watch::Receiver<bool>`] that
/// can be set to `true` to stop the loop; the loop also exits if
/// the sender side is dropped (treated as shutdown).
pub async fn run_balloon_loop<P>(
    backend: Arc<dyn VmBackend + Send + Sync>,
    controller: BalloonController<P>,
    config: BalloonRuntimeConfig,
    mut shutdown: watch::Receiver<bool>,
) where
    P: HostPressureSource,
{
    let mut rng = StdRng::from_entropy();
    loop {
        let sleep_for = jittered_interval(&mut rng, config.base_interval, config.jitter);
        let sleep = tokio::time::sleep(sleep_for);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("balloon loop received shutdown signal; exiting");
                    return;
                }
            }
        }

        match run_one_tick(backend.as_ref(), &controller) {
            Ok(outcomes) => {
                for outcome in &outcomes {
                    log_outcome(outcome);
                }
            }
            Err(e) => {
                tracing::error!("balloon tick failed (pressure read error or similar): {e:#}");
            }
        }
    }
}

fn log_outcome(outcome: &TickOutcome) {
    use crate::supervisor::balloon::BalloonAction;
    if let Some(err) = &outcome.error {
        tracing::warn!(vm = %outcome.vm.0, "balloon apply failed: {err}");
        return;
    }
    match &outcome.action {
        BalloonAction::Hold => {
            // Hold is the steady state — log at trace so an
            // operator can confirm ticks are running but the
            // signal doesn't flood the log under quiet pressure.
            tracing::trace!(vm = %outcome.vm.0, "balloon hold");
        }
        BalloonAction::Inflate {
            target_inflate_mib, ..
        } => {
            tracing::info!(
                vm = %outcome.vm.0,
                target_mib = *target_inflate_mib,
                "balloon inflate",
            );
        }
        BalloonAction::Deflate {
            target_inflate_mib, ..
        } => {
            tracing::info!(
                vm = %outcome.vm.0,
                target_mib = *target_inflate_mib,
                "balloon deflate",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use anyhow::bail;
    use mvm_core::vm_backend::{
        BackendSecurityProfile, BalloonState, ClaimStatus, LayerCoverage, VmCapabilities,
        VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
    };

    use crate::supervisor::balloon::{BalloonAction, BalloonPolicy, HostPressure};

    // ── Test fixtures ──────────────────────────────────────────────

    /// Minimal `HostPressureSource` returning a fixed value. Used
    /// throughout the tests so policy decisions are deterministic.
    struct FixedPressure(f32);
    impl HostPressureSource for FixedPressure {
        fn current(&self) -> anyhow::Result<HostPressure> {
            Ok(HostPressure::clamped(self.0))
        }
    }

    /// Pressure source that always errors — used to assert the
    /// loop surfaces pressure-read failures.
    struct ErrPressure;
    impl HostPressureSource for ErrPressure {
        fn current(&self) -> anyhow::Result<HostPressure> {
            bail!("pressure read failed by fixture")
        }
    }

    /// Minimal `VmBackend` impl for the tick-loop tests. Records
    /// `balloon_set_target` calls so assertions can inspect what
    /// the controller decided. All other methods are stubbed —
    /// only the surfaces the tick uses are real.
    struct TestBackend {
        balloon_supported: bool,
        vms: Vec<TestVm>,
        applies: Mutex<Vec<(VmId, u32)>>,
        /// When set, `balloon_set_target` returns Err for the
        /// listed VM names. Tests use this to drive the "apply
        /// failure surfaces in TickOutcome" path.
        apply_fails_for: Vec<String>,
    }

    #[derive(Clone)]
    struct TestVm {
        id: VmId,
        status: VmStatus,
        state: BalloonState,
    }

    impl TestBackend {
        fn new(balloon_supported: bool) -> Self {
            Self {
                balloon_supported,
                vms: Vec::new(),
                applies: Mutex::new(Vec::new()),
                apply_fails_for: Vec::new(),
            }
        }
        fn with_vm(mut self, id: &str, status: VmStatus, max: u32, inflated: u32) -> Self {
            self.vms.push(TestVm {
                id: VmId(id.to_string()),
                status,
                state: BalloonState {
                    max_mib: max,
                    inflated_mib: inflated,
                    host_committed_mib: max.saturating_sub(inflated),
                },
            });
            self
        }
        fn fail_apply_for(mut self, id: &str) -> Self {
            self.apply_fails_for.push(id.to_string());
            self
        }
        fn applied(&self) -> Vec<(VmId, u32)> {
            self.applies.lock().unwrap().clone()
        }
    }

    impl VmBackend for TestBackend {
        fn name(&self) -> &str {
            "test"
        }
        fn capabilities(&self) -> VmCapabilities {
            VmCapabilities {
                pause_resume: true,
                snapshots: false,
                vsock: false,
                tap_networking: false,
                balloon: self.balloon_supported,
                fs_quick_checkpoint: false,
            }
        }
        fn start_with_mode(
            &self,
            _config: &VmStartConfig,
            _mode: mvm_core::vm_backend::StartMode,
        ) -> anyhow::Result<VmId> {
            unimplemented!("test backend: start")
        }
        fn wait(&self, _id: &VmId) -> anyhow::Result<VmExitStatus> {
            unimplemented!("test backend: wait")
        }
        fn stop(&self, _id: &VmId) -> anyhow::Result<()> {
            unimplemented!("test backend: stop")
        }
        fn stop_all(&self) -> anyhow::Result<()> {
            unimplemented!("test backend: stop_all")
        }
        fn pause(&self, _id: &VmId) -> anyhow::Result<()> {
            unimplemented!("test backend: pause")
        }
        fn resume(&self, _id: &VmId) -> anyhow::Result<()> {
            unimplemented!("test backend: resume")
        }
        fn status(&self, id: &VmId) -> anyhow::Result<VmStatus> {
            for vm in &self.vms {
                if vm.id == *id {
                    return Ok(vm.status.clone());
                }
            }
            Ok(VmStatus::Stopped)
        }
        fn list(&self) -> anyhow::Result<Vec<VmInfo>> {
            Ok(self
                .vms
                .iter()
                .map(|vm| VmInfo {
                    id: vm.id.clone(),
                    name: vm.id.0.clone(),
                    status: vm.status.clone(),
                    guest_ip: None,
                    cpus: 1,
                    memory_mib: vm.state.max_mib,
                    profile: None,
                    revision: None,
                    flake_ref: None,
                    ports: Vec::new(),
                })
                .collect())
        }
        fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> anyhow::Result<String> {
            unimplemented!("test backend: logs")
        }
        fn is_available(&self) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn install(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> anyhow::Result<()> {
            if self.apply_fails_for.iter().any(|n| n == &id.0) {
                bail!("test fixture: apply failure for {}", id.0);
            }
            self.applies
                .lock()
                .unwrap()
                .push((id.clone(), target_inflate_mib));
            Ok(())
        }
        fn balloon_state(&self, id: &VmId) -> anyhow::Result<BalloonState> {
            for vm in &self.vms {
                if vm.id == *id {
                    return Ok(vm.state);
                }
            }
            bail!("test backend: no state for {}", id.0)
        }
        fn security_profile(&self) -> BackendSecurityProfile {
            BackendSecurityProfile {
                claims: [ClaimStatus::DoesNotHold; 7],
                layer_coverage: LayerCoverage::default(),
                tier: "Tier 3 (test-only)",
                notes: &[],
            }
        }
    }

    fn controller_pressure(p: f32) -> BalloonController<FixedPressure> {
        BalloonController::new(BalloonPolicy::default(), FixedPressure(p))
    }

    // ── Synchronous tick tests ─────────────────────────────────────

    #[test]
    fn run_one_tick_skips_unsupported_backend() {
        // Backend that doesn't advertise balloon support => the
        // tick must not even read VM state, let alone call apply.
        let backend = TestBackend::new(false).with_vm("vm-a", VmStatus::Running, 1024, 0);
        let controller = controller_pressure(0.95);
        let outcomes = run_one_tick(&backend, &controller).expect("tick");
        assert!(outcomes.is_empty(), "unsupported backend must yield empty");
        assert!(backend.applied().is_empty(), "must not call apply");
    }

    #[test]
    fn run_one_tick_filters_to_running_vms() {
        // Mix running + stopped; only running participates.
        let backend = TestBackend::new(true)
            .with_vm("running-vm", VmStatus::Running, 1024, 0)
            .with_vm("stopped-vm", VmStatus::Stopped, 1024, 0);
        // High pressure => inflate.
        let controller = controller_pressure(0.95);
        let outcomes = run_one_tick(&backend, &controller).expect("tick");
        assert_eq!(outcomes.len(), 1, "only running VMs participate");
        assert_eq!(outcomes[0].vm.0, "running-vm");
        let applied = backend.applied();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].0.0, "running-vm");
    }

    #[test]
    fn run_one_tick_propagates_pressure_read_error() {
        // ErrPressure short-circuits the tick at the pressure read.
        let backend = TestBackend::new(true).with_vm("vm-a", VmStatus::Running, 1024, 0);
        let controller = BalloonController::new(BalloonPolicy::default(), ErrPressure);
        let err = run_one_tick(&backend, &controller).unwrap_err();
        assert!(err.to_string().contains("pressure read failed"));
        assert!(backend.applied().is_empty());
    }

    #[test]
    fn run_one_tick_records_apply_errors_per_vm() {
        // Two VMs, one fails to apply — outcome must surface the
        // error for the failing VM and still succeed for the
        // healthy one.
        let backend = TestBackend::new(true)
            .with_vm("good", VmStatus::Running, 1024, 0)
            .with_vm("bad", VmStatus::Running, 1024, 0)
            .fail_apply_for("bad");
        let controller = controller_pressure(0.95);
        let outcomes = run_one_tick(&backend, &controller).expect("tick");
        assert_eq!(outcomes.len(), 2);
        let bad = outcomes.iter().find(|o| o.vm.0 == "bad").unwrap();
        assert!(!bad.applied, "bad VM apply must report not applied");
        assert!(bad.error.is_some());
        let good = outcomes.iter().find(|o| o.vm.0 == "good").unwrap();
        assert!(good.applied, "good VM apply must succeed");
        assert!(good.error.is_none());
    }

    #[test]
    fn run_one_tick_holds_in_dead_band() {
        // Pressure between deflate_below (0.6) and inflate_above
        // (0.8) => Hold.
        let backend = TestBackend::new(true).with_vm("vm-a", VmStatus::Running, 1024, 256);
        let controller = controller_pressure(0.70);
        let outcomes = run_one_tick(&backend, &controller).expect("tick");
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0].action, BalloonAction::Hold));
        assert!(!outcomes[0].applied, "Hold must not call apply");
        assert!(backend.applied().is_empty());
    }

    // ── Async loop tests ───────────────────────────────────────────

    /// Counts how many ticks ran by wrapping `TestBackend` in an
    /// `Arc` and watching `applied()` grow.
    #[tokio::test(start_paused = true)]
    async fn run_balloon_loop_calls_tick_periodically() {
        // High pressure + one running VM => every tick inflates
        // (until ceiling). With base 1 s + jitter 0, three ticks
        // in 3.5 s paused time. Drive the loop by advancing time
        // one tick at a time and yielding so the runtime gets to
        // resume the spawned task after each advance.
        let backend = Arc::new(TestBackend::new(true).with_vm("vm-a", VmStatus::Running, 1024, 0));
        let controller = controller_pressure(0.95);
        let (tx, rx) = watch::channel(false);
        let config = BalloonRuntimeConfig {
            base_interval: Duration::from_secs(1),
            jitter: Duration::ZERO,
        };
        let backend_loop: Arc<dyn VmBackend + Send + Sync> = backend.clone();
        let task = tokio::spawn(run_balloon_loop(backend_loop, controller, config, rx));
        // Advance time tick-by-tick and poll the apply counter
        // until we've observed three ticks. Bounded by a hard
        // ceiling so a wedged loop doesn't spin forever.
        let mut iterations = 0;
        while backend.applied().len() < 3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            iterations += 1;
            assert!(
                iterations < 50,
                "loop didn't reach 3 ticks within 50 iterations; got {}",
                backend.applied().len()
            );
        }
        tx.send(true).expect("send shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
        assert!(backend.applied().len() >= 3);
    }

    #[tokio::test(start_paused = true)]
    async fn run_balloon_loop_exits_on_shutdown() {
        // No advance => no tick fires, but shutdown signal still
        // exits the loop within bounded time.
        let backend: Arc<dyn VmBackend + Send + Sync> = Arc::new(TestBackend::new(true));
        let controller = controller_pressure(0.5);
        let (tx, rx) = watch::channel(false);
        let config = BalloonRuntimeConfig {
            base_interval: Duration::from_secs(60),
            jitter: Duration::ZERO,
        };
        let task = tokio::spawn(run_balloon_loop(backend, controller, config, rx));
        tx.send(true).expect("send shutdown");
        let res = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("loop must exit within 1 s of shutdown");
        res.expect("task panicked");
    }
}
