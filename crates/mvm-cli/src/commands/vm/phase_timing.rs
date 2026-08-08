//! Phase timing for one transient `machine run` / `mvmctl run`: where the
//! host wall-clock goes between image resolution, admission, backend start,
//! guest readiness, command execution, and teardown.
//!
//! Off by default. `MVM_PHASE_TIMING=1` makes the transient runner emit a
//! one-line breakdown to stderr. The mark→span collapse and the rendered
//! line are pure, so they are unit-tested without booting a VM — mirroring
//! the bench harness's `BootMarks`→`IterationTiming`.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::launch_sample::LaunchSubTimings;

/// Whether the backend satisfied the launch from a warm standby or performed
/// a normal boot/restore path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMode {
    /// A claimed standby child resumed from captured memory.
    Warm,
    /// A cold boot or template snapshot restore supplied the VM.
    Cold,
}

impl LaunchMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Cold => "cold",
        }
    }
}

/// Host-monotonic instants captured at the boundaries of one transient run.
/// Marks are taken in runner order; spans are `Instant` differences so they
/// can never go negative for in-order marks.
#[derive(Debug, Clone, Copy)]
pub struct RunPhaseMarks {
    /// The path that produced this launch.
    pub launch_mode: LaunchMode,
    /// Runner entry, before any artifact resolution.
    pub start: Instant,
    /// Kernel/rootfs artifacts resolved (template load or prebuilt pair).
    pub image_resolved: Instant,
    /// Boot inputs prepared and the verity sidecar probed.
    pub drives_ready: Instant,
    /// The transient workload's signed plan was admitted (or admission skipped).
    pub admitted: Instant,
    /// Start of warm-pool maintenance and compatible-parent selection.
    pub pool_wait_started: Option<Instant>,
    /// Start of the actual warm claim after pool maintenance completed.
    pub claim_started: Option<Instant>,
    /// The backend reported the VM booted (cold start or snapshot restore).
    pub backend_started: Instant,
    /// The guest agent first became reachable over vsock — i.e. the command
    /// is about to be dispatched. The `backend_started`..`vsock_ready` span
    /// is the boot-to-ready wait; `start`..`vsock_ready` is the full dispatch
    /// window.
    pub vsock_ready: Instant,
    /// The guest command finished and its exit code was captured.
    pub command_done: Instant,
    /// The VM was stopped and transient staging was cleaned up.
    pub torn_down: Instant,
}

/// Per-phase host wall-clock spans, milliseconds. `total_ms` is the headline:
/// `start` to `torn_down`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPhaseTimings {
    pub launch_mode: LaunchMode,
    pub resolve_ms: f64,
    pub drives_ms: f64,
    pub admit_ms: f64,
    pub pool_wait_ms: f64,
    pub claim_ms: f64,
    pub backend_start_ms: f64,
    pub vsock_wait_ms: f64,
    pub warm_window_ms: f64,
    pub command_ms: f64,
    pub teardown_ms: f64,
    pub total_ms: f64,
}

/// Mutable timing marks owned by the boot selector while it decides whether a
/// launch can use a warm parent. Keeping these marks separate from
/// [`RunPhaseMarks`] lets cold launches retain a zero-valued warm breakdown.
#[derive(Debug, Default)]
pub struct WarmClaimMarks {
    /// When warm-pool maintenance and compatible-parent selection began.
    pub pool_wait_started: Option<Instant>,
    /// When the backend claim began after pool maintenance.
    pub claim_started: Option<Instant>,
}

/// The sub-phases a launch can time below the coarse buckets above.
///
/// The three mount sub-phases have no producer on the live-share `--mount`
/// path, which attaches a host directory over virtio-fs and materializes
/// nothing; a content-addressed mount image is what records them. They are
/// declared here because the prepared-cold lane gate has to be able to see
/// mount materialization to refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubPhase {
    MountFingerprint,
    MountCacheLookup,
    MountMaterialize,
    ArtifactVerify,
    VmmCreate,
    GuestKernelEntry,
    AgentAuth,
    FirstDispatch,
    CleanupHandoff,
    /// Stopping the backend VM, inside cleanup.
    StopTransient,
    /// Topping the warm pool back up, inside cleanup.
    PoolReplenish,
    /// Removing the VM state directories, inside cleanup.
    StateRemove,
}

/// One optional sub-phase span.
///
/// A span with no marks collapses to `None`, never `0.0` — "did not happen"
/// and "took no measurable time" are different facts, and a report that
/// merges them cannot answer where a launch spent its milliseconds.
#[derive(Debug, Default, Clone, Copy)]
struct SpanMark {
    started: Option<Instant>,
    finished: Option<Instant>,
}

impl SpanMark {
    fn elapsed_ms(self) -> Option<f64> {
        let (start, end) = (self.started?, self.finished?);
        Some(end.saturating_duration_since(start).as_secs_f64() * 1000.0)
    }
}

/// Sub-phase marks for one launch. Construct with [`LaunchSubMarks::new`];
/// when disabled every `start`/`finish` is a no-op and every span reports
/// `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LaunchSubMarks {
    enabled: bool,
    mount_fingerprint: SpanMark,
    mount_cache_lookup: SpanMark,
    mount_materialize: SpanMark,
    artifact_verify: SpanMark,
    vmm_create: SpanMark,
    guest_kernel_entry: SpanMark,
    agent_auth: SpanMark,
    first_dispatch: SpanMark,
    cleanup_handoff: SpanMark,
    stop_transient: SpanMark,
    pool_replenish: SpanMark,
    state_remove: SpanMark,
}

impl LaunchSubMarks {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    fn slot(&mut self, phase: SubPhase) -> &mut SpanMark {
        match phase {
            SubPhase::MountFingerprint => &mut self.mount_fingerprint,
            SubPhase::MountCacheLookup => &mut self.mount_cache_lookup,
            SubPhase::MountMaterialize => &mut self.mount_materialize,
            SubPhase::ArtifactVerify => &mut self.artifact_verify,
            SubPhase::VmmCreate => &mut self.vmm_create,
            SubPhase::GuestKernelEntry => &mut self.guest_kernel_entry,
            SubPhase::AgentAuth => &mut self.agent_auth,
            SubPhase::FirstDispatch => &mut self.first_dispatch,
            SubPhase::CleanupHandoff => &mut self.cleanup_handoff,
            SubPhase::StopTransient => &mut self.stop_transient,
            SubPhase::PoolReplenish => &mut self.pool_replenish,
            SubPhase::StateRemove => &mut self.state_remove,
        }
    }

    /// Open (or re-open) a span. Re-opening is deliberate: a retried phase —
    /// a readiness handshake that failed and was polled again — reports the
    /// attempt that finished, not the first one that started.
    pub fn start(&mut self, phase: SubPhase) {
        if !self.enabled {
            return;
        }
        let slot = self.slot(phase);
        slot.started = Some(Instant::now());
        slot.finished = None;
    }

    /// Close a span. A close with no matching open is dropped, so an
    /// error path that skipped the opening mark reports `None` rather than a
    /// span measured from the wrong instant.
    pub fn finish(&mut self, phase: SubPhase) {
        if !self.enabled {
            return;
        }
        let slot = self.slot(phase);
        if slot.started.is_some() {
            slot.finished = Some(Instant::now());
        }
    }

    /// Whether `phase` recorded a complete span.
    #[must_use]
    pub fn recorded(&self, phase: SubPhase) -> bool {
        let mut copy = *self;
        copy.slot(phase).elapsed_ms().is_some()
    }

    /// Collapse every mark into the reported spans.
    #[must_use]
    pub fn to_timings(self) -> LaunchSubTimings {
        LaunchSubTimings {
            mount_fingerprint_ms: self.mount_fingerprint.elapsed_ms(),
            mount_cache_lookup_ms: self.mount_cache_lookup.elapsed_ms(),
            mount_materialize_ms: self.mount_materialize.elapsed_ms(),
            artifact_verify_ms: self.artifact_verify.elapsed_ms(),
            vmm_create_ms: self.vmm_create.elapsed_ms(),
            guest_kernel_entry_ms: self.guest_kernel_entry.elapsed_ms(),
            agent_auth_ms: self.agent_auth.elapsed_ms(),
            first_dispatch_ms: self.first_dispatch.elapsed_ms(),
            cleanup_handoff_ms: self.cleanup_handoff.elapsed_ms(),
            stop_transient_ms: self.stop_transient.elapsed_ms(),
            pool_replenish_ms: self.pool_replenish.elapsed_ms(),
            state_remove_ms: self.state_remove.elapsed_ms(),
        }
    }
}

impl RunPhaseMarks {
    /// Collapse the marks into per-phase spans. Arithmetic is saturating
    /// `Instant` difference, so an out-of-order mark yields `0` rather than
    /// a negative span.
    pub fn to_timings(self) -> RunPhaseTimings {
        let ms = |a: Instant, b: Instant| b.saturating_duration_since(a).as_secs_f64() * 1000.0;
        RunPhaseTimings {
            launch_mode: self.launch_mode,
            resolve_ms: ms(self.start, self.image_resolved),
            drives_ms: ms(self.image_resolved, self.drives_ready),
            admit_ms: ms(self.drives_ready, self.admitted),
            pool_wait_ms: if self.launch_mode == LaunchMode::Warm {
                self.pool_wait_started.map_or(0.0, |start| {
                    ms(start, self.claim_started.unwrap_or(self.admitted))
                })
            } else {
                0.0
            },
            claim_ms: if self.launch_mode == LaunchMode::Warm {
                self.claim_started
                    .map_or(0.0, |start| ms(start, self.backend_started))
            } else {
                0.0
            },
            backend_start_ms: ms(self.admitted, self.backend_started),
            vsock_wait_ms: ms(self.backend_started, self.vsock_ready),
            warm_window_ms: ms(self.admitted, self.vsock_ready),
            command_ms: ms(self.vsock_ready, self.command_done),
            teardown_ms: ms(self.command_done, self.torn_down),
            total_ms: ms(self.start, self.torn_down),
        }
    }
}

/// Hard warm-launch ceiling for [`RunPhaseTimings::dispatch_window_ms`], in
/// milliseconds. The SLO is deliberately scoped to a claimed warm standby:
/// admission has completed, the child is assigned, and the guest agent is
/// reachable. Cold artifact resolution, VMM creation, guest boot, command
/// execution, and teardown are separate measurements and are not disguised
/// as warm-launch latency.
pub const WARM_START_MAX_MS: f64 = 300.0;

impl RunPhaseTimings {
    /// Admitted-plan to command-dispatch: the window the warm-start SLO is set
    /// against (backend claim/restore + boot-to-agent wait).
    pub fn dispatch_window_ms(&self) -> f64 {
        self.backend_start_ms + self.vsock_wait_ms
    }

    /// Whether this run's dispatch window cleared the strict warm-start
    /// [`WARM_START_MAX_MS`] ceiling. A result at exactly 300ms misses the
    /// sub-300ms requirement.
    pub fn within_warm_start_slo(&self) -> bool {
        self.dispatch_window_ms() < WARM_START_MAX_MS
    }

    /// Render the warm SLO only for a warm claim. Cold launches are diagnostic
    /// baselines, not warm-SLO failures.
    fn warm_slo_status(&self) -> &'static str {
        match self.launch_mode {
            LaunchMode::Warm if self.within_warm_start_slo() => "ok",
            LaunchMode::Warm => "over",
            LaunchMode::Cold => "na",
        }
    }

    /// A single stable, greppable line for logs and the benchmark harness.
    /// The trailing `warm_slo=ok|over` token reports this run against the
    /// warm-start ceiling so a regression is visible in the line itself, not
    /// just inferable from the raw window.
    pub fn render(&self) -> String {
        format!(
            "[mvm] phase-timing: resolve={:.1}ms drives={:.1}ms admit={:.1}ms \
             pool_wait_ms={:.1} claim_ms={:.1} backend_start={:.1}ms \
             vsock_wait={:.1}ms warm_window_ms={:.1} command={:.1}ms \
             teardown={:.1}ms total={:.1}ms launch_mode={} dispatch_window={:.1}ms warm_slo={}",
            self.resolve_ms,
            self.drives_ms,
            self.admit_ms,
            self.pool_wait_ms,
            self.claim_ms,
            self.backend_start_ms,
            self.vsock_wait_ms,
            self.warm_window_ms,
            self.command_ms,
            self.teardown_ms,
            self.total_ms,
            self.launch_mode.as_str(),
            self.dispatch_window_ms(),
            self.warm_slo_status(),
        )
    }
}

/// p50 latency budget for a warm-started run's hot-start window (backend
/// claim/restore + boot-to-agent-reachable). Tighter than
/// [`WARM_START_MAX_MS`]; this is the aggregate target a warm pool should
/// reach once the hard per-run SLO is met.
#[cfg(test)]
pub const WARM_START_P50_BUDGET_MS: u64 = 30;

/// Aggregate p99 target for warm-start dispatch windows. It is intentionally
/// below the hard per-run ceiling, leaving room for scheduler variance
/// without making a 300ms outlier normal.
#[cfg(test)]
pub const WARM_START_P99_BUDGET_MS: u64 = 50;

/// Comparison of a warm-started run's hot-start latency against a cold
/// run's: whether the warm run clears the hard SLO and tighter p50 target,
/// and how much faster it was.
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub struct WarmVsColdReport {
    pub warm_hot_ms: u64,
    pub cold_hot_ms: u64,
    pub clears_slo: bool,
    pub clears_p50_target: bool,
    pub speedup: f64,
}

/// Compare a warm-started run's hot-start latency against a cold run's.
/// Hot-start latency is [`RunPhaseTimings::dispatch_window_ms`] — backend
/// boot plus boot-to-agent-reachable, the part a warm start improves.
/// Pure: reads only the two timings, no clock or I/O.
#[cfg(test)]
pub fn warm_vs_cold(warm: &RunPhaseTimings, cold: &RunPhaseTimings) -> WarmVsColdReport {
    let warm_hot_ms = warm.dispatch_window_ms().round() as u64;
    let cold_hot_ms = cold.dispatch_window_ms().round() as u64;
    let speedup = if warm_hot_ms == 0 {
        f64::INFINITY
    } else {
        cold_hot_ms as f64 / warm_hot_ms as f64
    };
    WarmVsColdReport {
        warm_hot_ms,
        cold_hot_ms,
        clears_slo: warm.dispatch_window_ms() < WARM_START_MAX_MS,
        clears_p50_target: warm_hot_ms <= WARM_START_P50_BUDGET_MS,
        speedup,
    }
}

/// Whether phase timing is enabled, pure over the raw env value so the gate
/// is testable without mutating process env.
fn timing_enabled_from(value: Option<&str>) -> bool {
    matches!(value, Some(v) if v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Read `MVM_PHASE_TIMING` and decide whether to emit a breakdown.
pub fn enabled() -> bool {
    timing_enabled_from(std::env::var("MVM_PHASE_TIMING").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    fn ordered_marks(t0: Instant) -> RunPhaseMarks {
        RunPhaseMarks {
            launch_mode: LaunchMode::Warm,
            start: t0,
            image_resolved: t0 + Duration::from_millis(5),
            drives_ready: t0 + Duration::from_millis(12),
            admitted: t0 + Duration::from_millis(20),
            pool_wait_started: Some(t0 + Duration::from_millis(20)),
            claim_started: Some(t0 + Duration::from_millis(25)),
            backend_started: t0 + Duration::from_millis(120),
            vsock_ready: t0 + Duration::from_millis(150),
            command_done: t0 + Duration::from_millis(160),
            torn_down: t0 + Duration::from_millis(175),
        }
    }

    #[test]
    fn marks_collapse_to_ordered_non_negative_spans() {
        let t = ordered_marks(Instant::now()).to_timings();
        approx(t.resolve_ms, 5.0);
        approx(t.drives_ms, 7.0);
        approx(t.admit_ms, 8.0);
        approx(t.pool_wait_ms, 5.0);
        approx(t.claim_ms, 95.0);
        approx(t.backend_start_ms, 100.0);
        approx(t.vsock_wait_ms, 30.0);
        approx(t.warm_window_ms, 130.0);
        approx(t.command_ms, 10.0);
        approx(t.teardown_ms, 15.0);
        approx(t.total_ms, 175.0);
        // The phases partition the run: their sum is the total.
        approx(
            t.resolve_ms
                + t.drives_ms
                + t.admit_ms
                + t.backend_start_ms
                + t.vsock_wait_ms
                + t.command_ms
                + t.teardown_ms,
            t.total_ms,
        );
    }

    #[test]
    fn dispatch_window_is_backend_start_plus_vsock_wait() {
        // The dispatch window is "backend start to command dispatch":
        // admitted -> backend booted -> guest agent reachable.
        let t = ordered_marks(Instant::now()).to_timings();
        approx(t.dispatch_window_ms(), 130.0);
    }

    #[test]
    fn out_of_order_mark_saturates_to_zero() {
        let t0 = Instant::now();
        let marks = RunPhaseMarks {
            launch_mode: LaunchMode::Cold,
            start: t0,
            image_resolved: t0 + Duration::from_millis(5),
            drives_ready: t0 + Duration::from_millis(12),
            admitted: t0 + Duration::from_millis(20),
            pool_wait_started: None,
            claim_started: None,
            // backend_started before admitted (clock anomaly): clamps to 0.
            backend_started: t0 + Duration::from_millis(10),
            vsock_ready: t0 + Duration::from_millis(150),
            command_done: t0 + Duration::from_millis(160),
            torn_down: t0 + Duration::from_millis(175),
        };
        let t = marks.to_timings();
        approx(t.backend_start_ms, 0.0);
    }

    #[test]
    fn render_is_stable_and_greppable() {
        let t = RunPhaseTimings {
            launch_mode: LaunchMode::Warm,
            resolve_ms: 5.0,
            drives_ms: 7.0,
            admit_ms: 8.0,
            pool_wait_ms: 5.0,
            claim_ms: 95.0,
            backend_start_ms: 100.0,
            vsock_wait_ms: 30.0,
            warm_window_ms: 130.0,
            command_ms: 10.0,
            teardown_ms: 15.0,
            total_ms: 175.0,
        };
        assert_eq!(
            t.render(),
            "[mvm] phase-timing: resolve=5.0ms drives=7.0ms admit=8.0ms pool_wait_ms=5.0 claim_ms=95.0 backend_start=100.0ms vsock_wait=30.0ms warm_window_ms=130.0 command=10.0ms teardown=15.0ms total=175.0ms launch_mode=warm dispatch_window=130.0ms warm_slo=ok"
        );
    }

    /// Build timings with a chosen dispatch window (`backend_start +
    /// vsock_wait`); the other phases are irrelevant to the warm SLO.
    fn timings_with_dispatch_window(backend_start_ms: f64, vsock_wait_ms: f64) -> RunPhaseTimings {
        RunPhaseTimings {
            launch_mode: LaunchMode::Warm,
            resolve_ms: 0.0,
            drives_ms: 0.0,
            admit_ms: 0.0,
            pool_wait_ms: 0.0,
            claim_ms: 0.0,
            backend_start_ms,
            vsock_wait_ms,
            warm_window_ms: backend_start_ms + vsock_wait_ms,
            command_ms: 0.0,
            teardown_ms: 0.0,
            total_ms: backend_start_ms + vsock_wait_ms,
        }
    }

    #[test]
    fn warm_slo_is_strictly_below_the_ceiling() {
        // Exactly at 300ms fails. A warm standby claim (near-zero
        // backend_start) clears it; a cold boot does not.
        let under = timings_with_dispatch_window(WARM_START_MAX_MS - 30.0, 30.0);
        approx(under.dispatch_window_ms(), WARM_START_MAX_MS);
        assert!(!under.within_warm_start_slo(), "window == 300ms must fail");

        let over = timings_with_dispatch_window(WARM_START_MAX_MS, 0.1);
        assert!(!over.within_warm_start_slo(), "window > 300ms must fail");

        let warm = timings_with_dispatch_window(0.5, 130.0);
        assert!(
            warm.within_warm_start_slo(),
            "warm 130ms window clears 300ms"
        );

        let cold = timings_with_dispatch_window(2250.0, 30.0);
        assert!(!cold.within_warm_start_slo(), "cold 2.28s exceeds 300ms");
    }

    #[test]
    fn render_reports_warm_slo_over_for_a_cold_window() {
        let cold = timings_with_dispatch_window(2250.0, 30.0);
        let mut cold = cold;
        cold.launch_mode = LaunchMode::Cold;
        assert!(
            cold.render()
                .ends_with("launch_mode=cold dispatch_window=2280.0ms warm_slo=na")
        );
    }

    #[test]
    fn warm_slo_constant_is_pinned() {
        // Pin the published latency target so a change is deliberate and
        // must be accompanied by a contract update.
        approx(WARM_START_MAX_MS, 300.0);
        assert_eq!(WARM_START_P50_BUDGET_MS, 30);
        assert_eq!(WARM_START_P99_BUDGET_MS, 50);
    }

    /// Every sub-phase, so a mis-wired `slot()` arm shows up as one phase
    /// overwriting another rather than as a silently wrong benchmark column.
    const ALL_SUB_PHASES: [SubPhase; 12] = [
        SubPhase::MountFingerprint,
        SubPhase::MountCacheLookup,
        SubPhase::MountMaterialize,
        SubPhase::ArtifactVerify,
        SubPhase::VmmCreate,
        SubPhase::GuestKernelEntry,
        SubPhase::AgentAuth,
        SubPhase::FirstDispatch,
        SubPhase::CleanupHandoff,
        SubPhase::StopTransient,
        SubPhase::PoolReplenish,
        SubPhase::StateRemove,
    ];

    #[test]
    fn every_sub_phase_records_its_own_independent_span() {
        let mut marks = LaunchSubMarks::new(true);
        for phase in ALL_SUB_PHASES {
            assert!(!marks.recorded(phase));
            marks.start(phase);
            marks.finish(phase);
            assert!(marks.recorded(phase), "{phase:?} did not record a span");
        }
        let timings = marks.to_timings();
        assert_eq!(
            timings.recorded().len(),
            ALL_SUB_PHASES.len(),
            "each phase must map to its own field: {timings:?}"
        );
    }

    #[test]
    fn a_disabled_mark_set_records_nothing() {
        let mut marks = LaunchSubMarks::new(false);
        for phase in ALL_SUB_PHASES {
            marks.start(phase);
            marks.finish(phase);
            assert!(!marks.recorded(phase));
        }
        assert_eq!(marks.to_timings(), LaunchSubTimings::default());
    }

    #[test]
    fn a_finish_without_a_start_records_nothing() {
        // An error path that skipped the opening mark must report "not
        // measured", never a span measured from some unrelated instant.
        let mut marks = LaunchSubMarks::new(true);
        marks.finish(SubPhase::VmmCreate);
        assert!(!marks.recorded(SubPhase::VmmCreate));
        assert_eq!(marks.to_timings().vmm_create_ms, None);
    }

    #[test]
    fn restarting_a_span_reports_the_attempt_that_finished() {
        // The readiness handshake is polled: a failed attempt reopens the
        // span, and the reported cost must be the attempt that succeeded.
        let mut marks = LaunchSubMarks::new(true);
        marks.start(SubPhase::AgentAuth);
        std::thread::sleep(Duration::from_millis(20));
        marks.start(SubPhase::AgentAuth);
        assert!(
            !marks.recorded(SubPhase::AgentAuth),
            "reopening must clear the prior close"
        );
        marks.finish(SubPhase::AgentAuth);
        let measured = marks
            .to_timings()
            .agent_auth_ms
            .expect("the second attempt closed");
        assert!(
            measured < 20.0,
            "reported {measured}ms includes the abandoned attempt"
        );
    }

    #[test]
    fn timing_gate_only_trips_on_truthy_values() {
        assert!(timing_enabled_from(Some("1")));
        assert!(timing_enabled_from(Some("true")));
        assert!(timing_enabled_from(Some("TRUE")));
        assert!(!timing_enabled_from(Some("0")));
        assert!(!timing_enabled_from(Some("")));
        assert!(!timing_enabled_from(Some("yes")));
        assert!(!timing_enabled_from(None));
    }

    #[test]
    fn warm_vs_cold_clears_slo_when_hot_under_budget() {
        let warm = timings_with_dispatch_window(15.0, 10.0); // hot = 25ms
        let cold = timings_with_dispatch_window(370.0, 30.0); // hot = 400ms
        let report = warm_vs_cold(&warm, &cold);
        assert_eq!(report.warm_hot_ms, 25);
        assert_eq!(report.cold_hot_ms, 400);
        assert!(
            report.clears_slo,
            "25ms warm hot-start must clear the 300ms hard SLO"
        );
        assert!(report.clears_p50_target);
        approx(report.speedup, 16.0);
    }

    #[test]
    fn warm_vs_cold_misses_p50_target_when_hot_over_budget() {
        let warm = timings_with_dispatch_window(45.0, 0.0); // hot = 45ms
        let cold = timings_with_dispatch_window(370.0, 30.0);
        let report = warm_vs_cold(&warm, &cold);
        assert!(report.clears_slo, "45ms warm hot-start is below 300ms");
        assert!(!report.clears_p50_target, "45ms warm hot-start misses p50");
    }

    #[test]
    fn warm_vs_cold_speedup_infinite_when_warm_zero() {
        let warm = timings_with_dispatch_window(0.0, 0.0); // hot = 0ms
        let cold = timings_with_dispatch_window(370.0, 30.0);
        let report = warm_vs_cold(&warm, &cold);
        assert!(report.speedup.is_infinite());
    }
}
