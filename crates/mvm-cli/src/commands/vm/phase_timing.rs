//! Phase timing for one transient `machine run` / `mvmctl run`: where the
//! host wall-clock goes between image resolution, admission, backend start,
//! guest readiness, command execution, and teardown.
//!
//! Off by default. `MVM_PHASE_TIMING=1` makes the transient runner emit a
//! one-line breakdown to stderr. The mark→span collapse and the rendered
//! line are pure, so they are unit-tested without booting a VM — mirroring
//! the bench harness's `BootMarks`→`IterationTiming`.

use std::time::Instant;

use crate::bench::cold_launch::MIN_MATRIX_SAMPLES;
use mvm_core::launch_trace::PhaseTimingMode;
use mvm_runtime::workload_runner::StopTiming;
use serde::{Deserialize, Serialize};

use super::launch_sample::LaunchSubTimings;

/// Timing collected for one completed transient launch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPhaseTimingReport {
    pub phases: RunPhaseTimings,
    pub sub_phases: LaunchSubTimings,
    pub backend_phases: Vec<mvm_core::launch_trace::TracePhase>,
    pub degraded: Vec<String>,
}

impl RunPhaseTimingReport {
    #[must_use]
    pub fn new(
        phases: RunPhaseTimings,
        sub_phases: LaunchSubTimings,
        backend_phases: Vec<mvm_core::launch_trace::TracePhase>,
        degraded: Vec<String>,
    ) -> Self {
        Self {
            phases,
            sub_phases,
            backend_phases,
            degraded,
        }
    }

    /// Render the report as a compact human-readable table.
    #[must_use]
    pub fn render_table(&self) -> String {
        let mut rows = vec![
            ("resolve", self.phases.resolve_ms),
            ("drives", self.phases.drives_ms),
            ("admit", self.phases.admit_ms),
        ];
        if self.phases.launch_mode == LaunchMode::Warm {
            rows.extend([
                ("pool wait", self.phases.pool_wait_ms),
                ("claim", self.phases.claim_ms),
            ]);
        }
        rows.extend([
            ("backend start", self.phases.backend_start_ms),
            ("guest ready", self.phases.vsock_wait_ms),
            ("command", self.phases.command_ms),
            ("teardown", self.phases.teardown_ms),
            ("total", self.phases.total_ms),
        ]);
        let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
        let mut out = format!(
            "[mvm] phase timing ({})\n{:<width$}  {:>9}\n",
            self.phases.launch_mode.as_str(),
            "phase",
            "duration",
            width = width
        );
        out.push_str(&format!("{}  {}\n", "-".repeat(width), "-".repeat(9)));
        for (name, ms) in rows {
            out.push_str(&format!("{name:<width$}  {ms:>8.1}ms\n"));
        }
        out.push_str(&format!(
            "dispatch window: {:.1}ms\nwarm SLO: {}",
            self.phases.dispatch_window_ms(),
            self.phases.warm_slo_status()
        ));
        out
    }
}

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
    stop_timing: Option<StopTiming>,
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

    /// Record the backend's stop sequence when the selected backend exposes
    /// the shared workload-runner timing surface.
    pub fn record_stop_timing(&mut self, timing: Option<StopTiming>) {
        if self.enabled {
            self.stop_timing = timing;
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
            stop_attach_ms: self
                .stop_timing
                .map(|timing| timing.attach.as_secs_f64() * 1000.0),
            stop_endpoint_reaping_ms: self
                .stop_timing
                .map(|timing| timing.endpoint_reaping.as_secs_f64() * 1000.0),
            stop_driver_kill_ms: self
                .stop_timing
                .map(|timing| timing.driver_kill.as_secs_f64() * 1000.0),
            stop_console_cleanup_ms: self
                .stop_timing
                .map(|timing| timing.console_cleanup.as_secs_f64() * 1000.0),
            stop_supervisor_signal_ms: self
                .stop_timing
                .and_then(|timing| timing.driver_detail)
                .map(|timing| timing.supervisor_signal.as_secs_f64() * 1000.0),
            stop_pid_disappearance_ms: self
                .stop_timing
                .and_then(|timing| timing.driver_detail)
                .map(|timing| timing.pid_disappearance.as_secs_f64() * 1000.0),
            stop_force_kill_wait_ms: self
                .stop_timing
                .and_then(|timing| timing.driver_detail)
                .map(|timing| timing.force_kill_wait.as_secs_f64() * 1000.0),
            stop_state_cleanup_ms: self
                .stop_timing
                .and_then(|timing| timing.driver_detail)
                .map(|timing| timing.state_cleanup.as_secs_f64() * 1000.0),
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

/// Whether one warm-claim dispatch window satisfies the strict hard ceiling.
///
/// This is the shared contract for the CLI timing report and live conformance
/// witnesses. Keeping the comparison beside the constant prevents a scenario
/// from substituting the prepared-cold 200ms target for the warm-claim limit.
pub fn within_warm_start_slo_ms(dispatch_window_ms: f64) -> bool {
    dispatch_window_ms < WARM_START_MAX_MS
}

/// Which span contains which, as `(span, parent)`.
///
/// Parents named here are either another sub-span or one of the coarse bucket
/// labels [`RunPhaseTimings::coarse_rows`] emits. This table is the single
/// place the report's shape is stated, and it is asserted against the spans
/// themselves by `every_parent_covers_its_children` — a row placed under the
/// wrong parent renders a plausible, wrong partition, and the arithmetic is
/// the only thing that catches it.
///
/// The non-obvious entries: `artifact_verify` is recorded while drives are
/// being prepared, not during admission; and `stop_driver_kill` and
/// `stop_console_cleanup` are siblings under `stop_transient`, not nested —
/// stopping the console happens after the driver is killed, not inside it.
const SPAN_PARENTS: &[(&str, &str)] = &[
    ("mount_fingerprint", "drives"),
    ("mount_cache_lookup", "drives"),
    ("mount_materialize", "drives"),
    ("artifact_verify", "drives"),
    ("vmm_create", "backend start"),
    ("guest_kernel_entry", "guest ready"),
    ("agent_auth", "guest ready"),
    ("first_dispatch", "command"),
    ("cleanup_handoff", "teardown"),
    ("stop_transient", "cleanup_handoff"),
    ("pool_replenish", "cleanup_handoff"),
    ("state_remove", "cleanup_handoff"),
    ("stop_attach", "stop_transient"),
    ("stop_endpoint_reaping", "stop_transient"),
    ("stop_driver_kill", "stop_transient"),
    ("stop_console_cleanup", "stop_transient"),
    ("stop_supervisor_signal", "stop_driver_kill"),
    ("stop_pid_disappearance", "stop_driver_kill"),
    ("stop_force_kill_wait", "stop_driver_kill"),
    ("stop_state_cleanup", "stop_driver_kill"),
];

/// One rendered row, before the label column has been sized.
struct TreeRow {
    /// Indent already applied, so sizing is one `max` over these.
    label: String,
    ms: f64,
    share: Option<f64>,
}

/// One coarse bucket, with its share of the launch.
struct CoarseRow {
    label: &'static str,
    ms: f64,
    share: f64,
}

impl CoarseRow {
    fn new(label: &'static str, ms: f64, total_ms: f64) -> Self {
        let share = if total_ms > 0.0 {
            ms / total_ms * 100.0
        } else {
            0.0
        };
        Self { label, ms, share }
    }
}

/// Size the label column to the widest row, then emit.
///
/// Two passes rather than a fixed column because the deepest labels
/// (`stop supervisor signal` at four levels of indent) are more than twice the
/// width of the shallowest, and any constant wide enough for them wastes a
/// screen of space on every other row.
fn render_rows(rows: &[TreeRow]) -> String {
    let width = rows.iter().map(|r| r.label.len()).max().unwrap_or(0);
    rows.iter()
        .map(|row| {
            let value = format!("{:.1}ms", row.ms);
            let mut line = format!("{:<width$}  {:>9}", row.label, value);
            if let Some(share) = row.share {
                line.push_str(&format!("  {share:>3.0}%"));
            }
            line.trim_end().to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Append every recorded descendant of `parent`, depth-first, in the order
/// [`LaunchSubTimings::recorded`] declares them.
fn push_children(
    rows: &mut Vec<TreeRow>,
    parent: &str,
    depth: usize,
    recorded: &[(&'static str, f64)],
) {
    for (name, ms) in recorded {
        if SPAN_PARENTS
            .iter()
            .any(|(span, span_parent)| span == name && *span_parent == parent)
        {
            rows.push(TreeRow {
                label: format!("{}{}", "  ".repeat(depth), name.replace('_', " ")),
                ms: *ms,
                share: None,
            });
            push_children(rows, name, depth + 1, recorded);
        }
    }
}

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
        within_warm_start_slo_ms(self.dispatch_window_ms())
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

    /// Render the launch as a nested, aligned report.
    ///
    /// Same spans as [`render`](Self::render); only the shape differs. The
    /// nesting is the containment the flat line hides — `teardown` holds
    /// `cleanup_handoff` holds `stop_transient`, and reading four sibling
    /// `stop_*` tokens off one line gives no way to tell which of them add up.
    #[must_use]
    pub fn render_tree(&self, sub: &LaunchSubTimings) -> String {
        let mut out = format!(
            "[mvm] launch {} — total {:.1}ms, dispatch window {:.1}ms{}",
            self.launch_mode.as_str(),
            self.total_ms,
            self.dispatch_window_ms(),
            self.budget_context(),
        );
        let recorded = sub.recorded();
        let mut rows = Vec::new();
        for bucket in self.coarse_rows() {
            rows.push(TreeRow {
                label: format!("  {}", bucket.label),
                ms: bucket.ms,
                share: Some(bucket.share),
            });
            push_children(&mut rows, bucket.label, 2, &recorded);
        }
        out.push('\n');
        out.push_str(&render_rows(&rows));
        out
    }

    /// The budget the launch's lane publishes, as context only.
    ///
    /// Deliberately renders no pass/fail. The published number is a p50 over at
    /// least [`MIN_MATRIX_SAMPLES`] samples, and one launch is one sample — a
    /// per-run "ok" against a percentile is the exact conflation
    /// `bench::doc_table` warns about, and it would read as a gate that nothing
    /// is actually gating here.
    fn budget_context(&self) -> String {
        let (lane, budget) = match self.launch_mode {
            LaunchMode::Warm => (
                "warm-claim",
                crate::bench::cold_launch::WARM_CLAIM_P50_BUDGET_MS,
            ),
            LaunchMode::Cold => (
                "prepared-cold",
                crate::bench::cold_launch::PREPARED_COLD_P50_BUDGET_MS,
            ),
        };
        format!(" ({lane} p50 budget {budget:.0}ms across {MIN_MATRIX_SAMPLES} samples)")
    }

    /// The coarse buckets in runner order, with the warm-only pair dropped on a
    /// cold launch where they are structurally zero rather than measured.
    fn coarse_rows(&self) -> Vec<CoarseRow> {
        let mut rows = vec![
            CoarseRow::new("resolve", self.resolve_ms, self.total_ms),
            CoarseRow::new("drives", self.drives_ms, self.total_ms),
            CoarseRow::new("admit", self.admit_ms, self.total_ms),
        ];
        if self.launch_mode == LaunchMode::Warm {
            rows.push(CoarseRow::new(
                "pool wait",
                self.pool_wait_ms,
                self.total_ms,
            ));
            rows.push(CoarseRow::new("claim", self.claim_ms, self.total_ms));
        }
        rows.extend([
            CoarseRow::new("backend start", self.backend_start_ms, self.total_ms),
            CoarseRow::new("guest ready", self.vsock_wait_ms, self.total_ms),
            CoarseRow::new("command", self.command_ms, self.total_ms),
            CoarseRow::new("teardown", self.teardown_ms, self.total_ms),
        ]);
        rows
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
        clears_slo: within_warm_start_slo_ms(warm.dispatch_window_ms()),
        clears_p50_target: warm_hot_ms <= WARM_START_P50_BUDGET_MS,
        speedup,
    }
}

/// Read `MVM_PHASE_TIMING` and decide how to render a breakdown.
///
/// Delegates to `mvm_core::launch_trace`, which owns the variable's name and
/// its accepted spellings. A second parse here drifted from that one once
/// already — this module hardcoded the variable name rather than using the
/// constant beside the parse it was duplicating.
pub fn mode() -> PhaseTimingMode {
    mvm_core::launch_trace::phase_timing_mode()
}

/// Whether phase timing should emit anything at all.
pub fn enabled() -> bool {
    mode().is_on()
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
    fn standalone_warm_ceiling_check_is_strict() {
        assert!(within_warm_start_slo_ms(WARM_START_MAX_MS - 0.1));
        assert!(!within_warm_start_slo_ms(WARM_START_MAX_MS));
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

    #[test]
    fn report_renders_as_a_table_and_roundtrips_as_json() {
        let phases = RunPhaseTimings {
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
        let report =
            RunPhaseTimingReport::new(phases, LaunchSubTimings::default(), Vec::new(), Vec::new());
        let table = report.render_table();
        assert!(table.contains("phase timing (warm)"));
        assert!(table.contains("backend start"));
        assert!(table.contains("total"));
        assert!(!table.contains("phase-timing:"));

        let json = serde_json::to_string(&report).expect("serialize timing report");
        let decoded: RunPhaseTimingReport =
            serde_json::from_str(&json).expect("deserialize timing report");
        assert_eq!(decoded, report);
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
    fn backend_stop_timing_is_projected_into_launch_sub_phases() {
        let mut marks = LaunchSubMarks::new(true);
        marks.record_stop_timing(Some(StopTiming {
            attach: Duration::from_millis(1),
            endpoint_reaping: Duration::from_millis(2),
            driver_kill: Duration::from_millis(3),
            console_cleanup: Duration::from_millis(4),
            total: Duration::from_millis(10),
            driver_detail: Some(mvm_vmm::driver::RunningVmStopTiming {
                supervisor_signal: Duration::from_millis(5),
                pid_disappearance: Duration::from_millis(6),
                force_kill_wait: Duration::from_millis(7),
                state_cleanup: Duration::from_millis(8),
            }),
        }));

        let timings = marks.to_timings();
        assert_eq!(timings.stop_attach_ms, Some(1.0));
        assert_eq!(timings.stop_endpoint_reaping_ms, Some(2.0));
        assert_eq!(timings.stop_driver_kill_ms, Some(3.0));
        assert_eq!(timings.stop_console_cleanup_ms, Some(4.0));
        assert_eq!(timings.stop_supervisor_signal_ms, Some(5.0));
        assert_eq!(timings.stop_pid_disappearance_ms, Some(6.0));
        assert_eq!(timings.stop_force_kill_wait_ms, Some(7.0));
        assert_eq!(timings.stop_state_cleanup_ms, Some(8.0));
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
        use mvm_core::launch_trace::phase_timing_mode_from as parse;
        assert!(parse(Some("1")).is_on());
        assert!(parse(Some("true")).is_on());
        assert!(parse(Some("TRUE")).is_on());
        assert!(parse(Some("tree")).is_on());
        assert!(!parse(Some("0")).is_on());
        assert!(!parse(Some("")).is_on());
        assert!(!parse(Some("yes")).is_on());
        assert!(!parse(None).is_on());
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

    /// The launch from the report that prompted the tree renderer: a real
    /// `machine run --image alpine` on HVF/macOS. Using observed numbers rather
    /// than invented ones means the containment assertions below are checked
    /// against a partition a real launch actually produced.
    fn observed_launch() -> (RunPhaseTimings, LaunchSubTimings) {
        let phases = RunPhaseTimings {
            launch_mode: LaunchMode::Cold,
            resolve_ms: 8.7,
            drives_ms: 13.4,
            admit_ms: 47.4,
            pool_wait_ms: 0.0,
            claim_ms: 0.0,
            backend_start_ms: 16.1,
            vsock_wait_ms: 58.2,
            warm_window_ms: 74.3,
            command_ms: 52.0,
            teardown_ms: 91.4,
            total_ms: 287.2,
        };
        let sub = LaunchSubTimings {
            artifact_verify_ms: Some(0.2),
            vmm_create_ms: Some(12.0),
            guest_kernel_entry_ms: Some(57.1),
            agent_auth_ms: Some(1.1),
            first_dispatch_ms: Some(0.0),
            cleanup_handoff_ms: Some(91.3),
            stop_transient_ms: Some(90.7),
            stop_attach_ms: Some(0.0),
            stop_endpoint_reaping_ms: Some(0.0),
            stop_driver_kill_ms: Some(33.7),
            stop_console_cleanup_ms: Some(57.0),
            stop_supervisor_signal_ms: Some(0.0),
            stop_pid_disappearance_ms: Some(33.7),
            stop_force_kill_wait_ms: Some(0.0),
            stop_state_cleanup_ms: Some(0.0),
            state_remove_ms: Some(0.5),
            ..LaunchSubTimings::default()
        };
        (phases, sub)
    }

    #[test]
    fn every_parent_covers_its_children() {
        let (phases, sub) = observed_launch();
        let mut by_name: std::collections::HashMap<&str, f64> = phases
            .coarse_rows()
            .into_iter()
            .map(|row| (row.label, row.ms))
            .collect();
        by_name.extend(sub.recorded());

        for (parent, _) in SPAN_PARENTS
            .iter()
            .map(|(_, p)| (*p, ()))
            .collect::<std::collections::BTreeSet<_>>()
        {
            let Some(parent_ms) = by_name.get(parent).copied() else {
                continue;
            };
            let children: f64 = SPAN_PARENTS
                .iter()
                .filter(|(_, p)| *p == parent)
                .filter_map(|(span, _)| by_name.get(span).copied())
                .sum();
            assert!(
                parent_ms + 0.05 >= children,
                "{parent} is {parent_ms}ms but its declared children sum to {children}ms — \
                 the containment table places a span under a parent that does not contain it",
            );
        }
    }

    #[test]
    fn every_table_entry_names_a_span_that_can_be_rendered() {
        // A typo in the table is silent: the row simply never matches a
        // recorded span and vanishes from the report, which reads as "that
        // work did not happen" rather than as a broken table.
        let (phases, sub) = observed_launch();
        let sub_names: Vec<&str> = LaunchSubTimings {
            mount_fingerprint_ms: Some(0.0),
            mount_cache_lookup_ms: Some(0.0),
            mount_materialize_ms: Some(0.0),
            pool_replenish_ms: Some(0.0),
            ..sub
        }
        .recorded()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
        let coarse: Vec<&str> = phases.coarse_rows().into_iter().map(|r| r.label).collect();

        for (span, parent) in SPAN_PARENTS {
            assert!(sub_names.contains(span), "table names unknown span {span}");
            assert!(
                sub_names.contains(parent) || coarse.contains(parent),
                "span {span} is parented to unknown {parent}",
            );
        }
    }

    #[test]
    fn every_recorded_span_has_a_place_in_the_tree() {
        // The converse gap: a span added to LaunchSubTimings but not to the
        // table is measured, serialized into the JSON sample, and silently
        // missing from the human report.
        let all = LaunchSubTimings {
            mount_fingerprint_ms: Some(1.0),
            mount_cache_lookup_ms: Some(1.0),
            mount_materialize_ms: Some(1.0),
            pool_replenish_ms: Some(1.0),
            ..observed_launch().1
        };
        for (name, _) in all.recorded() {
            assert!(
                SPAN_PARENTS.iter().any(|(span, _)| *span == name),
                "recorded span {name} has no parent declared, so the tree drops it",
            );
        }
    }

    #[test]
    fn tree_renders_the_observed_launch() {
        let (phases, sub) = observed_launch();
        let expected = [
            "[mvm] launch cold — total 287.2ms, dispatch window 74.3ms (prepared-cold p50 budget 200ms across 20 samples)",
            "  resolve                             8.7ms    3%",
            "  drives                             13.4ms    5%",
            "    artifact verify                   0.2ms",
            "  admit                              47.4ms   17%",
            "  backend start                      16.1ms    6%",
            "    vmm create                       12.0ms",
            "  guest ready                        58.2ms   20%",
            "    guest kernel entry               57.1ms",
            "    agent auth                        1.1ms",
            "  command                            52.0ms   18%",
            "    first dispatch                    0.0ms",
            "  teardown                           91.4ms   32%",
            "    cleanup handoff                  91.3ms",
            "      stop transient                 90.7ms",
            "        stop attach                   0.0ms",
            "        stop endpoint reaping         0.0ms",
            "        stop driver kill             33.7ms",
            "          stop supervisor signal      0.0ms",
            "          stop pid disappearance     33.7ms",
            "          stop force kill wait        0.0ms",
            "          stop state cleanup          0.0ms",
            "        stop console cleanup         57.0ms",
            "      state remove                    0.5ms",
        ]
        .join("\n");
        assert_eq!(phases.render_tree(&sub), expected);

        // The coarse buckets partition the launch: they must add up to the
        // total, or the report is attributing time to nothing.
        let coarse: f64 = phases.coarse_rows().into_iter().map(|r| r.ms).sum();
        assert!(
            (coarse - phases.total_ms).abs() < 0.05,
            "coarse buckets sum to {coarse}ms against a {}ms total",
            phases.total_ms,
        );
    }

    #[test]
    fn tree_hides_the_warm_only_rows_on_a_cold_launch() {
        let (phases, sub) = observed_launch();
        let cold = phases.render_tree(&sub);
        assert!(
            !cold.contains("pool wait"),
            "cold launch shows a warm-only row"
        );
        assert!(
            !cold.contains("\n  claim"),
            "cold launch shows a warm-only row"
        );

        let warm = RunPhaseTimings {
            launch_mode: LaunchMode::Warm,
            pool_wait_ms: 2.0,
            claim_ms: 4.1,
            ..phases
        }
        .render_tree(&sub);
        assert!(warm.contains("pool wait"));
        assert!(warm.contains("claim"));
    }

    #[test]
    fn tree_reports_the_budget_as_context_and_never_as_a_verdict() {
        // One launch is one sample; the published budget is a p50 over 20.
        // Rendering a pass/fail here would read as a gate nothing is applying.
        let (phases, sub) = observed_launch();
        let out = phases.render_tree(&sub);
        assert!(out.contains("p50 budget 200ms across 20 samples"));
        for verdict in ["ok", "over", "pass", "fail", "PASS", "FAIL", "✓", "✗"] {
            assert!(
                !out.contains(verdict),
                "tree renders a verdict token {verdict}"
            );
        }
    }

    #[test]
    fn tree_omits_spans_that_were_never_measured() {
        let (phases, _) = observed_launch();
        let out = phases.render_tree(&LaunchSubTimings::default());
        assert!(!out.contains("vmm create"));
        assert!(!out.contains("stop transient"));
        // The coarse partition still prints in full — an unmeasured sub-span
        // is absent, but a bucket that ran is never silently dropped.
        for bucket in [
            "resolve",
            "drives",
            "admit",
            "backend start",
            "guest ready",
            "command",
            "teardown",
        ] {
            assert!(out.contains(bucket), "coarse bucket {bucket} vanished");
        }
    }

    #[test]
    fn the_greppable_line_is_unchanged_by_the_tree_renderer() {
        // scripts/check-hvf-warm-restore.sh parses this line; the tree is an
        // addition, never a replacement.
        let (phases, _) = observed_launch();
        assert!(
            phases
                .render()
                .starts_with("[mvm] phase-timing: resolve=8.7ms")
        );
        assert!(
            phases
                .render()
                .ends_with("launch_mode=cold dispatch_window=74.3ms warm_slo=na")
        );
    }
}
