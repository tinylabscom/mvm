//! Phase timing for one transient `machine run` / `mvmctl run`: where the
//! host wall-clock goes between the seams of a single cold run — image
//! resolve, drive materialization, plan admission, backend start, the guest
//! run, and teardown.
//!
//! Off by default. `MVM_PHASE_TIMING=1` makes the transient runner emit a
//! one-line breakdown to stderr. The mark→span collapse and the rendered
//! line are pure, so they are unit-tested without booting a VM — mirroring
//! the bench harness's `BootMarks`→`IterationTiming`.

use std::time::Instant;

/// Host-monotonic instants captured at the boundaries of one transient run.
/// Marks are taken in runner order; spans are `Instant` differences so they
/// can never go negative for in-order marks.
#[derive(Debug, Clone, Copy)]
pub struct RunPhaseMarks {
    /// Runner entry, before any artifact resolution.
    pub start: Instant,
    /// Kernel/rootfs artifacts resolved (template load or prebuilt pair).
    pub image_resolved: Instant,
    /// `--add-dir` images built and the verity sidecar probed.
    pub drives_ready: Instant,
    /// The transient workload's signed plan was admitted (or admission skipped).
    pub admitted: Instant,
    /// The backend reported the VM booted (cold start or snapshot restore).
    pub backend_started: Instant,
    /// The guest agent first became reachable over vsock — i.e. the command
    /// is about to be dispatched. The `backend_started`..`vsock_ready` span
    /// is the boot-to-ready wait; `start`..`vsock_ready` is the dispatch bar.
    pub vsock_ready: Instant,
    /// The guest command finished and its exit code was captured.
    pub command_done: Instant,
    /// The VM was stopped and transient staging was cleaned up.
    pub torn_down: Instant,
}

/// Per-phase host wall-clock spans, milliseconds. `total_ms` is the headline:
/// `start` to `torn_down`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RunPhaseTimings {
    pub resolve_ms: f64,
    pub drives_ms: f64,
    pub admit_ms: f64,
    pub backend_start_ms: f64,
    pub vsock_wait_ms: f64,
    pub command_ms: f64,
    pub teardown_ms: f64,
    pub total_ms: f64,
}

impl RunPhaseMarks {
    /// Collapse the marks into per-phase spans. Arithmetic is saturating
    /// `Instant` difference, so an out-of-order mark yields `0` rather than
    /// a negative span.
    pub fn to_timings(self) -> RunPhaseTimings {
        let ms = |a: Instant, b: Instant| b.saturating_duration_since(a).as_secs_f64() * 1000.0;
        RunPhaseTimings {
            resolve_ms: ms(self.start, self.image_resolved),
            drives_ms: ms(self.image_resolved, self.drives_ready),
            admit_ms: ms(self.drives_ready, self.admitted),
            backend_start_ms: ms(self.admitted, self.backend_started),
            vsock_wait_ms: ms(self.backend_started, self.vsock_ready),
            command_ms: ms(self.vsock_ready, self.command_done),
            teardown_ms: ms(self.command_done, self.torn_down),
            total_ms: ms(self.start, self.torn_down),
        }
    }
}

impl RunPhaseTimings {
    /// Admitted-plan to command-dispatch: the window the `<200 ms` dispatch
    /// latency bar is set against (backend boot + boot-to-agent wait).
    pub fn dispatch_window_ms(&self) -> f64 {
        self.backend_start_ms + self.vsock_wait_ms
    }

    /// A single stable, greppable line for logs and the benchmark harness.
    pub fn render(&self) -> String {
        format!(
            "[mvm] phase-timing: resolve={:.1}ms drives={:.1}ms admit={:.1}ms \
             backend_start={:.1}ms vsock_wait={:.1}ms command={:.1}ms \
             teardown={:.1}ms total={:.1}ms dispatch_window={:.1}ms",
            self.resolve_ms,
            self.drives_ms,
            self.admit_ms,
            self.backend_start_ms,
            self.vsock_wait_ms,
            self.command_ms,
            self.teardown_ms,
            self.total_ms,
            self.dispatch_window_ms(),
        )
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
            start: t0,
            image_resolved: t0 + Duration::from_millis(5),
            drives_ready: t0 + Duration::from_millis(12),
            admitted: t0 + Duration::from_millis(20),
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
        approx(t.backend_start_ms, 100.0);
        approx(t.vsock_wait_ms, 30.0);
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
        // The `<200 ms` dispatch latency bar is "backend start to command
        // dispatch": admitted -> backend booted -> guest agent reachable.
        let t = ordered_marks(Instant::now()).to_timings();
        approx(t.dispatch_window_ms(), 130.0);
    }

    #[test]
    fn out_of_order_mark_saturates_to_zero() {
        let t0 = Instant::now();
        let marks = RunPhaseMarks {
            start: t0,
            image_resolved: t0 + Duration::from_millis(5),
            drives_ready: t0 + Duration::from_millis(12),
            admitted: t0 + Duration::from_millis(20),
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
            resolve_ms: 5.0,
            drives_ms: 7.0,
            admit_ms: 8.0,
            backend_start_ms: 100.0,
            vsock_wait_ms: 30.0,
            command_ms: 10.0,
            teardown_ms: 15.0,
            total_ms: 175.0,
        };
        assert_eq!(
            t.render(),
            "[mvm] phase-timing: resolve=5.0ms drives=7.0ms admit=8.0ms backend_start=100.0ms vsock_wait=30.0ms command=10.0ms teardown=15.0ms total=175.0ms dispatch_window=130.0ms"
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
}
