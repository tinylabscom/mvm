//! Timing + statistics (pure).

use serde::{Deserialize, Serialize};

/// Report schema version. Bump on any breaking change to
/// [`super::BenchReport`]; a baseline with a different version is refused as
/// incomparable rather than mis-compared.
pub const BENCH_SCHEMA_VERSION: u32 = 1;

/// One iteration's per-phase host wall-clock timing, milliseconds.
///
/// All four fields are host-clock spans. Guest-monotonic milestones
/// (first-accept / entrypoint-ready, read from the guest's
/// `BootTimingReport`) are intentionally NOT folded in here — mixing
/// clock domains would double-count. `total_ready_ms` is the headline:
/// host wall-clock from `start()` entry to the control plane reporting
/// `Ready`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct IterationTiming {
    pub start_to_pid_ms: f64,
    pub pid_to_connect_ms: f64,
    pub handshake_ms: f64,
    pub total_ready_ms: f64,
}

/// Four host-monotonic instants captured during one boot. `start` is
/// `LibkrunBackend::start` entry; `pid_seen` is when the supervisor
/// PID file first appears; `connected` is the first successful vsock
/// connect to the guest agent; `ready` is when the guest reports the
/// control plane Ready.
// Live probe wiring will construct BootMarks from the real instants
// captured during the boot sequence.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct BootMarks {
    pub start: std::time::Instant,
    pub pid_seen: std::time::Instant,
    pub connected: std::time::Instant,
    pub ready: std::time::Instant,
}

impl BootMarks {
    /// Collapse the marks into the four reported spans. All arithmetic
    /// is `Instant`-difference so it can never go negative for marks
    /// captured in order. Takes `self` by value (`BootMarks` is `Copy`).
    // Live probe wiring is the first non-test caller.
    #[allow(dead_code)]
    pub fn to_timing(self) -> IterationTiming {
        let ms = |a: std::time::Instant, b: std::time::Instant| {
            b.saturating_duration_since(a).as_secs_f64() * 1000.0
        };
        IterationTiming {
            start_to_pid_ms: ms(self.start, self.pid_seen),
            pid_to_connect_ms: ms(self.pid_seen, self.connected),
            handshake_ms: ms(self.connected, self.ready),
            total_ready_ms: ms(self.start, self.ready),
        }
    }
}

/// Summary statistics for one phase across all measured iterations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct PhaseStats {
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
}

/// Linear-interpolated percentile over an unsorted sample. `p` is in
/// `[0, 100]`. Returns `NaN` for an empty sample (callers summarise
/// only non-empty run sets).
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return f64::NAN;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * ((sorted.len() - 1) as f64);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] + (sorted[hi] - sorted[lo]) * frac
    }
}

/// Collapse a phase's samples into [`PhaseStats`]. Panics-free on
/// non-empty input; an empty input yields all-`NaN` (guarded upstream).
pub fn summarize(samples: &[f64]) -> PhaseStats {
    let n = samples.len();
    let mean = if n == 0 {
        f64::NAN
    } else {
        samples.iter().sum::<f64>() / n as f64
    };
    let stddev = if n < 2 {
        0.0
    } else {
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        var.sqrt()
    };
    PhaseStats {
        min: samples.iter().cloned().fold(f64::INFINITY, f64::min),
        p50: percentile(samples, 50.0),
        p90: percentile(samples, 90.0),
        p99: percentile(samples, 99.0),
        max: samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        mean,
        stddev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn percentile_linear_interpolation_on_known_vector() {
        let v = vec![10.0, 20.0, 30.0, 40.0]; // n=4
        approx(percentile(&v, 0.0), 10.0);
        approx(percentile(&v, 100.0), 40.0);
        // p50 = midpoint of the [0..3] index range = rank 1.5 → 25.
        approx(percentile(&v, 50.0), 25.0);
    }

    #[test]
    fn percentile_single_and_empty() {
        approx(percentile(&[7.0], 50.0), 7.0);
        assert!(percentile(&[], 50.0).is_nan());
    }

    #[test]
    fn summarize_known_vector() {
        let v = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let s = summarize(&v);
        approx(s.min, 2.0);
        approx(s.max, 9.0);
        approx(s.mean, 5.0);
        // Population stddev of this classic set is 2.0.
        approx(s.stddev, 2.0);
    }

    #[test]
    fn spans_from_marks_are_non_negative_and_ordered() {
        use std::time::Duration;
        let t0 = std::time::Instant::now();
        let marks = BootMarks {
            start: t0,
            pid_seen: t0 + Duration::from_millis(10),
            connected: t0 + Duration::from_millis(25),
            ready: t0 + Duration::from_millis(40),
        };
        let it = marks.to_timing();
        approx(it.start_to_pid_ms, 10.0);
        approx(it.pid_to_connect_ms, 15.0);
        approx(it.handshake_ms, 15.0);
        approx(it.total_ready_ms, 40.0);
        assert!(it.total_ready_ms >= it.start_to_pid_ms);
    }
}
