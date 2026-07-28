//! Interaction round-trip latency: cold RPC (fresh dial + handshake + one
//! Ping) vs warm RPC (N Pings over one held session). The steady warm p50 is
//! the number the "feels instant" budget is set against.

use serde::{Deserialize, Serialize};

use super::report::{HostDescriptor, TailLatencyStats, summarize_tail_latency};
use super::stats::{BENCH_SCHEMA_VERSION, IterationTiming, percentile};

/// Warm-RPC p50 budget (ms): a local vsock encrypted round-trip. A working
/// hypothesis pending the first clean baseline; the verdict is recorded, not
/// gating, until a committed baseline ratchets it down.
pub const WARM_RPC_P50_BUDGET_MS: f64 = 2.0;

/// Raw per-sample interaction round-trips, milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InteractionTimings {
    /// One fresh dial + handshake + Ping each; median is reported.
    pub cold_rtt_ms: Vec<f64>,
    /// Sequential Pings over one held session.
    pub warm_rtt_ms: Vec<f64>,
}

/// Warm p50 measured against the budget.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SloVerdict {
    pub warm_p50_ms: f64,
    pub budget_ms: f64,
    pub within_budget: bool,
}

/// Compare a warm-RPC tail against the budget (inclusive at the boundary).
pub fn interaction_verdict(warm: &TailLatencyStats, budget_ms: f64) -> SloVerdict {
    SloVerdict {
        warm_p50_ms: warm.p50,
        budget_ms,
        within_budget: warm.p50 <= budget_ms,
    }
}

/// One instant-loop measurement: a single cold boot's timing plus the cold and
/// warm interaction round-trips. Start is cold-boot only; a warm-start field is
/// intentionally absent until a warm-restore path exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantLoopReport {
    pub schema_version: u32,
    pub host: HostDescriptor,
    pub start_boot: IterationTiming,
    pub interaction_cold_rtt_ms: f64,
    pub interaction_warm_rtt: TailLatencyStats,
    pub interaction_verdict: SloVerdict,
}

/// Collapse raw interaction samples into the report, reusing the shared
/// percentile / tail-latency helpers.
pub fn build_instant_loop_report(
    host: HostDescriptor,
    start_boot: IterationTiming,
    timings: &InteractionTimings,
    budget_ms: f64,
) -> InstantLoopReport {
    let warm = summarize_tail_latency(&timings.warm_rtt_ms);
    InstantLoopReport {
        schema_version: BENCH_SCHEMA_VERSION,
        host,
        start_boot,
        interaction_cold_rtt_ms: percentile(&timings.cold_rtt_ms, 50.0),
        interaction_warm_rtt: warm,
        interaction_verdict: interaction_verdict(&warm, budget_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::report::HostDescriptor;
    use crate::bench::stats::IterationTiming;

    fn host() -> HostDescriptor {
        HostDescriptor {
            os: "macos".into(),
            arch: "aarch64".into(),
            hypervisor: "libkrun".into(),
            libkrun_version: Some("1.0".into()),
            kernel_sha256: Some("deadbeef".into()),
            cmdline: Some("root=/dev/vda rw init=/init".into()),
            readiness_boundary: Some("guest-agent-ping".into()),
        }
    }

    fn boot() -> IterationTiming {
        IterationTiming {
            start_to_pid_ms: 5.0,
            pid_to_connect_ms: 3.0,
            handshake_ms: 2.0,
            total_ready_ms: 40.0,
        }
    }

    #[test]
    fn report_aggregates_cold_median_and_warm_tail() {
        let timings = InteractionTimings {
            cold_rtt_ms: vec![4.0, 6.0, 5.0], // median 5.0
            warm_rtt_ms: vec![1.0, 1.0, 2.0, 3.0, 4.0],
        };
        let report = build_instant_loop_report(host(), boot(), &timings, WARM_RPC_P50_BUDGET_MS);
        assert_eq!(report.interaction_cold_rtt_ms, 5.0);
        assert_eq!(report.interaction_warm_rtt.p50, 2.0);
        assert_eq!(report.start_boot.total_ready_ms, 40.0);
    }

    #[test]
    fn verdict_boundary_is_inclusive() {
        let at = TailLatencyStats {
            p50: 2.0,
            p95: 2.0,
            p99: 2.0,
        };
        assert!(interaction_verdict(&at, 2.0).within_budget); // == budget passes
        let over = TailLatencyStats {
            p50: 2.001,
            p95: 3.0,
            p99: 4.0,
        };
        assert!(!interaction_verdict(&over, 2.0).within_budget);
    }

    #[test]
    fn report_json_roundtrips() {
        let timings = InteractionTimings {
            cold_rtt_ms: vec![5.0],
            warm_rtt_ms: vec![1.0, 2.0],
        };
        let report = build_instant_loop_report(host(), boot(), &timings, 2.0);
        let json = serde_json::to_string(&report).unwrap();
        let back: InstantLoopReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.interaction_verdict, report.interaction_verdict);
        assert_eq!(back.interaction_cold_rtt_ms, report.interaction_cold_rtt_ms);
    }
}
