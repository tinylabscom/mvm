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

/// Sample counts for one interaction measurement.
#[cfg(feature = "libkrun-live")]
#[derive(Debug, Clone, Copy)]
pub struct InteractionRunCfg {
    /// Fresh dial+handshake+Ping sessions (cold RPC); median reported.
    pub cold_samples: u32,
    /// Warm Pings discarded before measuring, to settle the held session.
    pub warmup: u32,
    /// Measured warm Pings over the held session.
    pub samples: u32,
}

#[cfg(feature = "libkrun-live")]
impl Default for InteractionRunCfg {
    fn default() -> Self {
        Self {
            cold_samples: 10,
            warmup: 20,
            samples: 200,
        }
    }
}

/// Open a fresh authenticated session, issue one Ping, and confirm Pong.
/// Used both as the cold-RPC sample and to seed the warm loop.
#[cfg(feature = "libkrun-live")]
fn ping_once_cold(vm_name: &str) -> anyhow::Result<f64> {
    use std::time::Instant;

    use mvm_agentd::vsock::{ControlSession, GUEST_AGENT_PORT, GuestRequest, GuestResponse};

    let t = Instant::now();
    // Mirror the backend-agnostic dial used by `mvmctl fs`/`proc`/`diff`:
    // `mvm_runtime::vsock_transport::for_vm(name)?.connect(GUEST_AGENT_PORT)?`.
    let mut stream = mvm_runtime::vsock_transport::for_vm(vm_name)?.connect(GUEST_AGENT_PORT)?;
    let mut session = ControlSession::open(&mut stream)?;
    let resp = session.call_unary(&mut stream, &GuestRequest::Ping)?;
    anyhow::ensure!(
        matches!(resp, GuestResponse::Pong),
        "cold ping: expected Pong"
    );
    Ok(t.elapsed().as_secs_f64() * 1000.0)
}

/// Measure cold and warm interaction RTT against an already-booted VM.
#[cfg(feature = "libkrun-live")]
pub fn measure_interaction(
    vm_name: &str,
    cfg: &InteractionRunCfg,
) -> anyhow::Result<InteractionTimings> {
    use std::time::Instant;

    use mvm_agentd::vsock::{ControlSession, GUEST_AGENT_PORT, GuestRequest, GuestResponse};

    let mut cold = Vec::with_capacity(cfg.cold_samples as usize);
    for _ in 0..cfg.cold_samples {
        cold.push(ping_once_cold(vm_name)?);
    }

    // Warm: one held session, timer around each call_unary write→read.
    let mut stream = mvm_runtime::vsock_transport::for_vm(vm_name)?.connect(GUEST_AGENT_PORT)?;
    let mut session = ControlSession::open(&mut stream)?;
    for _ in 0..cfg.warmup {
        let _ = session.call_unary(&mut stream, &GuestRequest::Ping)?;
    }
    let mut warm = Vec::with_capacity(cfg.samples as usize);
    for _ in 0..cfg.samples {
        let t = Instant::now();
        let resp = session.call_unary(&mut stream, &GuestRequest::Ping)?;
        anyhow::ensure!(
            matches!(resp, GuestResponse::Pong),
            "warm ping: expected Pong"
        );
        warm.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    Ok(InteractionTimings {
        cold_rtt_ms: cold,
        warm_rtt_ms: warm,
    })
}

/// Boot one VM, capture its cold-boot start timing, measure interaction RTT,
/// tear it down, and assemble the report.
#[cfg(feature = "libkrun-live")]
pub fn run_instant_loop(
    vm_name: &str,
    cfg: &InteractionRunCfg,
    budget_ms: f64,
) -> anyhow::Result<InstantLoopReport> {
    use crate::bench::harness::LaunchProbe;
    use crate::bench::probes::LibkrunProbe;

    let host = LibkrunProbe::new_with_prefix(format!("{vm_name}-host"))?.host_descriptor();
    let held = crate::bench::probe::boot_hold_once(vm_name)?;
    let start_boot = held.marks().to_timing();
    let timings = measure_interaction(vm_name, cfg)?;
    drop(held); // RAII teardown
    Ok(build_instant_loop_report(
        host, start_boot, &timings, budget_ms,
    ))
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
