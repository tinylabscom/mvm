//! Live interaction-latency gate. Boots one real VM, measures cold + warm Ping
//! RTT over vsock, and asserts the steady-interaction invariants. Runs only
//! under `libkrun-live` on a host where libkrun boots; excluded from stock
//! builds, so it never fabricates a number.

#![cfg(feature = "libkrun-live")]

use mvm_cli::bench::interaction::{InteractionRunCfg, WARM_RPC_P50_BUDGET_MS, run_instant_loop};
use mvm_cli::bench::write_report_with_latest;

#[test]
fn warm_interaction_beats_cold_and_records_verdict() {
    let cfg = InteractionRunCfg {
        cold_samples: 10,
        warmup: 20,
        samples: 200,
    };
    let report = run_instant_loop("mvm-instant-loop-gate", &cfg, WARM_RPC_P50_BUDGET_MS)
        .expect("instant-loop measurement");

    // Finite, non-empty stats.
    assert!(
        report.interaction_warm_rtt.p50.is_finite(),
        "warm p50 not finite"
    );
    assert!(
        report.interaction_cold_rtt_ms.is_finite(),
        "cold median not finite"
    );
    assert!(
        report.start_boot.total_ready_ms > 0.0,
        "boot never reached ready"
    );

    // The held session amortizes the handshake, so steady warm p50 must beat a
    // cold dial. This is the load-bearing invariant of the whole measurement.
    assert!(
        report.interaction_warm_rtt.p50 < report.interaction_cold_rtt_ms,
        "warm p50 {:.3}ms should be < cold median {:.3}ms",
        report.interaction_warm_rtt.p50,
        report.interaction_cold_rtt_ms,
    );

    // Record the numbers + soft verdict (not a hard failure until a committed
    // baseline ratchets the budget) and persist the JSON report artifact.
    eprintln!(
        "[instant-loop] start_ready={:.2}ms cold_median={:.3}ms warm_p50={:.3}ms \
         warm_p99={:.3}ms budget={:.1}ms within_budget={}",
        report.start_boot.total_ready_ms,
        report.interaction_cold_rtt_ms,
        report.interaction_warm_rtt.p50,
        report.interaction_warm_rtt.p99,
        report.interaction_verdict.budget_ms,
        report.interaction_verdict.within_budget,
    );
    let path = write_report_with_latest(&report, None, "instant-loop").expect("persist report");
    eprintln!("[instant-loop] report at {}", path.display());
}
