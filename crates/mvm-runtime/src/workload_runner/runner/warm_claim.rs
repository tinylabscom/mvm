use std::time::Instant;

pub(super) fn record_phase(
    claim_started: Instant,
    claim_debug: &mut Option<std::fs::File>,
    phase: &'static str,
) {
    let elapsed_us = claim_started.elapsed().as_micros();
    tracing::debug!(
        target: "mvm_runtime::warm_claim",
        phase,
        elapsed_us,
        "warm claim phase"
    );
    if let Some(file) = claim_debug.as_mut() {
        use std::io::Write;

        let _ = writeln!(file, "[warm-claim] phase={phase} elapsed_us={elapsed_us}");
    }
}
