use anyhow::Result;

use crate::commands::vm::phase_timing::{LaunchMode, WARM_START_MAX_MS, within_warm_start_slo_ms};

pub(super) fn enforce_startup_slo(
    started: std::time::Instant,
    ready: std::time::Instant,
    launch_mode: LaunchMode,
) -> Result<()> {
    if launch_mode == LaunchMode::Cold {
        return Ok(());
    }
    let elapsed_ms = ready.saturating_duration_since(started).as_secs_f64() * 1000.0;
    anyhow::ensure!(
        within_warm_start_slo_ms(elapsed_ms),
        "startup took {elapsed_ms:.1}ms; successful launches must be strictly below \
         {WARM_START_MAX_MS}ms"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_contract_accepts_only_a_sub_300ms_warm_launch() {
        let started = std::time::Instant::now();
        assert!(
            enforce_startup_slo(
                started,
                started + std::time::Duration::from_millis(299),
                LaunchMode::Warm,
            )
            .is_ok()
        );
        assert!(
            enforce_startup_slo(
                started,
                started + std::time::Duration::from_millis(300),
                LaunchMode::Warm,
            )
            .is_err()
        );
        assert!(
            enforce_startup_slo(
                started,
                started + std::time::Duration::from_millis(1),
                LaunchMode::Cold,
            )
            .is_ok()
        );
    }
}
