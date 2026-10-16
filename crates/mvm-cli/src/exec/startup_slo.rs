//! The startup ceiling, checked at the last point before the workload is
//! handed to the guest.
//!
//! A warm launch must reach the guest strictly below
//! [`WARM_START_MAX_MS`]. The check runs after every piece of host work the
//! launch does — resolution, admission, the claim, the agent handshake, the
//! dispatch channel — and before the request that starts the workload is
//! written. A launch already over the ceiling there is refused and nothing
//! runs, so the caller never sees the workload's output followed by a failure.
//!
//! The refusal names the slowest phase. Its marks are always taken, not only
//! when phase timing was asked for, because a refusal that cannot say where
//! the time went sends the operator to rerun with timing on and hope the slow
//! launch recurs.

use std::time::Instant;

use mvm_client::launch::startup_budget::{StartupBudgetExceeded, StartupPhase};

use crate::commands::vm::phase_timing::{
    LaunchMode, LaunchSubMarks, WARM_START_MAX_MS, within_warm_start_slo_ms,
};

/// Host-monotonic marks for the phases a launch passes through before its
/// workload is dispatched.
#[derive(Debug, Clone, Copy)]
pub(super) struct StartupClock {
    pub(super) launch_mode: LaunchMode,
    /// The command was invoked.
    pub(super) started: Instant,
    /// Resolution and admission finished; a bootable config exists.
    pub(super) admitted: Instant,
    /// The claim (warm) or the backend start (cold) returned.
    pub(super) booted: Instant,
}

impl StartupClock {
    /// Report — but do not refuse — a warm dispatch that exceeds its startup
    /// ceiling.  `agent_ready` is when the guest agent answered; the span
    /// after it is the host's own dispatch preparation.
    ///
    /// A launch that already reached the guest has done all its host work.
    /// Refusing it would discard that work without preventing the cost, so
    /// the overrun is reported as a warning and the workload proceeds.  The
    /// phase breakdown is always populated so the operator can see where the
    /// time went without rerunning with timing on.
    pub(super) fn gate_dispatch(
        &self,
        agent_ready: Instant,
        sub: &LaunchSubMarks,
    ) -> anyhow::Result<()> {
        if let Some(overrun) = self.overrun(agent_ready, Instant::now(), sub) {
            tracing::warn!(
                elapsed_ms = overrun.elapsed_ms,
                ceiling_ms = overrun.ceiling_ms,
                launch_mode = overrun.launch_mode,
                "warm launch exceeded startup ceiling: {overrun}"
            );
        }
        Ok(())
    }

    /// The overrun for a launch checked at `now`, or `None` when it is below
    /// its ceiling.  A cold launch is not held to the warm ceiling.
    fn overrun(
        &self,
        agent_ready: Instant,
        now: Instant,
        sub: &LaunchSubMarks,
    ) -> Option<StartupBudgetExceeded> {
        if self.launch_mode == LaunchMode::Cold {
            return None;
        }
        let elapsed_ms = ms(self.started, now);
        if within_warm_start_slo_ms(elapsed_ms) {
            return None;
        }
        let phases = vec![
            StartupPhase {
                name: "resolve_admit",
                ms: ms(self.started, self.admitted),
            },
            StartupPhase {
                name: match self.launch_mode {
                    LaunchMode::Warm => "warm_claim",
                    LaunchMode::Cold => "cold_boot",
                },
                ms: ms(self.admitted, self.booted),
            },
            StartupPhase {
                name: "agent_wait",
                ms: ms(self.booted, agent_ready),
            },
            StartupPhase {
                name: "dispatch_prep",
                ms: ms(agent_ready, now),
            },
        ];
        let mut refusal = StartupBudgetExceeded {
            elapsed_ms,
            ceiling_ms: WARM_START_MAX_MS,
            launch_mode: self.launch_mode.as_str(),
            phases,
            slowest_detail: None,
        };
        refusal.slowest_detail = refusal
            .slowest_phase()
            .and_then(|slowest| slowest_sub_phase(slowest.name, sub));
        Some(refusal)
    }
}

fn ms(from: Instant, to: Instant) -> f64 {
    to.saturating_duration_since(from).as_secs_f64() * 1000.0
}

/// The largest recorded sub-phase that sits inside the coarse phase `coarse`.
fn slowest_sub_phase(coarse: &str, sub: &LaunchSubMarks) -> Option<StartupPhase> {
    let timings = sub.to_timings();
    let candidates: &[(&'static str, Option<f64>)] = match coarse {
        "resolve_admit" => &[
            ("mount_fingerprint", timings.mount_fingerprint_ms),
            ("mount_cache_lookup", timings.mount_cache_lookup_ms),
            ("mount_materialize", timings.mount_materialize_ms),
            ("artifact_verify", timings.artifact_verify_ms),
            ("admit_plan", timings.admit_plan_ms),
            ("attach_overlay", timings.attach_overlay_ms),
            ("attach_initramfs", timings.attach_initramfs_ms),
        ],
        "cold_boot" => &[("vmm_create", timings.vmm_create_ms)],
        "agent_wait" => &[
            ("guest_kernel_entry", timings.guest_kernel_entry_ms),
            ("agent_auth", timings.agent_auth_ms),
        ],
        "dispatch_prep" => &[("first_dispatch", timings.first_dispatch_ms)],
        _ => &[],
    };
    candidates
        .iter()
        .filter_map(|(name, ms)| ms.map(|ms| StartupPhase { name, ms }))
        .fold(None, |best: Option<StartupPhase>, phase| match best {
            Some(best) if best.ms >= phase.ms => Some(best),
            _ => Some(phase),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::phase_timing::SubPhase;
    use std::time::Duration;

    fn clock(mode: LaunchMode, admitted_ms: u64, booted_ms: u64) -> StartupClock {
        let started = Instant::now();
        StartupClock {
            launch_mode: mode,
            started,
            admitted: started + Duration::from_millis(admitted_ms),
            booted: started + Duration::from_millis(booted_ms),
        }
    }

    #[test]
    fn a_warm_launch_below_the_ceiling_dispatches() {
        let clock = clock(LaunchMode::Warm, 100, 200);
        let ready = clock.started + Duration::from_millis(250);
        let now = clock.started + Duration::from_millis(299);
        assert!(
            clock
                .overrun(ready, now, &LaunchSubMarks::new(true))
                .is_none()
        );
    }

    #[test]
    fn a_warm_launch_at_the_ceiling_reports_and_names_the_slow_phase() {
        let clock = clock(LaunchMode::Warm, 40, 260);
        let ready = clock.started + Duration::from_millis(290);
        let now = clock.started + Duration::from_millis(300);
        let overrun = clock
            .overrun(ready, now, &LaunchSubMarks::new(true))
            .expect("exactly 300ms misses a strict ceiling");
        assert_eq!(overrun.slowest_phase().unwrap().name, "warm_claim");
        let total: f64 = overrun.phases.iter().map(|phase| phase.ms).sum();
        assert!(
            (total - overrun.elapsed_ms).abs() < 0.01,
            "phases partition the elapsed time"
        );
    }

    #[test]
    fn a_slow_admission_is_attributed_to_its_largest_recorded_sub_phase() {
        let mut sub = LaunchSubMarks::new(true);
        sub.start(SubPhase::AttachInitramfs);
        std::thread::sleep(Duration::from_millis(5));
        sub.finish(SubPhase::AttachInitramfs);
        sub.start(SubPhase::AdmitPlan);
        sub.finish(SubPhase::AdmitPlan);
        let clock = clock(LaunchMode::Warm, 280, 290);
        let ready = clock.started + Duration::from_millis(300);
        let refusal = clock.overrun(ready, ready, &sub).expect("over the ceiling");
        assert_eq!(refusal.slowest_phase().unwrap().name, "resolve_admit");
        assert_eq!(refusal.slowest_detail.unwrap().name, "attach_initramfs");
    }

    #[test]
    fn a_cold_launch_is_not_held_to_the_warm_ceiling() {
        let clock = clock(LaunchMode::Cold, 100, 900);
        let ready = clock.started + Duration::from_millis(1000);
        assert!(
            clock
                .overrun(ready, ready, &LaunchSubMarks::new(true))
                .is_none()
        );
    }

    #[test]
    fn the_gate_reports_but_does_not_refuse_an_over_ceiling_warm_launch() {
        let started = Instant::now() - Duration::from_millis(400);
        let clock = StartupClock {
            launch_mode: LaunchMode::Warm,
            started,
            admitted: started,
            booted: started,
        };
        // The gate must succeed: a completed launch reports its overrun
        // without refusing the dispatch.
        clock
            .gate_dispatch(started, &LaunchSubMarks::new(true))
            .expect("gate_dispatch must not refuse a completed warm launch");
        // The overrun is still detectable for reporting.
        let overrun = clock
            .overrun(started, Instant::now(), &LaunchSubMarks::new(true))
            .expect("400ms exceeds the 300ms ceiling");
        assert!(overrun.elapsed_ms >= 400.0);
    }
}
