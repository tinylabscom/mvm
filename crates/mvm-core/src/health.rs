//! Host-observed liveness state for a persistent service: fold periodic probe
//! results into a health state and decide whether to restart. Pure logic — the
//! daemon supplies probe results, the clock, and the policy; this module owns no
//! I/O so it is exhaustively unit-testable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthAction {
    None,
    Restart,
    GiveUp,
}

#[derive(Debug, Clone)]
pub struct HealthPolicy {
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub retries: u32,
    pub start_period_secs: u32,
    pub backoff_base_secs: u64,
    pub backoff_cap_secs: u64,
    pub max_restart_attempts: u32,
}

#[derive(Debug, Clone)]
pub struct HealthTracker {
    pub state: HealthState,
    pub consecutive_failures: u32,
    pub started_at_unix: u64,
    pub last_healthy_at_unix: Option<u64>,
    pub restart_attempts: u32,
    pub next_restart_after_unix: Option<u64>,
}

impl HealthTracker {
    pub fn new(started_at_unix: u64) -> Self {
        Self {
            state: HealthState::Starting,
            consecutive_failures: 0,
            started_at_unix,
            last_healthy_at_unix: None,
            restart_attempts: 0,
            next_restart_after_unix: None,
        }
    }
}

/// Fold one probe result into the tracker and return what the daemon should do.
pub fn fold(
    tracker: &mut HealthTracker,
    result: ProbeResult,
    policy: &HealthPolicy,
    now_unix: u64,
) -> HealthAction {
    let in_start_period = now_unix < tracker.started_at_unix + u64::from(policy.start_period_secs);

    match result {
        ProbeResult::Pass => {
            tracker.state = HealthState::Healthy;
            tracker.consecutive_failures = 0;
            tracker.last_healthy_at_unix = Some(now_unix);
            // A sustained-healthy period resets the restart budget.
            tracker.restart_attempts = 0;
            tracker.next_restart_after_unix = None;
            HealthAction::None
        }
        ProbeResult::Fail => {
            if in_start_period {
                // Grace: failures during startup do not count and do not flip state.
                return HealthAction::None;
            }
            // Once already unhealthy, every further failed probe is another
            // chance to restart or give up — it doesn't need to re-earn the
            // Unhealthy transition by re-accumulating consecutive failures.
            if tracker.state == HealthState::Unhealthy {
                if tracker.restart_attempts >= policy.max_restart_attempts {
                    // Parked: drop any pending restart so a give-up never fires.
                    tracker.next_restart_after_unix = None;
                    return HealthAction::GiveUp;
                }
                tracker.restart_attempts = tracker.restart_attempts.saturating_add(1);
                let backoff = backoff_secs(tracker.restart_attempts, policy);
                tracker.next_restart_after_unix = Some(now_unix + backoff);
                tracker.consecutive_failures = 0;
                return HealthAction::Restart;
            }
            tracker.consecutive_failures = tracker.consecutive_failures.saturating_add(1);
            if tracker.consecutive_failures < policy.retries.max(1) {
                return HealthAction::None;
            }
            tracker.state = HealthState::Unhealthy;
            if tracker.restart_attempts >= policy.max_restart_attempts {
                tracker.next_restart_after_unix = None;
                return HealthAction::GiveUp;
            }
            tracker.restart_attempts = tracker.restart_attempts.saturating_add(1);
            let backoff = backoff_secs(tracker.restart_attempts, policy);
            tracker.next_restart_after_unix = Some(now_unix + backoff);
            tracker.consecutive_failures = 0;
            HealthAction::Restart
        }
    }
}

/// Exponential backoff for the Nth restart attempt (1-based), capped.
pub fn backoff_secs(attempt: u32, policy: &HealthPolicy) -> u64 {
    let shift = attempt.saturating_sub(1).min(32);
    policy
        .backoff_base_secs
        .saturating_mul(1u64 << shift)
        .min(policy.backoff_cap_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> HealthPolicy {
        HealthPolicy {
            interval_secs: 10,
            timeout_secs: 5,
            retries: 3,
            start_period_secs: 30,
            backoff_base_secs: 1,
            backoff_cap_secs: 300,
            max_restart_attempts: 5,
        }
    }
    fn tracker(now: u64) -> HealthTracker {
        HealthTracker {
            state: HealthState::Starting,
            consecutive_failures: 0,
            started_at_unix: now,
            last_healthy_at_unix: None,
            restart_attempts: 0,
            next_restart_after_unix: None,
        }
    }

    #[test]
    fn failures_during_start_period_do_not_count() {
        let mut t = tracker(1000);
        // 5s in, still inside the 30s start period
        assert_eq!(
            fold(&mut t, ProbeResult::Fail, &policy(), 1005),
            HealthAction::None
        );
        assert_eq!(t.state, HealthState::Starting);
        assert_eq!(t.consecutive_failures, 0);
    }

    #[test]
    fn pass_becomes_healthy() {
        let mut t = tracker(1000);
        assert_eq!(
            fold(&mut t, ProbeResult::Pass, &policy(), 1005),
            HealthAction::None
        );
        assert_eq!(t.state, HealthState::Healthy);
        assert_eq!(t.last_healthy_at_unix, Some(1005));
    }

    #[test]
    fn retries_consecutive_failures_then_unhealthy_and_restart() {
        let mut t = tracker(1000);
        fold(&mut t, ProbeResult::Pass, &policy(), 1005); // Healthy, past this point failures count
        assert_eq!(
            fold(&mut t, ProbeResult::Fail, &policy(), 1040),
            HealthAction::None
        );
        assert_eq!(
            fold(&mut t, ProbeResult::Fail, &policy(), 1050),
            HealthAction::None
        );
        // third consecutive failure (retries=3) -> Unhealthy + Restart
        assert_eq!(
            fold(&mut t, ProbeResult::Fail, &policy(), 1060),
            HealthAction::Restart
        );
        assert_eq!(t.state, HealthState::Unhealthy);
        assert_eq!(t.restart_attempts, 1);
    }

    #[test]
    fn recovery_resets_failures_and_backoff() {
        let mut t = tracker(1000);
        fold(&mut t, ProbeResult::Pass, &policy(), 1005);
        fold(&mut t, ProbeResult::Fail, &policy(), 1040);
        fold(&mut t, ProbeResult::Pass, &policy(), 1050);
        assert_eq!(t.state, HealthState::Healthy);
        assert_eq!(t.consecutive_failures, 0);
    }

    #[test]
    fn gives_up_after_max_restart_attempts() {
        let mut t = tracker(1000);
        t.state = HealthState::Unhealthy;
        t.restart_attempts = 5; // == max
        assert_eq!(
            fold(&mut t, ProbeResult::Fail, &policy(), 2000),
            HealthAction::GiveUp
        );
    }
}
