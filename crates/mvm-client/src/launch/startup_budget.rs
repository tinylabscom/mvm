//! The refusal a launch returns when it reached the guest too late to start
//! its workload inside the startup ceiling.
//!
//! The launch path checks its elapsed time at the last point before the
//! workload is handed to the guest. A launch already over the ceiling there is
//! refused with this error, and nothing runs. It is a typed error rather than a
//! formatted string so the audit path can record it under its own class instead
//! of the generic launch failure.

/// `plan.failed` class for a launch refused by its startup ceiling.
pub const STARTUP_BUDGET_CLASS: &str = "startup-budget";

/// One named span of the launch, in milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct StartupPhase {
    pub name: &'static str,
    pub ms: f64,
}

/// A launch that reached the guest at or past its startup ceiling.
#[derive(Debug, Clone, PartialEq)]
pub struct StartupBudgetExceeded {
    /// Invocation to the dispatch check, in milliseconds.
    pub elapsed_ms: f64,
    /// The ceiling the launch is held strictly below, in milliseconds.
    pub ceiling_ms: f64,
    /// `warm` or `cold`.
    pub launch_mode: &'static str,
    /// The launch's coarse phases, in launch order. They partition
    /// `elapsed_ms`.
    pub phases: Vec<StartupPhase>,
    /// The largest named sub-phase inside the slowest coarse phase, when one
    /// was recorded.
    pub slowest_detail: Option<StartupPhase>,
}

impl StartupBudgetExceeded {
    /// The coarse phase that took longest. Ties keep the earlier phase.
    #[must_use]
    pub fn slowest_phase(&self) -> Option<&StartupPhase> {
        self.phases
            .iter()
            .fold(None, |best: Option<&StartupPhase>, phase| match best {
                Some(best) if best.ms >= phase.ms => Some(best),
                _ => Some(phase),
            })
    }

    fn breakdown(&self) -> String {
        self.phases
            .iter()
            .map(|phase| format!("{}={:.1}ms", phase.name, phase.ms))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl std::fmt::Display for StartupBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} launch reached the guest after {:.1}ms, not strictly below the {}ms startup \
             ceiling; the workload was not started",
            self.launch_mode, self.elapsed_ms, self.ceiling_ms
        )?;
        if let Some(slowest) = self.slowest_phase() {
            write!(f, ". Slowest phase: {} ({:.1}ms", slowest.name, slowest.ms)?;
            if let Some(detail) = &self.slowest_detail {
                write!(f, ", of which {} {:.1}ms", detail.name, detail.ms)?;
            }
            write!(f, ")")?;
        }
        write!(f, ". Phases: {}", self.breakdown())
    }
}

impl std::error::Error for StartupBudgetExceeded {}

/// The `plan.failed` class an error is recorded under: the startup-ceiling
/// class when the launch was refused for time, `fallback` otherwise.
#[must_use]
pub fn failure_class<'a>(err: &anyhow::Error, fallback: &'a str) -> &'a str {
    if err.downcast_ref::<StartupBudgetExceeded>().is_some() {
        STARTUP_BUDGET_CLASS
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal() -> StartupBudgetExceeded {
        StartupBudgetExceeded {
            elapsed_ms: 312.4,
            ceiling_ms: 300.0,
            launch_mode: "warm",
            phases: vec![
                StartupPhase {
                    name: "resolve_admit",
                    ms: 210.0,
                },
                StartupPhase {
                    name: "warm_claim",
                    ms: 80.0,
                },
                StartupPhase {
                    name: "agent_wait",
                    ms: 20.0,
                },
                StartupPhase {
                    name: "dispatch_prep",
                    ms: 2.4,
                },
            ],
            slowest_detail: Some(StartupPhase {
                name: "attach_initramfs",
                ms: 180.0,
            }),
        }
    }

    #[test]
    fn the_refusal_names_the_slowest_phase_and_says_nothing_ran() {
        let text = refusal().to_string();
        assert!(text.contains("312.4ms"), "{text}");
        assert!(text.contains("300ms"), "{text}");
        assert!(text.contains("the workload was not started"), "{text}");
        assert!(
            text.contains(
                "Slowest phase: resolve_admit (210.0ms, of which attach_initramfs 180.0ms)"
            ),
            "{text}"
        );
        assert!(text.contains("warm_claim=80.0ms"), "{text}");
    }

    #[test]
    fn slowest_phase_keeps_the_earlier_of_a_tie() {
        let mut refusal = refusal();
        refusal.phases[1].ms = 210.0;
        assert_eq!(refusal.slowest_phase().unwrap().name, "resolve_admit");
        refusal.phases.clear();
        assert!(refusal.slowest_phase().is_none());
    }

    #[test]
    fn only_a_startup_refusal_is_recorded_under_its_own_class() {
        let refused = anyhow::Error::new(refusal()).context("running the workload");
        assert_eq!(failure_class(&refused, "launch"), STARTUP_BUDGET_CLASS);
        let other = anyhow::anyhow!("guest agent did not become reachable within 30s");
        assert_eq!(failure_class(&other, "launch"), "launch");
    }
}
