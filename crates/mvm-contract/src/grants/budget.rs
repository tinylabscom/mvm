//! The bound on what *every* workload on a host may consume at once.
//!
//! [`GrantCeiling`](crate::grants::ceiling::GrantCeiling) bounds one workload.
//! A host running ten well-formed 4 GiB VMs on 32 GiB of RAM never violated
//! that ceiling once, and is thrashing. This is the other question: does the
//! sum still fit.
//!
//! Pure arithmetic, deliberately. What is *live* and what each live machine
//! was granted are host-side facts that need process probing and on-disk
//! state; keeping the decision separate from the measurement means the
//! decision is testable without a host and the measurement has one home.

use serde::{Deserialize, Serialize};

/// A dimension in which the host's committed total, plus a pending request,
/// would exceed the budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetViolation {
    /// Dotted path of the offending dimension, for the refusal message.
    pub dimension: &'static str,
    /// What is already committed to live machines.
    pub committed: u64,
    /// What the pending boot asks for on top of that.
    pub requested: u64,
    /// The configured host-wide bound.
    pub budget: u64,
}

impl BudgetViolation {
    /// Whether `committed + requested` overflows or exceeds `budget`.
    ///
    /// Saturating rather than wrapping: an overflowed sum that wrapped low
    /// would admit the one boot the budget exists to refuse.
    fn detect(
        dimension: &'static str,
        committed: u64,
        requested: u64,
        budget: Option<u64>,
    ) -> Option<Self> {
        let budget = budget?;
        (committed.saturating_add(requested) > budget).then_some(Self {
            dimension,
            committed,
            requested,
            budget,
        })
    }
}

/// What one machine is charged against the host budget.
///
/// Always the *configured maximum*, never the current usage. The balloon
/// controller moves a running VM's host commitment down under pressure and
/// back up when the guest needs its pages; a budget summed from that figure
/// would re-admit memory the host has already promised, and then discover the
/// overcommit at the worst possible moment — when both guests want their pages
/// at once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineCharge {
    /// Guest RAM the machine was admitted with, in MiB.
    pub memory_mib: u64,
    /// CPU share the machine was granted, in thousandths of one host core.
    ///
    /// Zero means the machine declared no CPU grant, and so is uncapped rather
    /// than free. See [`HostBudget`]'s note on what the CPU arm does and does
    /// not bound.
    pub cpu_millicores: u32,
}

impl MachineCharge {
    /// Sum, saturating. A total that wrapped would read as headroom.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        Self {
            memory_mib: self.memory_mib.saturating_add(other.memory_mib),
            cpu_millicores: self.cpu_millicores.saturating_add(other.cpu_millicores),
        }
    }
}

/// The host-wide headroom, read from operator config and never from a plan.
///
/// `None` in a dimension means unbounded *in that dimension*; it does not open
/// the others — the same rule the per-VM ceiling follows, for the same reason.
///
/// # What the CPU arm bounds
///
/// Only *granted* shares. A workload that declared no CPU grant is uncapped,
/// contributes zero, and so cannot be summed against anything. The memory arm
/// has no such hole: guest RAM is fixed at VM creation whether or not anyone
/// asked for it, so every live machine contributes its real figure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_memory_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cpu_millicores: Option<u32>,
}

impl HostBudget {
    /// Whether this host still has room for `request` on top of `committed`.
    ///
    /// Memory first, CPU second: when a request exceeds in both dimensions the
    /// reported one has to be stable, or the refusal a user sees depends on
    /// evaluation order.
    ///
    /// # Errors
    ///
    /// Returns the first dimension whose committed total plus the request
    /// exceeds the configured budget.
    pub fn admits(
        &self,
        committed: MachineCharge,
        request: MachineCharge,
    ) -> Result<(), BudgetViolation> {
        if let Some(v) = BudgetViolation::detect(
            "host.total_memory_mib",
            committed.memory_mib,
            request.memory_mib,
            self.max_total_memory_mib,
        ) {
            return Err(v);
        }
        if let Some(v) = BudgetViolation::detect(
            "host.total_cpu_millicores",
            u64::from(committed.cpu_millicores),
            u64::from(request.cpu_millicores),
            self.max_total_cpu_millicores.map(u64::from),
        ) {
            return Err(v);
        }
        Ok(())
    }

    /// Whether either dimension is configured. An unconfigured budget bounds
    /// nothing, and a caller that wants to say so needs to be able to ask.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.max_total_memory_mib.is_some() || self.max_total_cpu_millicores.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> HostBudget {
        HostBudget {
            max_total_memory_mib: Some(8192),
            max_total_cpu_millicores: Some(4000),
        }
    }

    fn charge(memory_mib: u64, cpu_millicores: u32) -> MachineCharge {
        MachineCharge {
            memory_mib,
            cpu_millicores,
        }
    }

    #[test]
    fn an_unconfigured_budget_bounds_nothing() {
        let open = HostBudget::default();
        assert!(!open.is_configured());
        assert_eq!(
            open.admits(charge(u64::MAX, u32::MAX), charge(4096, 4000)),
            Ok(())
        );
    }

    #[test]
    fn a_request_that_exactly_fills_the_budget_is_admitted() {
        assert_eq!(
            budget().admits(charge(4096, 2000), charge(4096, 2000)),
            Ok(())
        );
    }

    #[test]
    fn memory_is_reported_before_cpu_when_both_are_exceeded() {
        let violation = budget()
            .admits(charge(8192, 4000), charge(1, 1))
            .expect_err("both dimensions are over");
        assert_eq!(violation.dimension, "host.total_memory_mib");
        assert_eq!(violation.committed, 8192);
        assert_eq!(violation.requested, 1);
        assert_eq!(violation.budget, 8192);
    }

    #[test]
    fn cpu_is_bounded_independently_of_memory() {
        let budget = HostBudget {
            max_total_memory_mib: None,
            max_total_cpu_millicores: Some(4000),
        };
        assert_eq!(
            budget.admits(charge(u64::MAX, 3000), charge(u64::MAX, 1000)),
            Ok(())
        );
        let violation = budget
            .admits(charge(0, 3500), charge(0, 1000))
            .expect_err("the cpu total is over");
        assert_eq!(violation.dimension, "host.total_cpu_millicores");
    }

    #[test]
    fn an_overflowing_sum_refuses_rather_than_wrapping_into_headroom() {
        let violation = budget()
            .admits(charge(u64::MAX, 0), charge(u64::MAX, 0))
            .expect_err("a wrapped total would read as headroom");
        assert_eq!(violation.dimension, "host.total_memory_mib");
    }

    #[test]
    fn charges_sum_saturating() {
        let total = charge(u64::MAX, u32::MAX).plus(charge(1, 1));
        assert_eq!(total, charge(u64::MAX, u32::MAX));
    }

    #[test]
    fn a_host_budget_round_trips_through_json() {
        let budget = budget();
        let json = serde_json::to_string(&budget).expect("serializing the budget");
        let back: HostBudget = serde_json::from_str(&json).expect("deserializing the budget");
        assert_eq!(back, budget);
    }
}
