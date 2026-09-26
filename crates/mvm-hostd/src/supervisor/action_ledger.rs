//! Cumulative per-VM action ledger — the generic sibling of the AI token
//! budget tracker.
//!
//! Where `AiBudgetTracker` totals one channel (provider-reported token
//! usage), this ledger totals every other host-observable action channel:
//! egress flows and bytes, DNS queries, secret substitutions, stdin grants,
//! and collected output. Rate limits bound how fast a guest can act; these
//! cumulative ceilings bound how much it can act in total, so a looping or
//! compromised workload that holds itself under a per-second rate is still
//! stopped eventually.
//!
//! Semantics mirror the AI tracker: a record that crosses a ceiling is
//! still recorded, the dimension's exceeded latch is set, and the *next*
//! action in that dimension must be refused by the caller — a single
//! oversized action can never strand an in-flight flow. A dimension with no
//! ceiling (`None`) never latches.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use mvm_contract::policy::action_budget::ActionBudget;

/// One host-observable action channel the ledger totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDimension {
    /// Outbound flows opened over the workload's lifetime.
    EgressFlows,
    /// Bytes relayed outbound and inbound over the workload's lifetime.
    EgressBytes,
    /// DNS queries answered over the workload's lifetime.
    DnsQueries,
    /// Secret substitutions performed over the workload's lifetime.
    SecretSubstitutions,
    /// Stdin/stream input grants over the workload's lifetime.
    StdinGrants,
    /// Bytes collected from output volumes over the workload's lifetime.
    OutputBytes,
    /// Entries collected from output volumes over the workload's lifetime.
    OutputEntries,
}

impl ActionDimension {
    /// Every dimension, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::EgressFlows,
        Self::EgressBytes,
        Self::DnsQueries,
        Self::SecretSubstitutions,
        Self::StdinGrants,
        Self::OutputBytes,
        Self::OutputEntries,
    ];

    /// Stable slot in the ledger's counter and latch arrays.
    fn index(self) -> usize {
        match self {
            Self::EgressFlows => 0,
            Self::EgressBytes => 1,
            Self::DnsQueries => 2,
            Self::SecretSubstitutions => 3,
            Self::StdinGrants => 4,
            Self::OutputBytes => 5,
            Self::OutputEntries => 6,
        }
    }

    /// The configured ceiling for this dimension, if any.
    fn ceiling(self, budget: &ActionBudget) -> Option<u64> {
        match self {
            Self::EgressFlows => budget.max_egress_flows,
            Self::EgressBytes => budget.max_egress_bytes,
            Self::DnsQueries => budget.max_dns_queries,
            Self::SecretSubstitutions => budget.max_secret_substitutions,
            Self::StdinGrants => budget.max_stdin_grants,
            Self::OutputBytes => budget.max_output_bytes,
            Self::OutputEntries => budget.max_output_entries,
        }
    }
}

/// What one [`ActionLedger::record`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Recorded and under the configured ceiling (or the dimension has no
    /// ceiling).
    WithinBudget,
    /// Recorded, and this record is the one that crossed the dimension's
    /// ceiling. The latch is set: the caller must refuse the *next* action
    /// in this dimension.
    CrossedCeiling,
    /// The dimension's ceiling was already crossed by an earlier record.
    /// The caller should have refused before recording; the count is still
    /// taken so the refusal audit reports honest totals.
    AlreadyExceeded,
}

/// Cumulative totals per dimension, plus the any-dimension latch state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActionTotals {
    pub egress_flows: u64,
    pub egress_bytes: u64,
    pub dns_queries: u64,
    pub secret_substitutions: u64,
    pub stdin_grants: u64,
    pub output_bytes: u64,
    pub output_entries: u64,
    /// Whether any dimension's ceiling has been crossed at any point.
    pub exceeded: bool,
}

/// Thread-safe per-VM cumulative action ledger.
///
/// Counters are monotonically increasing and saturate rather than wrap, so
/// a hostile workload cannot roll a total back under its ceiling by
/// overflowing it.
pub struct ActionLedger {
    budget: Option<ActionBudget>,
    counters: [AtomicU64; 7],
    exceeded: [AtomicBool; 7],
}

impl ActionLedger {
    /// Create a ledger with the given budget. `None` means meter-only:
    /// totals accumulate, no dimension ever latches.
    pub fn new(budget: Option<ActionBudget>) -> Self {
        Self {
            budget,
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            exceeded: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    /// Record `n` actions in `dim` and return the outcome.
    ///
    /// The record is always taken. When it pushes the dimension's total
    /// strictly over its ceiling, the exceeded latch for that dimension is
    /// set and [`RecordOutcome::CrossedCeiling`] is returned; the caller
    /// refuses the next action in this dimension.
    pub fn record(&self, dim: ActionDimension, n: u64) -> RecordOutcome {
        let idx = dim.index();
        // A raw fetch_add wraps on overflow, which would let a hostile
        // workload roll a total back under its ceiling. A compare-exchange
        // loop with saturating_add keeps every total monotonically
        // increasing on every toolchain (fetch_update is deprecated on the
        // nightly CI lanes and try_update is not on the stable floor).
        let mut current = self.counters[idx].load(Ordering::SeqCst);
        let total = loop {
            let next = current.saturating_add(n);
            match self.counters[idx].compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break next,
                Err(actual) => current = actual,
            }
        };
        if self.exceeded[idx].load(Ordering::SeqCst) {
            return RecordOutcome::AlreadyExceeded;
        }
        let crossed = self
            .budget
            .as_ref()
            .and_then(|budget| dim.ceiling(budget))
            .is_some_and(|limit| total > limit);
        if crossed {
            self.exceeded[idx].store(true, Ordering::SeqCst);
            RecordOutcome::CrossedCeiling
        } else {
            RecordOutcome::WithinBudget
        }
    }

    /// Whether the next action in `dim` may proceed: false once the
    /// dimension's ceiling has been crossed.
    pub fn check(&self, dim: ActionDimension) -> bool {
        !self.exceeded[dim.index()].load(Ordering::SeqCst)
    }

    /// Whether `dim`'s ceiling has been crossed at any point.
    pub fn is_exceeded(&self, dim: ActionDimension) -> bool {
        !self.check(dim)
    }

    /// Current cumulative totals without recording anything.
    pub fn totals(&self) -> ActionTotals {
        let load = |dim: ActionDimension| self.counters[dim.index()].load(Ordering::SeqCst);
        let latched = |dim: ActionDimension| self.exceeded[dim.index()].load(Ordering::SeqCst);
        ActionTotals {
            egress_flows: load(ActionDimension::EgressFlows),
            egress_bytes: load(ActionDimension::EgressBytes),
            dns_queries: load(ActionDimension::DnsQueries),
            secret_substitutions: load(ActionDimension::SecretSubstitutions),
            stdin_grants: load(ActionDimension::StdinGrants),
            output_bytes: load(ActionDimension::OutputBytes),
            output_entries: load(ActionDimension::OutputEntries),
            exceeded: ActionDimension::ALL.iter().any(|&dim| latched(dim)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(ceiling: impl FnOnce(&mut ActionBudget)) -> ActionBudget {
        let mut budget = ActionBudget::default();
        ceiling(&mut budget);
        budget
    }

    #[test]
    fn ledger_without_budget_records_everything() {
        let ledger = ActionLedger::new(None);
        for dim in ActionDimension::ALL {
            assert_eq!(
                ledger.record(dim, 10),
                RecordOutcome::WithinBudget,
                "no ceiling means no latch, ever"
            );
            assert!(ledger.check(dim));
        }
        let totals = ledger.totals();
        assert_eq!(totals.egress_flows, 10);
        assert_eq!(totals.egress_bytes, 10);
        assert_eq!(totals.dns_queries, 10);
        assert_eq!(totals.secret_substitutions, 10);
        assert_eq!(totals.stdin_grants, 10);
        assert_eq!(totals.output_bytes, 10);
        assert_eq!(totals.output_entries, 10);
        assert!(!totals.exceeded);
    }

    #[test]
    fn zero_ceiling_refuses_the_first_record() {
        let ledger = ActionLedger::new(Some(ActionBudget::default().with_max_egress_flows(0)));
        assert_eq!(
            ledger.record(ActionDimension::EgressFlows, 1),
            RecordOutcome::CrossedCeiling
        );
        assert!(!ledger.check(ActionDimension::EgressFlows));
        assert_eq!(
            ledger.record(ActionDimension::EgressFlows, 1),
            RecordOutcome::AlreadyExceeded
        );
    }

    #[test]
    fn crossing_record_is_taken_and_the_next_is_refused() {
        let ledger = ActionLedger::new(Some(ActionBudget::default().with_max_egress_flows(3)));
        assert_eq!(
            ledger.record(ActionDimension::EgressFlows, 2),
            RecordOutcome::WithinBudget
        );
        // 2 + 2 = 4 > 3: this record crosses, and it is still taken.
        assert_eq!(
            ledger.record(ActionDimension::EgressFlows, 2),
            RecordOutcome::CrossedCeiling
        );
        assert!(!ledger.check(ActionDimension::EgressFlows));
        assert_eq!(
            ledger.totals().egress_flows,
            4,
            "the crossing record counts"
        );
        assert!(ledger.totals().exceeded);
    }

    #[test]
    fn dimensions_are_independent() {
        let ledger = ActionLedger::new(Some(ActionBudget::default().with_max_egress_flows(1)));
        assert_eq!(
            ledger.record(ActionDimension::EgressFlows, 2),
            RecordOutcome::CrossedCeiling
        );
        assert!(!ledger.check(ActionDimension::EgressFlows));
        // An unbudgeted dimension is unaffected by another dimension's latch.
        assert!(ledger.check(ActionDimension::DnsQueries));
        assert_eq!(
            ledger.record(ActionDimension::DnsQueries, 500),
            RecordOutcome::WithinBudget
        );
    }

    #[test]
    fn unbudgeted_dimension_never_latches() {
        let ledger = ActionLedger::new(Some(budget(|b| {
            b.max_dns_queries = Some(1);
        })));
        for _ in 0..5 {
            assert_eq!(
                ledger.record(ActionDimension::OutputBytes, 1_000_000),
                RecordOutcome::WithinBudget
            );
        }
        assert!(ledger.check(ActionDimension::OutputBytes));
        assert!(
            !ledger.totals().exceeded,
            "a latched DNS dim is not reported for output"
        );
        // Latch the budgeted dimension: now the any-dimension flag reports it.
        assert_eq!(
            ledger.record(ActionDimension::DnsQueries, 2),
            RecordOutcome::CrossedCeiling
        );
        assert!(ledger.totals().exceeded);
    }

    #[test]
    fn totals_saturate_instead_of_wrapping() {
        let ledger = ActionLedger::new(Some(ActionBudget::default().with_max_egress_bytes(1)));
        assert_eq!(
            ledger.record(ActionDimension::EgressBytes, u64::MAX),
            RecordOutcome::CrossedCeiling
        );
        assert_eq!(
            ledger.record(ActionDimension::EgressBytes, 1),
            RecordOutcome::AlreadyExceeded
        );
        // Saturated at u64::MAX, not rolled back to 0 — a hostile workload
        // cannot roll a total under its ceiling by overflowing it.
        assert_eq!(ledger.totals().egress_bytes, u64::MAX);
    }

    #[test]
    fn totals_reflect_state_without_recording() {
        let ledger = ActionLedger::new(None);
        ledger.record(ActionDimension::SecretSubstitutions, 7);
        ledger.record(ActionDimension::StdinGrants, 3);
        let totals = ledger.totals();
        assert_eq!(totals.secret_substitutions, 7);
        assert_eq!(totals.stdin_grants, 3);
        assert_eq!(totals.egress_flows, 0);
        assert!(!totals.exceeded);
    }
}
