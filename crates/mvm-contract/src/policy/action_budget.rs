//! Cumulative per-VM action budget — the signed carrier for lifetime
//! ceilings over the host-observable action channels (egress flows and
//! bytes, DNS queries, secret substitutions, stdin grants, and collected
//! output).
//!
//! Rate limits bound how fast a guest can act; these budgets bound how much
//! it can act in total. A looping or compromised workload can hold itself
//! under a per-second rate indefinitely — a cumulative ceiling is what turns
//! "slow" into "stopped". Every `None` field means no limit for that
//! dimension; the default budget imposes nothing, and a plan that sets one
//! dimension leaves the others unlimited.

use serde::{Deserialize, Serialize};

/// Cumulative lifetime ceilings for one workload, enforced host-side at the
/// seams where each action crosses from guest to host.
///
/// Semantics mirror the AI token budget: a request that crosses a ceiling is
/// recorded, and the *next* one is refused — so a single oversized action can
/// never strand an in-flight flow. Budgets are per-VM lifetime totals, not
/// per-turn or per-conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ActionBudget {
    /// Maximum outbound flows opened over the workload's lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_flows: Option<u64>,
    /// Maximum bytes relayed outbound and inbound over the workload's
    /// lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_bytes: Option<u64>,
    /// Maximum DNS queries answered over the workload's lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_dns_queries: Option<u64>,
    /// Maximum secret substitutions performed over the workload's lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_secret_substitutions: Option<u64>,
    /// Maximum stdin/stream input grants over the workload's lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stdin_grants: Option<u64>,
    /// Maximum bytes collected from output volumes over the workload's
    /// lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
    /// Maximum entries collected from output volumes over the workload's
    /// lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_entries: Option<u64>,
}

impl ActionBudget {
    /// Return this budget with a ceiling on outbound flows opened.
    #[must_use]
    pub fn with_max_egress_flows(mut self, max: u64) -> Self {
        self.max_egress_flows = Some(max);
        self
    }

    /// Return this budget with a ceiling on relayed bytes.
    #[must_use]
    pub fn with_max_egress_bytes(mut self, max: u64) -> Self {
        self.max_egress_bytes = Some(max);
        self
    }

    /// Return this budget with a ceiling on DNS queries.
    #[must_use]
    pub fn with_max_dns_queries(mut self, max: u64) -> Self {
        self.max_dns_queries = Some(max);
        self
    }

    /// Return this budget with a ceiling on secret substitutions.
    #[must_use]
    pub fn with_max_secret_substitutions(mut self, max: u64) -> Self {
        self.max_secret_substitutions = Some(max);
        self
    }

    /// Return this budget with a ceiling on stdin/stream input grants.
    #[must_use]
    pub fn with_max_stdin_grants(mut self, max: u64) -> Self {
        self.max_stdin_grants = Some(max);
        self
    }

    /// Return this budget with a ceiling on collected output bytes.
    #[must_use]
    pub fn with_max_output_bytes(mut self, max: u64) -> Self {
        self.max_output_bytes = Some(max);
        self
    }

    /// Return this budget with a ceiling on collected output entries.
    #[must_use]
    pub fn with_max_output_entries(mut self, max: u64) -> Self {
        self.max_output_entries = Some(max);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_budget_defaults_to_no_limits() {
        let budget = ActionBudget::default();
        assert!(budget.max_egress_flows.is_none());
        assert!(budget.max_egress_bytes.is_none());
        assert!(budget.max_dns_queries.is_none());
        assert!(budget.max_secret_substitutions.is_none());
        assert!(budget.max_stdin_grants.is_none());
        assert!(budget.max_output_bytes.is_none());
        assert!(budget.max_output_entries.is_none());
    }

    #[test]
    fn action_budget_roundtrips_each_dimension_through_serde() {
        let budget = ActionBudget::default()
            .with_max_egress_flows(10)
            .with_max_egress_bytes(1_048_576)
            .with_max_dns_queries(1_000)
            .with_max_secret_substitutions(5)
            .with_max_stdin_grants(50)
            .with_max_output_bytes(8_388_608)
            .with_max_output_entries(512);
        let json = serde_json::to_string(&budget).expect("budget serializes");
        let back: ActionBudget = serde_json::from_str(&json).expect("budget deserializes");
        assert_eq!(budget, back);

        let empty = serde_json::to_string(&ActionBudget::default()).expect("serializes");
        assert_eq!(empty, "{}", "an all-None budget carries no wire bytes");
        let back: ActionBudget = serde_json::from_str(&empty).expect("deserializes");
        assert_eq!(back, ActionBudget::default());
    }

    #[test]
    fn action_budget_setters_build_the_intended_budget() {
        let budget = ActionBudget::default().with_max_egress_flows(3);
        assert_eq!(budget.max_egress_flows, Some(3));
        assert!(
            budget.max_egress_bytes.is_none(),
            "setters are per-dimension"
        );
    }
}
