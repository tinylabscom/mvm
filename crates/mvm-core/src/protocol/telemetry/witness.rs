//! Activation-aware startup-witness ledger for expected telemetry producers.
//!
//! The host owns the expectations: launcher policy decides which producers must
//! start, and every producer that does start needs its capture witness. An
//! optional helper that is never launched is not a missing producer. This is a
//! pure bookkeeping model — it certifies nothing at runtime by itself, and a
//! startup record alone does not certify coverage.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CoverageState, Label, RecordError, SourceKind};

/// Maximum registered expectations plus tracked unexpected producers.
pub const MAX_WITNESS_PRODUCERS: usize = 64;

/// How launcher policy decides whether a producer must start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    /// Launched on every boot of the image tier; a missing witness is a gap.
    Always,
    /// Launched only under an explicit condition the host observes.
    Conditional,
    /// Runs only when explicitly invoked; never required to witness.
    OnDemand,
}

/// Visible degradation classes; a clean stop is state, not a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A required producer never reported startup.
    Missing,
    /// The producer reported impaired capture.
    Degraded,
    /// The producer reported an interval without capture.
    Unavailable,
    /// A producer reported coverage without being registered.
    Unexpected,
}

/// One visible coverage gap for a named producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFinding {
    /// Producer identity as registered or observed.
    pub id: Label,
    /// Gap class.
    pub kind: FindingKind,
}

/// Result of recording an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The producer was registered; its state was updated.
    Registered,
    /// The producer was not registered; it is reported as unexpected.
    Unexpected,
    /// The unexpected-producer table is full; the gap is counted, not named.
    UnexpectedUntracked,
}

#[derive(Debug, Clone)]
struct Expected {
    source: SourceKind,
    activation: Activation,
    activated: bool,
    last: Option<CoverageState>,
}

/// Host-side ledger of expected producers and their observed coverage.
#[derive(Debug, Clone, Default)]
pub struct WitnessLedger {
    expected: BTreeMap<String, Expected>,
    unexpected: BTreeMap<String, CoverageState>,
    untracked_unexpected: u64,
}

impl WitnessLedger {
    /// Empty ledger; expectations come from launcher policy, never guest data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one expected producer. Duplicate ids and table overflow refuse.
    pub fn expect(
        &mut self,
        id: Label,
        source: SourceKind,
        activation: Activation,
    ) -> Result<(), RecordError> {
        if self.expected.len() >= MAX_WITNESS_PRODUCERS {
            return Err(RecordError::Capacity);
        }
        let key = id.as_str().to_owned();
        if self.expected.contains_key(&key) {
            return Err(RecordError::Invalid);
        }
        self.expected.insert(
            key,
            Expected {
                source,
                activation,
                activated: matches!(activation, Activation::Always),
                last: None,
            },
        );
        Ok(())
    }

    /// Mark a conditional producer as launched, making its witness required.
    pub fn activate(&mut self, id: &str) -> Result<(), RecordError> {
        let entry = self.expected.get_mut(id).ok_or(RecordError::Identity)?;
        if matches!(entry.activation, Activation::OnDemand) {
            return Err(RecordError::Invalid);
        }
        entry.activated = true;
        Ok(())
    }

    /// Record an observed coverage state for a producer.
    pub fn observe(&mut self, id: &str, state: CoverageState) -> Observation {
        if let Some(entry) = self.expected.get_mut(id) {
            entry.last = Some(state);
            return Observation::Registered;
        }
        if self.unexpected.contains_key(id)
            || self.expected.len() + self.unexpected.len() < MAX_WITNESS_PRODUCERS
        {
            self.unexpected.insert(id.to_owned(), state);
            return Observation::Unexpected;
        }
        self.untracked_unexpected = self.untracked_unexpected.saturating_add(1);
        Observation::UnexpectedUntracked
    }

    /// Declared source kind of a registered producer.
    pub fn source(&self, id: &str) -> Option<SourceKind> {
        self.expected.get(id).map(|entry| entry.source)
    }

    /// Observations shed because the unexpected-producer table was full.
    pub fn untracked_unexpected(&self) -> u64 {
        self.untracked_unexpected
    }

    /// Visible gaps, deterministically ordered by producer id.
    pub fn assess(&self) -> Vec<WitnessFinding> {
        let mut findings = Vec::new();
        for (id, entry) in &self.expected {
            let kind = match entry.last {
                None if entry.activated => Some(FindingKind::Missing),
                Some(CoverageState::Degraded) => Some(FindingKind::Degraded),
                Some(CoverageState::Unavailable) => Some(FindingKind::Unavailable),
                None | Some(CoverageState::Started) | Some(CoverageState::Stopped) => None,
            };
            if let (Some(kind), Ok(id)) = (kind, Label::new(id)) {
                findings.push(WitnessFinding { id, kind });
            }
        }
        for id in self.unexpected.keys() {
            if let Ok(id) = Label::new(id) {
                findings.push(WitnessFinding {
                    id,
                    kind: FindingKind::Unexpected,
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(text: &str) -> Label {
        Label::new(text).unwrap()
    }

    fn kinds(ledger: &WitnessLedger) -> Vec<(String, FindingKind)> {
        ledger
            .assess()
            .into_iter()
            .map(|finding| (finding.id.as_str().to_owned(), finding.kind))
            .collect()
    }

    #[test]
    fn required_producer_without_startup_is_missing() {
        let mut ledger = WitnessLedger::new();
        ledger
            .expect(label("agent"), SourceKind::GuestAgent, Activation::Always)
            .unwrap();
        assert_eq!(kinds(&ledger), vec![("agent".into(), FindingKind::Missing)]);
        ledger.observe("agent", CoverageState::Started);
        assert!(ledger.assess().is_empty());
    }

    #[test]
    fn unlaunched_conditional_producer_is_not_a_missing_producer() {
        let mut ledger = WitnessLedger::new();
        ledger
            .expect(
                label("egress-client"),
                SourceKind::GuestHelper,
                Activation::Conditional,
            )
            .unwrap();
        assert!(ledger.assess().is_empty());
        ledger.activate("egress-client").unwrap();
        assert_eq!(
            kinds(&ledger),
            vec![("egress-client".into(), FindingKind::Missing)]
        );
    }

    #[test]
    fn on_demand_producers_never_require_a_witness() {
        let mut ledger = WitnessLedger::new();
        ledger
            .expect(
                label("display-bridge"),
                SourceKind::GuestHelper,
                Activation::OnDemand,
            )
            .unwrap();
        assert!(ledger.assess().is_empty());
        assert_eq!(ledger.activate("display-bridge"), Err(RecordError::Invalid));
        ledger.observe("display-bridge", CoverageState::Degraded);
        assert_eq!(
            kinds(&ledger),
            vec![("display-bridge".into(), FindingKind::Degraded)]
        );
    }

    #[test]
    fn degraded_and_unavailable_are_visible_and_clean_stop_is_not() {
        let mut ledger = WitnessLedger::new();
        for (id, state, expected) in [
            ("a", CoverageState::Degraded, Some(FindingKind::Degraded)),
            (
                "b",
                CoverageState::Unavailable,
                Some(FindingKind::Unavailable),
            ),
            ("c", CoverageState::Stopped, None),
        ] {
            ledger
                .expect(label(id), SourceKind::GuestHelper, Activation::Always)
                .unwrap();
            ledger.observe(id, CoverageState::Started);
            ledger.observe(id, state);
            let found = ledger
                .assess()
                .iter()
                .find(|finding| finding.id.as_str() == id)
                .map(|finding| finding.kind);
            assert_eq!(found, expected, "{id}");
        }
    }

    #[test]
    fn unexpected_producer_is_reported_and_bounded() {
        let mut ledger = WitnessLedger::new();
        assert_eq!(
            ledger.observe("stray", CoverageState::Started),
            Observation::Unexpected
        );
        assert_eq!(
            kinds(&ledger),
            vec![("stray".into(), FindingKind::Unexpected)]
        );
        for index in 1..MAX_WITNESS_PRODUCERS {
            assert_eq!(
                ledger.observe(&format!("stray-{index}"), CoverageState::Started),
                Observation::Unexpected
            );
        }
        assert_eq!(
            ledger.observe("one-too-many", CoverageState::Started),
            Observation::UnexpectedUntracked
        );
        assert_eq!(ledger.untracked_unexpected(), 1);
        assert_eq!(
            ledger.observe("stray", CoverageState::Degraded),
            Observation::Unexpected,
            "an already-tracked producer stays updatable at the cap"
        );
    }

    #[test]
    fn duplicate_capacity_and_unknown_ids_refuse() {
        let mut ledger = WitnessLedger::new();
        ledger
            .expect(label("agent"), SourceKind::GuestAgent, Activation::Always)
            .unwrap();
        assert_eq!(
            ledger.expect(label("agent"), SourceKind::GuestAgent, Activation::Always),
            Err(RecordError::Invalid)
        );
        assert_eq!(ledger.activate("unknown"), Err(RecordError::Identity));
        for index in 1..MAX_WITNESS_PRODUCERS {
            ledger
                .expect(
                    label(&format!("p-{index}")),
                    SourceKind::GuestHelper,
                    Activation::OnDemand,
                )
                .unwrap();
        }
        assert_eq!(
            ledger.expect(
                label("overflow"),
                SourceKind::GuestHelper,
                Activation::OnDemand
            ),
            Err(RecordError::Capacity)
        );
        assert_eq!(ledger.source("agent"), Some(SourceKind::GuestAgent));
        assert_eq!(ledger.source("unknown"), None);
    }

    #[test]
    fn findings_roundtrip_and_stay_deterministically_ordered() {
        let mut ledger = WitnessLedger::new();
        for id in ["zeta", "alpha"] {
            ledger
                .expect(label(id), SourceKind::GuestHelper, Activation::Always)
                .unwrap();
        }
        let findings = ledger.assess();
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        let encoded = serde_json::to_string(&findings).unwrap();
        let decoded: Vec<WitnessFinding> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, findings);
        let activation: Activation = serde_json::from_str("\"on_demand\"").unwrap();
        assert_eq!(activation, Activation::OnDemand);
    }
}
