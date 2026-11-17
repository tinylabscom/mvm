//! The `stage` label on an egress refusal: which step of reaching a
//! destination the host refused. Event names stay as they were
//! (`host.flow.denied`, `dns.refused`); the label lets a reader treat a refused
//! lookup, connect and datagram as the same kind of record.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The label key carrying the stage.
pub const LABEL_STAGE: &str = "stage";

/// Which step of reaching a destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DenialStage {
    /// A DNS lookup of a name.
    Lookup,
    /// A stream connection (TCP, or a flow refused before one was classed).
    Connect,
    /// A UDP datagram or association.
    Datagram,
}

impl DenialStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Connect => "connect",
            Self::Datagram => "datagram",
        }
    }

    fn parse(label: &str) -> Option<Self> {
        match label {
            "lookup" => Some(Self::Lookup),
            "connect" => Some(Self::Connect),
            "datagram" => Some(Self::Datagram),
            _ => None,
        }
    }

    /// The stage a refusal event belongs to, from the event and its `class`
    /// label. `None` for an event that is not a refusal of reaching a
    /// destination. An entry written before the label existed reads the same
    /// way, so old chains still normalize.
    pub fn of_event(event: &str, class: Option<&str>) -> Option<Self> {
        match event {
            "dns.refused" => Some(Self::Lookup),
            "host.flow.denied" if class == Some("udp") => Some(Self::Datagram),
            "host.flow.denied" => Some(Self::Connect),
            _ => None,
        }
    }

    /// The stage `labels` record, falling back to the event's own shape.
    pub fn of_entry(event: &str, labels: &BTreeMap<String, String>) -> Option<Self> {
        labels
            .get(LABEL_STAGE)
            .and_then(|label| Self::parse(label))
            .or_else(|| Self::of_event(event, labels.get("class").map(String::as_str)))
    }
}

impl fmt::Display for DenialStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Add the `stage` label a refusal event should carry; any other event is left
/// as it is.
pub fn stamp(event: &str, labels: &mut BTreeMap<String, String>) {
    let class = labels.get("class").map(String::as_str);
    if let Some(stage) = DenialStage::of_event(event, class) {
        labels.insert(LABEL_STAGE.into(), stage.as_str().into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn each_refusal_event_gets_its_stage() {
        for (event, class, want) in [
            ("dns.refused", None, "lookup"),
            ("host.flow.denied", Some("tcp"), "connect"),
            ("host.flow.denied", Some("session"), "connect"),
            ("host.flow.denied", None, "connect"),
            ("host.flow.denied", Some("udp"), "datagram"),
        ] {
            let mut l = class.map_or_else(BTreeMap::new, |c| labels(&[("class", c)]));
            stamp(event, &mut l);
            assert_eq!(
                l.get(LABEL_STAGE).map(String::as_str),
                Some(want),
                "{event}"
            );
        }
    }

    #[test]
    fn other_events_are_not_stamped() {
        let mut l = labels(&[("class", "tcp")]);
        stamp("host.flow.allowed", &mut l);
        stamp("icmp.refused", &mut l);
        assert!(!l.contains_key(LABEL_STAGE));
    }

    #[test]
    fn an_entry_without_the_label_reads_from_its_shape() {
        assert_eq!(
            DenialStage::of_entry("dns.refused", &BTreeMap::new()),
            Some(DenialStage::Lookup)
        );
        assert_eq!(
            DenialStage::of_entry("host.flow.denied", &labels(&[("class", "udp")])),
            Some(DenialStage::Datagram)
        );
    }

    #[test]
    fn a_recorded_label_wins_and_a_garbled_one_falls_back() {
        let recorded = labels(&[("stage", "lookup"), ("class", "tcp")]);
        assert_eq!(
            DenialStage::of_entry("host.flow.denied", &recorded),
            Some(DenialStage::Lookup)
        );
        let garbled = labels(&[("stage", "bogus"), ("class", "tcp")]);
        assert_eq!(
            DenialStage::of_entry("host.flow.denied", &garbled),
            Some(DenialStage::Connect)
        );
    }
}
