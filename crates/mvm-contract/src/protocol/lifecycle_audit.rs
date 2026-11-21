//! Lifecycle-chain entries a keyless host process may ask a signer to append.
//!
//! The host's keyless brokers record a refused cell operation or a refused
//! liveness signal on the tenant's lifecycle chain, which only a key-holding
//! process can write. They ask the signer they already talk to, with one of
//! these entries. The shape is closed on purpose: the event is one of a fixed
//! set, each label key is one of a fixed set the event allows, and each value
//! is bounded, so the request cannot be used to write anything else onto the
//! chain.

use alloc::collections::BTreeMap;
use alloc::string::String;

use serde::{Deserialize, Serialize};

/// The longest label value accepted, in bytes.
pub const MAX_LIFECYCLE_LABEL_BYTES: usize = 1024;

/// The events a lifecycle entry may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleEvent {
    /// The cell store refused an operation for want of authority.
    #[serde(rename = "state_cell.refused")]
    StateCellRefused,
    /// A liveness signal was refused.
    #[serde(rename = "liveness.signal_refused")]
    LivenessSignalRefused,
}

impl LifecycleEvent {
    /// The chain event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateCellRefused => "state_cell.refused",
            Self::LivenessSignalRefused => "liveness.signal_refused",
        }
    }

    /// Whether this event carries `label`.
    #[must_use]
    pub const fn allows(self, label: LifecycleLabel) -> bool {
        match self {
            Self::StateCellRefused => true,
            Self::LivenessSignalRefused => {
                matches!(
                    label,
                    LifecycleLabel::Unit
                        | LifecycleLabel::Epoch
                        | LifecycleLabel::Reason
                        | LifecycleLabel::Suppressed
                )
            }
        }
    }
}

/// The label keys a lifecycle entry may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleLabel {
    Operation,
    Cell,
    Unit,
    Epoch,
    Reason,
    /// How many refusals of the same kind went unrecorded since the last
    /// entry of that kind.
    Suppressed,
}

impl LifecycleLabel {
    /// The label key on the chain.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Cell => "cell",
            Self::Unit => "unit",
            Self::Epoch => "epoch",
            Self::Reason => "reason",
            Self::Suppressed => "suppressed",
        }
    }
}

/// An entry's labels, at most one value per key.
pub type LifecycleLabels = BTreeMap<LifecycleLabel, String>;

/// One entry for a tenant's lifecycle chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEntry {
    /// Must be the tenant the signer serves.
    pub tenant_id: String,
    pub event: LifecycleEvent,
    pub labels: LifecycleLabels,
}

/// Why a lifecycle entry is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEntryInvalid {
    /// The event does not carry this label.
    LabelNotAllowed(LifecycleLabel),
    /// A label value is longer than [`MAX_LIFECYCLE_LABEL_BYTES`].
    LabelTooLong(LifecycleLabel),
}

impl core::fmt::Display for LifecycleEntryInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LabelNotAllowed(label) => {
                write!(f, "the event does not carry `{}`", label.as_str())
            }
            Self::LabelTooLong(label) => write!(
                f,
                "label `{}` is longer than {MAX_LIFECYCLE_LABEL_BYTES} bytes",
                label.as_str()
            ),
        }
    }
}

impl core::error::Error for LifecycleEntryInvalid {}

impl LifecycleEntry {
    /// Check every label against the event and the size bound. The tenant is
    /// the signer's to check, against the one it serves.
    pub fn validate(&self) -> Result<(), LifecycleEntryInvalid> {
        for (label, value) in &self.labels {
            if !self.event.allows(*label) {
                return Err(LifecycleEntryInvalid::LabelNotAllowed(*label));
            }
            if value.len() > MAX_LIFECYCLE_LABEL_BYTES {
                return Err(LifecycleEntryInvalid::LabelTooLong(*label));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn entry(event: LifecycleEvent, labels: &[(LifecycleLabel, &str)]) -> LifecycleEntry {
        LifecycleEntry {
            tenant_id: "acme".into(),
            event,
            labels: labels.iter().map(|(k, v)| (*k, v.to_string())).collect(),
        }
    }

    #[test]
    fn the_wire_form_is_closed() {
        let ok = serde_json::json!({
            "tenant_id": "acme",
            "event": "state_cell.refused",
            "labels": {"cell": "setpoint", "reason": "no"}
        });
        let parsed: LifecycleEntry = serde_json::from_value(ok.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), ok);
        for bad in [
            serde_json::json!({"tenant_id": "acme", "event": "plan.admitted", "labels": {}}),
            serde_json::json!({"tenant_id": "acme", "event": "state_cell.refused", "labels": {"image": "x"}}),
            serde_json::json!({"tenant_id": "acme", "event": "state_cell.refused", "labels": {}, "extra": 1}),
        ] {
            assert!(serde_json::from_value::<LifecycleEntry>(bad).is_err());
        }
    }

    #[test]
    fn labels_are_checked_against_the_event_and_bounded() {
        let ok = entry(
            LifecycleEvent::LivenessSignalRefused,
            &[(LifecycleLabel::Unit, "u"), (LifecycleLabel::Reason, "r")],
        );
        assert_eq!(ok.validate(), Ok(()));
        let cell_on_liveness = entry(
            LifecycleEvent::LivenessSignalRefused,
            &[(LifecycleLabel::Cell, "c")],
        );
        assert_eq!(
            cell_on_liveness.validate(),
            Err(LifecycleEntryInvalid::LabelNotAllowed(LifecycleLabel::Cell))
        );
        let long = "x".repeat(MAX_LIFECYCLE_LABEL_BYTES + 1);
        let too_long = entry(
            LifecycleEvent::StateCellRefused,
            &[(LifecycleLabel::Reason, &long)],
        );
        assert_eq!(
            too_long.validate(),
            Err(LifecycleEntryInvalid::LabelTooLong(LifecycleLabel::Reason))
        );
    }
}
