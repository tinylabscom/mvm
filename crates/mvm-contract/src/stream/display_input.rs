//! Host-to-guest display input events.
//!
//! These are what a human attending a run sends toward the guest display:
//! pointer motion and buttons, wheel, keys, typed text, a paste, and the two
//! markers that bracket a credential entry. Every event has a stable kind word,
//! and the kind is all the audit chain ever records about it — never the key,
//! the text, or the coordinates. The text is the point: a human typing a
//! password into an attended run is the case this plane exists for.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plan::execution_plan::ExecutionPlan;
use crate::plan::verb::VerbId;
use crate::stream::display::grants_display_view;

/// The verb a host-signed grant names for the guest-to-host frame stream.
pub const DISPLAY_VIEW_VERB: &str = "display-view";

/// The verb a host-signed grant names for host-to-guest display input.
pub const DISPLAY_INPUT_VERB: &str = "display-input";

/// Most events one input frame may carry.
pub const MAX_DISPLAY_INPUT_EVENTS: usize = 256;

/// Longest key name, in bytes. Key names are DOM `KeyboardEvent.key` values
/// such as `Enter` or `a`; the longest standard one is well under this.
pub const MAX_DISPLAY_KEY_BYTES: usize = 32;

/// Longest typed-text event, in bytes. A paste is bounded by its own grant.
pub const MAX_DISPLAY_TEXT_BYTES: usize = 4096;

/// Largest coordinate accepted on either axis.
pub const MAX_DISPLAY_COORDINATE: u32 = 16_384;

/// Which pointer button an event names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PointerButton {
    Left,
    Middle,
    Right,
}

/// One input event bound for the guest display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DisplayInputEvent {
    PointerMove {
        x: u32,
        y: u32,
    },
    PointerButton {
        x: u32,
        y: u32,
        button: PointerButton,
        pressed: bool,
    },
    Wheel {
        x: u32,
        y: u32,
        delta_x: i32,
        delta_y: i32,
    },
    Key {
        key: String,
        pressed: bool,
    },
    Text {
        text: String,
    },
    /// A paste. Accepted only under a clipboard grant, and bounded by it.
    Paste {
        text: String,
    },
    /// A human is about to type a credential. Accepted only under a
    /// human-credential grant; recording pauses until the matching end.
    CredentialEntryBegin,
    /// The credential entry that the last begin opened is over.
    CredentialEntryEnd,
}

impl DisplayInputEvent {
    /// Wire-stable kind word: the one fact about an event the audit chain
    /// records.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PointerMove { .. } => "pointer-move",
            Self::PointerButton { .. } => "pointer-button",
            Self::Wheel { .. } => "wheel",
            Self::Key { .. } => "key",
            Self::Text { .. } => "text",
            Self::Paste { .. } => "paste",
            Self::CredentialEntryBegin => "credential-entry-begin",
            Self::CredentialEntryEnd => "credential-entry-end",
        }
    }

    fn validate(&self) -> Result<(), DisplayInputFrameError> {
        match self {
            Self::PointerMove { x, y }
            | Self::PointerButton { x, y, .. }
            | Self::Wheel { x, y, .. } => {
                if *x > MAX_DISPLAY_COORDINATE || *y > MAX_DISPLAY_COORDINATE {
                    return Err(DisplayInputFrameError::CoordinateOutOfRange);
                }
            }
            Self::Key { key, .. } => {
                if key.is_empty()
                    || key.len() > MAX_DISPLAY_KEY_BYTES
                    || key.chars().any(char::is_control)
                {
                    return Err(DisplayInputFrameError::InvalidKey);
                }
            }
            Self::Text { text } => {
                if text.is_empty() || text.len() > MAX_DISPLAY_TEXT_BYTES {
                    return Err(DisplayInputFrameError::InvalidText);
                }
            }
            // The clipboard grant bounds a paste, so only emptiness is a
            // contract-level error.
            Self::Paste { text } => {
                if text.is_empty() {
                    return Err(DisplayInputFrameError::InvalidText);
                }
            }
            Self::CredentialEntryBegin | Self::CredentialEntryEnd => {}
        }
        Ok(())
    }
}

/// One host-to-guest batch of display input.
///
/// `seq` orders one writer's frames exactly as the stdin plane's `InputFrame`
/// does: the gate refuses a frame that does not advance past the last one it
/// accepted rather than reordering it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DisplayInputFrame {
    pub seq: u64,
    pub events: Vec<DisplayInputEvent>,
}

impl DisplayInputFrame {
    /// Check the frame's shape and every event's bounds.
    ///
    /// # Errors
    /// The first violation found.
    pub fn validate(&self) -> Result<(), DisplayInputFrameError> {
        if self.events.is_empty() {
            return Err(DisplayInputFrameError::Empty);
        }
        if self.events.len() > MAX_DISPLAY_INPUT_EVENTS {
            return Err(DisplayInputFrameError::TooManyEvents);
        }
        self.events.iter().try_for_each(DisplayInputEvent::validate)
    }

    /// How many events of each kind the frame carries — the payload-free
    /// summary the audit chain records.
    #[must_use]
    pub fn kind_counts(&self) -> BTreeMap<&'static str, u32> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let count = counts.entry(event.kind()).or_insert(0u32);
            *count = count.saturating_add(1);
        }
        counts
    }
}

/// Why an input frame is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DisplayInputFrameError {
    #[error("display input frame carries no events")]
    Empty,
    #[error("display input frame carries more than {limit} events", limit = MAX_DISPLAY_INPUT_EVENTS)]
    TooManyEvents,
    #[error("display input coordinate exceeds {limit}", limit = MAX_DISPLAY_COORDINATE)]
    CoordinateOutOfRange,
    #[error("display input key name is empty, too long, or contains a control character")]
    InvalidKey,
    #[error("display input text is empty or too long")]
    InvalidText,
}

impl DisplayInputFrameError {
    /// Wire-stable reason word for the audit chain.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty-frame",
            Self::TooManyEvents => "too-many-events",
            Self::CoordinateOutOfRange => "coordinate-out-of-range",
            Self::InvalidKey => "invalid-key",
            Self::InvalidText => "invalid-text",
        }
    }
}

/// The display verbs a host-signed grant carries for `plan`: view when the
/// plan carries the view token, input when it carries the input grant. Each
/// is independent of the other, so a view-only plan names no input verb.
#[must_use]
pub fn display_verbs(plan: &ExecutionPlan) -> Vec<VerbId> {
    let mut verbs = Vec::new();
    if grants_display_view(plan) {
        verbs.push(VerbId::new(DISPLAY_VIEW_VERB).expect("display-view is a valid verb id"));
    }
    if crate::grants::display::display_input_grant(plan.grants.as_ref()).is_some() {
        verbs.push(VerbId::new(DISPLAY_INPUT_VERB).expect("display-input is a valid verb id"));
    }
    verbs
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::grants::{DisplayInputGrant, Grants};
    use crate::plan::execution_plan::minimal_plan;
    use crate::protocol::broker::ServiceId;
    use crate::stream::display::DISPLAY_VIEW_GRANT_SERVICE;

    fn frame(events: Vec<DisplayInputEvent>) -> DisplayInputFrame {
        DisplayInputFrame { seq: 0, events }
    }

    #[test]
    fn frames_round_trip_through_json_with_kebab_kinds() {
        let sent = frame(vec![
            DisplayInputEvent::PointerButton {
                x: 10,
                y: 20,
                button: PointerButton::Left,
                pressed: true,
            },
            DisplayInputEvent::Key {
                key: "Enter".into(),
                pressed: false,
            },
            DisplayInputEvent::CredentialEntryBegin,
        ]);
        let json = serde_json::to_string(&sent).unwrap();
        assert!(json.contains(r#""kind":"pointer-button""#));
        assert!(json.contains(r#""kind":"credential-entry-begin""#));
        assert_eq!(
            serde_json::from_str::<DisplayInputFrame>(&json).unwrap(),
            sent
        );
    }

    #[test]
    fn unknown_event_kinds_and_fields_are_refused() {
        let unknown = r#"{"seq":0,"events":[{"kind":"evaluate","expression":"1"}]}"#;
        assert!(serde_json::from_str::<DisplayInputFrame>(unknown).is_err());
        let extra = r#"{"seq":0,"events":[{"kind":"text","text":"a","raw":true}]}"#;
        assert!(serde_json::from_str::<DisplayInputFrame>(extra).is_err());
    }

    #[test]
    fn kind_counts_carry_no_key_or_text() {
        let sent = frame(vec![
            DisplayInputEvent::Text {
                text: "hunter2".into(),
            },
            DisplayInputEvent::Key {
                key: "a".into(),
                pressed: true,
            },
            DisplayInputEvent::Key {
                key: "a".into(),
                pressed: false,
            },
        ]);
        let counts = sent.kind_counts();
        assert_eq!(counts.get("key"), Some(&2));
        assert_eq!(counts.get("text"), Some(&1));
        let rendered = alloc::format!("{counts:?}");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn malformed_frames_are_refused() {
        assert_eq!(
            frame(Vec::new()).validate(),
            Err(DisplayInputFrameError::Empty)
        );
        assert_eq!(
            frame(vec![
                DisplayInputEvent::CredentialEntryEnd;
                MAX_DISPLAY_INPUT_EVENTS + 1
            ])
            .validate(),
            Err(DisplayInputFrameError::TooManyEvents)
        );
        assert_eq!(
            frame(vec![DisplayInputEvent::PointerMove {
                x: MAX_DISPLAY_COORDINATE + 1,
                y: 0
            }])
            .validate(),
            Err(DisplayInputFrameError::CoordinateOutOfRange)
        );
        assert_eq!(
            frame(vec![DisplayInputEvent::Key {
                key: "\u{1b}".to_string(),
                pressed: true
            }])
            .validate(),
            Err(DisplayInputFrameError::InvalidKey)
        );
        assert_eq!(
            frame(vec![DisplayInputEvent::Text {
                text: "x".repeat(MAX_DISPLAY_TEXT_BYTES + 1)
            }])
            .validate(),
            Err(DisplayInputFrameError::InvalidText)
        );
    }

    #[test]
    fn view_and_input_are_distinct_verbs() {
        let mut plan = minimal_plan();
        assert!(display_verbs(&plan).is_empty());

        plan.services = vec![ServiceId::parse(DISPLAY_VIEW_GRANT_SERVICE).unwrap()];
        let view_only = display_verbs(&plan);
        assert_eq!(view_only.len(), 1);
        assert_eq!(view_only[0].as_str(), DISPLAY_VIEW_VERB);

        plan.grants = Some(Grants {
            display_input: Some(DisplayInputGrant::default()),
            ..Grants::default()
        });
        let both: Vec<_> = display_verbs(&plan)
            .iter()
            .map(|verb| verb.as_str().to_string())
            .collect();
        assert_eq!(both, vec![DISPLAY_VIEW_VERB, DISPLAY_INPUT_VERB]);
    }
}
