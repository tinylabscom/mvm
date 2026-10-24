//! Finished spans in exporter-neutral form, and the field visitor that fills
//! them.

use std::fmt;
use std::time::SystemTime;

use tracing::field::{Field, Visit};

/// A typed attribute value, mirroring the scalar subset of OTLP's `AnyValue`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AttrValue {
    Str(String),
    Int(i64),
    Double(f64),
    Bool(bool),
}

/// An ordered attribute list. A `Vec` rather than a map: spans carry a
/// handful of fields, and a re-recorded field replaces in place.
pub(crate) type Attributes = Vec<(String, AttrValue)>;

/// Insert `key`, replacing an earlier value so `Span::record` overwrites.
pub(crate) fn set_attribute(attributes: &mut Attributes, key: &str, value: AttrValue) {
    match attributes.iter_mut().find(|(k, _)| k == key) {
        Some((_, existing)) => *existing = value,
        None => attributes.push((key.to_string(), value)),
    }
}

/// An event recorded inside a span.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EventRecord {
    pub(crate) time: SystemTime,
    pub(crate) name: String,
    pub(crate) attributes: Attributes,
}

/// A closed span, ready to encode.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SpanRecord {
    pub(crate) trace_id: u128,
    pub(crate) span_id: u64,
    pub(crate) parent_span_id: Option<u64>,
    pub(crate) name: String,
    pub(crate) start: SystemTime,
    pub(crate) end: SystemTime,
    pub(crate) attributes: Attributes,
    pub(crate) events: Vec<EventRecord>,
    pub(crate) error: bool,
}

/// The field name `tracing` uses for an event's format-string message.
pub(crate) const MESSAGE_FIELD: &str = "message";
/// A span field under this name marks the span as failed.
pub(crate) const ERROR_FIELD: &str = "error";

/// Attributes one span or event carries. Beyond this a new key is dropped
/// and counted; 128 follows the OpenTelemetry SDK's default attribute limit.
pub(crate) const MAX_ATTRIBUTES: usize = 128;
/// Bytes one string attribute value (or message) keeps; the rest is cut at a
/// character boundary. Bounds what one field can add to held span state and
/// to an export body.
pub(crate) const MAX_ATTR_VALUE_BYTES: usize = 4096;
/// The attribute recording how many attributes were dropped at capture.
pub(crate) const DROPPED_ATTRIBUTES_ATTR: &str = "attributes.dropped";

/// Cut `value` to at most [`MAX_ATTR_VALUE_BYTES`], on a character boundary.
pub(crate) fn bounded_string(mut value: String) -> String {
    if value.len() > MAX_ATTR_VALUE_BYTES {
        let mut end = MAX_ATTR_VALUE_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

/// Collects `tracing` field values into typed attributes.
///
/// Integers outside `i64` and non-finite floats are carried as strings: OTLP's
/// integer is signed 64-bit, and JSON has no representation for NaN or
/// infinity.
#[derive(Default)]
pub(crate) struct FieldVisitor {
    pub(crate) attributes: Attributes,
    pub(crate) message: Option<String>,
    pub(crate) saw_error_field: bool,
    /// New keys refused because the attribute set was full.
    pub(crate) dropped_attributes: u64,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: AttrValue) {
        if field.name() == ERROR_FIELD {
            self.saw_error_field = true;
        }
        let value = match value {
            AttrValue::Str(text) => AttrValue::Str(bounded_string(text)),
            other => other,
        };
        if field.name() == MESSAGE_FIELD
            && let AttrValue::Str(message) = &value
        {
            self.message = Some(message.clone());
            return;
        }
        let known = self.attributes.iter().any(|(k, _)| k == field.name());
        if !known && self.attributes.len() >= MAX_ATTRIBUTES {
            self.dropped_attributes += 1;
            return;
        }
        set_attribute(&mut self.attributes, field.name(), value);
    }

    /// Record the dropped-attribute count on `attributes`, when there was one.
    pub(crate) fn note_dropped(dropped: u64, attributes: &mut Attributes) {
        if dropped > 0 {
            let dropped = i64::try_from(dropped).unwrap_or(i64::MAX);
            set_attribute(attributes, DROPPED_ATTRIBUTES_ATTR, AttrValue::Int(dropped));
        }
    }
}

/// An integer as OTLP's signed 64-bit value when it fits, else its decimal
/// string, so a large value is carried exactly rather than wrapped.
fn integer<T: TryInto<i64> + ToString + Copy>(value: T) -> AttrValue {
    value
        .try_into()
        .map_or_else(|_| AttrValue::Str(value.to_string()), AttrValue::Int)
}

impl Visit for FieldVisitor {
    fn record_f64(&mut self, field: &Field, value: f64) {
        let value = if value.is_finite() {
            AttrValue::Double(value)
        } else {
            AttrValue::Str(value.to_string())
        };
        self.put(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, AttrValue::Int(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, integer(value));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, integer(value));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, integer(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, AttrValue::Bool(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, AttrValue::Str(value.to_string()));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, AttrValue::Str(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, AttrValue::Str(format!("{value:?}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_outside_i64_are_carried_as_exact_strings() {
        assert_eq!(integer(42_u64), AttrValue::Int(42));
        assert_eq!(integer(u64::MAX), AttrValue::Str(u64::MAX.to_string()));
        assert_eq!(integer(i128::MIN), AttrValue::Str(i128::MIN.to_string()));
    }

    #[test]
    fn string_values_are_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_ATTR_VALUE_BYTES);
        let cut = bounded_string(long);
        assert!(cut.len() <= MAX_ATTR_VALUE_BYTES);
        assert!(cut.chars().all(|c| c == 'é'));
        assert_eq!(bounded_string("short".into()), "short");
    }

    #[test]
    fn a_re_recorded_attribute_replaces_the_earlier_value() {
        let mut attributes = Attributes::new();
        set_attribute(&mut attributes, "k", AttrValue::Int(1));
        set_attribute(&mut attributes, "other", AttrValue::Bool(true));
        set_attribute(&mut attributes, "k", AttrValue::Int(2));
        assert_eq!(
            attributes,
            vec![
                ("k".to_string(), AttrValue::Int(2)),
                ("other".to_string(), AttrValue::Bool(true)),
            ]
        );
    }
}
