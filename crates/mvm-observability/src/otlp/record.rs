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
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: AttrValue) {
        if field.name() == ERROR_FIELD {
            self.saw_error_field = true;
        }
        if field.name() == MESSAGE_FIELD
            && let AttrValue::Str(message) = &value
        {
            self.message = Some(message.clone());
            return;
        }
        set_attribute(&mut self.attributes, field.name(), value);
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
