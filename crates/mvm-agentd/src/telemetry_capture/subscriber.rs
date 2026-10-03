//! Hand-rolled events-only `tracing` collector over the capture core.
//!
//! Built directly on the `tracing` facade: the sealed agent deliberately
//! carries no subscriber crate, so this implements `tracing::Subscriber` by
//! hand. Events become bounded typed records; spans are explicitly
//! unsupported in this slice — `new_span` returns a valid trivial id, the
//! span lifecycle calls are ignored, and no active-span table exists, so
//! span state cannot grow. Nothing here installs the collector.

use std::fmt::{self, Write as _};
use std::sync::Arc;

use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, Attributes, Label, Level, MAX_ATTRIBUTES, Message, RecordBody,
};
use tracing::field::{Field, Visit};

use super::state::{CaptureState, ProducerId};

/// Byte ceiling of the bounded [`Message`] text; pinned by a test below so it
/// cannot drift from the contract type.
const MESSAGE_BYTES: usize = 2048;
/// Byte ceiling of the bounded [`Label`] key; pinned by a test below.
const LABEL_BYTES: usize = 128;

/// Events-only collector feeding the shared capture core. Every event turns
/// into one non-waiting emission attempt for the agent-diagnostics producer;
/// a shed is counted, never retried and never re-reported through `tracing`.
pub struct AgentSubscriber {
    state: Arc<CaptureState>,
}

impl AgentSubscriber {
    /// Wrap the shared capture core. Installation is the caller's decision;
    /// constructing this value has no global effect.
    pub fn new(state: Arc<CaptureState>) -> Self {
        Self { state }
    }
}

impl tracing::Subscriber for AgentSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    // A valid trivial id: span records are unsupported here, so every span
    // shares it and no per-span state is allocated or retained.
    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = BoundedVisitor::new();
        event.record(&mut visitor);
        let (name, name_dropped) = bounded_text::<LABEL_BYTES>(event.metadata().name());
        if name_dropped > 0 {
            visitor.count_truncation(name_dropped);
        }
        let name = match Label::new(name) {
            Ok(name) => Some(name),
            // Unreachable while the pinned ceiling holds; losing the event
            // beats panicking inside an instrumented callback.
            Err(_) => {
                visitor.lost_value();
                None
            }
        };
        let (attributes, truncated_values, truncated_bytes) = visitor.finish();
        self.state.record_truncation(
            ProducerId::AgentDiagnostics,
            truncated_values,
            truncated_bytes,
        );
        let Some(name) = name else {
            return;
        };
        let body = RecordBody::Event {
            context: None,
            level: severity(event.metadata().level()),
            name,
            attributes,
        };
        let producer = ProducerId::AgentDiagnostics;
        // A shed is already counted per producer; a callback can do no more.
        let _ = self.state.emit(producer.default_source(), producer, body);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn severity(level: &tracing::Level) -> Level {
    if *level == tracing::Level::TRACE {
        Level::Trace
    } else if *level == tracing::Level::DEBUG {
        Level::Debug
    } else if *level == tracing::Level::INFO {
        Level::Info
    } else if *level == tracing::Level::WARN {
        Level::Warn
    } else {
        Level::Error
    }
}

/// Truncate to at most `LIMIT` bytes on a character boundary, returning the
/// kept prefix and the number of bytes dropped.
fn bounded_text<const LIMIT: usize>(value: &str) -> (&str, u64) {
    if value.len() <= LIMIT {
        return (value, 0);
    }
    let mut end = LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], (value.len() - end) as u64)
}

/// Bounded field capture: typed primitives pass through, strings truncate
/// into the bounded message text, and `Debug` values format through a
/// fixed-capacity truncating writer — never an unbounded growing buffer.
/// Fields beyond the attribute ceiling are dropped and counted.
struct BoundedVisitor {
    attributes: Vec<Attribute>,
    truncated_values: u64,
    truncated_bytes: u64,
}

impl BoundedVisitor {
    fn new() -> Self {
        Self {
            attributes: Vec::with_capacity(MAX_ATTRIBUTES),
            truncated_values: 0,
            truncated_bytes: 0,
        }
    }

    /// Consume the visitor: the bounded attributes plus the truncated value
    /// and byte tallies its arms accumulated.
    fn finish(self) -> (Attributes, u64, u64) {
        // The push path never exceeds the ceiling, so this cannot refuse.
        let attributes = Attributes::new(self.attributes).unwrap_or_default();
        (attributes, self.truncated_values, self.truncated_bytes)
    }

    fn count_truncation(&mut self, bytes: u64) {
        self.truncated_values += 1;
        self.truncated_bytes += bytes;
    }

    fn lost_value(&mut self) {
        self.truncated_values += 1;
    }

    fn push(&mut self, field: &Field, value: AttributeValue) {
        if self.attributes.len() == MAX_ATTRIBUTES {
            self.lost_value();
            return;
        }
        let (name, dropped) = bounded_text::<LABEL_BYTES>(field.name());
        if dropped > 0 {
            self.count_truncation(dropped);
        }
        match Label::new(name) {
            Ok(key) => self.attributes.push(Attribute { key, value }),
            Err(_) => self.lost_value(),
        }
    }

    fn push_text(&mut self, field: &Field, value: &str) {
        match Message::new(value) {
            Ok(message) => self.push(field, AttributeValue::Text(message)),
            // Unreachable while the pinned ceiling holds; count, don't panic.
            Err(_) => self.lost_value(),
        }
    }
}

impl Visit for BoundedVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let mut writer = TruncatingWriter::new(MESSAGE_BYTES);
        // A `Debug` impl that errors mid-format only loses this one value.
        let _ = write!(writer, "{value:?}");
        if writer.dropped > 0 {
            self.count_truncation(writer.dropped as u64);
        }
        let text = writer.buffer;
        self.push_text(field, &text);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let (kept, dropped) = bounded_text::<MESSAGE_BYTES>(value);
        if dropped > 0 {
            self.count_truncation(dropped);
        }
        self.push_text(field, kept);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, AttributeValue::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, AttributeValue::Signed(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, AttributeValue::Unsigned(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        match AttributeValue::float(value) {
            Ok(value) => self.push(field, value),
            // JSON cannot represent a non-finite value; count it as lost
            // rather than smuggling a lossy substitute.
            Err(_) => self.lost_value(),
        }
    }
}

/// Fixed-capacity `fmt::Write` sink: keeps at most `limit` bytes (respecting
/// character boundaries), counts everything beyond, and never reallocates
/// past its ceiling or aborts the formatter mid-value.
struct TruncatingWriter {
    buffer: String,
    limit: usize,
    dropped: usize,
}

impl TruncatingWriter {
    fn new(limit: usize) -> Self {
        Self {
            buffer: String::with_capacity(limit),
            limit,
            dropped: 0,
        }
    }
}

impl fmt::Write for TruncatingWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        // Once truncation starts, keep a clean prefix: count later chunks
        // instead of splicing fragments after the cut.
        if self.dropped > 0 {
            self.dropped += text.len();
            return Ok(());
        }
        let remaining = self.limit - self.buffer.len();
        let (kept, dropped) = bounded_text_dynamic(text, remaining);
        self.buffer.push_str(kept);
        self.dropped += dropped;
        Ok(())
    }
}

fn bounded_text_dynamic(value: &str, limit: usize) -> (&str, usize) {
    if value.len() <= limit {
        return (value, 0);
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], value.len() - end)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::net::telemetry::outbox::Outbox;
    use mvm_core::protocol::telemetry::{MAX_RECORD_BYTES, SourceKind, TelemetryRecord};

    use super::super::state::SourceLosses;
    use super::*;

    fn capture() -> (Arc<Outbox>, Arc<CaptureState>, AgentSubscriber) {
        let outbox = Arc::new(Outbox::new(8, 8 * MAX_RECORD_BYTES).unwrap());
        let state = Arc::new(CaptureState::new(outbox.clone()).unwrap());
        let subscriber = AgentSubscriber::new(state.clone());
        (outbox, state, subscriber)
    }

    fn drain(outbox: &Outbox) -> Vec<TelemetryRecord> {
        let mut records = Vec::new();
        while let Some(prepared) = outbox.take_for_test().unwrap() {
            records.push(TelemetryRecord::decode(prepared.encoded_for_test()).unwrap());
        }
        records
    }

    fn event_attributes(record: &TelemetryRecord) -> &[Attribute] {
        match record.body() {
            RecordBody::Event { attributes, .. } => attributes.as_slice(),
            other => panic!("expected an event body, got {other:?}"),
        }
    }

    fn value_of<'a>(record: &'a TelemetryRecord, key: &str) -> &'a AttributeValue {
        &event_attributes(record)
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .unwrap_or_else(|| panic!("missing attribute {key}"))
            .value
    }

    fn losses(state: &CaptureState) -> SourceLosses {
        state.losses(ProducerId::AgentDiagnostics)
    }

    #[test]
    fn the_bounded_ceilings_stay_pinned_to_the_contract_types() {
        assert!(Message::new(&"a".repeat(MESSAGE_BYTES)).is_ok());
        assert!(Message::new(&"a".repeat(MESSAGE_BYTES + 1)).is_err());
        assert!(Label::new(&"a".repeat(LABEL_BYTES)).is_ok());
        assert!(Label::new(&"a".repeat(LABEL_BYTES + 1)).is_err());
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // Three-byte characters never divide the limit evenly.
        let text = "あ".repeat(1000);
        let (kept, dropped) = bounded_text::<MESSAGE_BYTES>(&text);
        assert_eq!(kept.len(), 2046);
        assert_eq!(dropped, 954);
        assert!(kept.chars().all(|c| c == 'あ'));
        let (all, none) = bounded_text::<MESSAGE_BYTES>("short");
        assert_eq!((all, none), ("short", 0));
    }

    #[test]
    fn an_event_with_typed_fields_becomes_a_wellformed_record_in_the_queue() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                flag = true,
                count = -7i64,
                size = 9u64,
                ratio = 0.5f64,
                note = "hello",
                "capture works"
            );
        });
        let records = drain(&outbox);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.source(), SourceKind::GuestAgent);
        assert_eq!(record.producer(), 1);
        assert_eq!(record.sequence(), 1);
        let RecordBody::Event { level, context, .. } = record.body() else {
            panic!("expected an event body");
        };
        assert_eq!(*level, Level::Warn);
        assert!(context.is_none());
        assert_eq!(value_of(record, "flag"), &AttributeValue::Bool(true));
        assert_eq!(value_of(record, "count"), &AttributeValue::Signed(-7));
        assert_eq!(value_of(record, "size"), &AttributeValue::Unsigned(9));
        assert!(matches!(
            value_of(record, "ratio"),
            AttributeValue::Float(_)
        ));
        let AttributeValue::Text(note) = value_of(record, "note") else {
            panic!("note must be text");
        };
        assert_eq!(note.as_str(), "hello");
        let AttributeValue::Text(message) = value_of(record, "message") else {
            panic!("message must be text");
        };
        assert_eq!(message.as_str(), "capture works");
    }

    #[test]
    fn string_fields_truncate_at_the_message_ceiling_and_count_loss() {
        let (outbox, state, subscriber) = capture();
        let oversize = "x".repeat(MESSAGE_BYTES + 500);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(note = oversize.as_str(), "bounded");
        });
        let records = drain(&outbox);
        let AttributeValue::Text(note) = value_of(&records[0], "note") else {
            panic!("note must be text");
        };
        assert_eq!(note.as_str().len(), MESSAGE_BYTES);
        let losses = losses(&state);
        assert_eq!(losses.truncated.records, 1);
        assert_eq!(losses.truncated.bytes, 500);
    }

    #[test]
    fn debug_fields_format_through_a_fixed_capacity_writer() {
        struct Chunky;
        impl fmt::Debug for Chunky {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Many small writes, multibyte content: the writer must stay
                // bounded across chunk boundaries, not per call.
                for _ in 0..2000 {
                    f.write_str("ab漢")?;
                }
                Ok(())
            }
        }
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(blob = ?Chunky, "bounded debug");
        });
        let records = drain(&outbox);
        let AttributeValue::Text(blob) = value_of(&records[0], "blob") else {
            panic!("blob must be text");
        };
        assert!(blob.as_str().len() <= MESSAGE_BYTES);
        assert!(blob.as_str().starts_with("ab漢"));
        let losses = losses(&state);
        assert!(losses.truncated.records >= 1);
        // 2000 chunks × 5 bytes, minus what the bounded buffer kept.
        assert_eq!(
            losses.truncated.bytes,
            (10_000 - blob.as_str().len()) as u64
        );
    }

    #[test]
    fn fields_beyond_the_attribute_ceiling_are_dropped_and_counted() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            // 17 named fields plus the message: two past the ceiling of 16.
            tracing::info!(
                f01 = 1u64,
                f02 = 2u64,
                f03 = 3u64,
                f04 = 4u64,
                f05 = 5u64,
                f06 = 6u64,
                f07 = 7u64,
                f08 = 8u64,
                f09 = 9u64,
                f10 = 10u64,
                f11 = 11u64,
                f12 = 12u64,
                f13 = 13u64,
                f14 = 14u64,
                f15 = 15u64,
                f16 = 16u64,
                f17 = 17u64,
                "overflow"
            );
        });
        let records = drain(&outbox);
        assert_eq!(event_attributes(&records[0]).len(), MAX_ATTRIBUTES);
        assert_eq!(losses(&state).truncated.records, 2);
    }

    #[test]
    fn nonfinite_floats_are_counted_as_lost_not_captured() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(bad = f64::NAN, good = 1.0f64, "floats");
        });
        let records = drain(&outbox);
        let attributes = event_attributes(&records[0]);
        assert!(attributes.iter().all(|a| a.key.as_str() != "bad"));
        assert!(matches!(
            value_of(&records[0], "good"),
            AttributeValue::Float(_)
        ));
        assert_eq!(losses(&state).truncated.records, 1);
    }

    #[test]
    fn spans_get_a_valid_trivial_id_and_produce_no_records() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("unsupported", key = 1u64);
            let _entered = span.enter();
        });
        assert!(drain(&outbox).is_empty());
    }

    #[test]
    fn a_saturated_queue_sheds_events_without_a_recursive_report() {
        let outbox = Arc::new(Outbox::new(1, MAX_RECORD_BYTES).unwrap());
        let state = Arc::new(CaptureState::new(outbox.clone()).unwrap());
        let subscriber = AgentSubscriber::new(state.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("first fits");
            tracing::info!("second sheds");
            tracing::info!("third sheds");
        });
        assert_eq!(drain(&outbox).len(), 1);
        let losses = state.losses(ProducerId::AgentDiagnostics);
        assert_eq!(losses.attempts, 3);
        assert_eq!(losses.capacity.records, 2);
        assert_eq!(outbox.losses().capacity.records, 2);
    }
}
