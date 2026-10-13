//! Hand-rolled `tracing` collector over the capture core.
//!
//! Built directly on the `tracing` facade: the sealed agent deliberately
//! carries no subscriber crate, so this implements `tracing::Subscriber` by
//! hand. Events and spans become bounded typed records for the
//! agent-diagnostics producer. Nothing here installs the collector.
//!
//! Every callback keeps the capture core's guarantees. None waits: the
//! active-span table is preallocated and changed only by atomic exchange
//! (see [`super::span_table`]), the per-thread entered-span stack is a fixed
//! array, and emission is one non-waiting offer. Nothing grows: a full table
//! or a full stack sheds and counts instead. And nothing here emits through
//! `tracing`, so capture cannot recurse into itself.
//!
//! What a span produces:
//!
//! * open: one `span_open` with a fresh span id, the parent's trace (or a new
//!   trace for a root span), the parent's context and the initial fields;
//! * `Span::record`: one `span_update` carrying the recorded fields;
//! * the last handle dropped: one `span_close`, with outcome `error` when an
//!   `error` field was recorded on the span and `unset` otherwise;
//! * an event inside an entered span carries that span's context.
//!
//! A follows-from relationship declared after open cannot be represented:
//! the record contract carries links only on `span_open`, which has already
//! left by then. Rather than invent a record, the subscriber counts each one
//! as a truncated value, so the loss summary shows it was dropped.
//!
//! The entered-span stack is the subscriber's own: it decides the parent of
//! a contextual span and the context of a contextual event. `current_span`
//! keeps the facade's default (unknown), because answering it needs a type
//! only `tracing-core` exports and the sealed agent does not depend on that
//! crate directly; so `Span::current()` in the guest reports no span, which
//! does not affect what capture records.
//!
//! A span the table has no room for gets an id that names no slot. Its open
//! is counted as a capacity shed (a spent sequence number, so the host sees
//! the gap), and its updates, close, and the context of events inside it are
//! not produced — an event inside it is still captured, without context,
//! because attaching an enclosing span's context would misattribute it.

use std::cell::RefCell;
use std::fmt::{self, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::protocol::telemetry::{
    Attribute, AttributeValue, Attributes, BoundedList, Label, Level, MAX_ATTRIBUTES, Message,
    RecordBody, SpanOutcome, TraceReference,
};
use mvm_core::trace_context::TraceContext;
use tracing::field::{Field, Visit};
use tracing::span;

use super::emit::ShedReason;
use super::span_table::{
    DEFAULT_SPAN_SLOTS, IdSource, Release, SlotRef, SpanTable, UNTRACKED_SPAN,
};
use super::state::{CaptureState, ProducerId};

/// Byte ceiling of the bounded [`Message`] text; pinned by a test below so it
/// cannot drift from the contract type.
const MESSAGE_BYTES: usize = 2048;
/// Byte ceiling of the bounded [`Label`] key; pinned by a test below.
const LABEL_BYTES: usize = 128;
/// Spans one thread can have entered at once and still be tracked.
const STACK_DEPTH: usize = 32;

/// Distinguishes collectors sharing a thread's entered-span stack.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Collector feeding the shared capture core. Every record is one
/// non-waiting emission attempt for the agent-diagnostics producer; a shed is
/// counted, never retried and never re-reported through `tracing`.
pub struct AgentSubscriber {
    state: Arc<CaptureState>,
    spans: SpanTable,
    ids: IdSource,
    instance: u64,
}

/// Where a new span's parent came from.
enum Parent {
    /// A root span: no parent was asked for.
    None,
    /// A tracked parent.
    Tracked(TraceContext),
    /// A parent was asked for but capture is not tracking it.
    Lost,
}

impl AgentSubscriber {
    /// Wrap the shared capture core. Installation is the caller's decision;
    /// constructing this value has no global effect.
    pub fn new(state: Arc<CaptureState>) -> Self {
        Self::with_span_slots(state, DEFAULT_SPAN_SLOTS)
    }

    fn with_span_slots(state: Arc<CaptureState>, slots: usize) -> Self {
        Self {
            state,
            spans: SpanTable::with_slots(slots),
            ids: IdSource::default(),
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
        }
    }

    fn slot(&self, id: &span::Id) -> Option<SlotRef> {
        SlotRef::from_id_bits(id.into_u64(), self.spans.capacity())
    }

    fn context_of(&self, id: &span::Id) -> Option<TraceContext> {
        self.spans.context(self.slot(id)?)
    }

    /// The parent a span or event names: explicit, contextual (the innermost
    /// span this thread entered under this collector), or none.
    fn parent(&self, explicit: Option<&span::Id>, contextual: bool) -> Parent {
        let id = match explicit {
            Some(id) => id.into_u64(),
            None if contextual => match innermost(self.instance) {
                Some(bits) => bits,
                None => return Parent::None,
            },
            None => return Parent::None,
        };
        SlotRef::from_id_bits(id, self.spans.capacity())
            .and_then(|slot| self.spans.context(slot))
            .map_or(Parent::Lost, Parent::Tracked)
    }

    fn emit(&self, body: RecordBody) {
        let producer = ProducerId::AgentDiagnostics;
        // A shed is already counted per producer; a callback can do no more.
        let _ = self.state.emit(producer.default_source(), producer, body);
    }

    fn count_lost(&self, values: u64) {
        self.state
            .record_truncation(ProducerId::AgentDiagnostics, values, 0);
    }

    /// Fold a visitor's tallies into the producer's truncation counters.
    fn finish(&self, visitor: BoundedVisitor) -> Attributes {
        let (attributes, truncated_values, truncated_bytes) = visitor.finish();
        self.state.record_truncation(
            ProducerId::AgentDiagnostics,
            truncated_values,
            truncated_bytes,
        );
        attributes
    }
}

/// The wire form of a context the subscriber minted or read back. Every
/// context it holds is nonzero by construction, so this only fails if that
/// invariant broke; the caller then drops the record rather than panic.
fn reference(context: TraceContext) -> Option<TraceReference> {
    TraceReference::new(context).ok()
}

impl tracing::Subscriber for AgentSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &span::Attributes<'_>) -> span::Id {
        let untracked = span::Id::from_u64(UNTRACKED_SPAN);
        let producer = ProducerId::AgentDiagnostics;
        let parent = self.parent(attributes.parent(), attributes.is_contextual());
        let Some((epoch, _)) = self.state.identity_now() else {
            let _ = self.state.shed_unbuilt(producer, ShedReason::Unavailable);
            return untracked;
        };
        let parent_context = match parent {
            Parent::Tracked(context) => Some(context),
            Parent::None | Parent::Lost => None,
        };
        let context = self
            .ids
            .mint(epoch.into(), parent_context.map(|parent| parent.trace_id));
        let Some(slot) = self.spans.open(context) else {
            let _ = self.state.shed_unbuilt(producer, ShedReason::Capacity);
            return untracked;
        };
        let mut visitor = BoundedVisitor::new();
        attributes.record(&mut visitor);
        if visitor.reported_error {
            self.spans.mark_failed(slot);
        }
        if matches!(parent, Parent::Lost) {
            // The span is captured as a root of a fresh trace; the link to the
            // parent capture never tracked is the value lost.
            visitor.lost_value();
        }
        let name = visitor.label(attributes.metadata().name());
        let attributes = self.finish(visitor);
        let id = span::Id::from_u64(slot.id_bits());
        // The span stays tracked even if its open sheds: its sequence gap
        // already tells the host a record is missing, and its children and
        // events keep their correlation.
        let (Some(name), Some(context)) = (name, reference(context)) else {
            return id;
        };
        self.emit(RecordBody::SpanOpen {
            context,
            parent: parent_context.and_then(reference),
            name,
            attributes,
            links: BoundedList::default(),
        });
        id
    }

    fn record(&self, span: &span::Id, values: &span::Record<'_>) {
        let Some(slot) = self.slot(span) else {
            return;
        };
        let Some(context) = self.spans.context(slot).and_then(reference) else {
            return;
        };
        let mut visitor = BoundedVisitor::new();
        values.record(&mut visitor);
        if visitor.reported_error {
            self.spans.mark_failed(slot);
        }
        let attributes = self.finish(visitor);
        if attributes.as_slice().is_empty() {
            return;
        }
        self.emit(RecordBody::SpanUpdate {
            context,
            attributes,
        });
    }

    // See the module documentation: links ride only on `span_open`, so a
    // follows-from declared later is counted as lost rather than carried.
    fn record_follows_from(&self, span: &span::Id, _follows: &span::Id) {
        if self.context_of(span).is_some() {
            self.count_lost(1);
        }
    }

    fn event(&self, event: &tracing::Event<'_>) {
        let context = match self.parent(event.parent(), event.is_contextual()) {
            Parent::Tracked(context) => reference(context),
            Parent::None | Parent::Lost => None,
        };
        let mut visitor = BoundedVisitor::new();
        event.record(&mut visitor);
        let name = visitor.label(event.metadata().name());
        let attributes = self.finish(visitor);
        let Some(name) = name else {
            return;
        };
        self.emit(RecordBody::Event {
            context,
            level: severity(event.metadata().level()),
            name,
            attributes,
        });
    }

    fn enter(&self, span: &span::Id) {
        if !push_entered(self.instance, span.into_u64()) {
            // Deeper than the stack tracks: events in here are attributed to
            // the innermost span still on it.
            self.count_lost(1);
        }
    }

    fn exit(&self, span: &span::Id) {
        pop_entered(self.instance, span.into_u64());
    }

    fn clone_span(&self, span: &span::Id) -> span::Id {
        if let Some(slot) = self.slot(span) {
            self.spans.retain(slot);
        }
        span.clone()
    }

    fn try_close(&self, span: span::Id) -> bool {
        let Some(slot) = self.slot(&span) else {
            return false;
        };
        let Release::Closed { context, failed } = self.spans.release(slot) else {
            return false;
        };
        if let Some(context) = reference(context) {
            let outcome = if failed {
                SpanOutcome::Error
            } else {
                SpanOutcome::Unset
            };
            self.emit(RecordBody::SpanClose { context, outcome });
        }
        true
    }
}

/// One thread's entered spans, innermost last. Shared by every collector on
/// the thread, so each entry names the collector that entered it.
struct EnteredStack {
    entries: [(u64, u64); STACK_DEPTH],
    len: usize,
    /// Enters past the depth limit not yet matched by an exit.
    overflow: usize,
}

thread_local! {
    static ENTERED: RefCell<EnteredStack> = const {
        RefCell::new(EnteredStack {
            entries: [(0, 0); STACK_DEPTH],
            len: 0,
            overflow: 0,
        })
    };
}

/// Run `f` on this thread's stack. `None` when the stack is unavailable —
/// thread teardown, or a re-entrant callback already holding it — in which
/// case the caller proceeds as if no span were entered rather than wait.
fn with_entered<T>(f: impl FnOnce(&mut EnteredStack) -> T) -> Option<T> {
    ENTERED
        .try_with(|cell| cell.try_borrow_mut().ok().map(|mut stack| f(&mut stack)))
        .ok()
        .flatten()
}

/// Push an entered span; `false` when the stack is full.
fn push_entered(instance: u64, id: u64) -> bool {
    with_entered(|stack| {
        if stack.len == STACK_DEPTH {
            stack.overflow += 1;
            return false;
        }
        stack.entries[stack.len] = (instance, id);
        stack.len += 1;
        true
    })
    .unwrap_or(false)
}

/// Remove the innermost entry for this span. Exits pair with enters
/// innermost-first, so an outstanding overflow is what an exit closes first.
fn pop_entered(instance: u64, id: u64) {
    with_entered(|stack| {
        if stack.overflow > 0 {
            stack.overflow -= 1;
            return;
        }
        let len = stack.len;
        if let Some(at) = stack.entries[..len]
            .iter()
            .rposition(|entry| *entry == (instance, id))
        {
            stack.entries.copy_within(at + 1..len, at);
            stack.len -= 1;
        }
    });
}

/// The innermost span this collector entered on this thread.
fn innermost(instance: u64) -> Option<u64> {
    with_entered(|stack| {
        stack.entries[..stack.len]
            .iter()
            .rev()
            .find(|(owner, _)| *owner == instance)
            .map(|(_, id)| *id)
    })
    .flatten()
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
    /// An `error` field was recorded with any value but `false`: the
    /// `tracing` convention for marking a span failed.
    reported_error: bool,
}

/// The field name that marks a span failed.
const ERROR_FIELD: &str = "error";

impl BoundedVisitor {
    fn new() -> Self {
        Self {
            attributes: Vec::with_capacity(MAX_ATTRIBUTES),
            truncated_values: 0,
            truncated_bytes: 0,
            reported_error: false,
        }
    }

    /// Bound a span or event name into a label, counting what was cut.
    /// `None` only if the pinned ceiling stopped holding; the caller then
    /// drops the record rather than panic inside an instrumented callback.
    fn label(&mut self, name: &str) -> Option<Label> {
        let (name, dropped) = bounded_text::<LABEL_BYTES>(name);
        if dropped > 0 {
            self.count_truncation(dropped);
        }
        let label = Label::new(name).ok();
        if label.is_none() {
            self.lost_value();
        }
        label
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
        if field.name() == ERROR_FIELD && value != AttributeValue::Bool(false) {
            self.reported_error = true;
        }
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
        capture_with_slots(DEFAULT_SPAN_SLOTS)
    }

    fn capture_with_slots(slots: usize) -> (Arc<Outbox>, Arc<CaptureState>, AgentSubscriber) {
        let outbox = Arc::new(Outbox::new(128, 128 * MAX_RECORD_BYTES).unwrap());
        let state = Arc::new(CaptureState::new(outbox.clone()).unwrap());
        let subscriber = AgentSubscriber::with_span_slots(state.clone(), slots);
        (outbox, state, subscriber)
    }

    /// One record body, reduced to what span tests compare.
    #[derive(Debug, Clone, PartialEq)]
    enum Seen {
        Open {
            name: String,
            context: TraceContext,
            parent: Option<TraceContext>,
            attributes: Vec<String>,
        },
        Update {
            context: TraceContext,
            attributes: Vec<String>,
        },
        Close {
            context: TraceContext,
            outcome: SpanOutcome,
        },
        Event {
            message: String,
            context: Option<TraceContext>,
        },
    }

    fn keys(attributes: &Attributes) -> Vec<String> {
        attributes
            .as_slice()
            .iter()
            .map(|attribute| attribute.key.as_str().to_string())
            .collect()
    }

    fn seen(outbox: &Outbox) -> Vec<Seen> {
        drain(outbox)
            .iter()
            .map(|record| match record.body() {
                RecordBody::SpanOpen {
                    context,
                    parent,
                    name,
                    attributes,
                    links,
                } => {
                    assert!(links.as_slice().is_empty());
                    Seen::Open {
                        name: name.as_str().to_string(),
                        context: context.context(),
                        parent: parent.map(TraceReference::context),
                        attributes: keys(attributes),
                    }
                }
                RecordBody::SpanUpdate {
                    context,
                    attributes,
                } => Seen::Update {
                    context: context.context(),
                    attributes: keys(attributes),
                },
                RecordBody::SpanClose { context, outcome } => Seen::Close {
                    context: context.context(),
                    outcome: *outcome,
                },
                RecordBody::Event { context, .. } => {
                    let AttributeValue::Text(message) = value_of(record, "message") else {
                        panic!("message must be text");
                    };
                    Seen::Event {
                        message: message.as_str().to_string(),
                        context: context.map(TraceReference::context),
                    }
                }
                other => panic!("unexpected record {other:?}"),
            })
            .collect()
    }

    fn opened(seen: &[Seen], wanted: &str) -> (TraceContext, Option<TraceContext>) {
        seen.iter()
            .find_map(|record| match record {
                Seen::Open {
                    name,
                    context,
                    parent,
                    ..
                } if name == wanted => Some((*context, *parent)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no span_open for {wanted} in {seen:?}"))
    }

    fn event_context(seen: &[Seen], wanted: &str) -> Option<TraceContext> {
        seen.iter()
            .find_map(|record| match record {
                Seen::Event { message, context } if message == wanted => Some(*context),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no event {wanted} in {seen:?}"))
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
    fn a_span_opens_and_closes_with_its_parent_linkage() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let parent = tracing::info_span!("parent", key = 1u64);
            let _in_parent = parent.enter();
            let child = tracing::info_span!("child");
            drop(child);
        });
        let seen = seen(&outbox);
        let (parent, grandparent) = opened(&seen, "parent");
        let (child, child_parent) = opened(&seen, "child");
        assert_eq!(grandparent, None);
        assert_eq!(child_parent, Some(parent));
        assert_eq!(child.trace_id, parent.trace_id);
        assert_ne!(child.span_id, parent.span_id);
        assert_eq!(
            seen,
            vec![
                Seen::Open {
                    name: "parent".into(),
                    context: parent,
                    parent: None,
                    attributes: vec!["key".into()],
                },
                Seen::Open {
                    name: "child".into(),
                    context: child,
                    parent: Some(parent),
                    attributes: vec![],
                },
                Seen::Close {
                    context: child,
                    outcome: SpanOutcome::Unset,
                },
                Seen::Close {
                    context: parent,
                    outcome: SpanOutcome::Unset,
                },
            ]
        );
        assert_eq!(
            losses(&state),
            SourceLosses {
                attempts: 4,
                ..SourceLosses::default()
            }
        );
    }

    #[test]
    fn nested_spans_share_their_roots_trace_and_separate_roots_do_not() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let root = tracing::info_span!("root");
            let middle = tracing::info_span!(parent: &root, "middle");
            let _leaf = tracing::info_span!(parent: &middle, "leaf");
            let _other = tracing::info_span!("other");
        });
        let seen = seen(&outbox);
        let (root, _) = opened(&seen, "root");
        let (middle, middle_parent) = opened(&seen, "middle");
        let (leaf, leaf_parent) = opened(&seen, "leaf");
        let (other, other_parent) = opened(&seen, "other");
        assert_eq!(middle_parent, Some(root));
        assert_eq!(leaf_parent, Some(middle));
        assert_eq!(middle.trace_id, root.trace_id);
        assert_eq!(leaf.trace_id, root.trace_id);
        assert_eq!(other_parent, None);
        assert_ne!(other.trace_id, root.trace_id);
    }

    #[test]
    fn an_event_inside_an_entered_span_carries_its_context_and_one_outside_does_not() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("before");
            let span = tracing::info_span!("work");
            span.in_scope(|| tracing::info!("inside"));
            tracing::info!(parent: &span, "explicit");
            tracing::info!(parent: None, "detached");
            tracing::info!("after");
        });
        let seen = seen(&outbox);
        let (work, _) = opened(&seen, "work");
        assert_eq!(event_context(&seen, "before"), None);
        assert_eq!(event_context(&seen, "inside"), Some(work));
        assert_eq!(event_context(&seen, "explicit"), Some(work));
        assert_eq!(event_context(&seen, "detached"), None);
        assert_eq!(event_context(&seen, "after"), None);
    }

    #[test]
    fn recorded_fields_become_a_span_update() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("work", bytes = tracing::field::Empty);
            span.record("bytes", 42u64);
        });
        let seen = seen(&outbox);
        let (work, _) = opened(&seen, "work");
        assert!(seen.contains(&Seen::Update {
            context: work,
            attributes: vec!["bytes".into()],
        }));
    }

    #[test]
    fn an_error_field_closes_the_span_with_an_error_outcome() {
        let (outbox, _state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let opened_failed = tracing::info_span!("opened", error = "refused");
            let recorded_failed = tracing::info_span!("recorded", error = tracing::field::Empty);
            recorded_failed.record("error", "timed out");
            let not_failed = tracing::info_span!("cleared", error = false);
            drop((opened_failed, recorded_failed, not_failed));
        });
        let seen = seen(&outbox);
        for (name, outcome) in [
            ("opened", SpanOutcome::Error),
            ("recorded", SpanOutcome::Error),
            ("cleared", SpanOutcome::Unset),
        ] {
            let (context, _) = opened(&seen, name);
            assert!(
                seen.contains(&Seen::Close { context, outcome }),
                "{name} must close {outcome:?}: {seen:?}"
            );
        }
    }

    #[test]
    fn a_full_span_table_sheds_the_open_counts_it_and_never_misattributes_events() {
        let (outbox, state, subscriber) = capture_with_slots(1);
        tracing::subscriber::with_default(subscriber, || {
            let tracked = tracing::info_span!("tracked");
            let _in_tracked = tracked.enter();
            let untracked = tracing::info_span!("untracked", key = 1u64);
            untracked.record("key", 2u64);
            let _in_untracked = untracked.enter();
            tracing::info!("inside untracked");
        });
        let seen = seen(&outbox);
        let (tracked, _) = opened(&seen, "tracked");
        assert!(
            !seen
                .iter()
                .any(|record| matches!(record, Seen::Open { name, .. } if name == "untracked"))
        );
        // Not the enclosing tracked span's context: that would claim the
        // event happened directly in a span it did not.
        assert_eq!(event_context(&seen, "inside untracked"), None);
        assert_eq!(
            seen.iter()
                .filter(|record| matches!(record, Seen::Update { .. } | Seen::Close { .. }))
                .collect::<Vec<_>>(),
            vec![&Seen::Close {
                context: tracked,
                outcome: SpanOutcome::Unset,
            }]
        );
        let losses = losses(&state);
        assert_eq!(losses.capacity.records, 1);
        // tracked open, shed untracked open, the event, tracked close.
        assert_eq!(losses.attempts, 4);
    }

    #[test]
    fn a_span_under_an_untracked_parent_starts_a_fresh_trace_and_counts_the_lost_link() {
        let (outbox, state, subscriber) = capture_with_slots(1);
        tracing::subscriber::with_default(subscriber, || {
            let first = tracing::info_span!("first");
            let untracked = tracing::info_span!("untracked");
            drop(first);
            let _in_untracked = untracked.enter();
            let _orphan = tracing::info_span!("orphan");
        });
        let seen = seen(&outbox);
        let (first, _) = opened(&seen, "first");
        let (orphan, orphan_parent) = opened(&seen, "orphan");
        assert_eq!(orphan_parent, None);
        assert_ne!(orphan.trace_id, first.trace_id);
        assert_eq!(losses(&state).truncated.records, 1);
    }

    #[test]
    fn a_span_id_kept_past_its_close_is_ignored_once_the_slot_is_reused() {
        let (outbox, _state, subscriber) = capture_with_slots(1);
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            let first = tracing::info_span!("first");
            let stale = first.id().unwrap();
            drop(first);
            let second = tracing::info_span!("second");
            assert_ne!(second.id().unwrap(), stale);
            // A stale clone must not pin, and a stale close must not end,
            // the span now holding the slot.
            let _ = dispatch.clone_span(&stale);
            assert!(!dispatch.try_close(stale.clone()));
            assert!(!dispatch.try_close(stale.clone()));
            dispatch.enter(&stale);
            tracing::info!("in stale");
            dispatch.exit(&stale);
            tracing::info!(parent: stale.clone(), "explicit stale");
            second.in_scope(|| tracing::info!("in second"));
        });
        let seen = seen(&outbox);
        let (second, _) = opened(&seen, "second");
        assert_eq!(event_context(&seen, "in stale"), None);
        assert_eq!(event_context(&seen, "explicit stale"), None);
        assert_eq!(event_context(&seen, "in second"), Some(second));
        let closes: Vec<_> = seen
            .iter()
            .filter(|record| matches!(record, Seen::Close { .. }))
            .collect();
        assert_eq!(closes.len(), 2, "first and second close once each");
        assert_eq!(
            closes[1],
            &Seen::Close {
                context: second,
                outcome: SpanOutcome::Unset,
            }
        );
    }

    #[test]
    fn a_contended_queue_sheds_the_span_open_without_waiting_and_keeps_tracking() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            // This thread holds the queue lock itself: a callback that waited
            // for it would deadlock here instead of returning.
            let held = state.outbox().hold_queue_lock_for_test();
            let span = tracing::info_span!("contended");
            drop(held);
            span.in_scope(|| tracing::info!("inside contended"));
        });
        let seen = seen(&outbox);
        assert!(
            !seen
                .iter()
                .any(|record| matches!(record, Seen::Open { .. }))
        );
        let context = event_context(&seen, "inside contended").expect("still tracked");
        assert!(seen.contains(&Seen::Close {
            context,
            outcome: SpanOutcome::Unset,
        }));
        let losses = losses(&state);
        assert_eq!(losses.contention.records, 1);
        assert_eq!(losses.attempts, 3);
    }

    #[test]
    fn each_thread_attributes_events_to_its_own_entered_span() {
        let (outbox, _state, subscriber) = capture();
        let dispatch = tracing::Dispatch::new(subscriber);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for name in ["left", "right"] {
                let dispatch = dispatch.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        let span = tracing::info_span!("thread", side = name);
                        let _entered = span.enter();
                        // Both threads are inside their spans at once.
                        barrier.wait();
                        tracing::info!(side = name, "{name} event");
                        barrier.wait();
                    });
                });
            }
        });
        let records = drain(&outbox);
        let mut span_of_side = std::collections::HashMap::new();
        for record in &records {
            if let RecordBody::SpanOpen {
                context,
                attributes,
                ..
            } = record.body()
            {
                let AttributeValue::Text(side) = &attributes.as_slice()[0].value else {
                    panic!("side must be text");
                };
                span_of_side.insert(side.as_str().to_string(), context.context());
            }
        }
        for record in &records {
            if let RecordBody::Event { context, .. } = record.body() {
                let AttributeValue::Text(side) = value_of(record, "side") else {
                    panic!("side must be text");
                };
                assert_eq!(
                    context.map(TraceReference::context),
                    Some(span_of_side[side.as_str()])
                );
            }
        }
        assert_eq!(span_of_side.len(), 2);
    }

    #[test]
    fn a_follows_from_after_open_is_counted_as_a_lost_value() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let cause = tracing::info_span!("cause");
            let effect = tracing::info_span!("effect");
            effect.follows_from(&cause);
        });
        assert_eq!(losses(&state).truncated.records, 1);
        let seen = seen(&outbox);
        opened(&seen, "effect");
    }

    #[test]
    fn entering_deeper_than_the_stack_counts_the_overflow_and_unwinds_cleanly() {
        let (outbox, state, subscriber) = capture();
        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!("outer");
            let _in_outer = outer.enter();
            let spans: Vec<_> = (0..STACK_DEPTH + 2)
                .map(|_| tracing::info_span!(parent: None, "deep"))
                .collect();
            let guards: Vec<_> = spans.iter().map(|span| span.enter()).collect();
            // Exits pair with enters innermost-first, as scoped guards do.
            for guard in guards.into_iter().rev() {
                drop(guard);
            }
            tracing::info!("back in outer");
        });
        assert_eq!(losses(&state).truncated.records, 3);
        let seen = seen(&outbox);
        let (outer, _) = opened(&seen, "outer");
        assert_eq!(event_context(&seen, "back in outer"), Some(outer));
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
