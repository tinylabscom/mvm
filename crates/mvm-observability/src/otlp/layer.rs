//! The `tracing` layer that turns spans into OTLP span records.

use std::num::NonZeroU64;
use std::time::SystemTime;

use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::{LookupSpan, SpanRef};

use super::export::SpanQueue;
use super::record::{AttrValue, EventRecord, FieldVisitor, SpanRecord, set_attribute};

/// Per-span state held in the registry's span extensions until close.
struct OtlpSpan {
    trace_id: u128,
    span_id: u64,
    parent_span_id: Option<u64>,
    start: SystemTime,
    visitor: FieldVisitor,
    events: Vec<EventRecord>,
    saw_error_event: bool,
}

/// Exports every span it is enabled for.
///
/// Attach it with a per-layer filter, as with the span-timing layer, so spans
/// are constructed even when the log filter is quieter. Events are exported
/// only as events of an enclosing span; an event outside any span is not a
/// trace signal.
pub struct OtlpLayer {
    queue: SpanQueue,
}

impl OtlpLayer {
    pub(crate) fn new(queue: SpanQueue) -> Self {
        Self { queue }
    }
}

/// A random id that is never zero, since OTLP treats an all-zero id as absent.
fn nonzero_u64() -> u64 {
    loop {
        if let Some(id) = NonZeroU64::new(rand::random()) {
            return id.get();
        }
    }
}

fn nonzero_u128() -> u128 {
    loop {
        let id: u128 = rand::random();
        if id != 0 {
            return id;
        }
    }
}

/// The parent's trace and span id, if the parent is one this layer tracks.
fn parent_ids<S>(span: &SpanRef<'_, S>) -> Option<(u128, u64)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let parent = span.parent()?;
    let extensions = parent.extensions();
    let data = extensions.get::<OtlpSpan>()?;
    Some((data.trace_id, data.span_id))
}

fn code_attributes(visitor: &mut FieldVisitor, metadata: &tracing::Metadata<'_>) {
    let attributes = &mut visitor.attributes;
    set_attribute(
        attributes,
        "code.namespace",
        AttrValue::Str(metadata.target().to_string()),
    );
    if let Some(file) = metadata.file() {
        set_attribute(
            attributes,
            "code.filepath",
            AttrValue::Str(file.to_string()),
        );
    }
    if let Some(line) = metadata.line() {
        set_attribute(attributes, "code.lineno", AttrValue::Int(i64::from(line)));
    }
}

/// An event's span-event form: its message (or, lacking one, its callsite
/// name) as the name, and its other fields plus the level as attributes.
fn event_record(event: &Event<'_>) -> EventRecord {
    let mut visitor = FieldVisitor::default();
    event.record(&mut visitor);
    let metadata = event.metadata();
    set_attribute(
        &mut visitor.attributes,
        "level",
        AttrValue::Str(metadata.level().to_string()),
    );
    EventRecord {
        time: SystemTime::now(),
        name: visitor
            .message
            .unwrap_or_else(|| metadata.name().to_string()),
        attributes: visitor.attributes,
    }
}

impl<S> Layer<S> for OtlpLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let (trace_id, parent_span_id) = match parent_ids(&span) {
            Some((trace_id, parent)) => (trace_id, Some(parent)),
            None => (nonzero_u128(), None),
        };
        let mut visitor = FieldVisitor::default();
        code_attributes(&mut visitor, span.metadata());
        attrs.record(&mut visitor);
        span.extensions_mut().insert(OtlpSpan {
            trace_id,
            span_id: nonzero_u64(),
            parent_span_id,
            start: SystemTime::now(),
            visitor,
            events: Vec::new(),
            saw_error_event: false,
        });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        if let Some(data) = span.extensions_mut().get_mut::<OtlpSpan>() {
            values.record(&mut data.visitor);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.event_span(event) else {
            return;
        };
        let record = event_record(event);
        if let Some(data) = span.extensions_mut().get_mut::<OtlpSpan>() {
            data.saw_error_event |= *event.metadata().level() == Level::ERROR;
            data.events.push(record);
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(data) = span.extensions_mut().remove::<OtlpSpan>() else {
            return;
        };
        let error = data.visitor.saw_error_field || data.saw_error_event;
        // A span has no message; a `message` field on one is an attribute.
        let mut attributes = data.visitor.attributes;
        if let Some(message) = data.visitor.message {
            set_attribute(&mut attributes, "message", AttrValue::Str(message));
        }
        self.queue.offer(SpanRecord {
            trace_id: data.trace_id,
            span_id: data.span_id,
            parent_span_id: data.parent_span_id,
            name: span.metadata().name().to_string(),
            start: data.start,
            end: SystemTime::now(),
            attributes,
            events: data.events,
            error,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::export::{Message, span_queue};
    use super::*;
    use std::sync::mpsc::Receiver;
    use tracing_subscriber::prelude::*;

    /// Run `body` under a subscriber carrying only this layer and return the
    /// spans it closed, in close order.
    fn capture(body: impl FnOnce()) -> Vec<SpanRecord> {
        let (queue, rx) = span_queue(64);
        let subscriber = tracing_subscriber::registry().with(OtlpLayer::new(queue));
        tracing::subscriber::with_default(subscriber, body);
        drain(&rx)
    }

    fn drain(rx: &Receiver<Message>) -> Vec<SpanRecord> {
        rx.try_iter()
            .filter_map(|m| match m {
                Message::Span(span) => Some(*span),
                Message::Shutdown => None,
            })
            .collect()
    }

    fn named<'a>(spans: &'a [SpanRecord], name: &str) -> &'a SpanRecord {
        spans.iter().find(|s| s.name == name).unwrap()
    }

    fn attribute<'a>(span: &'a SpanRecord, key: &str) -> Option<&'a AttrValue> {
        span.attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[test]
    fn nested_spans_share_the_trace_and_link_to_their_parent() {
        let spans = capture(|| {
            let outer = tracing::info_span!("outer");
            let _outer = outer.enter();
            let inner = tracing::info_span!("inner");
            let _inner = inner.enter();
        });
        let outer = named(&spans, "outer");
        let inner = named(&spans, "inner");
        assert_eq!(inner.trace_id, outer.trace_id);
        assert_eq!(inner.parent_span_id, Some(outer.span_id));
        assert_eq!(outer.parent_span_id, None);
        assert_ne!(inner.span_id, outer.span_id);
        assert_ne!(outer.trace_id, 0);
        assert_ne!(outer.span_id, 0);
    }

    #[test]
    fn sibling_root_spans_start_distinct_traces() {
        let spans = capture(|| {
            tracing::info_span!("first").in_scope(|| {});
            tracing::info_span!("second").in_scope(|| {});
        });
        assert_ne!(
            named(&spans, "first").trace_id,
            named(&spans, "second").trace_id
        );
    }

    #[test]
    fn events_attach_to_the_enclosing_span_with_their_fields_and_level() {
        let spans = capture(|| {
            tracing::info_span!("work").in_scope(|| {
                tracing::info!(attempt = 2_u64, "kernel loaded");
            });
            tracing::info!("outside any span");
        });
        assert_eq!(spans.len(), 1);
        let work = named(&spans, "work");
        assert_eq!(work.events.len(), 1);
        let event = &work.events[0];
        assert_eq!(event.name, "kernel loaded");
        assert!(
            event
                .attributes
                .contains(&("attempt".to_string(), AttrValue::Int(2)))
        );
        assert!(
            event
                .attributes
                .contains(&("level".to_string(), AttrValue::Str("INFO".into())))
        );
        assert!(!work.error);
    }

    #[test]
    fn creation_and_recorded_fields_become_typed_attributes() {
        let spans = capture(|| {
            let span = tracing::info_span!(
                "boot",
                vcpus = 2_i64,
                cached = true,
                ratio = 0.5_f64,
                vm = "alpha",
                phase = tracing::field::Empty,
            );
            span.record("phase", "kernel");
            span.record("vcpus", 4_i64);
        });
        let boot = named(&spans, "boot");
        assert_eq!(attribute(boot, "vcpus"), Some(&AttrValue::Int(4)));
        assert_eq!(attribute(boot, "cached"), Some(&AttrValue::Bool(true)));
        assert_eq!(attribute(boot, "ratio"), Some(&AttrValue::Double(0.5)));
        assert_eq!(attribute(boot, "vm"), Some(&AttrValue::Str("alpha".into())));
        assert_eq!(
            attribute(boot, "phase"),
            Some(&AttrValue::Str("kernel".into()))
        );
        assert_eq!(
            attribute(boot, "code.namespace"),
            Some(&AttrValue::Str(module_path!().into()))
        );
    }

    #[test]
    fn an_error_field_or_error_event_marks_the_span_failed() {
        let spans = capture(|| {
            let failed_field = tracing::info_span!("field", error = tracing::field::Empty);
            failed_field.record("error", "disk full");
            drop(failed_field);
            tracing::info_span!("event").in_scope(|| tracing::error!("boom"));
            tracing::info_span!("clean").in_scope(|| tracing::warn!("fine"));
        });
        assert!(named(&spans, "field").error);
        assert!(named(&spans, "event").error);
        assert!(!named(&spans, "clean").error);
    }

    #[test]
    fn a_full_queue_drops_closed_spans_without_blocking_the_instrumented_thread() {
        let (queue, rx) = span_queue(1);
        let counter = queue.clone();
        let subscriber = tracing_subscriber::registry().with(OtlpLayer::new(queue));
        let started = std::time::Instant::now();
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..50 {
                tracing::info_span!("burst").in_scope(|| {});
            }
        });
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(drain(&rx).len(), 1);
        assert_eq!(counter.dropped(), 49);
    }
}
