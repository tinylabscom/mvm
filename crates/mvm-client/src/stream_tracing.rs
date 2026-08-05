//! Republish a workload's stream into the consumer's own `tracing` setup.
//!
//! Adapt at the edge, store verbatim. The record on the wire is hash-chained,
//! so whatever this bridge emits must carry the bytes it was handed
//! *unaltered* — reframe them and the chain proves something other than what
//! is shown. `tracing` has no byte-typed field, so the payload rides as
//! standard base64 in [`PAYLOAD_FIELD`] and [`decode_payload`] gives the
//! original bytes back. That is an encoding, not a reformat: no line
//! splitting, no lossy escaping, and nothing dropped, so `\r` progress
//! output, partial lines, NUL, and non-UTF-8 all survive.
//!
//! `Stdout` and `Stderr` are emitted at the same level. Mapping stderr onto
//! `WARN` would be metadata this bridge invented — the workload said nothing
//! about severity — so the channel travels as the `kind` field and the
//! consumer decides. `Trace` records *do* carry their own level, and that one
//! is honoured because the producer declared it.
//!
//! Feature-gated behind `tracing-bridge`: a consumer that does not want to
//! republish links none of this.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::stream::{StreamKind, StreamRecord, StreamSource};
use tracing::Level;

use crate::stream::{StreamError, StreamReader};

/// Event target every republished record carries, so a subscriber can filter
/// workload output away from mvm's own diagnostics.
pub const TARGET: &str = "mvm::workload";

/// Field carrying the record's payload, base64 of the exact captured bytes.
pub const PAYLOAD_FIELD: &str = "payload_b64";

/// Event name a `Trace` record gets when its payload is not the JSON object
/// the trace convention calls for. Surfaced rather than dropped: a producer
/// emitting malformed control records is a real defect, and silence here
/// would hide it.
pub const UNDECODABLE_TRACE_EVENT: &str = "stream.undecodable_trace";

/// Recover the exact captured bytes from a [`PAYLOAD_FIELD`] value.
pub fn decode_payload(payload_b64: &str) -> Option<Vec<u8>> {
    B64.decode(payload_b64).ok()
}

/// Drain `reader`, emitting one `tracing` event per record.
///
/// Returns when the stream ends. A verification failure stops the bridge and
/// propagates: republishing past a broken chain would put unverified bytes
/// into a consumer's log under the same target as verified ones.
pub fn republish_to_tracing(mut reader: Box<dyn StreamReader>) -> Result<(), StreamError> {
    while let Some(record) = reader.next_record()? {
        republish_record(&record);
    }
    Ok(())
}

/// Emit one record as a `tracing` event.
pub fn republish_record(record: &StreamRecord) {
    let payload_b64 = B64.encode(&record.payload);
    let common = Common {
        seq: record.seq,
        source: source_name(record.source),
        kind: kind_name(record.kind),
        payload_b64: &payload_b64,
    };
    match record.kind {
        StreamKind::Stdout | StreamKind::Stderr => emit_bytes(&common),
        StreamKind::Trace => emit_trace(&common, &record.payload),
    }
}

/// The fields every republished event carries, whatever its kind. Grouped so
/// the per-level match below states one field list instead of five.
struct Common<'a> {
    seq: u64,
    source: &'a str,
    kind: &'a str,
    payload_b64: &'a str,
}

fn emit_bytes(common: &Common<'_>) {
    tracing::event!(
        target: TARGET,
        Level::INFO,
        seq = common.seq,
        source = common.source,
        kind = common.kind,
        payload_b64 = common.payload_b64,
    );
}

/// A `Trace` payload is the JSON object the fd-3 control convention defines:
/// an `event` name, an optional `level`, and whatever else the producer put
/// there. The whole object travels as `detail` because `tracing` field names
/// are static and a record's keys are not.
fn emit_trace(common: &Common<'_>, payload: &[u8]) {
    let parsed: Option<serde_json::Map<String, serde_json::Value>> =
        serde_json::from_slice(payload).ok();
    let Some(object) = parsed else {
        emit_at(Level::WARN, common, UNDECODABLE_TRACE_EVENT, "");
        return;
    };
    let event = object
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let level = object
        .get("level")
        .and_then(serde_json::Value::as_str)
        .map_or(Level::INFO, parse_level);
    let detail = serde_json::to_string(&object).unwrap_or_default();
    emit_at(level, common, event, &detail);
}

/// `tracing`'s level is part of an event's static metadata, so a runtime
/// level means one call site per level. The field list is written once.
fn emit_at(level: Level, common: &Common<'_>, event: &str, detail: &str) {
    macro_rules! emit {
        ($lvl:expr) => {
            tracing::event!(
                target: TARGET,
                $lvl,
                seq = common.seq,
                source = common.source,
                kind = common.kind,
                event = event,
                detail = detail,
                payload_b64 = common.payload_b64,
            )
        };
    }
    match level {
        Level::ERROR => emit!(Level::ERROR),
        Level::WARN => emit!(Level::WARN),
        Level::INFO => emit!(Level::INFO),
        Level::DEBUG => emit!(Level::DEBUG),
        Level::TRACE => emit!(Level::TRACE),
    }
}

/// An unrecognised or absent level reads as `INFO`. Guessing higher would
/// invent severity the producer did not claim.
fn parse_level(raw: &str) -> Level {
    match raw.to_ascii_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

fn source_name(source: StreamSource) -> &'static str {
    match source {
        StreamSource::Console => "console",
        StreamSource::Entrypoint => "entrypoint",
    }
}

fn kind_name(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::Stdout => "stdout",
        StreamKind::Stderr => "stderr",
        StreamKind::Trace => "trace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::{Layer, Registry};

    /// One event this test subscriber saw, flattened to what the assertions
    /// need: its level and its fields as strings.
    #[derive(Debug, Clone)]
    struct CapturedEvent {
        level: Level,
        target: String,
        fields: BTreeMap<String, String>,
    }

    impl CapturedEvent {
        /// The exact bytes the bridge was handed, recovered from the event.
        fn raw_payload(&self) -> Vec<u8> {
            let encoded = self
                .fields
                .get(PAYLOAD_FIELD)
                .expect("every republished event carries the payload field");
            decode_payload(encoded).expect("the payload field must be valid base64")
        }

        fn field(&self, name: &str) -> &str {
            self.fields.get(name).map_or("", String::as_str)
        }
    }

    #[derive(Default)]
    struct FieldCollector(BTreeMap<String, String>);

    impl Visit for FieldCollector {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct CaptureLayer(Arc<Mutex<Vec<CapturedEvent>>>);

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = FieldCollector::default();
            event.record(&mut fields);
            let mut captured = self.0.lock().unwrap_or_else(|e| e.into_inner());
            captured.push(CapturedEvent {
                level: *event.metadata().level(),
                target: event.metadata().target().to_string(),
                fields: fields.0,
            });
        }
    }

    /// Run `body` with a capturing subscriber installed for this thread only,
    /// so a parallel test's events cannot land in these assertions.
    fn capture_tracing_events(body: impl FnOnce()) -> Vec<CapturedEvent> {
        let layer = CaptureLayer::default();
        let sink = Arc::clone(&layer.0);
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, body);
        let events = sink.lock().unwrap_or_else(|e| e.into_inner());
        events.clone()
    }

    fn record(kind: StreamKind, payload: &[u8]) -> StreamRecord {
        StreamRecord {
            seq: 3,
            source: StreamSource::Entrypoint,
            kind,
            host_unix_nanos: 42,
            prev_hash: [0u8; 32],
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn the_bridge_preserves_stdout_bytes_verbatim() {
        // Adapt at the edge, store verbatim: the bridge may format, but the
        // bytes it was handed must survive unaltered into the event it emits.
        let raw = b"progress\r50%\r100%\x00\xff".to_vec();
        let events = capture_tracing_events(|| republish_record(&record(StreamKind::Stdout, &raw)));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].raw_payload(), raw);
    }

    #[test]
    fn the_bridge_preserves_stderr_bytes_verbatim() {
        let raw = b"\x00\x01\x02\xfe\xff no trailing newline".to_vec();
        let events = capture_tracing_events(|| republish_record(&record(StreamKind::Stderr, &raw)));
        assert_eq!(events[0].raw_payload(), raw);
        assert_eq!(events[0].field("kind"), "stderr");
    }

    #[test]
    fn the_channel_travels_as_a_field_not_as_an_invented_severity() {
        let events = capture_tracing_events(|| {
            republish_record(&record(StreamKind::Stdout, b"out"));
            republish_record(&record(StreamKind::Stderr, b"err"));
        });
        assert_eq!(events[0].level, Level::INFO);
        assert_eq!(events[1].level, Level::INFO, "stderr is not a warning");
        assert_eq!(events[0].field("kind"), "stdout");
        assert_eq!(events[1].field("kind"), "stderr");
    }

    #[test]
    fn every_event_carries_the_records_identity() {
        let events = capture_tracing_events(|| republish_record(&record(StreamKind::Stdout, b"x")));
        assert_eq!(events[0].target, TARGET);
        assert_eq!(events[0].field("seq"), "3");
        assert_eq!(events[0].field("source"), "entrypoint");
    }

    #[test]
    fn a_trace_record_becomes_an_event_at_the_level_it_declared() {
        let payload = br#"{"event":"stream.redaction_failed","level":"error","dropped_bytes":40}"#;
        let events =
            capture_tracing_events(|| republish_record(&record(StreamKind::Trace, payload)));
        assert_eq!(events[0].level, Level::ERROR);
        assert_eq!(events[0].field("event"), "stream.redaction_failed");
        assert!(events[0].field("detail").contains("dropped_bytes"));
        assert_eq!(events[0].raw_payload(), payload.to_vec());
    }

    #[test]
    fn a_trace_record_without_a_level_is_not_promoted() {
        let payload = br#"{"event":"workload.checkpoint"}"#;
        let events =
            capture_tracing_events(|| republish_record(&record(StreamKind::Trace, payload)));
        assert_eq!(events[0].level, Level::INFO);
        assert_eq!(events[0].field("event"), "workload.checkpoint");
    }

    #[test]
    fn an_unparseable_trace_record_is_surfaced_not_dropped() {
        let payload = b"\xff\xfe not json";
        let events =
            capture_tracing_events(|| republish_record(&record(StreamKind::Trace, payload)));
        assert_eq!(events.len(), 1, "the record must not vanish");
        assert_eq!(events[0].level, Level::WARN);
        assert_eq!(events[0].field("event"), UNDECODABLE_TRACE_EVENT);
        assert_eq!(
            events[0].raw_payload(),
            payload.to_vec(),
            "even an undecodable record keeps its bytes"
        );
    }

    #[test]
    fn republishing_a_reader_emits_one_event_per_record_in_order() {
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        for seq in 0..3u64 {
            let record = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: format!("line-{seq}").into_bytes(),
            };
            prev = record.hash();
            records.push(record);
        }
        let mut framed = Vec::new();
        crate::stream::write_batch(
            &mut framed,
            &crate::stream::StreamBatch {
                anchor: [0u8; 32],
                records,
                gap: None,
                caught_up: true,
            },
        )
        .expect("frame");

        let events = capture_tracing_events(|| {
            let reader = crate::stream::FramedStreamReader::new(
                // Owned, not borrowed: `Box<dyn StreamReader>` is `'static`,
                // which is what lets `connect_stream` hand one back.
                std::io::Cursor::new(framed.clone()),
                crate::stream::StreamOpts::default(),
            );
            republish_to_tracing(Box::new(reader)).expect("republish");
        });
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].raw_payload(), b"line-0".to_vec());
        assert_eq!(events[2].raw_payload(), b"line-2".to_vec());
    }

    #[test]
    fn a_broken_chain_stops_the_bridge_instead_of_republishing_unverified_bytes() {
        let bad = StreamRecord {
            seq: 0,
            source: StreamSource::Entrypoint,
            kind: StreamKind::Stdout,
            host_unix_nanos: 1,
            // Not the genesis marker and not the anchor the batch declares.
            prev_hash: [9u8; 32],
            payload: b"unverified".to_vec(),
        };
        let mut framed = Vec::new();
        crate::stream::write_batch(
            &mut framed,
            &crate::stream::StreamBatch {
                anchor: [0u8; 32],
                records: vec![bad],
                gap: None,
                caught_up: true,
            },
        )
        .expect("frame");

        let mut outcome = None;
        let events = capture_tracing_events(|| {
            let reader = crate::stream::FramedStreamReader::new(
                // Owned, not borrowed: `Box<dyn StreamReader>` is `'static`,
                // which is what lets `connect_stream` hand one back.
                std::io::Cursor::new(framed.clone()),
                crate::stream::StreamOpts::default(),
            );
            outcome = Some(republish_to_tracing(Box::new(reader)));
        });
        assert!(matches!(outcome, Some(Err(StreamError::Chain(_)))));
        assert!(events.is_empty(), "nothing unverified reached the log");
    }

    #[test]
    fn every_level_spelling_maps_to_a_real_level() {
        assert_eq!(parse_level("ERROR"), Level::ERROR);
        assert_eq!(parse_level("warning"), Level::WARN);
        assert_eq!(parse_level("warn"), Level::WARN);
        assert_eq!(parse_level("Debug"), Level::DEBUG);
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("info"), Level::INFO);
        assert_eq!(parse_level("shouty-nonsense"), Level::INFO);
    }
}
