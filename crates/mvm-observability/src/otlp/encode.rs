//! OTLP/HTTP JSON encoding of finished spans.
//!
//! Follows the protobuf JSON mapping OTLP specifies: camelCase field names,
//! trace and span ids as lowercase hex rather than base64, 64-bit integers
//! (timestamps, `intValue`) as decimal strings, and enums as integers.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::record::{AttrValue, Attributes, EventRecord, SpanRecord};

/// Instrumentation scope reported for every span.
const SCOPE_NAME: &str = "mvm-observability";

/// `SPAN_KIND_INTERNAL`: every span here is in-process work, not an RPC edge.
const SPAN_KIND_INTERNAL: u8 = 1;
const STATUS_CODE_UNSET: u8 = 0;
const STATUS_CODE_ERROR: u8 = 2;

/// Process-level attributes attached once per export request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceInfo {
    pub(crate) service_name: String,
    pub(crate) service_version: String,
    pub(crate) process_pid: u32,
}

impl ResourceInfo {
    /// The resource for this process under `service_name`.
    pub(crate) fn current(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            process_pid: std::process::id(),
        }
    }

    fn attributes(&self) -> Vec<KeyValue> {
        vec![
            KeyValue::new("service.name", &AttrValue::Str(self.service_name.clone())),
            KeyValue::new(
                "service.version",
                &AttrValue::Str(self.service_version.clone()),
            ),
            KeyValue::new("process.pid", &AttrValue::Int(i64::from(self.process_pid))),
        ]
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportTraceServiceRequest {
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: Vec<ScopeSpans>,
}

#[derive(Serialize)]
struct Resource {
    attributes: Vec<KeyValue>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSpans {
    scope: Scope,
    spans: Vec<Span>,
}

#[derive(Serialize)]
struct Scope {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Span {
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    name: String,
    kind: u8,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<KeyValue>,
    events: Vec<Event>,
    status: Status,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    time_unix_nano: String,
    name: String,
    attributes: Vec<KeyValue>,
}

#[derive(Serialize)]
struct Status {
    code: u8,
}

#[derive(Serialize)]
struct KeyValue {
    key: String,
    value: AnyValue,
}

impl KeyValue {
    fn new(key: &str, value: &AttrValue) -> Self {
        Self {
            key: key.to_string(),
            value: AnyValue::from(value),
        }
    }
}

/// Serializes externally tagged, which is exactly OTLP's one-of shape:
/// `{"stringValue": "..."}`.
#[derive(Serialize)]
enum AnyValue {
    #[serde(rename = "stringValue")]
    String(String),
    /// A 64-bit integer, so a decimal string in the JSON mapping.
    #[serde(rename = "intValue")]
    Int(String),
    #[serde(rename = "doubleValue")]
    Double(f64),
    #[serde(rename = "boolValue")]
    Bool(bool),
}

impl From<&AttrValue> for AnyValue {
    fn from(value: &AttrValue) -> Self {
        match value {
            AttrValue::Str(s) => Self::String(s.clone()),
            AttrValue::Int(i) => Self::Int(i.to_string()),
            AttrValue::Double(d) => Self::Double(*d),
            AttrValue::Bool(b) => Self::Bool(*b),
        }
    }
}

/// Build the request body for one batch.
fn export_request(resource: &ResourceInfo, spans: &[SpanRecord]) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Resource {
                attributes: resource.attributes(),
            },
            scope_spans: vec![ScopeSpans {
                scope: Scope {
                    name: SCOPE_NAME,
                    version: env!("CARGO_PKG_VERSION"),
                },
                spans: spans.iter().map(encode_span).collect(),
            }],
        }],
    }
}

/// Serialize one batch to the bytes POSTed to the collector.
pub(crate) fn encode_batch(resource: &ResourceInfo, spans: &[SpanRecord]) -> Vec<u8> {
    // Every field is a string, integer, bool or finite float, so serialization
    // has no failure mode; an empty body would be rejected by the collector
    // rather than silently accepted.
    serde_json::to_vec(&export_request(resource, spans)).unwrap_or_default()
}

fn encode_span(span: &SpanRecord) -> Span {
    Span {
        trace_id: trace_id_hex(span.trace_id),
        span_id: span_id_hex(span.span_id),
        parent_span_id: span.parent_span_id.map(span_id_hex),
        name: span.name.clone(),
        kind: SPAN_KIND_INTERNAL,
        start_time_unix_nano: unix_nanos(span.start),
        end_time_unix_nano: unix_nanos(span.end),
        attributes: key_values(&span.attributes),
        events: span.events.iter().map(encode_event).collect(),
        status: Status {
            code: if span.error {
                STATUS_CODE_ERROR
            } else {
                STATUS_CODE_UNSET
            },
        },
    }
}

fn encode_event(event: &EventRecord) -> Event {
    Event {
        time_unix_nano: unix_nanos(event.time),
        name: event.name.clone(),
        attributes: key_values(&event.attributes),
    }
}

fn key_values(attributes: &Attributes) -> Vec<KeyValue> {
    attributes
        .iter()
        .map(|(key, value)| KeyValue::new(key, value))
        .collect()
}

fn trace_id_hex(id: u128) -> String {
    format!("{id:032x}")
}

fn span_id_hex(id: u64) -> String {
    format!("{id:016x}")
}

/// Nanoseconds since the Unix epoch as a decimal string. A clock set before
/// 1970 reports zero rather than failing the whole batch.
fn unix_nanos(time: SystemTime) -> String {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::time::Duration;

    fn at(nanos: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    fn resource() -> ResourceInfo {
        ResourceInfo {
            service_name: "mvmctl".into(),
            service_version: "1.2.3".into(),
            process_pid: 4242,
        }
    }

    fn root_span() -> SpanRecord {
        SpanRecord {
            trace_id: 0xabc,
            span_id: 0x1f,
            parent_span_id: None,
            name: "boot".into(),
            start: at(1_700_000_000_000_000_001),
            end: at(1_700_000_000_500_000_000),
            attributes: vec![
                ("code.namespace".into(), AttrValue::Str("mvm::boot".into())),
                ("vcpus".into(), AttrValue::Int(2)),
                ("ratio".into(), AttrValue::Double(0.5)),
                ("cached".into(), AttrValue::Bool(false)),
            ],
            events: vec![EventRecord {
                time: at(1_700_000_000_250_000_000),
                name: "kernel loaded".into(),
                attributes: vec![("level".into(), AttrValue::Str("INFO".into()))],
            }],
            error: false,
        }
    }

    fn encoded(spans: &[SpanRecord]) -> Value {
        serde_json::from_slice(&encode_batch(&resource(), spans)).unwrap()
    }

    #[test]
    fn a_root_span_encodes_to_the_otlp_json_shape() {
        let body = encoded(&[root_span()]);
        assert_eq!(
            body,
            json!({
                "resourceSpans": [{
                    "resource": {"attributes": [
                        {"key": "service.name", "value": {"stringValue": "mvmctl"}},
                        {"key": "service.version", "value": {"stringValue": "1.2.3"}},
                        {"key": "process.pid", "value": {"intValue": "4242"}},
                    ]},
                    "scopeSpans": [{
                        "scope": {"name": "mvm-observability", "version": env!("CARGO_PKG_VERSION")},
                        "spans": [{
                            "traceId": "00000000000000000000000000000abc",
                            "spanId": "000000000000001f",
                            "name": "boot",
                            "kind": 1,
                            "startTimeUnixNano": "1700000000000000001",
                            "endTimeUnixNano": "1700000000500000000",
                            "attributes": [
                                {"key": "code.namespace", "value": {"stringValue": "mvm::boot"}},
                                {"key": "vcpus", "value": {"intValue": "2"}},
                                {"key": "ratio", "value": {"doubleValue": 0.5}},
                                {"key": "cached", "value": {"boolValue": false}},
                            ],
                            "events": [{
                                "timeUnixNano": "1700000000250000000",
                                "name": "kernel loaded",
                                "attributes": [{"key": "level", "value": {"stringValue": "INFO"}}],
                            }],
                            "status": {"code": 0},
                        }],
                    }],
                }],
            })
        );
    }

    #[test]
    fn ids_are_fixed_width_lowercase_hex() {
        let mut span = root_span();
        span.trace_id = u128::MAX - 1;
        span.span_id = u64::MAX;
        let body = encoded(&[span]);
        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        let trace_id = span["traceId"].as_str().unwrap();
        let span_id = span["spanId"].as_str().unwrap();
        assert_eq!(trace_id.len(), 32);
        assert_eq!(span_id.len(), 16);
        assert_eq!(trace_id, "fffffffffffffffffffffffffffffffe");
        assert_eq!(span_id, "ffffffffffffffff");
    }

    #[test]
    fn a_child_span_links_to_its_parent_and_a_root_omits_the_link() {
        let root = root_span();
        let mut child = root_span();
        child.span_id = 0x2;
        child.parent_span_id = Some(root.span_id);
        let body = encoded(&[root, child]);
        let spans = &body["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert!(spans[0].get("parentSpanId").is_none());
        assert_eq!(spans[1]["parentSpanId"], "000000000000001f");
        assert_eq!(spans[0]["traceId"], spans[1]["traceId"]);
    }

    #[test]
    fn a_failed_span_carries_the_error_status_code() {
        let mut span = root_span();
        span.error = true;
        let body = encoded(&[span]);
        assert_eq!(
            body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"],
            json!({"code": 2})
        );
    }

    #[test]
    fn a_clock_before_the_epoch_encodes_as_zero_rather_than_failing() {
        assert_eq!(unix_nanos(UNIX_EPOCH - Duration::from_secs(1)), "0");
    }
}
