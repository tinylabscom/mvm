//! What a page (or a whole stream) of one machine's telemetry adds up to:
//! which spans opened and never closed, what the guest reported losing and
//! why, and where each producer's coverage stands.
//!
//! A host view must not present an incomplete span as a finished one, nor a
//! quiet stream as a healthy one. This fold keeps the evidence that says
//! otherwise — open spans, guest `Loss` records by stage and reason, and the
//! latest coverage mark per producer — so the CLI, the host library and a
//! desktop consumer render the same facts.
//!
//! Bounded: open spans are tracked up to [`MAX_TRACKED_OPEN_SPANS`]; past it
//! a newly opened span is counted, not stored, so a guest that opens spans
//! forever costs a counter, not memory.

use std::collections::BTreeMap;

use mvm_core::protocol::telemetry::served::ReceivedRecord;
use mvm_core::protocol::telemetry::{
    CoverageState, GuestLossStage, LossReason, RecordBody, SourceKind, SpanOutcome, TailState,
};
use serde::Serialize;

/// Open spans the summary tracks individually.
pub const MAX_TRACKED_OPEN_SPANS: usize = 4096;

/// A span that opened and has not closed in what was folded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenSpan {
    /// The span's W3C traceparent.
    pub traceparent: String,
    /// Its parent's traceparent, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub name: String,
    pub source: SourceKind,
    /// Host receive time of the open, when the line carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_at_ms: Option<u64>,
}

/// One guest loss class: every `Loss` record with this stage and reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GuestLoss {
    pub stage: GuestLossStage,
    pub reason: LossReason,
    pub records: u64,
    pub bytes: u64,
    /// Whether any contributing report said its counts were incomplete.
    pub tail_unknown: bool,
}

/// The latest coverage mark one producer sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageMark {
    pub source: SourceKind,
    pub producer: u32,
    pub state: CoverageState,
    pub code: String,
}

/// Counts by record kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KindCounts {
    pub span_open: u64,
    pub span_update: u64,
    pub span_close: u64,
    pub event: u64,
    pub log: u64,
    pub stdio: u64,
    pub coverage: u64,
    pub loss: u64,
}

/// The fold over a sequence of received records.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TelemetrySummary {
    pub kinds: KindCounts,
    /// Spans closed with an explicit error outcome.
    pub spans_failed: u64,
    /// Opened, not (yet) closed. A span still running is here as much as a
    /// span whose close was lost; the view says "incomplete", never "ok".
    pub open_spans: Vec<OpenSpan>,
    /// Opens past [`MAX_TRACKED_OPEN_SPANS`], counted rather than stored.
    pub open_spans_untracked: u64,
    /// Closes and updates for a span this fold never saw open — its open
    /// fell before the folded range, or was lost.
    pub unmatched_span_records: u64,
    pub guest_losses: Vec<GuestLoss>,
    pub coverage: Vec<CoverageMark>,
}

impl TelemetrySummary {
    /// Fold `records` in order.
    pub fn of<'a>(records: impl IntoIterator<Item = &'a ReceivedRecord>) -> Self {
        let mut summary = Self::default();
        for record in records {
            summary.observe(record);
        }
        summary
    }

    /// Fold one record.
    pub fn observe(&mut self, received: &ReceivedRecord) {
        let record = &received.record;
        match record.body() {
            RecordBody::SpanOpen {
                context,
                parent,
                name,
                ..
            } => {
                self.kinds.span_open += 1;
                if self.open_spans.len() >= MAX_TRACKED_OPEN_SPANS {
                    self.open_spans_untracked += 1;
                    return;
                }
                self.open_spans.push(OpenSpan {
                    traceparent: context.context().to_traceparent(),
                    parent: parent.map(|p| p.context().to_traceparent()),
                    name: name.as_str().to_string(),
                    source: record.source(),
                    opened_at_ms: received.received_at_ms,
                });
            }
            RecordBody::SpanUpdate { context, .. } => {
                self.kinds.span_update += 1;
                let traceparent = context.context().to_traceparent();
                if !self.open_spans.iter().any(|s| s.traceparent == traceparent) {
                    self.unmatched_span_records += 1;
                }
            }
            RecordBody::SpanClose { context, outcome } => {
                self.kinds.span_close += 1;
                if *outcome == SpanOutcome::Error {
                    self.spans_failed += 1;
                }
                let traceparent = context.context().to_traceparent();
                match self
                    .open_spans
                    .iter()
                    .position(|s| s.traceparent == traceparent)
                {
                    Some(at) => {
                        self.open_spans.remove(at);
                    }
                    None => self.unmatched_span_records += 1,
                }
            }
            RecordBody::Event { .. } => self.kinds.event += 1,
            RecordBody::Log { .. } => self.kinds.log += 1,
            RecordBody::Stdio { .. } => self.kinds.stdio += 1,
            RecordBody::Coverage { state, code } => {
                self.kinds.coverage += 1;
                let mark = CoverageMark {
                    source: record.source(),
                    producer: record.producer(),
                    state: *state,
                    code: code.as_str().to_string(),
                };
                match self
                    .coverage
                    .iter_mut()
                    .find(|m| m.source == mark.source && m.producer == mark.producer)
                {
                    Some(existing) => *existing = mark,
                    None => self.coverage.push(mark),
                }
            }
            RecordBody::Loss {
                stage,
                reason,
                records,
                bytes,
                tail,
            } => {
                self.kinds.loss += 1;
                let unknown = *tail == TailState::Unknown;
                match self
                    .guest_losses
                    .iter_mut()
                    .find(|l| l.stage == *stage && l.reason == *reason)
                {
                    Some(loss) => {
                        loss.records = loss.records.saturating_add(*records);
                        loss.bytes = loss.bytes.saturating_add(*bytes);
                        loss.tail_unknown |= unknown;
                    }
                    None => self.guest_losses.push(GuestLoss {
                        stage: *stage,
                        reason: *reason,
                        records: *records,
                        bytes: *bytes,
                        tail_unknown: unknown,
                    }),
                }
            }
        }
    }

    /// Records the guest reported losing, summed over every class.
    pub fn guest_records_lost(&self) -> u64 {
        self.guest_losses
            .iter()
            .fold(0u64, |sum, loss| sum.saturating_add(loss.records))
    }

    /// Producers whose latest mark says they are not capturing.
    pub fn impaired_producers(&self) -> impl Iterator<Item = &CoverageMark> {
        self.coverage.iter().filter(|mark| {
            matches!(
                mark.state,
                CoverageState::Degraded | CoverageState::Unavailable
            )
        })
    }

    /// Counts by kind, as label/count pairs for display.
    pub fn kind_counts(&self) -> BTreeMap<&'static str, u64> {
        let k = self.kinds;
        [
            ("span_open", k.span_open),
            ("span_update", k.span_update),
            ("span_close", k.span_close),
            ("event", k.event),
            ("log", k.log),
            ("stdio", k.stdio),
            ("coverage", k.coverage),
            ("loss", k.loss),
        ]
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::telemetry::{
        Attributes, BoundedList, Level, ProducerEpoch, TelemetryRecord, TraceReference,
    };
    use mvm_core::trace_context::TraceContext;

    fn received(sequence: u64, body: RecordBody) -> ReceivedRecord {
        ReceivedRecord {
            received_at_ms: Some(1_000 + sequence),
            record: TelemetryRecord::builder()
                .epoch(ProducerEpoch::new([3; 16]).unwrap())
                .producer(2)
                .sequence(sequence)
                .source(SourceKind::Sdk)
                .body(body)
                .build()
                .unwrap(),
        }
    }

    fn span(n: u8) -> TraceReference {
        let tp = format!(
            "00-{}-{}-01",
            format!("{n:02x}").repeat(16),
            format!("{n:02x}").repeat(8)
        );
        TraceReference::new(TraceContext::parse_traceparent(&tp).unwrap()).unwrap()
    }

    fn open(seq: u64, n: u8, parent: Option<u8>) -> ReceivedRecord {
        received(
            seq,
            RecordBody::SpanOpen {
                context: span(n),
                parent: parent.map(span),
                name: format!("op-{n}").as_str().try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
                links: BoundedList::new(Vec::new()).unwrap(),
            },
        )
    }

    fn close(seq: u64, n: u8, outcome: SpanOutcome) -> ReceivedRecord {
        received(
            seq,
            RecordBody::SpanClose {
                context: span(n),
                outcome,
            },
        )
    }

    #[test]
    fn a_span_that_never_closed_is_reported_incomplete_with_its_parent() {
        let records = [
            open(1, 1, None),
            open(2, 2, Some(1)),
            close(3, 2, SpanOutcome::Ok),
        ];
        let summary = TelemetrySummary::of(&records);
        assert_eq!(summary.open_spans.len(), 1);
        let incomplete = &summary.open_spans[0];
        assert_eq!(incomplete.name, "op-1");
        assert_eq!(incomplete.parent, None);
        assert_eq!(incomplete.opened_at_ms, Some(1_001));
        assert_eq!(summary.kinds.span_close, 1);
        assert_eq!(summary.unmatched_span_records, 0);
    }

    #[test]
    fn a_close_without_its_open_and_a_failed_span_are_both_counted() {
        let records = [close(1, 9, SpanOutcome::Error)];
        let summary = TelemetrySummary::of(&records);
        assert_eq!(summary.unmatched_span_records, 1);
        assert_eq!(summary.spans_failed, 1);
        assert!(summary.open_spans.is_empty());
    }

    #[test]
    fn guest_losses_sum_by_stage_and_reason_and_keep_an_unknown_tail() {
        let loss = |seq, records, tail| {
            received(
                seq,
                RecordBody::Loss {
                    stage: GuestLossStage::Capture,
                    reason: LossReason::Capacity,
                    records,
                    bytes: records * 10,
                    tail,
                },
            )
        };
        let other = received(
            3,
            RecordBody::Loss {
                stage: GuestLossStage::Pipe,
                reason: LossReason::Truncated,
                records: 1,
                bytes: 4096,
                tail: TailState::Known,
            },
        );
        let records = [
            loss(1, 5, TailState::Known),
            loss(2, 7, TailState::Unknown),
            other,
        ];
        let summary = TelemetrySummary::of(&records);
        assert_eq!(summary.guest_losses.len(), 2);
        let capture = summary.guest_losses[0];
        assert_eq!((capture.records, capture.bytes), (12, 120));
        assert!(capture.tail_unknown);
        assert_eq!(summary.guest_records_lost(), 13);
    }

    #[test]
    fn the_latest_coverage_mark_per_producer_wins_and_impairment_is_visible() {
        let mark = |seq, state| {
            received(
                seq,
                RecordBody::Coverage {
                    state,
                    code: "sdk".try_into().unwrap(),
                },
            )
        };
        let records = [
            mark(1, CoverageState::Started),
            mark(2, CoverageState::Degraded),
        ];
        let summary = TelemetrySummary::of(&records);
        assert_eq!(summary.coverage.len(), 1);
        assert_eq!(summary.impaired_producers().count(), 1);
    }

    #[test]
    fn standalone_events_and_logs_are_counted_as_their_own_kinds() {
        let records = [
            received(
                1,
                RecordBody::Event {
                    context: None,
                    level: Level::Info,
                    name: "ready".try_into().unwrap(),
                    attributes: Attributes::new(Vec::new()).unwrap(),
                },
            ),
            received(
                2,
                RecordBody::Log {
                    context: None,
                    level: Level::Warn,
                    message: "slow".try_into().unwrap(),
                    attributes: Attributes::new(Vec::new()).unwrap(),
                },
            ),
        ];
        let counts = TelemetrySummary::of(&records).kind_counts();
        assert_eq!(counts.get("event"), Some(&1));
        assert_eq!(counts.get("log"), Some(&1));
        assert_eq!(counts.get("span_open"), None);
    }

    #[test]
    fn open_span_tracking_is_bounded() {
        let mut summary = TelemetrySummary::default();
        for n in 1..=(MAX_TRACKED_OPEN_SPANS as u64 + 3) {
            let byte = u8::try_from(n % 250).unwrap() + 1;
            summary.observe(&open(n, byte, None));
        }
        assert_eq!(summary.open_spans.len(), MAX_TRACKED_OPEN_SPANS);
        assert_eq!(summary.open_spans_untracked, 3);
    }
}
