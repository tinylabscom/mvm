//! `mvmctl machine telemetry <name>` — what the host collected from a
//! machine's guest, read from the files its collector keeps beside the VM
//! state. No guest RPC and no attachment: a detached machine's telemetry is
//! read the same way as a running one's, and reading never touches the guest.
//!
//! The view never reads an absent record as health. It prints the collector's
//! standing, every loss the host or the guest counted (by reason), spans that
//! opened and have not closed, and each producer's latest coverage mark.

use std::fmt::Write as _;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_client::telemetry::LocalTelemetryReader;
use mvm_client::telemetry_summary::TelemetrySummary;
use mvm_core::protocol::telemetry::served::{
    CollectorState, ReceivedRecord, TelemetryCursor, TelemetryReadRequest, TelemetryStatus,
};
use mvm_core::protocol::telemetry::{AttributeValue, Attributes, RecordBody, StdioStream};
use mvm_core::user_config::MvmConfig;

use super::Cli;

/// A snapshot older than this means the process that owned the collector
/// is gone: a live collector rewrites it about once a second.
const STALE_SNAPSHOT_MS: u64 = 10_000;
/// The most characters one rendered record keeps.
const MAX_LINE_CHARS: usize = 8192;
/// How often `--follow` polls for new records.
const FOLLOW_POLL: Duration = Duration::from_millis(500);

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the machine.
    pub name: String,
    /// Print the status, the records and the summary as one JSON object.
    #[arg(long, conflicts_with = "follow")]
    pub json: bool,
    /// Keep printing new records as they arrive (Ctrl-C to stop).
    #[arg(short, long)]
    pub follow: bool,
    /// Show at most this many of the most recent records (0 shows only the
    /// status and summary).
    #[arg(long, default_value_t = 200)]
    pub tail: usize,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let reader = LocalTelemetryReader::for_machine(&args.name);
    if !reader.state_dir_exists() {
        anyhow::bail!("machine {:?} has no state on this host", args.name);
    }
    let status = reader
        .status()
        .with_context(|| format!("reading the telemetry status of {:?}", args.name))?;
    let (records, cursor) = read_all(&reader)?;
    let summary = TelemetrySummary::of(&records);
    let shown = &records[records.len().saturating_sub(args.tail)..];

    if args.json {
        let out = serde_json::json!({
            "machine": args.name,
            "status": status,
            "summary": summary,
            "records": shown,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    print!("{}", render_status(&args.name, &status));
    for record in shown {
        println!("{}", render_record(record));
    }
    print!("{}", render_summary(&summary));
    if args.follow {
        follow(&reader, cursor)?;
    }
    Ok(())
}

/// Every record from the start of the stream, page by page, and the cursor
/// after the last.
fn read_all(reader: &LocalTelemetryReader) -> Result<(Vec<ReceivedRecord>, TelemetryCursor)> {
    let mut records = Vec::new();
    let mut cursor = TelemetryCursor::START;
    loop {
        let page = reader
            .read(&TelemetryReadRequest::builder().cursor(cursor).build())
            .context("reading telemetry records")?;
        records.extend(page.records);
        cursor = page.next_cursor;
        if page.exhausted {
            return Ok((records, cursor));
        }
    }
}

fn follow(reader: &LocalTelemetryReader, mut cursor: TelemetryCursor) -> Result<()> {
    loop {
        let page = reader
            .read(&TelemetryReadRequest::builder().cursor(cursor).build())
            .context("reading telemetry records")?;
        for record in &page.records {
            println!("{}", render_record(record));
        }
        cursor = page.next_cursor;
        if page.exhausted {
            std::thread::sleep(FOLLOW_POLL);
        }
    }
}

fn render_status(name: &str, status: &TelemetryStatus) -> String {
    let mut out = String::new();
    match status {
        TelemetryStatus::NotProvisioned => {
            let _ = writeln!(
                out,
                "{name}: telemetry not collected for this boot (no collector was provisioned)"
            );
        }
        TelemetryStatus::Provisioned {
            state,
            shed,
            losses,
            snapshot_age_ms,
            records_bytes,
            ..
        } => {
            let standing = match state {
                CollectorState::Connecting => "connecting".to_string(),
                CollectorState::Collecting { generation } => {
                    format!("collecting (boot generation {generation})")
                }
                CollectorState::Degraded { code } => format!("degraded: {code}"),
                CollectorState::Stopped => "stopped".to_string(),
            };
            let stale = snapshot_age_ms.is_some_and(|age| age > STALE_SNAPSHOT_MS)
                && !matches!(state, CollectorState::Stopped);
            let _ = writeln!(out, "{name}: collector {standing}");
            if stale {
                let _ = writeln!(
                    out,
                    "  collector status is {}s old: the process that owned it has exited, \
                     and nothing is being collected now",
                    snapshot_age_ms.unwrap_or_default() / 1000
                );
            }
            let _ = writeln!(out, "  records file: {records_bytes} bytes");
            if *shed > 0 {
                let _ = writeln!(
                    out,
                    "  host shed {shed} record(s): queue full {}, cap reached {}, \
                     write failed {}, secret withheld {}",
                    losses.queue_full,
                    losses.cap_reached,
                    losses.write_failed,
                    losses.secret_withheld
                );
            }
        }
    }
    out
}

fn render_attributes(attributes: &Attributes) -> String {
    attributes
        .as_slice()
        .iter()
        .map(|attribute| {
            let value = match &attribute.value {
                AttributeValue::Bool(b) => b.to_string(),
                AttributeValue::Signed(i) => i.to_string(),
                AttributeValue::Unsigned(u) => u.to_string(),
                AttributeValue::Float(f) => f64::from(*f).to_string(),
                AttributeValue::Text(t) => format!("{:?}", t.as_str()),
            };
            format!(" {}={value}", attribute.key.as_str())
        })
        .collect()
}

fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// One record as one line: receive time, source, then the kind's own fields.
fn render_record(received: &ReceivedRecord) -> String {
    let record = &received.record;
    let at = received
        .received_at_ms
        .map(|ms| {
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap_or(0))
                .map(|t| t.format("%H:%M:%S%.3f").to_string())
                .unwrap_or_default()
        })
        .unwrap_or_else(|| "--:--:--.---".to_string());
    let source = label(&record.source());
    let body = match record.body() {
        RecordBody::SpanOpen {
            context,
            parent,
            name,
            attributes,
            ..
        } => format!(
            "span open {} {}{}{}",
            name.as_str(),
            context.context().to_traceparent(),
            parent
                .map(|p| format!(" parent={}", p.context().span_id.to_hex()))
                .unwrap_or_default(),
            render_attributes(attributes)
        ),
        RecordBody::SpanUpdate {
            context,
            attributes,
        } => format!(
            "span update {}{}",
            context.context().span_id.to_hex(),
            render_attributes(attributes)
        ),
        RecordBody::SpanClose { context, outcome } => format!(
            "span close {} {}",
            context.context().span_id.to_hex(),
            label(outcome)
        ),
        RecordBody::Event {
            context,
            level,
            name,
            attributes,
        } => format!(
            "event {} {}{}{}",
            label(level),
            name.as_str(),
            context
                .map(|c| format!(" span={}", c.context().span_id.to_hex()))
                .unwrap_or_default(),
            render_attributes(attributes)
        ),
        RecordBody::Log {
            level,
            message,
            attributes,
            ..
        } => format!(
            "log {} {}{}",
            label(level),
            message.as_str(),
            render_attributes(attributes)
        ),
        RecordBody::Stdio { stream, bytes } => format!(
            "{} {}",
            match stream {
                StdioStream::Stdout => "stdout",
                StdioStream::Stderr => "stderr",
            },
            String::from_utf8_lossy(bytes.as_slice()).trim_end_matches('\n')
        ),
        RecordBody::Coverage { state, code } => {
            format!("coverage {} {}", label(state), code.as_str())
        }
        RecordBody::Loss {
            stage,
            reason,
            records,
            bytes,
            tail,
        } => format!(
            "loss {}/{} {records} record(s) {bytes} byte(s) tail={}",
            label(stage),
            label(reason),
            label(tail)
        ),
    };
    // Every field above is guest-authored. Strip terminal control sequences
    // and control characters so guest output cannot drive the operator's
    // terminal, and cap the line.
    let body = mvm_client::audit::sanitize_free_text(&body, MAX_LINE_CHARS);
    format!("{at} {source:<13} {body}")
}

fn render_summary(summary: &TelemetrySummary) -> String {
    let mut out = String::new();
    let counts = summary
        .kind_counts()
        .into_iter()
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "summary: {}",
        if counts.is_empty() {
            "no records"
        } else {
            &counts
        }
    );
    if !summary.open_spans.is_empty() || summary.open_spans_untracked > 0 {
        let _ = writeln!(
            out,
            "  incomplete spans (opened, no close received): {}",
            summary.open_spans.len() as u64 + summary.open_spans_untracked
        );
        for span in summary.open_spans.iter().take(20) {
            let _ = writeln!(
                out,
                "    {} {}",
                mvm_client::audit::sanitize_free_text(&span.name, MAX_LINE_CHARS),
                span.traceparent
            );
        }
    }
    if summary.unmatched_span_records > 0 {
        let _ = writeln!(
            out,
            "  span records whose open was not seen: {}",
            summary.unmatched_span_records
        );
    }
    for loss in &summary.guest_losses {
        let _ = writeln!(
            out,
            "  guest lost {} record(s), {} byte(s) at {} ({}){}",
            loss.records,
            loss.bytes,
            label(&loss.stage),
            label(&loss.reason),
            if loss.tail_unknown {
                ", count incomplete"
            } else {
                ""
            }
        );
    }
    for mark in summary.impaired_producers() {
        let _ = writeln!(
            out,
            "  producer {} ({}) is {}: {}",
            mark.producer,
            label(&mark.source),
            label(&mark.state),
            mvm_client::audit::sanitize_free_text(&mark.code, MAX_LINE_CHARS)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::telemetry::served::HostLosses;
    use mvm_core::protocol::telemetry::{
        BoundedList, CoverageState, GuestLossStage, LossReason, ProducerEpoch, SourceKind,
        TailState, TelemetryRecord,
    };

    fn received(sequence: u64, body: RecordBody) -> ReceivedRecord {
        ReceivedRecord {
            received_at_ms: Some(1_760_000_000_000),
            record: TelemetryRecord::builder()
                .epoch(ProducerEpoch::new([1; 16]).unwrap())
                .producer(3)
                .sequence(sequence)
                .source(SourceKind::Stdio)
                .body(body)
                .build()
                .unwrap(),
        }
    }

    #[test]
    fn a_status_names_every_host_loss_class_and_a_collector_that_is_gone() {
        let status = TelemetryStatus::Provisioned {
            vm_name: "web".into(),
            state: CollectorState::Collecting { generation: 2 },
            shed: 4,
            losses: HostLosses {
                queue_full: 1,
                cap_reached: 1,
                write_failed: 1,
                secret_withheld: 1,
            },
            snapshot_age_ms: Some(60_000),
            records_bytes: 10,
        };
        let text = render_status("web", &status);
        assert!(text.contains("collecting (boot generation 2)"));
        assert!(text.contains("has exited"), "{text}");
        assert!(text.contains("queue full 1, cap reached 1, write failed 1, secret withheld 1"));
    }

    #[test]
    fn an_unprovisioned_machine_says_so_rather_than_showing_nothing() {
        let text = render_status("quiet", &TelemetryStatus::NotProvisioned);
        assert!(text.contains("not collected"), "{text}");
    }

    #[test]
    fn guest_output_cannot_drive_the_terminal() {
        let line = render_record(&received(
            1,
            RecordBody::Stdio {
                stream: StdioStream::Stdout,
                bytes: mvm_core::protocol::telemetry::BoundedList::new(
                    b"\x1b]0;owned\x07\x1b[2Jclear\rover".to_vec(),
                )
                .unwrap(),
            },
        ));
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.contains("clear"));
    }

    #[test]
    fn records_render_one_line_each_with_their_kind() {
        let stdout = received(
            1,
            RecordBody::Stdio {
                stream: StdioStream::Stdout,
                bytes: BoundedList::new(b"hello\n".to_vec()).unwrap(),
            },
        );
        let line = render_record(&stdout);
        assert!(line.ends_with("stdout hello"), "{line}");
        assert!(line.contains("stdio"), "{line}");
        assert!(!line.contains('\n'));

        let loss = received(
            2,
            RecordBody::Loss {
                stage: GuestLossStage::Capture,
                reason: LossReason::Capacity,
                records: 3,
                bytes: 30,
                tail: TailState::Unknown,
            },
        );
        assert!(
            render_record(&loss)
                .contains("loss capture/capacity 3 record(s) 30 byte(s) tail=unknown")
        );
    }

    #[test]
    fn the_summary_lists_guest_losses_and_impaired_producers() {
        let records = [
            received(
                1,
                RecordBody::Loss {
                    stage: GuestLossStage::Pipe,
                    reason: LossReason::Truncated,
                    records: 2,
                    bytes: 8192,
                    tail: TailState::Known,
                },
            ),
            received(
                2,
                RecordBody::Coverage {
                    state: CoverageState::Unavailable,
                    code: "early-boot".try_into().unwrap(),
                },
            ),
        ];
        let text = render_summary(&TelemetrySummary::of(&records));
        assert!(text.contains("guest lost 2 record(s), 8192 byte(s) at pipe (truncated)"));
        assert!(text.contains("is unavailable: early-boot"), "{text}");
    }
}
