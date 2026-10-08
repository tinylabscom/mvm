//! What the host-side collector persists for one machine, and the read
//! shapes a consumer gets it back through.
//!
//! The embedded collector (a thread in the per-VM network endpoint) keeps two
//! files in the VM state dir: a status snapshot it rewrites on a cadence, and
//! a capped, append-only JSONL of received records. These are the types both
//! sides share — the writer in `mvm-hostd` and the reader behind the
//! `MvmClient` telemetry methods — so neither can drift from the other.
//!
//! Records never name their machine: the reader attributes them by the state
//! dir it read them from, which the authenticated session bound on the way
//! in. A record pulled out of that context has no owner.

use serde::{Deserialize, Serialize};

use super::TelemetryRecord;

/// The status snapshot the collector persists beside the VM state. This is
/// the on-disk shape; [`TelemetryStatus`] is the typed view a reader serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorStatusSnapshot {
    pub vm_name: String,
    /// `connecting`, `collecting`, `degraded:<code>` or `stopped`.
    pub status: String,
    /// Boot generation when a session is live; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Records the host shed because its sink was full.
    pub shed: u64,
}

/// Where collection stands for one machine, as the read seam reports it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryCoverage {
    /// No collector was provisioned for this boot. Collection is opt-in, so
    /// this is the ordinary state of a machine nobody asked to observe; it
    /// is not a failure and carries no code.
    NotProvisioned,
    /// The collector is resolving the guest registration or dialing it.
    Connecting,
    /// An authenticated session is live under this boot generation.
    Collecting { generation: u64 },
    /// The last attempt failed for the named reason; the collector is
    /// backing off and will retry.
    Degraded { code: String },
    /// The collector was stopped with the machine.
    Stopped,
}

/// One machine's collector status: coverage plus the host-side shed count.
///
/// `shed` counts records the host dropped because its own sink was full. It
/// is distinct from the `loss` records inside the stream, which count what
/// the guest shed before sending; a complete picture adds both.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryStatus {
    pub coverage: TelemetryCoverage,
    pub shed: u64,
}

impl TelemetryStatus {
    /// The status of a machine no collector was provisioned for.
    pub fn not_provisioned() -> Self {
        Self {
            coverage: TelemetryCoverage::NotProvisioned,
            shed: 0,
        }
    }
}

/// A status label the snapshot carries that no reader recognises.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown collector status `{0}`")]
pub struct UnknownStatus(pub String);

impl TryFrom<&CollectorStatusSnapshot> for TelemetryStatus {
    type Error = UnknownStatus;

    /// Type the on-disk label. Fails closed on a label this reader does not
    /// know rather than guessing a coverage state for it.
    fn try_from(snapshot: &CollectorStatusSnapshot) -> Result<Self, UnknownStatus> {
        let coverage = match snapshot.status.as_str() {
            "connecting" => TelemetryCoverage::Connecting,
            "collecting" => TelemetryCoverage::Collecting {
                generation: snapshot.generation.unwrap_or(0),
            },
            "stopped" => TelemetryCoverage::Stopped,
            other => match other.strip_prefix("degraded:") {
                Some(code) if !code.is_empty() => TelemetryCoverage::Degraded {
                    code: code.to_string(),
                },
                _ => return Err(UnknownStatus(other.to_string())),
            },
        };
        Ok(Self {
            coverage,
            shed: snapshot.shed,
        })
    }
}

/// A position in one machine's record stream. Opaque to a consumer: hand
/// back the `next` a page returned to continue from where it ended. The
/// stream restarts when its machine reboots, and a cursor from before the
/// restart is refused rather than silently rebased.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TelemetryCursor(pub u64);

/// How many records one page returns when the caller names no limit.
pub const DEFAULT_PAGE_LIMIT: u32 = 256;
/// The most records one page returns, whatever the caller asked for.
pub const MAX_PAGE_LIMIT: u32 = 4096;

/// What one record read asks for.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryReadOpts {
    /// Continue after this position; `None` reads from the start.
    #[serde(default)]
    pub after: Option<TelemetryCursor>,
    /// At most this many records; `None` means [`DEFAULT_PAGE_LIMIT`], and
    /// anything above [`MAX_PAGE_LIMIT`] is clamped to it.
    #[serde(default)]
    pub limit: Option<u32>,
}

impl TelemetryReadOpts {
    /// Read from the start with the default page size.
    pub fn from_start() -> Self {
        Self::default()
    }

    /// Continue after `cursor` with the default page size.
    pub fn after(cursor: TelemetryCursor) -> Self {
        Self {
            after: Some(cursor),
            limit: None,
        }
    }

    /// The page size this read actually uses.
    pub fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT) as usize
    }
}

/// One page of a machine's records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryPage {
    pub records: Vec<TelemetryRecord>,
    /// The position after the last record returned. Equal to the position
    /// read from when nothing new had arrived.
    pub next: TelemetryCursor,
    /// Whether at least one more complete record was available past this
    /// page's limit.
    pub more: bool,
}

/// Why a page could not be cut from the record file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    /// A line the collector wrote does not decode as a record. The file is
    /// host-written by our own sink, so this is a bug to surface, not noise
    /// to skip past.
    #[error("telemetry record at byte {offset} does not decode: {reason}")]
    Malformed { offset: u64, reason: String },
}

/// Cut one page from `tail`, the record file's bytes from position `base`
/// onward.
///
/// Only complete lines (newline-terminated) are served, so a line the sink
/// is still writing is left for the next read and `next` never points into
/// the middle of a record.
pub fn page_from_jsonl(tail: &[u8], base: u64, limit: usize) -> Result<TelemetryPage, PageError> {
    let mut records = Vec::new();
    let mut consumed = 0usize;
    let mut more = false;
    let mut rest = tail;
    while let Some(newline) = rest.iter().position(|&b| b == b'\n') {
        if records.len() == limit {
            more = true;
            break;
        }
        let line = &rest[..newline];
        let offset = base + consumed as u64;
        if !line.is_empty() {
            let record = serde_json::from_slice::<TelemetryRecord>(line).map_err(|e| {
                PageError::Malformed {
                    offset,
                    reason: e.to_string(),
                }
            })?;
            records.push(record);
        }
        consumed += newline + 1;
        rest = &rest[newline + 1..];
    }
    Ok(TelemetryPage {
        records,
        next: TelemetryCursor(base + consumed as u64),
        more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::telemetry::{
        Attributes, CoverageState, Level, ProducerEpoch, RecordBody, SourceKind,
    };

    fn snapshot(status: &str, generation: Option<u64>, shed: u64) -> CollectorStatusSnapshot {
        CollectorStatusSnapshot {
            vm_name: "vm".into(),
            status: status.into(),
            generation,
            shed,
        }
    }

    #[test]
    fn every_on_disk_label_types_to_its_coverage() {
        let cases = [
            (
                snapshot("connecting", None, 0),
                TelemetryCoverage::Connecting,
            ),
            (
                snapshot("collecting", Some(3), 2),
                TelemetryCoverage::Collecting { generation: 3 },
            ),
            (
                snapshot("degraded:auth_failed", None, 0),
                TelemetryCoverage::Degraded {
                    code: "auth_failed".into(),
                },
            ),
            (snapshot("stopped", None, 9), TelemetryCoverage::Stopped),
        ];
        for (on_disk, coverage) in cases {
            let typed = TelemetryStatus::try_from(&on_disk).expect("known label");
            assert_eq!(typed.coverage, coverage);
            assert_eq!(typed.shed, on_disk.shed);
        }
    }

    #[test]
    fn an_unknown_label_is_refused_not_guessed() {
        for label in ["", "degraded:", "paused", "COLLECTING"] {
            let err = TelemetryStatus::try_from(&snapshot(label, None, 0)).unwrap_err();
            assert_eq!(err, UnknownStatus(label.into()));
        }
    }

    #[test]
    fn status_and_coverage_round_trip_through_json() {
        let status = TelemetryStatus {
            coverage: TelemetryCoverage::Degraded {
                code: "peer_closed".into(),
            },
            shed: 4,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"coverage":{"state":"degraded","code":"peer_closed"},"shed":4})
        );
        let back: TelemetryStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
        assert_eq!(
            serde_json::to_value(TelemetryStatus::not_provisioned()).unwrap(),
            serde_json::json!({"coverage":{"state":"not_provisioned"},"shed":0})
        );
    }

    #[test]
    fn read_opts_default_and_clamp_their_limit() {
        assert_eq!(
            TelemetryReadOpts::from_start().effective_limit(),
            DEFAULT_PAGE_LIMIT as usize
        );
        let opts = TelemetryReadOpts {
            after: Some(TelemetryCursor(7)),
            limit: Some(0),
        };
        assert_eq!(opts.effective_limit(), 1);
        let opts = TelemetryReadOpts {
            after: None,
            limit: Some(u32::MAX),
        };
        assert_eq!(opts.effective_limit(), MAX_PAGE_LIMIT as usize);
        let back: TelemetryReadOpts =
            serde_json::from_str(r#"{"after":12,"limit":3}"#).expect("parses");
        assert_eq!(back.after, Some(TelemetryCursor(12)));
        assert_eq!(back.limit, Some(3));
    }

    fn record(sequence: u64, name: &str) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([7; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence * 1000)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: name.try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap()
    }

    fn jsonl(records: &[TelemetryRecord]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            out.extend(serde_json::to_vec(r).unwrap());
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn a_page_walks_the_file_by_cursor_and_reports_more() {
        let all = [record(1, "a"), record(2, "b"), record(3, "c")];
        let bytes = jsonl(&all);

        let first = page_from_jsonl(&bytes, 0, 2).unwrap();
        assert_eq!(first.records, &all[..2]);
        assert!(first.more);

        let tail = &bytes[first.next.0 as usize..];
        let second = page_from_jsonl(tail, first.next.0, 2).unwrap();
        assert_eq!(second.records, &all[2..]);
        assert!(!second.more);
        assert_eq!(second.next.0 as usize, bytes.len());

        let idle = page_from_jsonl(&[], second.next.0, 2).unwrap();
        assert!(idle.records.is_empty());
        assert_eq!(idle.next, second.next, "nothing new keeps the cursor");
        assert!(!idle.more);
    }

    #[test]
    fn a_partial_trailing_line_is_left_for_the_next_read() {
        let all = [record(1, "a"), record(2, "b")];
        let mut bytes = jsonl(&all);
        let complete = bytes.len();
        bytes.extend_from_slice(br#"{"format":"mvm.telemetry.v1","epo"#);

        let page = page_from_jsonl(&bytes, 0, 10).unwrap();
        assert_eq!(page.records, all);
        assert_eq!(page.next.0 as usize, complete);
        assert!(!page.more);
    }

    #[test]
    fn exactly_limit_records_with_nothing_after_is_not_more() {
        let bytes = jsonl(&[record(1, "a"), record(2, "b")]);
        let page = page_from_jsonl(&bytes, 0, 2).unwrap();
        assert_eq!(page.records.len(), 2);
        assert!(!page.more);
    }

    #[test]
    fn a_line_that_is_not_a_record_names_its_offset() {
        let mut bytes = jsonl(&[record(1, "a")]);
        let bad_at = bytes.len() as u64;
        bytes.extend_from_slice(b"{\"format\":\"mvm.telemetry.v9\"}\n");
        let err = page_from_jsonl(&bytes, 0, 10).unwrap_err();
        assert!(
            matches!(err, PageError::Malformed { offset, .. } if offset == bad_at),
            "{err}"
        );
    }

    #[test]
    fn blank_lines_are_skipped_but_still_advance_the_cursor() {
        let mut bytes = b"\n".to_vec();
        bytes.extend(jsonl(&[record(1, "a")]));
        let page = page_from_jsonl(&bytes, 100, 10).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next.0 as usize, 100 + bytes.len());
    }

    #[test]
    fn a_coverage_record_pages_like_any_other() {
        let coverage = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([1; 16]).unwrap())
            .producer(1)
            .sequence(1)
            .monotonic_ns(1)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "guest-agent".try_into().unwrap(),
            })
            .build()
            .unwrap();
        let page = page_from_jsonl(&jsonl(std::slice::from_ref(&coverage)), 0, 1).unwrap();
        assert_eq!(page.records, vec![coverage]);
    }
}
