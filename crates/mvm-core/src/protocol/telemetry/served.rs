//! What a host serves a telemetry consumer: one VM's collector status and
//! its persisted records, paged by cursor.
//!
//! These are the shapes `mvm studio` renders. They sit beside the record
//! contract rather than with the client DTOs because three parties share
//! them: the collector writes the persisted line, the local reader decodes it
//! and pages it, and the host library carries the result over its C ABI. A
//! record never names its VM — the host binds identity through the
//! authenticated session — so attribution here is positional: every answer is
//! about the one machine the caller asked for.
//!
//! The persisted line is the record plus the host wall-clock time it was
//! received. The guest's `monotonic_ns` orders records within one producer
//! and epoch; only the host receive time places them on a wall clock.
//!
//! On disk each line is sealed: base64 of an AES-256-GCM frame of the JSON
//! line under the boot's records data key, which is itself stored wrapped
//! under the host transcript key-encryption key. [`ReceivedRecord::seal_line`]
//! and [`ReceivedRecord::open_line`] are the two ends.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use super::{MAX_RECORD_BYTES, TelemetryRecord};
use crate::crypto::aead;

/// Associated data every sealed records line is bound to.
pub const RECORDS_LINE_AAD: &[u8] = b"mvm.telemetry.records.v1";

/// The longest sealed line a reader opens: the base64 of a nonce, the
/// longest persisted line and a tag, without its newline.
pub const MAX_SEALED_LINE_BYTES: usize =
    (aead::NONCE_SIZE + MAX_PERSISTED_LINE_BYTES + aead::TAG_SIZE).div_ceil(3) * 4;

/// The longest persisted line a reader decodes. A record is bounded by
/// [`MAX_RECORD_BYTES`]; the envelope adds its receive time and field names.
/// Anything longer is counted as undecodable and skipped whole, so a corrupt
/// file cannot make a page unbounded.
pub const MAX_PERSISTED_LINE_BYTES: usize = MAX_RECORD_BYTES + 128;

/// Records per page when a request names no limit.
pub const DEFAULT_PAGE_RECORDS: usize = 256;
/// The most records one page carries, whatever the request asks for.
pub const MAX_PAGE_RECORDS: usize = 1024;

/// One record with the host wall-clock time it was received, in
/// milliseconds since the Unix epoch. `received_at_ms` is absent only for a
/// line persisted before the collector stamped receive time; a consumer
/// orders those by `monotonic_ns` alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at_ms: Option<u64>,
    pub record: TelemetryRecord,
}

/// Serialize-only view so the collector persists a line without cloning the
/// record it just received.
#[derive(Serialize)]
struct PersistedLine<'a> {
    received_at_ms: u64,
    record: &'a TelemetryRecord,
}

impl ReceivedRecord {
    /// Encode the line the collector appends to its records file: the
    /// envelope as one JSON object, newline-terminated.
    pub fn encode_line(
        received_at_ms: u64,
        record: &TelemetryRecord,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut line = serde_json::to_vec(&PersistedLine {
            received_at_ms,
            record,
        })?;
        line.push(b'\n');
        Ok(line)
    }

    /// Seal the line the collector appends to its records file: the
    /// envelope [`ReceivedRecord::encode_line`] produces, encrypted under the
    /// boot's records data key and base64-encoded, newline-terminated.
    pub fn seal_line(
        key: &aead::Key,
        received_at_ms: u64,
        record: &TelemetryRecord,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut plain = zeroize::Zeroizing::new(Self::encode_line(received_at_ms, record)?);
        plain.pop();
        let mut line = B64
            .encode(aead::seal(key, &plain, RECORDS_LINE_AAD))
            .into_bytes();
        line.push(b'\n');
        Ok(line)
    }

    /// The length, newline included, of the sealed line
    /// [`ReceivedRecord::seal_line`] writes for this record: what a cursor
    /// advances by. Sealing is length-preserving up to its fixed overhead,
    /// so this is exact without sealing anything.
    pub fn sealed_line_len(
        received_at_ms: u64,
        record: &TelemetryRecord,
    ) -> Result<u64, serde_json::Error> {
        let plain = Self::encode_line(received_at_ms, record)?.len() - 1;
        Ok(((aead::NONCE_SIZE + plain + aead::TAG_SIZE).div_ceil(3) * 4 + 1) as u64)
    }

    /// Open one line written by [`ReceivedRecord::seal_line`], with or
    /// without its newline. `None` for a line that is too long, not base64,
    /// sealed under another key, tampered with, or not a record once opened.
    pub fn open_line(key: &aead::Key, line: &[u8]) -> Option<Self> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        if line.len() > MAX_SEALED_LINE_BYTES {
            return None;
        }
        let framed = B64.decode(line).ok()?;
        let plain = zeroize::Zeroizing::new(aead::open(key, &framed, RECORDS_LINE_AAD).ok()?);
        Self::decode_line(&plain)
    }

    /// Decode one persisted line, with or without its trailing newline. A
    /// line is the envelope, or — for a file written before receive time was
    /// stamped — a bare record, which decodes with no `received_at_ms`.
    /// Anything else, including a line over [`MAX_PERSISTED_LINE_BYTES`], is
    /// `None`: the caller counts it and moves on rather than failing the page.
    pub fn decode_line(line: &[u8]) -> Option<Self> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        if line.len() > MAX_PERSISTED_LINE_BYTES {
            return None;
        }
        if let Ok(received) = serde_json::from_slice::<Self>(line) {
            return Some(received);
        }
        TelemetryRecord::decode(line)
            .ok()
            .map(|record| ReceivedRecord {
                received_at_ms: None,
                record,
            })
    }
}

/// Records the host shed after it received them, by why. The guest's own
/// losses travel inside the stream as `Loss` records; these are the ones the
/// guest cannot know about, because they happen on the host side of the
/// session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLosses {
    /// The collector's write queue was full: the records file's writer fell
    /// behind the session, and the receive loop shed rather than waited.
    #[serde(default)]
    pub queue_full: u64,
    /// The records file reached its byte cap.
    #[serde(default)]
    pub cap_reached: u64,
    /// A write to the records file failed (a full disk, an I/O error). The
    /// file is rolled back to its last whole line, so a failed write never
    /// leaves a torn record behind.
    #[serde(default)]
    pub write_failed: u64,
    /// The record carried a secret the host holds for this VM, so it was
    /// withheld from the records file entirely.
    #[serde(default)]
    pub secret_withheld: u64,
}

impl HostLosses {
    /// Every record shed, whatever the reason.
    pub fn total(&self) -> u64 {
        self.queue_full
            .saturating_add(self.cap_reached)
            .saturating_add(self.write_failed)
            .saturating_add(self.secret_withheld)
    }

    /// Whether nothing has been shed.
    pub fn is_zero(&self) -> bool {
        self.total() == 0
    }
}

/// The collector's standing for one VM, as its status snapshot reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollectorState {
    /// Provisioned and dialing; no authenticated session yet.
    Connecting,
    /// An authenticated session under this boot generation is delivering.
    Collecting { generation: u64 },
    /// Collection is impaired; `code` is the collector's short reason.
    Degraded { code: String },
    /// The collector ended cleanly.
    Stopped,
}

impl CollectorState {
    /// Parse the snapshot's status label (`connecting`, `collecting`,
    /// `degraded:<code>`, `stopped`) with the generation it carries beside
    /// it. `None` for a label this contract does not know.
    pub fn from_label(label: &str, generation: Option<u64>) -> Option<Self> {
        match label {
            "connecting" => Some(Self::Connecting),
            "collecting" => generation.map(|generation| Self::Collecting { generation }),
            "stopped" => Some(Self::Stopped),
            other => other.strip_prefix("degraded:").map(|code| Self::Degraded {
                code: code.to_string(),
            }),
        }
    }

    /// The label the snapshot carries for this state.
    pub fn label(&self) -> String {
        match self {
            Self::Connecting => "connecting".to_string(),
            Self::Collecting { .. } => "collecting".to_string(),
            Self::Degraded { code } => format!("degraded:{code}"),
            Self::Stopped => "stopped".to_string(),
        }
    }
}

/// Whether the host provisioned collection for a VM's current boot, and if
/// so how the collector stands. Absence of records is never evidence of
/// health; this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "collection", rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryStatus {
    /// No collector was provisioned for this VM: nothing dials the guest and
    /// no records are expected.
    NotProvisioned,
    /// A collector was provisioned and left a status snapshot.
    Provisioned {
        /// The VM the snapshot names.
        vm_name: String,
        /// The collector's standing.
        state: CollectorState,
        /// Records the host shed after receipt (a full or failed sink).
        shed: u64,
        /// The same sheds by reason; absent when nothing was shed.
        #[serde(default, skip_serializing_if = "HostLosses::is_zero")]
        losses: HostLosses,
        /// How long ago the snapshot was refreshed, when the host can tell.
        /// The collector rewrites it about once a second while it lives, so
        /// a large age means the process that owned the VM is gone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot_age_ms: Option<u64>,
        /// Bytes currently in the records file.
        records_bytes: u64,
    },
}

/// Position in a VM's record stream: the byte offset of the next line. A
/// cursor is valid only against the file it came from; one that no longer
/// lands on a line boundary is refused rather than guessed at, and the
/// consumer starts over from the beginning.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCursor {
    pub offset: u64,
}

impl TelemetryCursor {
    /// The beginning of the stream.
    pub const START: Self = Self { offset: 0 };
}

/// A cursor-paged read of one VM's records, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryReadRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<TelemetryCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

impl TelemetryReadRequest {
    /// Start building a request. An empty request reads the first
    /// [`DEFAULT_PAGE_RECORDS`] records from the start of the stream.
    pub fn builder() -> TelemetryReadRequestBuilder {
        TelemetryReadRequestBuilder::default()
    }

    /// Where to resume; the start of the stream when unset.
    pub fn cursor(&self) -> TelemetryCursor {
        self.cursor.unwrap_or(TelemetryCursor::START)
    }

    /// Effective page size: the default when unset, clamped to
    /// `1..=`[`MAX_PAGE_RECORDS`].
    pub fn effective_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_PAGE_RECORDS)
            .clamp(1, MAX_PAGE_RECORDS)
    }
}

/// Builder for [`TelemetryReadRequest`].
#[derive(Debug, Default)]
pub struct TelemetryReadRequestBuilder {
    request: TelemetryReadRequest,
}

impl TelemetryReadRequestBuilder {
    /// Resume from the cursor a previous page returned.
    #[must_use]
    pub fn cursor(mut self, cursor: TelemetryCursor) -> Self {
        self.request.cursor = Some(cursor);
        self
    }

    /// Records per page; clamped at read time.
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.request.limit = Some(limit);
        self
    }

    /// Finish the request.
    #[must_use]
    pub fn build(self) -> TelemetryReadRequest {
        self.request
    }
}

/// One page of a VM's records. `next_cursor` is always present: an empty
/// page with the same cursor means nothing new has arrived, and a consumer
/// polls it again rather than restarting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryReadResponse {
    /// Decoded records, oldest first.
    pub records: Vec<ReceivedRecord>,
    /// Where the next page starts.
    pub next_cursor: TelemetryCursor,
    /// Lines in this page's span that did not decode as records. Surfaced
    /// rather than hidden: a corrupt or foreign line is evidence too.
    pub undecodable: u64,
    /// Whether this page reached the end of what the file held at read
    /// time. `false` means another page is already waiting.
    pub exhausted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::telemetry::{
        Attributes, CoverageState, Level, ProducerEpoch, RecordBody, SourceKind,
    };

    fn record(sequence: u64) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([7; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence * 1_000)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: "served".try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn a_sealed_line_opens_only_under_its_key_and_hides_the_record() {
        let key = aead::Key::from_bytes([3; 32]);
        let line = ReceivedRecord::seal_line(&key, 42, &record(1)).unwrap();
        assert!(line.ends_with(b"\n"));
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
        assert!(
            !line.windows(b"served".len()).any(|w| w == b"served"),
            "no plaintext on disk"
        );
        let opened = ReceivedRecord::open_line(&key, &line).expect("opens");
        assert_eq!(opened.received_at_ms, Some(42));
        assert_eq!(opened.record, record(1));

        let other = aead::Key::from_bytes([4; 32]);
        assert_eq!(ReceivedRecord::open_line(&other, &line), None);

        let mut tampered = line.clone();
        tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
        assert_eq!(ReceivedRecord::open_line(&key, &tampered), None);

        // A plaintext line is not accepted in place of a sealed one.
        let plain = ReceivedRecord::encode_line(42, &record(1)).unwrap();
        assert_eq!(ReceivedRecord::open_line(&key, &plain), None);
    }

    #[test]
    fn the_longest_record_seals_within_the_sealed_line_bound() {
        let key = aead::Key::from_bytes([3; 32]);
        let big = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([7; 16]).unwrap())
            .producer(1)
            .sequence(u64::MAX)
            .monotonic_ns(u64::MAX)
            .source(SourceKind::Stdio)
            .body(RecordBody::Stdio {
                stream: crate::protocol::telemetry::StdioStream::Stdout,
                bytes: crate::protocol::telemetry::BoundedList::new(vec![255; 4096]).unwrap(),
            })
            .build()
            .unwrap();
        let line = ReceivedRecord::seal_line(&key, u64::MAX, &big).unwrap();
        assert!(line.len() - 1 <= MAX_SEALED_LINE_BYTES);
        assert_eq!(
            ReceivedRecord::sealed_line_len(u64::MAX, &big).unwrap(),
            line.len() as u64
        );
        assert!(ReceivedRecord::open_line(&key, &line).is_some());
    }

    #[test]
    fn a_persisted_line_round_trips_with_its_receive_time() {
        let line = ReceivedRecord::encode_line(1_700_000_000_123, &record(1)).unwrap();
        assert!(line.ends_with(b"\n"), "newline-terminated");
        let decoded = ReceivedRecord::decode_line(&line).expect("decodes");
        assert_eq!(decoded.received_at_ms, Some(1_700_000_000_123));
        assert_eq!(decoded.record, record(1));
        // With or without the newline.
        assert_eq!(
            ReceivedRecord::decode_line(&line[..line.len() - 1]),
            Some(decoded)
        );
    }

    #[test]
    fn a_bare_record_line_decodes_without_a_receive_time() {
        let bare = serde_json::to_vec(&record(2)).unwrap();
        let decoded = ReceivedRecord::decode_line(&bare).expect("legacy line decodes");
        assert_eq!(decoded.received_at_ms, None);
        assert_eq!(decoded.record, record(2));
    }

    #[test]
    fn garbage_an_unknown_envelope_field_and_an_overlong_line_are_undecodable() {
        assert_eq!(ReceivedRecord::decode_line(b"not json\n"), None);
        let mut with_extra: serde_json::Value =
            serde_json::from_slice(&ReceivedRecord::encode_line(1, &record(1)).unwrap()).unwrap();
        with_extra["vm"] = serde_json::json!("guest-authored");
        assert_eq!(
            ReceivedRecord::decode_line(&serde_json::to_vec(&with_extra).unwrap()),
            None,
            "a guest cannot smuggle identity through the envelope"
        );
        let overlong = vec![b' '; MAX_PERSISTED_LINE_BYTES + 1];
        assert_eq!(ReceivedRecord::decode_line(&overlong), None);
    }

    #[test]
    fn collector_state_labels_round_trip_and_unknown_labels_are_refused() {
        for state in [
            CollectorState::Connecting,
            CollectorState::Collecting { generation: 3 },
            CollectorState::Degraded {
                code: "authentication-failed".into(),
            },
            CollectorState::Stopped,
        ] {
            let generation = match &state {
                CollectorState::Collecting { generation } => Some(*generation),
                _ => None,
            };
            assert_eq!(
                CollectorState::from_label(&state.label(), generation),
                Some(state.clone())
            );
        }
        assert_eq!(CollectorState::from_label("collecting", None), None);
        assert_eq!(CollectorState::from_label("paused", None), None);
        assert_eq!(CollectorState::from_label("degraded", None), None);
    }

    #[test]
    fn status_and_state_serialize_as_tagged_objects() {
        let status = TelemetryStatus::Provisioned {
            vm_name: "web".into(),
            state: CollectorState::Degraded {
                code: "signer-unreachable".into(),
            },
            shed: 4,
            losses: Default::default(),
            snapshot_age_ms: Some(900),
            records_bytes: 2_048,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["collection"], "provisioned");
        assert_eq!(json["state"]["kind"], "degraded");
        assert_eq!(json["state"]["code"], "signer-unreachable");
        assert_eq!(
            serde_json::to_value(TelemetryStatus::NotProvisioned).unwrap(),
            serde_json::json!({ "collection": "not_provisioned" })
        );
        let back: TelemetryStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
        assert!(
            serde_json::from_str::<TelemetryStatus>(
                r#"{"collection":"provisioned","vm_name":"web","state":{"kind":"stopped"},"shed":0,"records_bytes":0,"extra":1}"#
            )
            .is_err(),
            "unknown fields fail closed"
        );
    }

    #[test]
    fn a_request_defaults_and_clamps_its_page() {
        let request = TelemetryReadRequest::default();
        assert_eq!(request.cursor(), TelemetryCursor::START);
        assert_eq!(request.effective_limit(), DEFAULT_PAGE_RECORDS);
        let request = TelemetryReadRequest::builder()
            .cursor(TelemetryCursor { offset: 40 })
            .limit(0)
            .build();
        assert_eq!(request.cursor().offset, 40);
        assert_eq!(request.effective_limit(), 1);
        let request = TelemetryReadRequest::builder()
            .limit(MAX_PAGE_RECORDS * 4)
            .build();
        assert_eq!(request.effective_limit(), MAX_PAGE_RECORDS);
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"limit":4096}"#, "unset fields stay off the wire");
        assert_eq!(
            serde_json::from_str::<TelemetryReadRequest>(&json).unwrap(),
            request
        );
    }

    #[test]
    fn a_coverage_record_survives_the_envelope() {
        let coverage = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([9; 16]).unwrap())
            .producer(1)
            .sequence(1)
            .monotonic_ns(10)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "guest-agent".try_into().unwrap(),
            })
            .build()
            .unwrap();
        let line = ReceivedRecord::encode_line(5, &coverage).unwrap();
        assert_eq!(
            ReceivedRecord::decode_line(&line).unwrap().record.body(),
            coverage.body()
        );
    }
}
