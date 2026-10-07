//! The local read seam over one machine's telemetry collector: its status
//! snapshot and its persisted records, paged by cursor.
//!
//! [`LocalTelemetryReader`] is the one path through which a local consumer
//! (mvm studio in desktop mode, the host library, `mvmctl`) reads what the
//! per-VM collector left beside the VM state. It reads files the collector
//! owns and never writes them: the status snapshot the collector replaces
//! atomically, and the append-only records file it fills up to its cap.
//! Both are observability, not retention — a stopped machine's files stay
//! until the machine is removed, and a restarted one's collector appends to
//! the same records file.
//!
//! Reads are bounded and oldest-first with a byte-offset cursor. The records
//! file only grows while a machine exists, so a cursor stays valid across
//! reads; one that lands past the end or inside a line (a removed and
//! recreated machine, or a hand-edited file) is refused with a typed error
//! rather than resynchronized by guesswork. A line that does not decode as a
//! record is counted and skipped, never served and never fatal.

use std::io::{BufRead, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use mvm_core::protocol::telemetry::served::{
    CollectorState, MAX_PERSISTED_LINE_BYTES, ReceivedRecord, TelemetryCursor,
    TelemetryReadRequest, TelemetryReadResponse, TelemetryStatus,
};
use mvm_hostd::telemetry_collector::CollectorStatusSnapshot;
use mvm_vmm::host::telemetry_provisioning::{
    TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE,
};
use thiserror::Error;

/// Why a read could not be answered. A machine with no collector is not an
/// error — that is [`TelemetryStatus::NotProvisioned`] — and a line that
/// does not decode is counted in the response; these are the cases where
/// nothing honest can be returned.
#[derive(Debug, Error)]
pub enum TelemetryReadError {
    /// A file the collector owns could not be read.
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The status snapshot exists but is not one this reader understands.
    #[error("telemetry status snapshot at {path} is unreadable: {reason}")]
    Snapshot { path: PathBuf, reason: String },
    /// The cursor does not land on a line boundary of the current file. The
    /// consumer starts over from [`TelemetryCursor::START`].
    #[error("telemetry cursor offset {offset} is not a line boundary of a {len}-byte stream")]
    CursorInvalid { offset: u64, len: u64 },
}

/// Reads one machine's collector outputs from its state directory.
#[derive(Debug, Clone)]
pub struct LocalTelemetryReader {
    state_dir: PathBuf,
}

impl LocalTelemetryReader {
    /// A reader over an explicit VM state directory.
    pub fn for_state_dir(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    /// A reader over the named machine's state directory under `MVM_HOME`.
    pub fn for_machine(name: &str) -> Self {
        Self::for_state_dir(mvm_core::config::vm_state_dir(name))
    }

    /// Whether the machine has a state directory at all. A machine that was
    /// defined but never booted has none, and that is not a telemetry fact.
    pub fn state_dir_exists(&self) -> bool {
        self.state_dir.is_dir()
    }

    fn status_path(&self) -> PathBuf {
        self.state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE)
    }

    fn records_path(&self) -> PathBuf {
        self.state_dir.join(TELEMETRY_RECORDS_FILE)
    }

    /// The collector's status for this machine. No snapshot means no
    /// collector was provisioned for the boot; a snapshot is served as the
    /// typed state it carries, with its age and the records file's size.
    pub fn status(&self) -> Result<TelemetryStatus, TelemetryReadError> {
        let path = self.status_path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(TelemetryStatus::NotProvisioned);
            }
            Err(source) => return Err(TelemetryReadError::Io { path, source }),
        };
        let snapshot: CollectorStatusSnapshot =
            serde_json::from_slice(&bytes).map_err(|e| TelemetryReadError::Snapshot {
                path: path.clone(),
                reason: e.to_string(),
            })?;
        let state =
            CollectorState::from_label(&snapshot.status, snapshot.generation).ok_or_else(|| {
                TelemetryReadError::Snapshot {
                    path: path.clone(),
                    reason: format!("unknown status label {:?}", snapshot.status),
                }
            })?;
        let snapshot_age_ms = std::fs::metadata(&path)
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX));
        let records_bytes = std::fs::metadata(self.records_path())
            .map(|meta| meta.len())
            .unwrap_or(0);
        Ok(TelemetryStatus::Provisioned {
            vm_name: snapshot.vm_name,
            state,
            shed: snapshot.shed,
            snapshot_age_ms,
            records_bytes,
        })
    }

    /// One page of records from the cursor the request names, oldest first.
    /// A missing records file is an empty stream, not an error: the
    /// collector creates it on its first record.
    pub fn read(
        &self,
        request: &TelemetryReadRequest,
    ) -> Result<TelemetryReadResponse, TelemetryReadError> {
        let path = self.records_path();
        let cursor = request.cursor();
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                if cursor.offset != 0 {
                    return Err(TelemetryReadError::CursorInvalid {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
                return Ok(TelemetryReadResponse {
                    records: Vec::new(),
                    next_cursor: TelemetryCursor::START,
                    undecodable: 0,
                    exhausted: true,
                });
            }
            Err(source) => return Err(TelemetryReadError::Io { path, source }),
        };
        let io = |source| TelemetryReadError::Io {
            path: path.clone(),
            source,
        };
        let len = file.metadata().map_err(io)?.len();
        validate_boundary(&file, cursor, len).map_err(io)??;

        let mut reader = std::io::BufReader::new(file);
        reader.seek(SeekFrom::Start(cursor.offset)).map_err(io)?;
        let mut page = Page::new(cursor.offset, request.effective_limit());
        let mut line = Vec::new();
        while page.records.len() < page.limit {
            line.clear();
            let read = reader
                .by_ref()
                .take(MAX_PERSISTED_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(io)?;
            if read == 0 {
                page.exhausted = true;
                break;
            }
            if !line.ends_with(b"\n") {
                if line.len() > MAX_PERSISTED_LINE_BYTES {
                    // An overlong line: skip to its end so one corrupt line
                    // cannot pin the cursor, counting it once.
                    let rest = skip_to_newline(&mut reader).map_err(io)?;
                    page.skip(read as u64 + rest);
                    continue;
                }
                // A partial trailing line is a write in progress; it belongs
                // to the next page once its newline lands.
                page.exhausted = true;
                break;
            }
            match ReceivedRecord::decode_line(&line) {
                Some(record) => page.push(record, read as u64),
                None => page.skip(read as u64),
            }
        }
        if !page.exhausted {
            page.exhausted = page.offset >= len;
        }
        Ok(page.into_response())
    }
}

/// A cursor is honored only on a line boundary: offset 0, or one byte past a
/// newline, and never past the end.
fn validate_boundary(
    file: &std::fs::File,
    cursor: TelemetryCursor,
    len: u64,
) -> std::io::Result<Result<(), TelemetryReadError>> {
    let invalid = Err(TelemetryReadError::CursorInvalid {
        offset: cursor.offset,
        len,
    });
    if cursor.offset > len {
        return Ok(invalid);
    }
    if cursor.offset == 0 {
        return Ok(Ok(()));
    }
    let mut probe = file;
    probe.seek(SeekFrom::Start(cursor.offset - 1))?;
    let mut byte = [0u8; 1];
    probe.read_exact(&mut byte)?;
    Ok(if byte[0] == b'\n' { Ok(()) } else { invalid })
}

/// Consume through the next newline (or the end), returning the bytes
/// consumed. Buffered, so an overlong line costs no allocation of its size.
fn skip_to_newline(reader: &mut impl BufRead) -> std::io::Result<u64> {
    let mut consumed = 0u64;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(consumed);
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(at) => {
                reader.consume(at + 1);
                return Ok(consumed + at as u64 + 1);
            }
            None => {
                let n = buf.len();
                reader.consume(n);
                consumed += n as u64;
            }
        }
    }
}

/// A page under construction: the records so far and the offset the next
/// page starts at.
struct Page {
    records: Vec<ReceivedRecord>,
    offset: u64,
    limit: usize,
    undecodable: u64,
    exhausted: bool,
}

impl Page {
    fn new(offset: u64, limit: usize) -> Self {
        Self {
            records: Vec::new(),
            offset,
            limit,
            undecodable: 0,
            exhausted: false,
        }
    }

    fn push(&mut self, record: ReceivedRecord, bytes: u64) {
        self.records.push(record);
        self.offset += bytes;
    }

    fn skip(&mut self, bytes: u64) {
        self.undecodable += 1;
        self.offset += bytes;
    }

    fn into_response(self) -> TelemetryReadResponse {
        TelemetryReadResponse {
            records: self.records,
            next_cursor: TelemetryCursor {
                offset: self.offset,
            },
            undecodable: self.undecodable,
            exhausted: self.exhausted,
        }
    }
}

/// Where a machine's collector files live, for callers that stage them in
/// tests or report them in diagnostics.
pub fn collector_files(state_dir: &Path) -> (PathBuf, PathBuf) {
    (
        state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE),
        state_dir.join(TELEMETRY_RECORDS_FILE),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::telemetry::served::{DEFAULT_PAGE_RECORDS, MAX_PAGE_RECORDS};
    use mvm_core::protocol::telemetry::{
        Attributes, CoverageState, Level, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
    };

    fn record(sequence: u64) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([3; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence * 10)
            .source(SourceKind::GuestAgent)
            .body(if sequence == 1 {
                RecordBody::Coverage {
                    state: CoverageState::Started,
                    code: "guest-agent".try_into().unwrap(),
                }
            } else {
                RecordBody::Event {
                    context: None,
                    level: Level::Info,
                    name: "tick".try_into().unwrap(),
                    attributes: Attributes::new(Vec::new()).unwrap(),
                }
            })
            .build()
            .unwrap()
    }

    fn line(sequence: u64) -> Vec<u8> {
        ReceivedRecord::encode_line(1_000 + sequence, &record(sequence)).unwrap()
    }

    fn stage(dir: &Path, lines: &[Vec<u8>]) -> LocalTelemetryReader {
        let (_, records) = collector_files(dir);
        std::fs::write(records, lines.concat()).unwrap();
        LocalTelemetryReader::for_state_dir(dir)
    }

    fn write_status(dir: &Path, status: &str, generation: Option<u64>, shed: u64) {
        let (path, _) = collector_files(dir);
        let snapshot = CollectorStatusSnapshot {
            vm_name: "web".into(),
            status: status.into(),
            generation,
            shed,
        };
        std::fs::write(path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    }

    fn sequences(response: &TelemetryReadResponse) -> Vec<u64> {
        response
            .records
            .iter()
            .map(|r| r.record.sequence())
            .collect()
    }

    #[test]
    fn no_snapshot_means_no_collector_was_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        let reader = LocalTelemetryReader::for_state_dir(dir.path());
        assert!(reader.state_dir_exists());
        assert_eq!(reader.status().unwrap(), TelemetryStatus::NotProvisioned);
        assert!(!LocalTelemetryReader::for_state_dir(dir.path().join("absent")).state_dir_exists());
    }

    #[test]
    fn a_snapshot_is_served_as_its_typed_state_with_age_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let reader = stage(dir.path(), &[line(1), line(2)]);
        let records_bytes = (line(1).len() + line(2).len()) as u64;
        for (label, generation, expected) in [
            ("connecting", None, CollectorState::Connecting),
            (
                "collecting",
                Some(4),
                CollectorState::Collecting { generation: 4 },
            ),
            (
                "degraded:authentication-failed",
                None,
                CollectorState::Degraded {
                    code: "authentication-failed".into(),
                },
            ),
            ("stopped", None, CollectorState::Stopped),
        ] {
            write_status(dir.path(), label, generation, 7);
            let TelemetryStatus::Provisioned {
                vm_name,
                state,
                shed,
                snapshot_age_ms,
                records_bytes: served_bytes,
            } = reader.status().unwrap()
            else {
                panic!("{label}: provisioned");
            };
            assert_eq!(vm_name, "web");
            assert_eq!(state, expected, "{label}");
            assert_eq!(shed, 7);
            assert!(
                snapshot_age_ms.is_some_and(|age| age < 60_000),
                "{label}: fresh"
            );
            assert_eq!(served_bytes, records_bytes);
        }
    }

    #[test]
    fn an_unreadable_snapshot_is_a_typed_error_not_a_guess() {
        let dir = tempfile::tempdir().unwrap();
        let reader = LocalTelemetryReader::for_state_dir(dir.path());
        let (path, _) = collector_files(dir.path());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            reader.status(),
            Err(TelemetryReadError::Snapshot { .. })
        ));
        write_status(dir.path(), "paused", None, 0);
        assert!(matches!(
            reader.status(),
            Err(TelemetryReadError::Snapshot { reason, .. }) if reason.contains("paused")
        ));
    }

    #[test]
    fn a_missing_records_file_is_an_empty_stream_from_the_start_only() {
        let dir = tempfile::tempdir().unwrap();
        let reader = LocalTelemetryReader::for_state_dir(dir.path());
        let page = reader.read(&TelemetryReadRequest::default()).unwrap();
        assert!(page.records.is_empty());
        assert_eq!(page.next_cursor, TelemetryCursor::START);
        assert!(page.exhausted);
        let stale = TelemetryReadRequest::builder()
            .cursor(TelemetryCursor { offset: 12 })
            .build();
        assert!(matches!(
            reader.read(&stale),
            Err(TelemetryReadError::CursorInvalid { offset: 12, len: 0 })
        ));
    }

    #[test]
    fn pages_walk_the_stream_oldest_first_and_the_last_cursor_polls_for_more() {
        let dir = tempfile::tempdir().unwrap();
        let reader = stage(dir.path(), &[line(1), line(2), line(3), line(4), line(5)]);
        let first = reader
            .read(&TelemetryReadRequest::builder().limit(2).build())
            .unwrap();
        assert_eq!(sequences(&first), vec![1, 2]);
        assert_eq!(first.records[0].received_at_ms, Some(1_001));
        assert!(!first.exhausted, "three more are waiting");
        assert_eq!(first.undecodable, 0);

        let second = reader
            .read(
                &TelemetryReadRequest::builder()
                    .cursor(first.next_cursor)
                    .limit(2)
                    .build(),
            )
            .unwrap();
        assert_eq!(sequences(&second), vec![3, 4]);
        assert!(!second.exhausted);

        let third = reader
            .read(
                &TelemetryReadRequest::builder()
                    .cursor(second.next_cursor)
                    .limit(2)
                    .build(),
            )
            .unwrap();
        assert_eq!(sequences(&third), vec![5]);
        assert!(third.exhausted);

        // Nothing new: the same cursor comes back and the page is empty.
        let quiet = reader
            .read(
                &TelemetryReadRequest::builder()
                    .cursor(third.next_cursor)
                    .build(),
            )
            .unwrap();
        assert!(quiet.records.is_empty());
        assert_eq!(quiet.next_cursor, third.next_cursor);
        assert!(quiet.exhausted);

        // The collector appends; the same cursor now yields the new record.
        let (_, records) = collector_files(dir.path());
        let mut appended = std::fs::read(&records).unwrap();
        appended.extend(line(6));
        std::fs::write(&records, appended).unwrap();
        let fresh = reader
            .read(
                &TelemetryReadRequest::builder()
                    .cursor(third.next_cursor)
                    .build(),
            )
            .unwrap();
        assert_eq!(sequences(&fresh), vec![6]);
    }

    #[test]
    fn a_full_page_that_ends_exactly_at_the_end_is_exhausted() {
        let dir = tempfile::tempdir().unwrap();
        let reader = stage(dir.path(), &[line(1), line(2)]);
        let page = reader
            .read(&TelemetryReadRequest::builder().limit(2).build())
            .unwrap();
        assert_eq!(sequences(&page), vec![1, 2]);
        assert!(page.exhausted, "the page consumed the whole file");
    }

    #[test]
    fn undecodable_lines_are_counted_skipped_and_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let bare = {
            let mut bare = serde_json::to_vec(&record(2)).unwrap();
            bare.push(b'\n');
            bare
        };
        let reader = stage(
            dir.path(),
            &[
                line(1),
                b"garbage\n".to_vec(),
                bare,
                b"{\"vm\":\"x\"}\n".to_vec(),
                line(3),
            ],
        );
        let page = reader.read(&TelemetryReadRequest::default()).unwrap();
        assert_eq!(sequences(&page), vec![1, 2, 3]);
        assert_eq!(
            page.records[1].received_at_ms, None,
            "a bare pre-envelope line decodes without a receive time"
        );
        assert_eq!(page.undecodable, 2);
        assert!(page.exhausted);
        let (_, records) = collector_files(dir.path());
        assert_eq!(
            page.next_cursor.offset,
            std::fs::metadata(records).unwrap().len(),
            "the cursor advanced past the skipped lines too"
        );
    }

    #[test]
    fn an_overlong_line_is_skipped_whole_and_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut huge = vec![b'x'; MAX_PERSISTED_LINE_BYTES * 3];
        huge.push(b'\n');
        let reader = stage(dir.path(), &[line(1), huge.clone(), line(2)]);
        let page = reader.read(&TelemetryReadRequest::default()).unwrap();
        assert_eq!(sequences(&page), vec![1, 2]);
        assert_eq!(page.undecodable, 1);
        assert_eq!(
            page.next_cursor.offset as usize,
            line(1).len() + huge.len() + line(2).len()
        );
    }

    #[test]
    fn a_partial_trailing_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let mut partial = line(2);
        partial.truncate(partial.len() / 2);
        let reader = stage(dir.path(), &[line(1), partial]);
        let page = reader.read(&TelemetryReadRequest::default()).unwrap();
        assert_eq!(sequences(&page), vec![1]);
        assert_eq!(page.next_cursor.offset as usize, line(1).len());
        assert_eq!(page.undecodable, 0, "a write in progress is not corruption");
        assert!(page.exhausted);
    }

    #[test]
    fn a_cursor_off_a_line_boundary_or_past_the_end_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let reader = stage(dir.path(), &[line(1), line(2)]);
        let len = (line(1).len() + line(2).len()) as u64;
        for offset in [1, line(1).len() as u64 - 1, len + 1, len + 500] {
            let request = TelemetryReadRequest::builder()
                .cursor(TelemetryCursor { offset })
                .build();
            assert!(
                matches!(
                    reader.read(&request),
                    Err(TelemetryReadError::CursorInvalid { offset: o, len: l }) if o == offset && l == len
                ),
                "offset {offset}"
            );
        }
        // Exactly the end is a valid (empty) position.
        let at_end = TelemetryReadRequest::builder()
            .cursor(TelemetryCursor { offset: len })
            .build();
        assert!(reader.read(&at_end).unwrap().records.is_empty());
    }

    #[test]
    fn the_page_size_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let lines: Vec<Vec<u8>> = (1..=(MAX_PAGE_RECORDS as u64 + 5)).map(line).collect();
        let reader = stage(dir.path(), &lines);
        let default = reader.read(&TelemetryReadRequest::default()).unwrap();
        assert_eq!(default.records.len(), DEFAULT_PAGE_RECORDS);
        let greedy = reader
            .read(&TelemetryReadRequest::builder().limit(usize::MAX).build())
            .unwrap();
        assert_eq!(greedy.records.len(), MAX_PAGE_RECORDS);
        assert!(!greedy.exhausted);
    }
}
