//! The local read side of host-mediated telemetry: what the embedded
//! collector persisted in a machine's state dir, served through the
//! `MvmClient` telemetry methods.
//!
//! The collector is a thread inside the per-VM network endpoint; it owns the
//! files. This module only reads them, so a consumer polling a dashboard can
//! never block, slow or corrupt collection. It also attributes records to a
//! machine: the records carry no identity of their own, and the state dir
//! they were read from is what binds them to one.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use mvm_core::client::{MvmError, Result};
use mvm_core::protocol::telemetry::{
    CollectorStatusSnapshot, PageError, TelemetryCursor, TelemetryPage, TelemetryReadOpts,
    TelemetryStatus, page_from_jsonl,
};
use mvm_vmm::host::telemetry_provisioning::{
    TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE,
};

/// The collector status for the machine whose state dir this is.
///
/// No status file means no collector was provisioned for the boot, which is
/// the ordinary opt-out state and answers `NotProvisioned`. A file that is
/// present but unreadable or carries a label this reader does not know is a
/// backend error: something wrote it, and guessing a coverage state for it
/// would misreport health.
pub fn read_status(state_dir: &Path) -> Result<TelemetryStatus> {
    let path = state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TelemetryStatus::not_provisioned());
        }
        Err(e) => {
            return Err(MvmError::Backend {
                reason: format!("reading {}: {e}", path.display()),
            });
        }
    };
    let snapshot: CollectorStatusSnapshot =
        serde_json::from_slice(&bytes).map_err(|e| MvmError::Backend {
            reason: format!("{} is not a collector status snapshot: {e}", path.display()),
        })?;
    TelemetryStatus::try_from(&snapshot).map_err(|e| MvmError::Backend {
        reason: format!("{}: {e}", path.display()),
    })
}

/// One page of the records persisted in `state_dir`, continuing from
/// `opts.after`.
///
/// Reads only the bytes past the cursor, so polling an idle machine costs a
/// `stat`. A cursor past the file's end means the stream was reset under
/// the reader (the machine rebooted and the collector started a fresh file);
/// that is refused as `Rejected` so the reader restarts knowingly instead of
/// splicing two boots together.
pub fn read_records(state_dir: &Path, opts: TelemetryReadOpts) -> Result<TelemetryPage> {
    let path = state_dir.join(TELEMETRY_RECORDS_FILE);
    let after = opts.after.unwrap_or(TelemetryCursor(0));
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if after.0 == 0 {
                Ok(TelemetryPage {
                    records: Vec::new(),
                    next: after,
                    more: false,
                })
            } else {
                Err(cursor_past_end(after, 0))
            };
        }
        Err(e) => return Err(io_error(&path, e)),
    };
    let len = file.metadata().map_err(|e| io_error(&path, e))?.len();
    if after.0 > len {
        return Err(cursor_past_end(after, len));
    }
    file.seek(SeekFrom::Start(after.0))
        .map_err(|e| io_error(&path, e))?;
    let mut tail = Vec::with_capacity((len - after.0) as usize);
    file.read_to_end(&mut tail)
        .map_err(|e| io_error(&path, e))?;
    page_from_jsonl(&tail, after.0, opts.effective_limit()).map_err(|e| match e {
        PageError::Malformed { .. } => MvmError::Backend {
            reason: format!("{}: {e}", path.display()),
        },
    })
}

fn cursor_past_end(cursor: TelemetryCursor, len: u64) -> MvmError {
    MvmError::Rejected {
        reason: format!(
            "telemetry cursor {} is past the end of the record stream ({len} bytes); \
             the stream was reset, read again from the start",
            cursor.0
        ),
    }
}

fn io_error(path: &Path, e: std::io::Error) -> MvmError {
    MvmError::Backend {
        reason: format!("reading {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::telemetry::{
        Attributes, Level, ProducerEpoch, RecordBody, SourceKind, TelemetryCoverage,
        TelemetryRecord,
    };

    fn record(sequence: u64) -> TelemetryRecord {
        TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([3; 16]).unwrap())
            .producer(1)
            .sequence(sequence)
            .monotonic_ns(sequence * 10)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Event {
                context: None,
                level: Level::Info,
                name: "tick".try_into().unwrap(),
                attributes: Attributes::new(Vec::new()).unwrap(),
            })
            .build()
            .unwrap()
    }

    fn append(dir: &Path, records: &[TelemetryRecord]) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(TELEMETRY_RECORDS_FILE))
            .unwrap();
        for r in records {
            file.write_all(&serde_json::to_vec(r).unwrap()).unwrap();
            file.write_all(b"\n").unwrap();
        }
    }

    #[test]
    fn an_unprovisioned_machine_reads_as_not_provisioned_with_an_empty_stream() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_status(dir.path()).unwrap(),
            TelemetryStatus::not_provisioned()
        );
        let page = read_records(dir.path(), TelemetryReadOpts::from_start()).unwrap();
        assert!(page.records.is_empty());
        assert_eq!(page.next, TelemetryCursor(0));
        assert!(!page.more);
    }

    #[test]
    fn the_status_file_the_collector_writes_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = CollectorStatusSnapshot {
            vm_name: "vm".into(),
            status: "collecting".into(),
            generation: Some(4),
            shed: 2,
        };
        std::fs::write(
            dir.path().join(TELEMETRY_COLLECTOR_STATUS_FILE),
            serde_json::to_vec_pretty(&snapshot).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_status(dir.path()).unwrap(),
            TelemetryStatus {
                coverage: TelemetryCoverage::Collecting { generation: 4 },
                shed: 2,
            }
        );
    }

    #[test]
    fn a_status_file_that_is_not_a_snapshot_is_a_backend_error_not_a_health_claim() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(TELEMETRY_COLLECTOR_STATUS_FILE), b"{}").unwrap();
        let err = read_status(dir.path()).unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }), "{err}");
        std::fs::write(
            dir.path().join(TELEMETRY_COLLECTOR_STATUS_FILE),
            br#"{"vm_name":"vm","status":"sideways","shed":0}"#,
        )
        .unwrap();
        let err = read_status(dir.path()).unwrap_err();
        assert!(matches!(err, MvmError::Backend { .. }), "{err}");
    }

    #[test]
    fn records_page_by_cursor_and_pick_up_what_arrived_since() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &[record(1), record(2), record(3)]);

        let first = read_records(
            dir.path(),
            TelemetryReadOpts {
                after: None,
                limit: Some(2),
            },
        )
        .unwrap();
        assert_eq!(first.records, vec![record(1), record(2)]);
        assert!(first.more);

        let second = read_records(dir.path(), TelemetryReadOpts::after(first.next)).unwrap();
        assert_eq!(second.records, vec![record(3)]);
        assert!(!second.more);

        let idle = read_records(dir.path(), TelemetryReadOpts::after(second.next)).unwrap();
        assert!(idle.records.is_empty());
        assert_eq!(idle.next, second.next);

        append(dir.path(), &[record(4)]);
        let fresh = read_records(dir.path(), TelemetryReadOpts::after(idle.next)).unwrap();
        assert_eq!(fresh.records, vec![record(4)]);
    }

    #[test]
    fn a_cursor_from_before_a_reset_is_refused_not_rebased() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &[record(1), record(2)]);
        let page = read_records(dir.path(), TelemetryReadOpts::from_start()).unwrap();

        // The next boot starts a fresh, shorter file.
        std::fs::remove_file(dir.path().join(TELEMETRY_RECORDS_FILE)).unwrap();
        let err = read_records(dir.path(), TelemetryReadOpts::after(page.next)).unwrap_err();
        assert!(matches!(err, MvmError::Rejected { .. }), "{err}");

        append(dir.path(), &[record(1)]);
        let err = read_records(dir.path(), TelemetryReadOpts::after(page.next)).unwrap_err();
        assert!(matches!(err, MvmError::Rejected { .. }), "{err}");

        let restarted = read_records(dir.path(), TelemetryReadOpts::from_start()).unwrap();
        assert_eq!(restarted.records, vec![record(1)]);
    }

    #[test]
    fn a_line_still_being_written_is_not_served() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &[record(1)]);
        let complete = std::fs::metadata(dir.path().join(TELEMETRY_RECORDS_FILE))
            .unwrap()
            .len();
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.path().join(TELEMETRY_RECORDS_FILE))
                .unwrap();
            file.write_all(br#"{"format":"mvm.telem"#).unwrap();
        }
        let page = read_records(dir.path(), TelemetryReadOpts::from_start()).unwrap();
        assert_eq!(page.records, vec![record(1)]);
        assert_eq!(page.next, TelemetryCursor(complete));
    }
}
