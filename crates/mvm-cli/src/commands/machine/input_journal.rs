//! The machine input journal: what was executed against this machine, in
//! order, so a later `machine replay` can re-run it from a checkpoint.
//!
//! One JSON line per executed command — the argv exactly as it was given,
//! the wall clock, and the outcome. Nothing else: the journal records the
//! input, never the output, so it stays small and never carries guest data.
//! Interactive shells (an empty argv) are not recorded: a human at a PTY
//! is not replayable input.
//!
//! Durability matches the audit-journal convention: append + fsync per
//! entry. A torn final line from a crash is dropped on read, never parsed.

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One recorded execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEntry {
    /// Dense sequence number, 1-based.
    pub seq: u64,
    /// Wall-clock seconds since the epoch.
    pub at_unix: u64,
    /// The argv exactly as it reached the guest (after `--`).
    pub argv: Vec<String>,
    /// `ok` or a short refusal reason; the output itself is never recorded.
    pub outcome: String,
}

/// The journal path under a machine's state dir.
pub fn journal_path(machine_state_dir: &Path) -> PathBuf {
    machine_state_dir.join("input-journal.jsonl")
}

/// Append one entry and fsync. `seq` is the next dense number.
pub fn record_exec(machine_state_dir: &Path, argv: &[String], outcome: &str) -> io::Result<()> {
    if argv.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(machine_state_dir)?;
    let path = journal_path(machine_state_dir);
    let seq = read(machine_state_dir)?.last().map_or(0, |entry| entry.seq) + 1;
    let at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry = InputEntry {
        seq,
        at_unix,
        argv: argv.to_vec(),
        outcome: outcome.to_string(),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    serde_json::to_writer(&mut file, &entry).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}

/// Every intact entry, in order. A torn final line (crash mid-append) is
/// dropped; corruption mid-file stops the read there rather than panicking.
pub fn read(machine_state_dir: &Path) -> io::Result<Vec<InputEntry>> {
    let path = journal_path(machine_state_dir);
    let Ok(mut file) = OpenOptions::new().read(true).open(&path) else {
        return Ok(Vec::new());
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(entry) => entries.push(entry),
            Err(_) => break,
        }
    }
    Ok(entries)
}

/// The entries recorded at or after `since_unix` — what a replay from a
/// checkpoint taken at that instant must re-run. Entries recorded before
/// the checkpoint are already part of its state.
pub fn select_after(entries: &[InputEntry], since_unix: u64) -> Vec<InputEntry> {
    entries
        .iter()
        .filter(|entry| entry.at_unix >= since_unix)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn records_and_reads_back_in_order() {
        let dir = dir();
        record_exec(dir.path(), &["ls".into(), "-la".into()], "ok").expect("record");
        record_exec(dir.path(), &["cargo".into(), "test".into()], "ok").expect("record");
        let entries = read(dir.path()).expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].seq, 2);
        assert_eq!(entries[1].argv, ["cargo", "test"]);
        assert_eq!(entries[1].outcome, "ok");
    }

    #[test]
    fn an_empty_argv_is_not_input() {
        let dir = dir();
        record_exec(dir.path(), &[], "ok").expect("record");
        assert!(read(dir.path()).expect("read").is_empty());
    }

    #[test]
    fn a_missing_journal_reads_empty() {
        let dir = dir();
        assert!(read(dir.path()).expect("read").is_empty());
    }

    #[test]
    fn a_torn_final_line_is_dropped_not_parsed() {
        let dir = dir();
        record_exec(dir.path(), &["one".into()], "ok").expect("record");
        let path = journal_path(dir.path());
        let mut text = fs::read_to_string(&path).expect("read journal");
        text.push_str("{\"seq\":2,\"at_unix\":1,\"ar"); // crash mid-append
        fs::write(&path, text).expect("write torn line");
        let entries = read(dir.path()).expect("read");
        assert_eq!(entries.len(), 1, "the torn line is dropped");
    }

    #[test]
    fn select_after_takes_only_entries_at_or_later() {
        let entries = vec![
            InputEntry {
                seq: 1,
                at_unix: 100,
                argv: vec!["before".into()],
                outcome: "ok".into(),
            },
            InputEntry {
                seq: 2,
                at_unix: 200,
                argv: vec!["at".into()],
                outcome: "ok".into(),
            },
            InputEntry {
                seq: 3,
                at_unix: 300,
                argv: vec!["after".into()],
                outcome: "ok".into(),
            },
        ];
        let selected = select_after(&entries, 200);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].argv, ["at"]);
        assert_eq!(selected[1].argv, ["after"]);
    }
}
