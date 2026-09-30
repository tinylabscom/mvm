//! Encrypted machine-exec input journal used by `machine replay`.
//!
//! The append-only JSONL journal carries only sequencing metadata, an
//! encrypted artifact reference, and a success/failure bit. Argument bytes
//! live in [`ReplayInputStore`], encrypted with the host KEK. The same
//! per-machine lock covers execution and checkpoint capture, making the
//! checkpoint's cursor an exact boundary rather than a wall-clock guess.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::util::atomic_io::FileLock;
use mvm_runtime::agent_session::replay_input::{
    ReplayInputBinding, ReplayInputRef, ReplayInputStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One completed execution, decrypted in memory for planning or replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEntry {
    pub seq: u64,
    pub at_unix: u64,
    pub argv: Vec<String>,
    pub succeeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum StoredEvent {
    Started {
        seq: u64,
        at_unix: u64,
        input: ReplayInputRef,
    },
    Finished {
        seq: u64,
        succeeded: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingExec {
    seq: u64,
}

struct CompletedEvent {
    seq: u64,
    at_unix: u64,
    input: ReplayInputRef,
    succeeded: bool,
}

pub fn journal_path(machine_state_dir: &Path) -> PathBuf {
    machine_state_dir.join("input-journal.jsonl")
}

/// Serialize exec and checkpoint operations for one machine.
pub fn lock(machine_state_dir: &Path) -> Result<FileLock> {
    FileLock::acquire(&journal_path(machine_state_dir)).with_context(|| {
        format!(
            "locking the machine input journal {}",
            journal_path(machine_state_dir).display()
        )
    })
}

/// Encrypt and durably record an execution before dispatching it.
pub fn begin_exec(machine_state_dir: &Path, argv: &[String]) -> Result<Option<PendingExec>> {
    if argv.is_empty() {
        return Ok(None);
    }
    let entries = scan(machine_state_dir)?;
    let seq = entries.last().map_or(1, |entry| entry.seq + 1);
    let at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let plaintext = serde_json::to_vec(argv).context("encoding machine exec input")?;
    let input = store(machine_state_dir)
        .record(binding(machine_state_dir, seq)?, &plaintext)
        .context("encrypting machine exec input")?;
    append(
        machine_state_dir,
        &StoredEvent::Started {
            seq,
            at_unix,
            input,
        },
    )?;
    Ok(Some(PendingExec { seq }))
}

/// Durably finish an execution while the journal lock remains held.
pub fn finish_exec(
    machine_state_dir: &Path,
    pending: Option<PendingExec>,
    succeeded: bool,
) -> Result<()> {
    let Some(pending) = pending else {
        return Ok(());
    };
    append(
        machine_state_dir,
        &StoredEvent::Finished {
            seq: pending.seq,
            succeeded,
        },
    )
}

/// Last fully committed input sequence. This refuses an unfinished exec, so a
/// checkpoint never seals ambiguous state.
pub fn cursor(machine_state_dir: &Path) -> Result<u64> {
    Ok(scan(machine_state_dir)?.last().map_or(0, |entry| entry.seq))
}

/// Read complete entries in order. A torn, unterminated final JSON line is
/// dropped; malformed durable lines and unfinished executions fail closed.
pub fn read(machine_state_dir: &Path) -> Result<Vec<InputEntry>> {
    let replay_store = store(machine_state_dir);
    scan(machine_state_dir)?
        .into_iter()
        .map(|entry| {
            let plaintext = replay_store
                .load(&entry.input)
                .with_context(|| format!("decrypting machine input sequence {}", entry.seq))?;
            let argv = serde_json::from_slice(&plaintext)
                .with_context(|| format!("decoding machine input sequence {}", entry.seq))?;
            Ok(InputEntry {
                seq: entry.seq,
                at_unix: entry.at_unix,
                argv,
                succeeded: entry.succeeded,
            })
        })
        .collect()
}

fn scan(machine_state_dir: &Path) -> Result<Vec<CompletedEvent>> {
    let path = journal_path(machine_state_dir);
    let Ok(mut file) = OpenOptions::new().read(true).open(&path) else {
        return Ok(Vec::new());
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading machine input journal {}", path.display()))?;
    let mut entries: Vec<CompletedEvent> = Vec::new();
    let mut pending: Option<(u64, u64, ReplayInputRef)> = None;
    for raw in text.split_inclusive('\n') {
        if !raw.ends_with('\n') {
            break;
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let event: StoredEvent = serde_json::from_str(line).with_context(|| {
            format!(
                "parsing durable machine input journal line in {}",
                path.display()
            )
        })?;
        match event {
            StoredEvent::Started {
                seq,
                at_unix,
                input,
            } => {
                if pending.is_some() || seq != entries.last().map_or(1, |entry| entry.seq + 1) {
                    bail!(
                        "machine input journal has a reordered or overlapping start at sequence {seq}"
                    );
                }
                pending = Some((seq, at_unix, input));
            }
            StoredEvent::Finished { seq, succeeded } => {
                let Some((started_seq, at_unix, input)) = pending.take() else {
                    bail!("machine input journal finishes sequence {seq} without a start");
                };
                if seq != started_seq {
                    bail!(
                        "machine input journal finishes sequence {seq} while {started_seq} is pending"
                    );
                }
                entries.push(CompletedEvent {
                    seq,
                    at_unix,
                    input,
                    succeeded,
                });
            }
        }
    }
    if let Some((seq, _, _)) = pending {
        bail!(
            "machine input sequence {seq} has no durable finish; refuse exec and checkpoint until the ambiguous operation is recovered"
        );
    }
    Ok(entries)
}

pub fn select_after_cursor(entries: &[InputEntry], cursor: u64) -> Vec<InputEntry> {
    entries
        .iter()
        .filter(|entry| entry.seq > cursor)
        .cloned()
        .collect()
}

fn append(machine_state_dir: &Path, event: &StoredEvent) -> Result<()> {
    std::fs::create_dir_all(machine_state_dir).with_context(|| {
        format!(
            "creating machine state directory {}",
            machine_state_dir.display()
        )
    })?;
    let path = journal_path(machine_state_dir);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening machine input journal {}", path.display()))?;
    serde_json::to_writer(&mut file, event).context("encoding machine input journal event")?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}

fn store(machine_state_dir: &Path) -> ReplayInputStore {
    ReplayInputStore::at(
        machine_state_dir.join("input-artifacts"),
        mvm_core::config::mvm_keys_dir(),
    )
}

fn binding(machine_state_dir: &Path, seq: u64) -> Result<ReplayInputBinding> {
    let digest = Sha256::digest(machine_state_dir.to_string_lossy().as_bytes());
    let session_id = AgentSessionId::parse(format!("machine-exec-{}", hex::encode(digest)))
        .context("deriving the machine input artifact binding")?;
    Ok(ReplayInputBinding {
        session_id,
        generation: 0,
        journal_cursor: seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated() -> (tempfile::TempDir, mvm_core::util::test_env::TestEnv) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        (dir, env)
    }

    fn record(dir: &Path, argv: &[&str], succeeded: bool) {
        let args = argv
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        let _lock = lock(dir).expect("lock");
        let pending = begin_exec(dir, &args).expect("begin");
        finish_exec(dir, pending, succeeded).expect("finish");
    }

    #[test]
    fn records_encrypted_input_and_reads_it_back_in_order() {
        let (dir, _env) = isolated();
        record(dir.path(), &["token=private-value"], true);
        record(dir.path(), &["cargo", "test"], false);
        let entries = read(dir.path()).expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].argv, ["token=private-value"]);
        assert!(entries[0].succeeded);
        assert!(!entries[1].succeeded);
        let on_disk = std::fs::read(journal_path(dir.path())).expect("journal");
        assert!(
            !on_disk
                .windows(b"private-value".len())
                .any(|bytes| bytes == b"private-value")
        );
    }

    #[test]
    fn an_empty_argv_is_not_input() {
        let (dir, _env) = isolated();
        let _lock = lock(dir.path()).expect("lock");
        assert_eq!(begin_exec(dir.path(), &[]).expect("begin"), None);
        assert!(read(dir.path()).expect("read").is_empty());
    }

    #[test]
    fn a_torn_final_line_is_dropped_but_a_finished_entry_survives() {
        let (dir, _env) = isolated();
        record(dir.path(), &["one"], true);
        let path = journal_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"event\":\"started\",\"seq\":2")
            .expect("tear");
        assert_eq!(read(dir.path()).expect("read").len(), 1);
    }

    #[test]
    fn an_unfinished_exec_fails_closed() {
        let (dir, _env) = isolated();
        let _lock = lock(dir.path()).expect("lock");
        begin_exec(dir.path(), &["ambiguous".into()]).expect("begin");
        let error = read(dir.path()).expect_err("unfinished input must refuse");
        assert!(error.to_string().contains("no durable finish"), "{error:#}");
    }

    #[test]
    fn select_after_cursor_uses_the_exact_sequence_boundary() {
        let entries = vec![
            InputEntry {
                seq: 1,
                at_unix: 200,
                argv: vec!["before".into()],
                succeeded: true,
            },
            InputEntry {
                seq: 2,
                at_unix: 200,
                argv: vec!["after".into()],
                succeeded: true,
            },
        ];
        let selected = select_after_cursor(&entries, 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].argv, ["after"]);
    }
}
