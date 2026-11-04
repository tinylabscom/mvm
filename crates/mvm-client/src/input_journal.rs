//! Encrypted machine-exec input journal used by `machine replay`.
//!
//! The append-only JSONL journal carries only sequencing metadata, an
//! encrypted artifact reference, and a success/failure bit. Argument bytes
//! live in [`ReplayInputStore`], encrypted with the host KEK. The same
//! per-machine lock covers execution and checkpoint capture, making the
//! checkpoint's cursor an exact boundary rather than a wall-clock guess.
//! Callers must hold that lock throughout execution, completion and capture.
//! The lock serializes cooperating callers, not out-of-band file changes.
//! Reading entries returns decrypted arguments; treat them as sensitive.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_core::util::atomic_io::FileLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::replay_input::{ReplayInputBinding, ReplayInputRef, ReplayInputStore};

const TORN_RECORD_ERROR: &str = "machine input journal has an unterminated final record; \
    refusing machine exec, checkpoint and replay until it is recovered";

/// One completed execution, decrypted in memory for planning or replay.
#[derive(Clone, PartialEq, Eq)]
pub struct InputEntry {
    /// Monotonic sequence assigned when the execution was recorded.
    pub seq: u64,
    /// Wall-clock timestamp of the execution's start, in Unix seconds.
    pub at_unix: u64,
    /// Decrypted command arguments. These can contain sensitive input.
    pub argv: Vec<String>,
    /// Whether the execution returned successfully.
    pub succeeded: bool,
}

impl std::fmt::Debug for InputEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InputEntry")
            .field("seq", &self.seq)
            .field("at_unix", &self.at_unix)
            .field("argv", &"[REDACTED]")
            .field("succeeded", &self.succeeded)
            .finish()
    }
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

/// One started execution, to be finished once under the same machine's lock.
///
/// A pending execution cannot be copied and finished twice.
///
/// ```compile_fail
/// use mvm_client::input_journal::PendingExec;
/// fn duplicate(pending: PendingExec) -> (PendingExec, PendingExec) {
///     (pending, pending)
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct PendingExec {
    seq: u64,
}

struct CompletedEvent {
    seq: u64,
    at_unix: u64,
    input: ReplayInputRef,
    succeeded: bool,
}

fn journal_path(machine_state_dir: &Path) -> PathBuf {
    machine_state_dir.join("input-journal.jsonl")
}

/// Serialize exec and checkpoint operations for one machine.
///
/// # Errors
///
/// The journal lock could not be created or acquired.
pub fn lock(machine_state_dir: &Path) -> Result<FileLock> {
    FileLock::acquire(&journal_path(machine_state_dir)).with_context(|| {
        format!(
            "locking the machine input journal {}",
            journal_path(machine_state_dir).display()
        )
    })
}

/// Encrypt and durably record an execution before dispatching it.
/// The caller must hold the machine journal lock until execution is finished.
///
/// # Errors
///
/// The journal is unreadable or ambiguous, the input cannot be encrypted,
/// or the start event cannot be durably appended.
pub fn begin_exec(machine_state_dir: &Path, argv: &[String]) -> Result<Option<PendingExec>> {
    let entries = scan(machine_state_dir)?;
    if argv.is_empty() {
        return Ok(None);
    }
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
///
/// Use the same machine directory and lock held when the execution was started.
///
/// # Errors
///
/// The finish event cannot be durably appended.
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
/// checkpoint never seals ambiguous state. Hold the journal lock through the
/// capture that consumes this cursor.
///
/// # Errors
///
/// The journal is unreadable, malformed or contains an unfinished execution.
pub fn cursor(machine_state_dir: &Path) -> Result<u64> {
    Ok(scan(machine_state_dir)?.last().map_or(0, |entry| entry.seq))
}

/// Read complete entries in order. Unterminated or malformed lines and
/// unfinished executions fail closed.
/// The returned arguments are decrypted and must be treated as sensitive.
///
/// # Errors
///
/// The journal or an encrypted input is unreadable, malformed or incomplete.
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
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(&path) {
                Err(metadata_error) if metadata_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(metadata_error) => {
                    return Err(metadata_error).with_context(|| {
                        format!("inspecting machine input journal {}", path.display())
                    });
                }
                Ok(_) => {
                    return Err(error).with_context(|| {
                        format!("opening machine input journal {}", path.display())
                    });
                }
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening machine input journal {}", path.display()));
        }
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading machine input journal {}", path.display()))?;
    if !text.is_empty() && !text.ends_with('\n') {
        bail!("{TORN_RECORD_ERROR}");
    }
    let mut entries: Vec<CompletedEvent> = Vec::new();
    let mut pending: Option<(u64, u64, ReplayInputRef)> = None;
    for raw in text.split_inclusive('\n') {
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
    if matches!(event, StoredEvent::Started { .. }) {
        std::fs::create_dir_all(machine_state_dir).with_context(|| {
            format!(
                "creating machine state directory {}",
                machine_state_dir.display()
            )
        })?;
    }
    let path = journal_path(machine_state_dir);
    let mut file = OpenOptions::new()
        .create(matches!(event, StoredEvent::Started { .. }))
        .read(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening machine input journal {}", path.display()))?;
    if file
        .metadata()
        .with_context(|| format!("inspecting machine input journal {}", path.display()))?
        .len()
        > 0
    {
        file.seek(SeekFrom::End(-1))
            .with_context(|| format!("seeking machine input journal {}", path.display()))?;
        let mut last = [0];
        file.read_exact(&mut last)
            .with_context(|| format!("reading machine input journal {}", path.display()))?;
        if last[0] != b'\n' {
            bail!("{TORN_RECORD_ERROR}");
        }
    }
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
    fn a_missing_journal_is_an_empty_history_without_creating_it() {
        let (dir, _env) = isolated();
        assert_eq!(cursor(dir.path()).expect("missing journal"), 0);
        assert!(read(dir.path()).expect("missing journal").is_empty());
        assert!(!journal_path(dir.path()).exists());
    }

    #[test]
    fn empty_and_newline_terminated_blank_journals_accept_execution() {
        for initial in [b"".as_slice(), b"\n", b" \t\r\n"] {
            let (dir, _env) = isolated();
            let path = journal_path(dir.path());
            std::fs::write(&path, initial).expect("journal");
            assert_eq!(cursor(dir.path()).expect("empty history"), 0);
            record(dir.path(), &["one"], true);
            assert_eq!(read(dir.path()).expect("read")[0].argv, ["one"]);
            assert!(std::fs::read(&path).expect("journal").starts_with(initial));
        }
    }

    #[test]
    fn any_unterminated_tail_refuses_before_recording_or_appending() {
        for tail in [b" ".as_slice(), b"\r", b"{}"] {
            let (dir, _env) = isolated();
            let path = journal_path(dir.path());
            std::fs::write(&path, tail).expect("torn journal");
            let _lock = lock(dir.path()).expect("lock");
            assert!(cursor(dir.path()).is_err(), "{tail:?}");
            assert!(read(dir.path()).is_err(), "{tail:?}");
            assert!(begin_exec(dir.path(), &["one".into()]).is_err(), "{tail:?}");
            assert!(begin_exec(dir.path(), &[]).is_err(), "{tail:?}");
            assert_eq!(std::fs::read(&path).expect("unchanged"), tail);
            assert!(!dir.path().join("input-artifacts").exists());
        }
    }

    #[test]
    fn an_unreadable_journal_is_not_an_empty_history() {
        let (dir, _env) = isolated();
        let not_a_directory = dir.path().join("not-a-directory");
        std::fs::write(&not_a_directory, b"preserve").expect("write");

        assert!(cursor(&not_a_directory).is_err());
        assert!(read(&not_a_directory).is_err());
        assert!(begin_exec(&not_a_directory, &["echo".into()]).is_err());
        assert_eq!(std::fs::read(&not_a_directory).expect("read"), b"preserve");
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_journal_symlink_is_not_an_absent_journal() {
        let (dir, _env) = isolated();
        let path = journal_path(dir.path());
        std::os::unix::fs::symlink("missing-target", &path).expect("symlink");

        assert!(cursor(dir.path()).is_err());
        assert!(read(dir.path()).is_err());
        assert_eq!(
            std::fs::read_link(&path).expect("symlink remains"),
            Path::new("missing-target")
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_journal_symlink_remains_readable() {
        let (dir, _env) = isolated();
        record(dir.path(), &["preserved"], true);
        let path = journal_path(dir.path());
        std::fs::rename(&path, dir.path().join("existing-journal")).expect("rename");
        std::os::unix::fs::symlink("existing-journal", &path).expect("symlink");

        assert_eq!(cursor(dir.path()).expect("cursor"), 1);
        assert_eq!(read(dir.path()).expect("read")[0].argv, ["preserved"]);
    }

    #[test]
    fn debug_output_never_contains_decrypted_arguments() {
        let entry = InputEntry {
            seq: 1,
            at_unix: 42,
            argv: vec!["private-input-must-not-appear".into()],
            succeeded: true,
        };
        let rendered = format!("{entry:?}");
        assert!(!rendered.contains("private-input-must-not-appear"));
        assert!(!format!("{entry:#?}").contains("private-input-must-not-appear"));
        assert!(rendered.contains("seq"));
    }

    #[test]
    fn a_torn_final_line_refuses_reads_and_checkpoint_cursors() {
        let (dir, _env) = isolated();
        record(dir.path(), &["one"], true);
        let path = journal_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"event\":\"started\",\"private\":\"sensitive-tail")
            .expect("tear");
        file.sync_data().expect("persist torn bytes");
        let before = std::fs::read(&path).expect("torn journal");
        for error in [
            read(dir.path()).expect_err("torn input must refuse"),
            cursor(dir.path()).expect_err("torn cursor must refuse"),
        ] {
            assert!(error.to_string().contains("unterminated"), "{error:#}");
            assert!(!format!("{error:#}").contains("sensitive-tail"));
        }
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
    }

    #[test]
    fn a_torn_start_refuses_a_new_execution_before_recording_input() {
        let (dir, _env) = isolated();
        record(dir.path(), &["one"], true);
        let path = journal_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"event\":\"started\",\"seq\":2")
            .expect("tear");
        file.sync_data().expect("persist torn bytes");
        let before = std::fs::read(&path).expect("torn journal");
        let next_artifact = dir
            .path()
            .join("input-artifacts")
            .join(binding(dir.path(), 2).expect("binding").session_id.as_str())
            .join("replay-inputs/generation-0/cursor-2.json");
        assert!(!next_artifact.exists());

        let _lock = lock(dir.path()).expect("lock");
        let error = begin_exec(dir.path(), &["two".into()]).expect_err("must refuse");
        assert!(error.to_string().contains("unterminated"), "{error:#}");
        assert!(
            begin_exec(dir.path(), &[]).is_err(),
            "shell entry must refuse"
        );
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
        assert!(
            !next_artifact.exists(),
            "no new encrypted input was recorded"
        );
    }

    #[test]
    fn a_torn_finish_after_a_started_execution_is_already_ambiguous() {
        let (dir, _env) = isolated();
        let _lock = lock(dir.path()).expect("lock");
        let _pending = begin_exec(dir.path(), &["one".into()]).expect("start");
        let path = journal_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"event\":\"finished\",\"seq\":1")
            .expect("tear");
        file.sync_data().expect("persist torn bytes");
        let before = std::fs::read(&path).expect("torn journal");

        let error = begin_exec(dir.path(), &["two".into()]).expect_err("unfinished start");
        assert!(error.to_string().contains("unterminated"), "{error:#}");
        assert!(cursor(dir.path()).is_err());
        assert!(read(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
    }

    #[test]
    fn a_torn_tail_added_after_start_refuses_the_finish_without_mutation() {
        let (dir, _env) = isolated();
        let _lock = lock(dir.path()).expect("lock");
        let pending = begin_exec(dir.path(), &["one".into()]).expect("start");
        let path = journal_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"event\":\"finished\",\"seq\":1")
            .expect("tear");
        file.sync_data().expect("persist torn bytes");
        let before = std::fs::read(&path).expect("torn journal");

        let error = finish_exec(dir.path(), pending, true).expect_err("must refuse");
        assert!(error.to_string().contains("unterminated"), "{error:#}");
        assert_eq!(std::fs::read(&path).expect("unchanged"), before);
        assert!(read(dir.path()).is_err());
    }

    #[test]
    fn a_missing_journal_after_start_is_not_recreated_by_finish() {
        let (dir, _env) = isolated();
        let _lock = lock(dir.path()).expect("lock");
        let pending = begin_exec(dir.path(), &["one".into()]).expect("start");
        let path = journal_path(dir.path());
        std::fs::remove_file(&path).expect("remove journal");

        assert!(finish_exec(dir.path(), pending, true).is_err());
        assert!(!path.exists(), "finish must not invent a new journal");
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_machine_directory_after_start_is_not_recreated_by_finish() {
        let (dir, _env) = isolated();
        let machine = dir.path().join("machine");
        std::fs::create_dir(&machine).expect("machine directory");
        let _lock = lock(&machine).expect("lock");
        let pending = begin_exec(&machine, &["one".into()]).expect("start");
        let before = std::fs::read(journal_path(&machine)).expect("started journal");
        let moved = dir.path().join("moved-machine");
        std::fs::rename(&machine, &moved).expect("move machine directory");

        assert!(finish_exec(&machine, pending, true).is_err());
        assert!(!machine.exists(), "finish must not recreate the directory");
        assert_eq!(
            std::fs::read(journal_path(&moved)).expect("preserved journal"),
            before
        );
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
