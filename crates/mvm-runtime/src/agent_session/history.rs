//! Durable, append-only persistence for an [`AgentSessionJournal`].
//!
//! The journal itself is transport-neutral and lives in memory. This module is
//! the one place its durable events reach disk: one JSON envelope per line,
//! each batch `fsync`'d before the caller acts on it, so a crash after a
//! prompt is accepted recovers with that acceptance on record. The history
//! carries digests and identifiers only; prompt bytes never enter it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_session::{
    AgentSessionCursor, AgentSessionEvent, AgentSessionEventEnvelope, AgentSessionId,
    AgentSessionJournal, DurableAgentSessionEvent, RetentionPolicy,
};

/// Largest history file this module will read back.
const MAX_DURABLE_HISTORY_BYTES: u64 = 32 * 1024 * 1024;
/// Events copied from the journal to disk per page.
const HISTORY_PAGE: u32 = 256;

/// A journal and the file its durable events are committed to.
pub struct DurableHistory {
    path: PathBuf,
    /// The live journal. Commands applied here reach disk only through
    /// [`DurableHistory::persist`].
    pub journal: AgentSessionJournal,
    persisted_sequence: u64,
}

impl DurableHistory {
    /// Recover the journal at `path`, or open a new one there.
    ///
    /// A recovered history must open with exactly this session and workload:
    /// a file that names another one is refused rather than adopted, because
    /// its cursor would be read as this session's.
    ///
    /// # Errors
    /// An unreadable, oversized, symlinked or non-contiguous history, one that
    /// names a different session or workload, or a failed first write.
    pub fn open(
        path: &Path,
        session_id: &AgentSessionId,
        workload_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> Result<Self> {
        if path.exists() {
            let history = load_history(path)?;
            verify_opening_identity(&history, session_id, workload_digest)?;
            let persisted_sequence = history
                .last()
                .and_then(|event| event.durable_sequence)
                .context("agent-session history has no durable sequence")?;
            let journal = AgentSessionJournal::from_history(
                session_id.clone(),
                history,
                RetentionPolicy::default(),
            )
            .context("recovering agent-session journal")?;
            return Ok(Self {
                path: path.to_path_buf(),
                journal,
                persisted_sequence,
            });
        }
        let (journal, opened) = AgentSessionJournal::open(
            session_id.clone(),
            workload_digest,
            now_unix_ms,
            RetentionPolicy::default(),
        )
        .context("opening agent-session journal")?;
        create_history(path, &opened)?;
        Ok(Self {
            path: path.to_path_buf(),
            journal,
            persisted_sequence: opened.durable_sequence.unwrap_or(0),
        })
    }

    /// The history file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The durable sequence of the last event committed to disk.
    #[must_use]
    pub fn committed_sequence(&self) -> u64 {
        self.persisted_sequence
    }

    /// Append every durable event the journal produced since the last call,
    /// and sync the file before returning.
    ///
    /// # Errors
    /// The journal could not be paged or the file could not be written.
    pub fn persist(&mut self) -> Result<()> {
        let mut cursor = Some(AgentSessionCursor {
            session_id: self.journal.session_id().clone(),
            durable_sequence: self.persisted_sequence,
        });
        loop {
            let page = self
                .journal
                .history(cursor, HISTORY_PAGE)
                .context("reading new agent-session events")?;
            if page.events.is_empty() {
                return Ok(());
            }
            append_history(&self.path, &page.events)?;
            self.persisted_sequence = page.next_cursor.durable_sequence;
            if !page.has_more {
                return Ok(());
            }
            cursor = Some(page.next_cursor);
        }
    }
}

/// Read a durable history back, refusing anything that is not a regular file
/// within the size bound.
///
/// # Errors
/// A missing, symlinked, oversized or unparseable history.
pub fn load_history(path: &Path) -> Result<Vec<AgentSessionEventEnvelope>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading agent-session metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("agent-session history must be a non-symlink file");
    }
    if metadata.len() > MAX_DURABLE_HISTORY_BYTES {
        bail!("agent-session history exceeds its size limit");
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading agent-session history {}", path.display()))?;
    body.lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).context("parsing durable agent-session event"))
        .collect()
}

fn verify_opening_identity(
    history: &[AgentSessionEventEnvelope],
    session_id: &AgentSessionId,
    workload_digest: [u8; 32],
) -> Result<()> {
    let Some(first) = history.first() else {
        bail!("agent-session history is empty");
    };
    if &first.session_id != session_id
        || !matches!(
            &first.event,
            AgentSessionEvent::Durable {
                event: DurableAgentSessionEvent::Opened {
                    workload_digest: recorded,
                }
            } if *recorded == workload_digest
        )
    {
        bail!("agent-session history identity does not match this session");
    }
    Ok(())
}

fn create_history(path: &Path, opened: &AgentSessionEventEnvelope) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating agent-session history {}", path.display()))?;
    write_event(&mut file, opened)?;
    file.sync_all().context("committing opened agent session")
}

fn append_history(path: &Path, events: &[AgentSessionEventEnvelope]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("opening agent-session history {}", path.display()))?;
    for event in events {
        write_event(&mut file, event)?;
    }
    file.sync_all().context("committing agent-session events")
}

fn write_event(file: &mut std::fs::File, event: &AgentSessionEventEnvelope) -> Result<()> {
    serde_json::to_writer(&mut *file, event).context("encoding durable agent-session event")?;
    file.write_all(b"\n")
        .context("terminating durable agent-session event")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::agent_session::{
        AgentRequestId, AgentSessionCommand, IdempotencyKey, PromptResult,
    };

    fn session() -> AgentSessionId {
        AgentSessionId::parse("history-test").unwrap()
    }

    fn prompt(key: &str, bytes: &[u8]) -> AgentSessionCommand {
        AgentSessionCommand::Prompt {
            request_id: AgentRequestId::parse(key).unwrap(),
            idempotency_key: IdempotencyKey::parse(key).unwrap(),
            prompt: bytes.to_vec(),
        }
    }

    #[test]
    fn a_reopened_history_resumes_the_same_cursor_and_carries_no_prompt_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.jsonl");
        let mut history = DurableHistory::open(&path, &session(), [7; 32], 1).unwrap();
        let outcome = history
            .journal
            .apply(prompt("p-1", b"a very particular prompt"), 2)
            .unwrap();
        history
            .journal
            .complete_prompt(
                AgentRequestId::parse("p-1").unwrap(),
                PromptResult::Succeeded,
                3,
            )
            .unwrap();
        history.persist().unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("very particular"));

        let mut reopened = DurableHistory::open(&path, &session(), [7; 32], 4).unwrap();
        let replay = reopened
            .journal
            .apply(prompt("p-1", b"a very particular prompt"), 5)
            .unwrap();
        assert!(!replay.applied, "the recovered journal forgot the request");
        assert_eq!(replay.last_sequence, outcome.last_sequence);
    }

    #[test]
    fn a_history_for_another_workload_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.jsonl");
        DurableHistory::open(&path, &session(), [7; 32], 1).unwrap();
        assert!(DurableHistory::open(&path, &session(), [8; 32], 2).is_err());
        let other = AgentSessionId::parse("other-session").unwrap();
        assert!(DurableHistory::open(&path, &other, [7; 32], 2).is_err());
    }
}
