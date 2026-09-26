//! The approval broker: a host-local socket the VM's endpoint asks on.
//!
//! One prompt per connection, answered by the configured backend on the
//! broker's own thread. Prompts are answered one at a time, so a person at a
//! terminal never sees two questions at once. The socket is created mode
//! 0600 in the VM's socket directory and removed when the broker is dropped.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_contract::policy::approval_prompt::{
    ApprovalAnswer, ApprovalPrompt, MAX_PROMPT_LINE_BYTES,
};

use super::ApprovalBackend;

/// How long the broker waits for a connected endpoint to send its prompt.
const PROMPT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A running broker. Stops, and removes its socket, when dropped.
pub struct ApprovalServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ApprovalServer {
    /// Bind the broker at `path` and answer every prompt with `backend`.
    ///
    /// A stale socket at `path` is replaced; anything else there is an error.
    ///
    /// # Errors
    ///
    /// The socket could not be bound.
    pub fn bind(path: &Path, backend: Arc<dyn ApprovalBackend>) -> Result<Self> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            use std::os::unix::fs::FileTypeExt;
            anyhow::ensure!(
                meta.file_type().is_socket(),
                "{} exists and is not a socket",
                path.display()
            );
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale approval socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding the approval socket {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("approval-broker".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        answer_one(stream, backend.as_ref());
                    }
                }
            })
            .context("starting the approval broker thread")?;
        Ok(Self {
            path: path.to_path_buf(),
            stop,
            thread: Some(thread),
        })
    }

    /// Where the broker listens.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ApprovalServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = UnixStream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
        // Not joined: a broker still waiting on a person at a terminal would
        // hold the run's teardown until its prompt expired. It exits at its
        // next accept instead, and nothing new can reach it once the socket
        // is gone.
        drop(self.thread.take());
    }
}

/// Read one prompt, answer it, write the answer. A prompt that does not
/// parse is closed without an answer, which the endpoint treats as a denial.
fn answer_one(stream: UnixStream, backend: &dyn ApprovalBackend) {
    let _ = stream.set_read_timeout(Some(PROMPT_READ_TIMEOUT));
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut line = Vec::new();
    let read = BufReader::new(reader)
        .take(MAX_PROMPT_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line);
    if read.is_err() || line.len() > MAX_PROMPT_LINE_BYTES || !line.ends_with(b"\n") {
        return;
    }
    let Ok(prompt) = serde_json::from_slice::<ApprovalPrompt>(&line) else {
        return;
    };
    let mut answer: ApprovalAnswer = backend.decide(&prompt);
    answer.request_id = prompt.request_id;
    let Ok(mut encoded) = serde_json::to_vec(&answer) else {
        return;
    };
    encoded.push(b'\n');
    let mut stream = stream;
    let _ = stream.write_all(&encoded);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_broker::{CallbackBackend, DenyBackend};
    use mvm_contract::policy::approval::{ApprovalOutcome, ApprovalRequestId};
    use mvm_contract::policy::approval_prompt::{ApprovalScope, ApprovalSubject};

    fn ask(path: &Path, prompt: &ApprovalPrompt) -> Option<ApprovalAnswer> {
        let mut stream = UnixStream::connect(path).unwrap();
        let mut line = serde_json::to_vec(prompt).unwrap();
        line.push(b'\n');
        stream.write_all(&line).unwrap();
        let mut answer = String::new();
        BufReader::new(stream).read_line(&mut answer).ok()?;
        serde_json::from_str(&answer).ok()
    }

    fn prompt(id: &str) -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse(id).unwrap(),
            subject: ApprovalSubject::ToolCall { tool: "t".into() },
            expires_in_ms: 1_000,
        }
    }

    #[test]
    fn a_prompt_is_answered_by_the_backend_and_the_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sock");
        let server = ApprovalServer::bind(
            &path,
            Arc::new(CallbackBackend::new(|p| {
                ApprovalAnswer::approved(p.request_id.clone(), ApprovalScope::Session, "sdk")
            })),
        )
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let answer = ask(&path, &prompt("appr-7")).unwrap();
        assert_eq!(answer.request_id.as_str(), "appr-7");
        assert_eq!(answer.outcome, ApprovalOutcome::Approved);
        drop(server);
        assert!(!path.exists(), "the socket goes with the broker");
    }

    #[test]
    fn a_malformed_prompt_gets_no_answer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sock");
        let _server = ApprovalServer::bind(&path, Arc::new(DenyBackend)).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(b"{\"not\":\"a prompt\"}\n").unwrap();
        let mut answer = String::new();
        BufReader::new(stream).read_line(&mut answer).unwrap();
        assert!(answer.is_empty());
    }

    #[test]
    fn a_stale_socket_is_replaced_and_a_regular_file_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sock");
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let server = ApprovalServer::bind(&path, Arc::new(DenyBackend)).unwrap();
        assert_eq!(
            ask(&path, &prompt("appr-1")).unwrap().outcome,
            ApprovalOutcome::Denied
        );
        drop(server);

        std::fs::write(&path, b"not a socket").unwrap();
        assert!(ApprovalServer::bind(&path, Arc::new(DenyBackend)).is_err());
    }
}
