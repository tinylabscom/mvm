//! `ExecBuilder` — stage files and run a command (or a chain) inside a leased
//! warm VM over **one** vsock stream, collected into an [`ExecOutcome`].
//!
//! Tier 1 (connection reuse): the builder opens a single stream, pipelines the
//! `FsWrite` staging frames, then the `Exec` / `RunEntrypoint` frame(s) on that
//! same stream instead of reconnecting per call. Wall-clock duration is
//! measured host-side. The argv (`Exec`) surface is the dev-shell debug path;
//! `run_entrypoint` routes through the production no-argv path.

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mvm_guest::vsock::{
    EntrypointEvent, ExecEvent, GUEST_AGENT_PORT, GuestRequest, GuestResponse, call_streaming,
    call_unary,
};

use super::lease::WarmLease;

/// The result of running a command (or the last of a chain) in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Process exit code (124 on timeout, GNU `timeout(1)` convention).
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Host-measured wall-clock of the command (or the chain).
    pub duration: Duration,
    /// Peak RSS in KiB when the agent reports it (agent-measured); `None` on
    /// the Tier-1 path, which has no in-guest measurement.
    pub peak_rss_kib: Option<u64>,
}

#[derive(Debug, Clone)]
struct StagedFile {
    path: String,
    content: Vec<u8>,
    mode: u32,
}

/// Staged files + command(s) to run on one stream. Created via
/// [`WarmLease::exec`].
pub struct ExecBuilder<'a> {
    lease: &'a WarmLease,
    stages: Vec<StagedFile>,
    commands: Vec<Vec<String>>,
    timeout: Option<Duration>,
}

impl<'a> ExecBuilder<'a> {
    pub(super) fn new(lease: &'a WarmLease) -> Self {
        Self {
            lease,
            stages: Vec::new(),
            commands: Vec::new(),
            timeout: None,
        }
    }

    /// Stage a file into the guest before running (mode 0644).
    pub fn stage_file(mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.stages.push(StagedFile {
            path: path.into(),
            content: content.into(),
            mode: 0o644,
        });
        self
    }

    /// The command to run (dev-shell `Exec` path). Call again / use [`chain`]
    /// to append more commands run sequentially on the same stream.
    ///
    /// [`chain`]: ExecBuilder::chain
    pub fn argv<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.commands
            .push(argv.into_iter().map(Into::into).collect());
        self
    }

    /// Append another command to run after the previous one(s) on the same
    /// stream — the chain stops at the first non-zero exit.
    pub fn chain<I, S>(self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.argv(argv)
    }

    /// Per-command timeout.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    /// Stage the files, then run the dev-shell argv command(s) — returns the
    /// last command's outcome (or the first failing one).
    pub fn output(self) -> Result<ExecOutcome> {
        let mut stream = self.connect()?;
        stage_files(&mut stream, &self.stages)?;
        let mut last = ExecOutcome {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
            peak_rss_kib: None,
        };
        for argv in &self.commands {
            last = run_exec(&mut stream, argv, self.timeout)?;
            if last.status != 0 {
                break;
            }
        }
        Ok(last)
    }

    /// Stage the files, then run the production entrypoint (no argv, no shell).
    pub fn run_entrypoint(self, stdin: Vec<u8>) -> Result<ExecOutcome> {
        let mut stream = self.connect()?;
        stage_files(&mut stream, &self.stages)?;
        run_entrypoint(&mut stream, stdin, self.timeout)
    }

    fn connect(&self) -> Result<UnixStream> {
        self.lease
            .transport()?
            .connect(GUEST_AGENT_PORT)
            .context("connecting to the guest agent for exec")
    }
}

fn stage_files(stream: &mut UnixStream, stages: &[StagedFile]) -> Result<()> {
    for s in stages {
        call_unary(
            stream,
            &GuestRequest::FsWrite {
                path: s.path.clone(),
                content: s.content.clone(),
                mode: s.mode,
                create_parents: true,
                follow_symlinks: false,
            },
        )
        .with_context(|| format!("staging {}", s.path))?;
    }
    Ok(())
}

/// Single-quote each argv element so spaces/metacharacters don't re-split when
/// the dev-shell agent runs the command through a shell.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_exec(
    stream: &mut UnixStream,
    argv: &[String],
    timeout: Option<Duration>,
) -> Result<ExecOutcome> {
    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = 0;
    call_streaming(
        stream,
        &GuestRequest::Exec {
            command: shell_join(argv),
            stdin: None,
            timeout_secs: timeout.map(|d| d.as_secs()),
        },
        |ev| {
            if let GuestResponse::ExecEvent(e) = ev {
                match e {
                    ExecEvent::Stdout { chunk } => stdout.extend_from_slice(chunk),
                    ExecEvent::Stderr { chunk } => stderr.extend_from_slice(chunk),
                    ExecEvent::Exit { code } => status = *code,
                    ExecEvent::TimedOut => status = 124,
                }
            }
        },
    )
    .with_context(|| format!("running {argv:?}"))?;
    Ok(ExecOutcome {
        status,
        stdout,
        stderr,
        duration: start.elapsed(),
        peak_rss_kib: None,
    })
}

fn run_entrypoint(
    stream: &mut UnixStream,
    stdin: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<ExecOutcome> {
    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = 0;
    call_streaming(
        stream,
        &GuestRequest::RunEntrypoint {
            stdin,
            timeout_secs: timeout.map_or(0, |d| d.as_secs()),
            env: Vec::new(),
        },
        |ev| {
            if let GuestResponse::EntrypointEvent(e) = ev {
                match e {
                    EntrypointEvent::Stdout { chunk } => stdout.extend_from_slice(chunk),
                    EntrypointEvent::Stderr { chunk } => stderr.extend_from_slice(chunk),
                    EntrypointEvent::Exit { code } => status = *code,
                    _ => {}
                }
            }
        },
    )
    .context("running entrypoint")?;
    Ok(ExecOutcome {
        status,
        stdout,
        stderr,
        duration: start.elapsed(),
        peak_rss_kib: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_backend::mock_guest_agent::MockGuestAgent;
    use mvm_guest::vsock::connect_to_port;

    /// Start a mock agent and return a connected, handshaken stream to it.
    fn agent_stream() -> (tempfile::TempDir, MockGuestAgent, UnixStream) {
        let dir = tempfile::tempdir().unwrap();
        let agent = MockGuestAgent::start(dir.path()).unwrap();
        let stream =
            connect_to_port(&agent.socket_path().to_string_lossy(), GUEST_AGENT_PORT, 5).unwrap();
        (dir, agent, stream)
    }

    #[test]
    fn shell_join_quotes_each_arg() {
        assert_eq!(shell_join(&["a b".into(), "c".into()]), "'a b' 'c'");
        assert_eq!(shell_join(&["it's".into()]), r"'it'\''s'");
    }

    #[test]
    fn stage_files_then_exec_on_one_stream_returns_outcome() {
        let (_d, _a, mut stream) = agent_stream();
        let stages = [StagedFile {
            path: "/tmp/main.rs".to_string(),
            content: b"fn main(){}".to_vec(),
            mode: 0o644,
        }];
        // Stage + run on the SAME stream (Tier 1 pipelining).
        stage_files(&mut stream, &stages).unwrap();
        let out = run_exec(&mut stream, &["echo".into(), "hi".into()], None).unwrap();
        assert_eq!(out.status, 0);
        assert!(out.duration >= Duration::ZERO);
    }

    #[test]
    fn run_entrypoint_returns_outcome_on_one_stream() {
        let (_d, _a, mut stream) = agent_stream();
        stage_files(&mut stream, &[]).unwrap();
        let out =
            run_entrypoint(&mut stream, b"input".to_vec(), Some(Duration::from_secs(5))).unwrap();
        assert_eq!(out.status, 0);
    }

    #[test]
    fn exec_after_staging_multiple_files_still_succeeds() {
        let (_d, _a, mut stream) = agent_stream();
        let stages = [
            StagedFile {
                path: "/tmp/a".to_string(),
                content: b"a".to_vec(),
                mode: 0o644,
            },
            StagedFile {
                path: "/tmp/b".to_string(),
                content: b"b".to_vec(),
                mode: 0o644,
            },
        ];
        stage_files(&mut stream, &stages).unwrap();
        let out = run_exec(&mut stream, &["true".into()], None).unwrap();
        assert_eq!(out.status, 0);
    }
}
