//! `ExecBuilder` — stage files and run a command (or a chain) inside a leased
//! warm VM over **one** vsock stream, collected into an [`ExecOutcome`].
//!
//! Tier 1 (connection reuse): the builder opens a single stream, pipelines the
//! `FsWrite` staging frames, then the `Exec` / `RunEntrypoint` frame(s) on that
//! same stream instead of reconnecting per call. Wall-clock duration is
//! measured host-side. The argv (`Exec`) surface is the interactive debug path;
//! `run_entrypoint` routes through the production no-argv path.

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{
    ControlSession, EntrypointEvent, ExecEvent, GUEST_AGENT_PORT, GuestRequest, GuestResponse,
    StageFile, call_unary,
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
    stdin: Vec<u8>,
    stream_input: bool,
}

impl<'a> ExecBuilder<'a> {
    pub(super) fn new(lease: &'a WarmLease) -> Self {
        Self {
            lease,
            stages: Vec::new(),
            commands: Vec::new(),
            timeout: None,
            stdin: Vec::new(),
            stream_input: false,
        }
    }

    /// Keep the entrypoint's stdin open past the payload, so a host writer can
    /// keep sending and the EOF becomes the host's to send.
    ///
    /// Off by default, which is the only safe default: with it on, a workload
    /// that reads to EOF never sees one unless something is holding the VM's
    /// input route and eventually closes it. Setting it without a writer
    /// behind it hangs the workload, not the caller.
    pub fn stream_input(mut self, stream_input: bool) -> Self {
        self.stream_input = stream_input;
        self
    }

    /// Bytes to supply as stdin for the `Exec` command(s). Empty ⇒ no stdin
    /// (`Exec.stdin = None`); non-empty bytes are utf8-lossy-decoded.
    ///
    /// Note: this setter is wired into warm-lease callers only. The live
    /// transient `machine run` path delivers stdin through `exec.rs::run_in_guest`
    /// directly, not through ExecBuilder.
    pub fn stdin_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = bytes;
        self
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

    /// The command to run (interactive `Exec` path). Call again / use [`chain`]
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

    /// Stage the files, then run the interactive argv command(s) — returns the
    /// last command's outcome (or the first failing one).
    pub fn output(self) -> Result<ExecOutcome> {
        let mut stream = self.connect()?;
        let mut session = ControlSession::open(&mut stream)?;
        stage_files(&mut session, &mut stream, &self.stages)?;
        let mut last = ExecOutcome {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
            peak_rss_kib: None,
        };
        for argv in &self.commands {
            last = run_exec(
                &mut session,
                &mut stream,
                argv,
                self.stdin.clone(),
                self.timeout,
            )?;
            if last.status != 0 {
                break;
            }
        }
        Ok(last)
    }

    /// Stage the files, then run the production entrypoint (no argv, no shell).
    pub fn run_entrypoint(self, stdin: Vec<u8>) -> Result<ExecOutcome> {
        let mut stream = self.connect()?;
        let mut session = ControlSession::open(&mut stream)?;
        stage_files(&mut session, &mut stream, &self.stages)?;
        run_entrypoint(
            &mut session,
            &mut stream,
            EntrypointStdin {
                payload: stdin,
                streamed: self.stream_input,
            },
            self.timeout,
        )
    }

    /// Tier-2: run the whole staged batch (files + every command) in **one
    /// round-trip** via `ExecBatch`, returning one outcome per command run
    /// (truncated at the first non-zero exit). `peak_rss_kib` is agent-measured
    /// on this path. Requires an `interactive` guest agent.
    pub fn batch(self) -> Result<Vec<ExecOutcome>> {
        let mut stream = self.connect()?;
        run_batch(&mut stream, &self.stages, &self.commands, self.timeout)
    }

    fn connect(&self) -> Result<UnixStream> {
        self.lease
            .transport()?
            .connect(GUEST_AGENT_PORT)
            .context("connecting to the guest agent for exec")
    }
}

fn stage_files(
    session: &mut ControlSession,
    stream: &mut UnixStream,
    stages: &[StagedFile],
) -> Result<()> {
    for s in stages {
        session
            .call_unary(
                stream,
                &GuestRequest::FsWrite {
                    path: s.path.clone(),
                    content: s.content.clone(),
                    mode: s.mode,
                    create_parents: true,
                    follow_symlinks: false,
                    offset: None,
                    truncate: true,
                },
            )
            .with_context(|| format!("staging {}", s.path))?;
    }
    Ok(())
}

/// Tier-2 batch: send one `ExecBatch` (staged files + every command) and map
/// the buffered wire outcomes back to [`ExecOutcome`]s.
fn run_batch(
    stream: &mut UnixStream,
    stages: &[StagedFile],
    commands: &[Vec<String>],
    timeout: Option<Duration>,
) -> Result<Vec<ExecOutcome>> {
    let wire_stages = stages
        .iter()
        .map(|s| StageFile {
            path: s.path.clone(),
            content: s.content.clone(),
            mode: s.mode,
        })
        .collect();
    let resp = call_unary(
        stream,
        &GuestRequest::ExecBatch {
            stages: wire_stages,
            commands: commands.to_vec(),
            timeout_secs: timeout.map(|d| d.as_secs()),
        },
    )
    .context("running exec batch")?;
    match resp {
        GuestResponse::ExecBatchResult { outcomes } => Ok(outcomes
            .into_iter()
            .map(|o| ExecOutcome {
                status: o.status,
                stdout: o.stdout,
                stderr: o.stderr,
                duration: Duration::from_millis(o.duration_ms),
                peak_rss_kib: o.peak_rss_kib,
            })
            .collect()),
        // Surface a grant refusal as the typed RpcError so the host audits it as
        // `verb_denied` rather than losing the verb in a stringified error.
        GuestResponse::VerbNotAuthorized { verb } => {
            Err(mvm_agentd::vsock::RpcError::VerbNotAuthorized { verb }.into())
        }
        other => bail!("unexpected response to ExecBatch: {:?}", other.variant()),
    }
}

/// Single-quote each argv element so spaces/metacharacters don't re-split when
/// the interactive agent runs the command through a shell.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build a `GuestRequest::Exec` from argv and optional stdin bytes.
///
/// Empty bytes ⇒ `stdin: None`; non-empty bytes are decoded lossy so the
/// existing `String` wire field carries the payload without a format change.
fn make_exec_request(
    argv: &[String],
    stdin_bytes: Vec<u8>,
    timeout: Option<Duration>,
) -> GuestRequest {
    let stdin = if stdin_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&stdin_bytes).into_owned())
    };
    GuestRequest::Exec {
        command: shell_join(argv),
        stdin,
        timeout_secs: timeout.map(|d| d.as_secs()),
    }
}

fn run_exec(
    session: &mut ControlSession,
    stream: &mut UnixStream,
    argv: &[String],
    stdin_bytes: Vec<u8>,
    timeout: Option<Duration>,
) -> Result<ExecOutcome> {
    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = 0;
    session
        .call_streaming(
            stream,
            &make_exec_request(argv, stdin_bytes, timeout),
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

/// How one `RunEntrypoint` call supplies the workload's stdin.
///
/// The two fields are one decision, not two knobs: `streamed` says whether the
/// guest keeps the pipe open after writing `payload`, which is the difference
/// between a workload that sees EOF and one that waits for a host writer to
/// send it.
struct EntrypointStdin {
    payload: Vec<u8>,
    streamed: bool,
}

fn run_entrypoint(
    session: &mut ControlSession,
    stream: &mut UnixStream,
    stdin: EntrypointStdin,
    timeout: Option<Duration>,
) -> Result<ExecOutcome> {
    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = 0;
    session
        .call_streaming(
            stream,
            &GuestRequest::RunEntrypoint {
                stdin: stdin.payload,
                timeout_secs: timeout.map_or(0, |d| d.as_secs()),
                env: Vec::new(),
                stream_input: stdin.streamed,
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

/// Build an `Exec` request for testing: takes argv + stdin bytes and returns
/// the `GuestRequest` the builder would send, without opening a connection.
#[cfg(test)]
pub(crate) fn build_exec_request_for_test(argv: Vec<String>, stdin_bytes: Vec<u8>) -> GuestRequest {
    make_exec_request(&argv, stdin_bytes, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "test-support")]
    use crate::mock_guest_agent::MockGuestAgent;
    #[cfg(feature = "test-support")]
    use mvm_agentd::vsock::connect_to_port;
    #[cfg(feature = "test-support")]
    use mvm_core::util::test_env::TestEnv;

    /// Start a mock agent and return a connected, handshaken stream to it.
    #[cfg(feature = "test-support")]
    fn agent_stream() -> Option<(TestEnv, tempfile::TempDir, MockGuestAgent, UnixStream)> {
        // MockGuestAgent resolves the process-wide MVM_HOME more than once
        // while creating and loading its signer. Hold the shared guard for the
        // full agent/session lifetime so another parallel test cannot move the
        // key root between those operations.
        let env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let agent = match MockGuestAgent::start(dir.path()) {
            Ok(agent) => agent,
            Err(err)
                if err
                    .chain()
                    .any(|cause| matches!(cause.downcast_ref::<std::io::Error>(), Some(io_err) if io_err.kind() == std::io::ErrorKind::PermissionDenied)) =>
            {
                eprintln!("test skipped: sandbox refused mock agent bind: {err:#}");
                return None;
            }
            Err(err) => panic!("start mock guest agent: {err:#}"),
        };
        let stream = match connect_to_port(&agent.socket_path().to_string_lossy(), GUEST_AGENT_PORT, 5)
        {
            Ok(stream) => stream,
            Err(err)
                if err
                    .chain()
                    .any(|cause| matches!(cause.downcast_ref::<std::io::Error>(), Some(io_err) if io_err.kind() == std::io::ErrorKind::PermissionDenied)) =>
            {
                eprintln!("test skipped: sandbox refused mock agent connect: {err:#}");
                return None;
            }
            Err(err) => panic!("connect to mock guest agent: {err:#}"),
        };
        Some((env, dir, agent, stream))
    }

    #[test]
    fn exec_frame_carries_stdin_payload() {
        let req = build_exec_request_for_test(vec!["/bin/cat".into()], b"STDIN-RT-42".to_vec());
        match req {
            mvm_agentd::vsock::GuestRequest::Exec { stdin, .. } => {
                assert_eq!(stdin.as_deref(), Some("STDIN-RT-42"));
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn exec_frame_empty_stdin_is_none() {
        let req = build_exec_request_for_test(vec!["/bin/true".into()], Vec::new());
        match req {
            mvm_agentd::vsock::GuestRequest::Exec { stdin, .. } => assert_eq!(stdin, None),
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn shell_join_quotes_each_arg() {
        assert_eq!(shell_join(&["a b".into(), "c".into()]), "'a b' 'c'");
        assert_eq!(shell_join(&["it's".into()]), r"'it'\''s'");
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn stage_files_then_exec_on_one_stream_returns_outcome() {
        let Some((_env, _d, _a, mut stream)) = agent_stream() else {
            return;
        };
        let mut session = ControlSession::open(&mut stream).unwrap();
        let stages = [StagedFile {
            path: "/tmp/main.rs".to_string(),
            content: b"fn main(){}".to_vec(),
            mode: 0o644,
        }];
        // Stage + run on the SAME stream (Tier 1 pipelining).
        stage_files(&mut session, &mut stream, &stages).unwrap();
        let out = run_exec(
            &mut session,
            &mut stream,
            &["echo".into(), "hi".into()],
            Vec::new(),
            None,
        )
        .unwrap();
        assert_eq!(out.status, 0);
        assert!(out.duration >= Duration::ZERO);
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn run_entrypoint_returns_outcome_on_one_stream() {
        let Some((_env, _d, _a, mut stream)) = agent_stream() else {
            return;
        };
        let mut session = ControlSession::open(&mut stream).unwrap();
        stage_files(&mut session, &mut stream, &[]).unwrap();
        let out = run_entrypoint(
            &mut session,
            &mut stream,
            EntrypointStdin {
                payload: b"input".to_vec(),
                streamed: false,
            },
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        assert_eq!(out.status, 0);
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn batch_stages_and_runs_commands_in_one_round_trip() {
        let Some((_env, _d, _a, mut stream)) = agent_stream() else {
            return;
        };
        let stages = [StagedFile {
            path: "/tmp/m.rs".to_string(),
            content: b"fn main(){}".to_vec(),
            mode: 0o644,
        }];
        let commands = [
            vec!["rustc".to_string(), "/tmp/m.rs".to_string()],
            vec!["/tmp/m".to_string()],
        ];
        let outcomes = run_batch(&mut stream, &stages, &commands, None).unwrap();
        // The mock returns one zero-exit outcome per command.
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.status == 0));
    }

    #[test]
    #[cfg(feature = "test-support")]
    fn exec_after_staging_multiple_files_still_succeeds() {
        let Some((_env, _d, _a, mut stream)) = agent_stream() else {
            return;
        };
        let mut session = ControlSession::open(&mut stream).unwrap();
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
        stage_files(&mut session, &mut stream, &stages).unwrap();
        let out = run_exec(
            &mut session,
            &mut stream,
            &["true".into()],
            Vec::new(),
            None,
        )
        .unwrap();
        assert_eq!(out.status, 0);
    }
}
