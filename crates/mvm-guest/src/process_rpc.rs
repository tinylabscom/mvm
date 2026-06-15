//! Process control RPC handler.
//!
//! **Dev-only.** The whole module is gated behind
//! `#[cfg(feature = "dev-shell")]` in `lib.rs`, so its symbols are
//! absent from the production guest agent (the combined
//! `prod-agent-runentry-contract` CI gate enforces the symbol
//! contract).
//!
//! See doc comments on individual handlers for the security
//! envelope (process_group(0), RLIMIT_CORE=0, env_clear,
//! PathPolicy on cwd, argv\[0\] validation, PID-token indirection).

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use mvm_core::crypto::policy::{OsCanonicalizer, PathOp, PathPolicy};
use mvm_core::domain::instance::BackpressureReason;

use crate::vsock::{ProcErrorKind, ProcInfo, ProcResult, ProcState, ProcWaitEvent};

// ============================================================================
// Caps
// ============================================================================

/// Per-call resource caps. Production agent wires `Caps::production()`.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// Concurrent live processes per agent.
    pub max_concurrent: usize,
    /// Bytes accepted by `ProcSendInput` per call.
    pub max_stdin_per_call: usize,
    /// Per-process captured-stdout / stderr buffer cap.
    pub max_output_buffer: usize,
    /// How long to keep an exited record around for `ProcList` /
    /// `ProcWait` after the child reaps.
    pub reap_grace: Duration,
    /// Polling interval inside the wait loop.
    pub wait_poll_interval: Duration,
}

impl Caps {
    pub const fn production() -> Self {
        Self {
            max_concurrent: 32,
            max_stdin_per_call: 1024 * 1024,
            max_output_buffer: 16 * 1024 * 1024,
            reap_grace: Duration::from_secs(60),
            wait_poll_interval: Duration::from_millis(50),
        }
    }
}

impl Default for Caps {
    fn default() -> Self {
        Self::production()
    }
}

// ============================================================================
// Registry
// ============================================================================

/// One tracked process. Held inside the registry's `HashMap`.
struct ProcessRecord {
    /// Display-only argv\[0\]; full argv is dropped after spawn.
    argv0: String,
    started_at: String,
    /// Child handle, or `None` once we've called `wait()`.
    child: Mutex<Option<Child>>,
    /// Stdin pipe held by the agent until ProcSendInput drops it.
    stdin: Mutex<Option<ChildStdin>>,
    /// Captured stdout. Background drain thread (holding an `Arc`
    /// clone) fills it; the wait path drains it.
    stdout_buf: Arc<Mutex<Vec<u8>>>,
    /// Captured stderr. Same `Arc`-shared shape as stdout.
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    /// Set once a terminal lifecycle event has been observed.
    terminal: Mutex<Option<TerminalState>>,
    /// When the record becomes reapable (after terminal + grace).
    reap_after: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Copy)]
enum TerminalState {
    Exited(i32),
    Killed(i32),
    TimedOut,
}

impl TerminalState {
    fn to_state(self) -> ProcState {
        match self {
            TerminalState::Exited(c) => ProcState::Exited(c),
            TerminalState::Killed(s) => ProcState::Killed(s),
            TerminalState::TimedOut => ProcState::TimedOut,
        }
    }
}

/// Process registry. Cheap to clone (Arc).
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<String, Arc<ProcessRecord>>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    fn gc_inplace(&self, now: Instant) {
        let mut map = self.inner.lock().expect("registry mutex");
        map.retain(|_, rec| {
            let reap = rec.reap_after.lock().expect("reap_after mutex");
            !matches!(*reap, Some(t) if now >= t)
        });
    }

    fn lookup(&self, token: &str) -> Option<Arc<ProcessRecord>> {
        let map = self.inner.lock().expect("registry mutex");
        map.get(token).cloned()
    }

    fn insert(&self, token: String, record: Arc<ProcessRecord>) {
        let mut map = self.inner.lock().expect("registry mutex");
        map.insert(token, record);
    }

    fn live_count(&self) -> usize {
        let map = self.inner.lock().expect("registry mutex");
        map.iter()
            .filter(|(_, r)| r.terminal.lock().expect("terminal mutex").is_none())
            .count()
    }

    /// Snapshot for `ProcList`.
    pub fn snapshot(&self) -> Vec<ProcInfo> {
        let map = self.inner.lock().expect("registry mutex");
        map.iter()
            .map(|(token, rec)| {
                let terminal = rec.terminal.lock().expect("terminal mutex");
                let state = match *terminal {
                    Some(t) => t.to_state(),
                    None => ProcState::Running,
                };
                ProcInfo {
                    pid_token: token.clone(),
                    started_at: rec.started_at.clone(),
                    argv0: rec.argv0.clone(),
                    state,
                }
            })
            .collect()
    }
}

fn fresh_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    format!("ptok-{}", hex)
}

// ============================================================================
// Building the security envelope around a `Command`
// ============================================================================

/// Validate request inputs against the policy + caps and return a
/// fully-constructed `Command` ready to spawn. Pure logic + path
/// canonicalization — no actual fork or execve happens here.
///
/// The constructed command carries:
/// - `env_clear()` then `envs(env)` — children see only the env
///   the host explicitly sent.
/// - `current_dir(cwd)` — when the host supplied one and it
///   passed `PathPolicy`.
/// - `process_group(0)` — children get their own pgroup so we can
///   signal the whole tree.
/// - `pre_exec` setting RLIMIT_CORE=0 — coredumps disabled before
///   the new image runs, no in-memory exfiltration via dumps.
fn build_command(
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
) -> Result<Command, (ProcErrorKind, String)> {
    if argv.is_empty() {
        return Err((ProcErrorKind::InvalidArgv, "argv is empty".to_string()));
    }
    let argv0 = &argv[0];
    if argv0.is_empty() {
        return Err((ProcErrorKind::InvalidArgv, "argv[0] is empty".to_string()));
    }
    if !std::path::Path::new(argv0).is_absolute() {
        return Err((
            ProcErrorKind::InvalidArgv,
            format!("argv[0] {argv0:?} must be an absolute path"),
        ));
    }

    for (k, v) in env {
        if k.is_empty() || k.contains('=') || k.as_bytes().contains(&0) {
            return Err((
                ProcErrorKind::InvalidEnv,
                format!("env key {k:?} is invalid"),
            ));
        }
        if v.as_bytes().contains(&0) {
            return Err((
                ProcErrorKind::InvalidEnv,
                format!("env value for {k:?} contains NUL"),
            ));
        }
    }

    let cwd_path = if let Some(c) = cwd {
        let policy = PathPolicy::default();
        let canonical = policy
            .validate(&OsCanonicalizer, c, PathOp::Read)
            .map_err(|e| (ProcErrorKind::BadCwd, e.to_string()))?;
        Some(canonical.into_path_buf())
    } else {
        None
    };

    let mut cmd = Command::new(argv0);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    cmd.envs(env);
    if let Some(p) = cwd_path {
        cmd.current_dir(p);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(unix)]
    cmd.process_group(0);

    // SAFETY: pre_exec's closure runs post-fork/pre-exec, where only async-
    // signal-safe calls are allowed. It calls only setrlimit (async-signal-safe),
    // allocates nothing, and touches no shared Rust state.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(cmd)
}

/// Spawn a drain thread that copies bytes from `reader` into `buf`,
/// truncating at `cap` so a chatty child can't exhaust agent memory.
fn spawn_drain<R: Read + Send + 'static>(mut reader: R, buf: Arc<Mutex<Vec<u8>>>, cap: usize) {
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut b = buf.lock().expect("drain buf mutex");
                    let room = cap.saturating_sub(b.len());
                    if room == 0 {
                        continue;
                    }
                    let take = n.min(room);
                    b.extend_from_slice(&chunk[..take]);
                }
                Err(_) => break,
            }
        }
    });
}

// ============================================================================
// Per-verb handlers
// ============================================================================

/// `ProcStart` handler — validates inputs, spawns the child with
/// the security envelope, registers it, and returns the opaque
/// `pid_token` the host uses for the rest of the process's life.
pub fn handle_proc_start(
    registry: &Registry,
    caps: &Caps,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
    initial_stdin: &[u8],
) -> ProcResult {
    registry.gc_inplace(Instant::now());

    if registry.live_count() >= caps.max_concurrent {
        return ProcResult::Error {
            kind: ProcErrorKind::CapExceeded,
            message: format!("max_concurrent {} reached", caps.max_concurrent),
        };
    }

    let mut cmd = match build_command(argv, env, cwd) {
        Ok(c) => c,
        Err((kind, message)) => return ProcResult::Error { kind, message },
    };

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ProcResult::Error {
                kind: ProcErrorKind::SpawnFailed,
                message: e.to_string(),
            };
        }
    };

    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    if let Some(out) = child.stdout.take() {
        spawn_drain(out, Arc::clone(&stdout_buf), caps.max_output_buffer);
    }
    if let Some(err) = child.stderr.take() {
        spawn_drain(err, Arc::clone(&stderr_buf), caps.max_output_buffer);
    }
    let stdin = child.stdin.take();

    let argv0 = argv.first().cloned().unwrap_or_default();
    let started_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let record = Arc::new(ProcessRecord {
        argv0,
        started_at,
        child: Mutex::new(Some(child)),
        stdin: Mutex::new(stdin),
        stdout_buf,
        stderr_buf,
        terminal: Mutex::new(None),
        reap_after: Mutex::new(None),
    });

    if !initial_stdin.is_empty()
        && let Some(ref mut s) = *record.stdin.lock().expect("stdin mutex")
    {
        let _ = s.write_all(initial_stdin);
    }

    let token = fresh_token();
    registry.insert(token.clone(), record);

    ProcResult::Started { pid_token: token }
}

/// `ProcList` handler.
pub fn handle_proc_list(registry: &Registry) -> ProcResult {
    registry.gc_inplace(Instant::now());
    ProcResult::List {
        processes: registry.snapshot(),
    }
}

/// `ProcSignal` handler — sends `signum` to the child's process
/// group (negative pid). Doesn't block waiting for delivery.
pub fn handle_proc_signal(registry: &Registry, pid_token: &str, signum: i32) -> ProcResult {
    let Some(record) = registry.lookup(pid_token) else {
        return ProcResult::Error {
            kind: ProcErrorKind::UnknownToken,
            message: format!("no such pid_token: {pid_token}"),
        };
    };
    let child_guard = record.child.lock().expect("child mutex");
    let Some(child) = child_guard.as_ref() else {
        return ProcResult::Error {
            kind: ProcErrorKind::Other,
            message: "child already reaped".to_string(),
        };
    };
    // SAFETY: kill performs no memory access; the negated pgid signals the
    // child's process group (group leader via process_group(0)).
    #[cfg(unix)]
    unsafe {
        let pgid = child.id() as libc::pid_t;
        if libc::kill(-pgid, signum) != 0 {
            return ProcResult::Error {
                kind: ProcErrorKind::Other,
                message: std::io::Error::last_os_error().to_string(),
            };
        }
    }
    let _ = child;
    ProcResult::Signaled
}

/// `ProcKill` handler — convenience for SIGKILL.
pub fn handle_proc_kill(registry: &Registry, pid_token: &str) -> ProcResult {
    match handle_proc_signal(registry, pid_token, 9) {
        ProcResult::Signaled => ProcResult::Killed,
        other => other,
    }
}

/// `ProcSendInput` handler.
pub fn handle_proc_send_input(
    registry: &Registry,
    caps: &Caps,
    pid_token: &str,
    bytes: &[u8],
) -> ProcResult {
    if bytes.len() > caps.max_stdin_per_call {
        return ProcResult::Error {
            kind: ProcErrorKind::CapExceeded,
            message: format!(
                "stdin {} bytes exceeds max_stdin_per_call {}",
                bytes.len(),
                caps.max_stdin_per_call
            ),
        };
    }
    let Some(record) = registry.lookup(pid_token) else {
        return ProcResult::Error {
            kind: ProcErrorKind::UnknownToken,
            message: format!("no such pid_token: {pid_token}"),
        };
    };
    let mut stdin_guard = record.stdin.lock().expect("stdin mutex");
    let Some(ref mut stdin) = *stdin_guard else {
        return ProcResult::Error {
            kind: ProcErrorKind::Other,
            message: "stdin already closed".to_string(),
        };
    };
    match stdin.write_all(bytes) {
        Ok(()) => ProcResult::InputAccepted {
            bytes_accepted: bytes.len() as u64,
        },
        Err(e) => ProcResult::Error {
            kind: ProcErrorKind::Other,
            message: e.to_string(),
        },
    }
}

// ============================================================================
// Streaming wait
// ============================================================================

fn drain_into_events(record: &ProcessRecord) -> Vec<ProcWaitEvent> {
    let mut events = Vec::new();
    let mut out = record.stdout_buf.lock().expect("stdout mutex");
    if !out.is_empty() {
        events.push(ProcWaitEvent::Stdout {
            chunk: std::mem::take(&mut *out),
        });
    }
    drop(out);
    let mut err = record.stderr_buf.lock().expect("stderr mutex");
    if !err.is_empty() {
        events.push(ProcWaitEvent::Stderr {
            chunk: std::mem::take(&mut *err),
        });
    }
    events
}

/// Rising-edge backpressure detection state held inside one
/// `handle_proc_wait` call. Tracks which backpressure conditions
/// have already been signaled this wait so the agent emits each
/// reason at most once per crossing — avoiding event spam when the
/// buffer hovers around its high-water mark.
///
/// Falling-edge clears the flag, so a buffer that fills → drains →
/// fills again will emit `OutputConsumerSlow` twice. That matches
/// the wait-reason renderer in `mvmctl proc wait`, which prints the
/// reason once per rising edge.
#[derive(Default)]
struct BackpressureWatch {
    output_consumer_slow: bool,
}

/// Threshold for `OutputConsumerSlow`: total captured stdout +
/// stderr at or above 75 % of `caps.max_output_buffer`. Picked to
/// give the host time to drain before the agent has to start
/// dropping bytes, while not firing on every small bursty write.
fn output_backpressure_threshold(caps: &Caps) -> usize {
    caps.max_output_buffer.saturating_mul(3) / 4
}

/// Inspect the captured-output buffers and, on the rising edge of
/// `total ≥ threshold`, return a `ProcWaitEvent::Backpressure`.
/// Falling edge clears the watch flag so future rises emit again.
///
/// `detail` is a short metadata-only sentence (byte counts +
/// threshold + cap) — never includes payload bytes, paths, argv,
/// env, or stdin content (redaction invariant).
fn check_output_backpressure(
    record: &ProcessRecord,
    caps: &Caps,
    watch: &mut BackpressureWatch,
) -> Option<ProcWaitEvent> {
    let out_len = record.stdout_buf.lock().map(|b| b.len()).unwrap_or(0);
    let err_len = record.stderr_buf.lock().map(|b| b.len()).unwrap_or(0);
    let total = out_len.saturating_add(err_len);
    let threshold = output_backpressure_threshold(caps);

    if total >= threshold {
        if !watch.output_consumer_slow {
            watch.output_consumer_slow = true;
            return Some(ProcWaitEvent::Backpressure {
                reason: BackpressureReason::OutputConsumerSlow,
                detail: format!(
                    "captured output {} bytes ≥ {} byte high-water (cap {} bytes)",
                    total, threshold, caps.max_output_buffer
                ),
            });
        }
    } else {
        watch.output_consumer_slow = false;
    }
    None
}

/// Try to reap the child non-blocking. Returns `Some(terminal)` if
/// the child has exited, `None` if it's still running.
fn try_reap(record: &ProcessRecord, reap_grace: Duration) -> Option<TerminalState> {
    let mut child_guard = record.child.lock().expect("child mutex");
    let Some(child) = child_guard.as_mut() else {
        return record
            .terminal
            .lock()
            .expect("terminal mutex")
            .as_ref()
            .copied();
    };
    match child.try_wait() {
        Ok(Some(status)) => {
            let terminal = if let Some(code) = status.code() {
                TerminalState::Exited(code)
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(sig) = status.signal() {
                        TerminalState::Killed(sig)
                    } else {
                        TerminalState::Exited(-1)
                    }
                }
                #[cfg(not(unix))]
                {
                    TerminalState::Exited(-1)
                }
            };
            *record.terminal.lock().expect("terminal mutex") = Some(terminal);
            *record.reap_after.lock().expect("reap_after mutex") =
                Some(Instant::now() + reap_grace);
            *child_guard = None;
            Some(terminal)
        }
        Ok(None) => None,
        Err(_) => Some(TerminalState::Exited(-1)),
    }
}

/// Streaming `ProcWait` handler. Calls `emit` once per chunk of
/// captured output and returns the terminal `ProcWaitEvent`. The
/// agent dispatch arm writes intermediate frames to the wire as
/// the closure fires, then writes the terminal frame on return.
pub fn handle_proc_wait<W: FnMut(ProcWaitEvent)>(
    registry: &Registry,
    caps: &Caps,
    pid_token: &str,
    timeout_secs: Option<u64>,
    mut emit: W,
) -> ProcWaitEvent {
    let Some(record) = registry.lookup(pid_token) else {
        return ProcWaitEvent::Error {
            kind: ProcErrorKind::UnknownToken,
            message: format!("no such pid_token: {pid_token}"),
        };
    };
    if let Some(terminal) = *record.terminal.lock().expect("terminal mutex") {
        for ev in drain_into_events(&record) {
            emit(ev);
        }
        return match terminal {
            TerminalState::Exited(c) => ProcWaitEvent::Exit { code: c },
            TerminalState::Killed(s) => ProcWaitEvent::Killed { signal: s },
            TerminalState::TimedOut => ProcWaitEvent::TimedOut,
        };
    }

    let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
    let mut bp_watch = BackpressureWatch::default();

    loop {
        // Emit `Backpressure` BEFORE draining
        // so the host learns the buffer crossed its high-water mark
        // before it sees the chunk that triggered the crossing. Rising
        // edge only — `BackpressureWatch` suppresses repeat emissions
        // while the condition persists.
        if let Some(ev) = check_output_backpressure(&record, caps, &mut bp_watch) {
            emit(ev);
        }
        for ev in drain_into_events(&record) {
            emit(ev);
        }
        if let Some(terminal) = try_reap(&record, caps.reap_grace) {
            for ev in drain_into_events(&record) {
                emit(ev);
            }
            return match terminal {
                TerminalState::Exited(c) => ProcWaitEvent::Exit { code: c },
                TerminalState::Killed(s) => ProcWaitEvent::Killed { signal: s },
                TerminalState::TimedOut => ProcWaitEvent::TimedOut,
            };
        }
        if let Some(d) = deadline
            && Instant::now() >= d
        {
            let _ = handle_proc_signal(registry, pid_token, 9);
            *record.terminal.lock().expect("terminal mutex") = Some(TerminalState::TimedOut);
            *record.reap_after.lock().expect("reap_after mutex") =
                Some(Instant::now() + caps.reap_grace);
            for ev in drain_into_events(&record) {
                emit(ev);
            }
            return ProcWaitEvent::TimedOut;
        }
        thread::sleep(caps.wait_poll_interval);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn small_caps() -> Caps {
        Caps {
            max_concurrent: 4,
            max_stdin_per_call: 1024,
            max_output_buffer: 4096,
            reap_grace: Duration::from_millis(100),
            wait_poll_interval: Duration::from_millis(10),
        }
    }

    #[test]
    fn build_command_rejects_empty_argv() {
        let env = BTreeMap::new();
        let err = build_command(&[], &env, None).unwrap_err();
        assert_eq!(err.0, ProcErrorKind::InvalidArgv);
    }

    #[test]
    fn build_command_rejects_relative_argv0() {
        let env = BTreeMap::new();
        let err = build_command(&["echo".to_string()], &env, None).unwrap_err();
        assert_eq!(err.0, ProcErrorKind::InvalidArgv);
    }

    #[test]
    fn build_command_rejects_env_with_eq_in_key() {
        let mut env = BTreeMap::new();
        env.insert("BAD=KEY".to_string(), "v".to_string());
        let err = build_command(&["/bin/echo".to_string()], &env, None).unwrap_err();
        assert_eq!(err.0, ProcErrorKind::InvalidEnv);
    }

    #[test]
    fn build_command_rejects_env_with_nul() {
        let mut env = BTreeMap::new();
        env.insert("KEY".to_string(), "val\0ue".to_string());
        let err = build_command(&["/bin/echo".to_string()], &env, None).unwrap_err();
        assert_eq!(err.0, ProcErrorKind::InvalidEnv);
    }

    #[test]
    fn fresh_token_is_unique() {
        let a = fresh_token();
        let b = fresh_token();
        assert!(a.starts_with("ptok-"));
        assert_ne!(a, b);
    }

    #[test]
    fn registry_starts_empty() {
        let reg = Registry::new();
        assert_eq!(reg.snapshot().len(), 0);
        assert_eq!(reg.live_count(), 0);
    }

    #[test]
    fn proc_signal_unknown_token_returns_unknown_token() {
        let reg = Registry::new();
        match handle_proc_signal(&reg, "no-such-token", 15) {
            ProcResult::Error { kind, .. } => assert_eq!(kind, ProcErrorKind::UnknownToken),
            other => panic!("expected Error UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn proc_send_input_unknown_token_returns_unknown_token() {
        let reg = Registry::new();
        let caps = small_caps();
        match handle_proc_send_input(&reg, &caps, "no-such-token", b"data") {
            ProcResult::Error { kind, .. } => assert_eq!(kind, ProcErrorKind::UnknownToken),
            other => panic!("expected Error UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn proc_send_input_caps_oversized_payload() {
        let reg = Registry::new();
        let caps = Caps {
            max_stdin_per_call: 4,
            ..small_caps()
        };
        match handle_proc_send_input(&reg, &caps, "tok", &[0u8; 8]) {
            ProcResult::Error { kind, .. } => assert_eq!(kind, ProcErrorKind::CapExceeded),
            other => panic!("expected CapExceeded, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn proc_start_then_wait_captures_stdout() {
        let reg = Registry::new();
        let caps = small_caps();

        let started = handle_proc_start(
            &reg,
            &caps,
            &["/bin/echo".to_string(), "hello".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        let token = match started {
            ProcResult::Started { pid_token } => pid_token,
            other => panic!("expected Started, got {other:?}"),
        };

        let mut events = Vec::new();
        let terminal = handle_proc_wait(&reg, &caps, &token, Some(5), |ev| events.push(ev));

        let stdout: Vec<u8> = events
            .iter()
            .flat_map(|e| match e {
                ProcWaitEvent::Stdout { chunk } => chunk.clone(),
                _ => Vec::new(),
            })
            .collect();
        let s = String::from_utf8_lossy(&stdout);
        assert!(
            s.contains("hello"),
            "expected stdout to contain 'hello', got {s:?}"
        );
        assert!(
            matches!(terminal, ProcWaitEvent::Exit { code: 0 }),
            "expected Exit 0, got {terminal:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn proc_start_lists_running_then_exited() {
        let reg = Registry::new();
        let caps = small_caps();

        let started = handle_proc_start(
            &reg,
            &caps,
            &["/bin/echo".to_string(), "x".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        let token = match started {
            ProcResult::Started { pid_token } => pid_token,
            other => panic!("expected Started, got {other:?}"),
        };

        let list_before = match handle_proc_list(&reg) {
            ProcResult::List { processes } => processes,
            other => panic!("expected List, got {other:?}"),
        };
        assert_eq!(list_before.len(), 1);
        assert_eq!(list_before[0].pid_token, token);

        let _ = handle_proc_wait(&reg, &caps, &token, Some(5), |_| {});

        let list_after = match handle_proc_list(&reg) {
            ProcResult::List { processes } => processes,
            other => panic!("expected List, got {other:?}"),
        };
        if let Some(info) = list_after.iter().find(|p| p.pid_token == token) {
            assert!(
                matches!(info.state, ProcState::Exited(_)),
                "expected Exited, got {:?}",
                info.state
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn proc_start_caps_concurrent_processes() {
        let reg = Registry::new();
        let caps = Caps {
            max_concurrent: 1,
            ..small_caps()
        };

        let first = handle_proc_start(
            &reg,
            &caps,
            &["/bin/sleep".to_string(), "5".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        let token = match first {
            ProcResult::Started { pid_token } => pid_token,
            other => panic!("expected Started, got {other:?}"),
        };

        let blocked = handle_proc_start(
            &reg,
            &caps,
            &["/bin/echo".to_string(), "x".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        match blocked {
            ProcResult::Error { kind, .. } => assert_eq!(kind, ProcErrorKind::CapExceeded),
            other => panic!("expected CapExceeded, got {other:?}"),
        }

        let _ = handle_proc_kill(&reg, &token);
        let _ = handle_proc_wait(&reg, &caps, &token, Some(5), |_| {});
    }

    #[test]
    #[cfg(unix)]
    fn proc_kill_returns_killed() {
        let reg = Registry::new();
        let caps = small_caps();

        let started = handle_proc_start(
            &reg,
            &caps,
            &["/bin/sleep".to_string(), "30".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        let token = match started {
            ProcResult::Started { pid_token } => pid_token,
            other => panic!("expected Started, got {other:?}"),
        };

        match handle_proc_kill(&reg, &token) {
            ProcResult::Killed => (),
            other => panic!("expected Killed, got {other:?}"),
        }
        let terminal = handle_proc_wait(&reg, &caps, &token, Some(5), |_| {});
        assert!(
            matches!(
                terminal,
                ProcWaitEvent::Killed { .. } | ProcWaitEvent::Exit { .. }
            ),
            "unexpected terminal: {terminal:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn proc_wait_times_out() {
        let reg = Registry::new();
        let caps = small_caps();

        let started = handle_proc_start(
            &reg,
            &caps,
            &["/bin/sleep".to_string(), "30".to_string()],
            &BTreeMap::new(),
            None,
            &[],
        );
        let token = match started {
            ProcResult::Started { pid_token } => pid_token,
            other => panic!("expected Started, got {other:?}"),
        };

        let terminal = handle_proc_wait(&reg, &caps, &token, Some(1), |_| {});
        assert!(
            matches!(terminal, ProcWaitEvent::TimedOut),
            "expected TimedOut, got {terminal:?}"
        );
    }

    // ---------------- Backpressure ----------------
    //
    // Tests target `check_output_backpressure` directly. The unit
    // doesn't need a real child process — it just needs a
    // `ProcessRecord` whose stdout/stderr buffers carry enough bytes
    // to cross the high-water mark. Building the record by hand
    // sidesteps spawning a `/bin/yes`-style flood, which would be
    // flaky inside CI.

    fn make_record_with_output(stdout_bytes: usize, stderr_bytes: usize) -> ProcessRecord {
        ProcessRecord {
            argv0: "/bin/test".to_string(),
            started_at: "2025-01-01T00:00:00Z".to_string(),
            child: Mutex::new(None),
            stdin: Mutex::new(None),
            stdout_buf: Arc::new(Mutex::new(vec![0u8; stdout_bytes])),
            stderr_buf: Arc::new(Mutex::new(vec![0u8; stderr_bytes])),
            terminal: Mutex::new(None),
            reap_after: Mutex::new(None),
        }
    }

    #[test]
    fn backpressure_threshold_at_three_quarters_of_cap() {
        let caps = small_caps();
        assert_eq!(caps.max_output_buffer, 4096);
        assert_eq!(output_backpressure_threshold(&caps), 3072);
    }

    #[test]
    fn backpressure_below_threshold_emits_nothing() {
        let caps = small_caps();
        let mut watch = BackpressureWatch::default();
        let record = make_record_with_output(1024, 0);
        assert!(check_output_backpressure(&record, &caps, &mut watch).is_none());
        assert!(!watch.output_consumer_slow);
    }

    #[test]
    fn backpressure_rising_edge_emits_output_consumer_slow_with_metadata_detail() {
        let caps = small_caps();
        let mut watch = BackpressureWatch::default();
        // 2 KiB stdout + 2 KiB stderr = 4 KiB total ≥ 3 KiB threshold.
        let record = make_record_with_output(2048, 2048);
        let ev = check_output_backpressure(&record, &caps, &mut watch)
            .expect("rising edge should emit Backpressure");
        match ev {
            ProcWaitEvent::Backpressure { reason, detail } => {
                assert!(matches!(reason, BackpressureReason::OutputConsumerSlow));
                // Detail is bounded metadata — byte counts only, no
                // payload bytes / paths / argv / env / stdin content.
                assert!(
                    detail.contains("4096"),
                    "detail missing byte count: {detail}"
                );
                assert!(
                    detail.contains("3072"),
                    "detail missing threshold: {detail}"
                );
                assert!(detail.contains("4096"), "detail missing cap: {detail}");
            }
            other => panic!("expected Backpressure, got {other:?}"),
        }
        assert!(watch.output_consumer_slow);
    }

    #[test]
    fn backpressure_does_not_re_emit_while_condition_persists() {
        let caps = small_caps();
        let mut watch = BackpressureWatch::default();
        let record = make_record_with_output(4000, 0);

        let first = check_output_backpressure(&record, &caps, &mut watch);
        assert!(first.is_some(), "rising edge should emit");

        // Buffer still above threshold — agent must NOT keep spamming.
        let second = check_output_backpressure(&record, &caps, &mut watch);
        assert!(second.is_none(), "persistent backpressure must not re-emit");
        assert!(watch.output_consumer_slow);
    }

    #[test]
    fn backpressure_falling_edge_clears_watch_so_next_rise_re_emits() {
        let caps = small_caps();
        let mut watch = BackpressureWatch::default();

        // Cross the threshold once.
        let high = make_record_with_output(4000, 0);
        assert!(check_output_backpressure(&high, &caps, &mut watch).is_some());

        // Buffer drained: total < threshold.
        let low = make_record_with_output(1024, 0);
        assert!(check_output_backpressure(&low, &caps, &mut watch).is_none());
        assert!(
            !watch.output_consumer_slow,
            "falling edge must clear the watch flag"
        );

        // Cross again: rising edge after a fall must re-emit.
        let high_again = make_record_with_output(4000, 0);
        assert!(
            check_output_backpressure(&high_again, &caps, &mut watch).is_some(),
            "rising edge after a fall must re-emit"
        );
    }
}
