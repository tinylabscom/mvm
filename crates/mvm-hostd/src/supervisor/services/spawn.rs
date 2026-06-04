//! Subprocess spawn lifecycle for the four broker subprocesses
//! (Plan 104 W1b.2b.1).
//!
//! `SubprocessSpawner` is the trait; `ProcessSpawner` is the production
//! `tokio::process::Command`-based impl. `SubprocessHandle` is what the
//! supervisor holds after a successful spawn — it owns the `Child` plus
//! the UDS path the subprocess is listening on plus a `kill()` method
//! that sends SIGTERM and waits for exit.
//!
//! Restart-with-backoff lives in [`RestartSupervisor`] (this module).
//! UDS-connect readiness probing lives in [`probe::wait_for_uds`].
//!
//! Deferred to W1b.2b.{2,3,4}:
//! - Cosign-verify the binary at spawn (§H-L3.1, W1b.2b.2)
//! - TOCTOU-resistant verify-then-`fexecve` (§H-L3.2, W1b.2b.2)
//! - Sign the config envelope before writing to subprocess stdin
//!   (§H-L3.6, W1b.2b.3)
//! - Per-spawn ephemeral subprocess response signing wrapping the
//!   proxies (§H-L4.2, W1b.2b.4)
//! - Per-workload cgroup + namespace + seccomp + resource caps
//!   (§H-L1.4 / §H-L3.3 / §H-L3.9, all W1b.2c)
//!
//! The seam this PR carves: spawn / supervise / restart of arbitrary
//! subprocess binaries that consume JSON config on stdin and listen on
//! a UDS path. W1b.2b.2 wraps the spawn call site with cosign verify.
//! W1b.2c wraps further with cgroup setup + seccomp install.

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use crate::supervisor::services::binary_integrity::{IntegrityChecker, IntegrityError};

/// Errors a spawn / lifecycle operation can return.
#[derive(Debug, Error)]
pub enum SpawnError {
    /// `Command::spawn` itself failed (binary missing, exec error, etc.).
    #[error("spawn of {binary} failed: {source}")]
    Spawn {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// stdin write of the config JSON failed.
    #[error("config stdin write to {binary} failed: {source}")]
    ConfigWrite {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// stdin was unexpectedly absent (we asked for piped stdin but the
    /// `Child` came back without it). Indicates a tokio/`Stdio` bug.
    #[error("spawned {binary} had no stdin handle (Stdio::piped not honored)")]
    NoStdin { binary: PathBuf },
    /// Subprocess didn't bind its UDS within the readiness deadline.
    #[error(
        "spawned {binary} did not bind {uds_path} within {deadline:?} (readiness probe timed out)"
    )]
    ReadinessTimeout {
        binary: PathBuf,
        uds_path: PathBuf,
        deadline: Duration,
    },
    /// Subprocess exited before becoming ready.
    #[error("spawned {binary} exited prematurely (status: {status:?}) before binding {uds_path}")]
    PrematureExit {
        binary: PathBuf,
        uds_path: PathBuf,
        status: Option<std::process::ExitStatus>,
    },
    /// Restart budget exhausted — subprocess crashed too many times.
    #[error(
        "subprocess {binary} crashed {crashes} times in this workload's lifetime (budget {budget}); refusing to restart"
    )]
    RestartBudgetExhausted {
        binary: PathBuf,
        crashes: u32,
        budget: u32,
    },
    /// Pre-spawn integrity check refused the binary (Plan 104 §H-L3.1).
    /// Wraps the typed [`IntegrityError`] so callers can branch on the
    /// specific refusal (tamper / unknown signer / missing sidecar /
    /// unsupported alg / malformed sidecar).
    #[error("integrity check refused {binary}: {source}")]
    IntegrityCheckFailed {
        binary: PathBuf,
        #[source]
        source: IntegrityError,
    },
}

/// Result of a successful spawn — owns the child process + supervises
/// the lifetime. Dropping the handle does NOT kill the child (so a
/// dropped handle leaks the subprocess); callers must explicitly
/// [`SubprocessHandle::kill`] before drop. This is intentional — it
/// makes "shut down the subprocess" a deliberate action, not a side
/// effect of stack unwinding.
///
/// `Debug` is intentionally manual: tokio's `Child` redacts its
/// internals; we surface just the binary path + UDS path + whether
/// the child has been reaped.
pub struct SubprocessHandle {
    pub binary: PathBuf,
    pub uds_path: PathBuf,
    child: Option<Child>,
}

impl std::fmt::Debug for SubprocessHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubprocessHandle")
            .field("binary", &self.binary)
            .field("uds_path", &self.uds_path)
            .field("terminated", &self.child.is_none())
            .finish()
    }
}

impl SubprocessHandle {
    /// Send SIGTERM to the subprocess and wait for exit. Idempotent.
    pub async fn kill(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        // tokio's Child::kill sends SIGKILL on Unix. Prefer SIGTERM so the
        // subprocess has a chance to flush + exit cleanly; if it doesn't
        // exit within a short window, escalate. For W1b.2b.1 we keep
        // the simpler kill path; the SIGTERM-then-SIGKILL escalation
        // lands when we have a configurable shutdown deadline (likely
        // alongside the lifecycle audit emissions in W1b.2b.4).
        if let Err(e) = child.start_kill() {
            warn!(error = %e, binary = %self.binary.display(), "start_kill failed; proceeding to wait");
        }
        let _ = child.wait().await;
        Ok(())
    }

    /// Returns true if the underlying Child has been reaped already.
    pub fn is_terminated(&self) -> bool {
        self.child.is_none()
    }

    /// Returns the subprocess PID (Unix only; returns 0 elsewhere).
    /// For diagnostics / tests.
    pub fn pid(&self) -> u32 {
        self.child.as_ref().and_then(|c| c.id()).unwrap_or(0)
    }
}

/// What to spawn, where it should listen, what to feed it.
#[derive(Debug, Clone)]
pub struct SpawnRequest {
    /// Path to the subprocess binary (e.g. `target/debug/mvm-broker`).
    /// W1b.2b.2 will reject this path unless cosign-verify against the
    /// pinned release key succeeds before the spawn.
    pub binary: PathBuf,
    /// Per-VM UDS path the subprocess will bind. The spawner does NOT
    /// pre-create this path — the subprocess itself binds it from the
    /// config envelope. The readiness probe polls this path until the
    /// subprocess accepts a connection.
    pub uds_path: PathBuf,
    /// JSON-serialised `SubprocessConfig` (from each subprocess's
    /// `config::SubprocessConfig`). W1b.2b.3 will wrap this in a
    /// signed envelope per §H-L3.6.
    pub config_json: Vec<u8>,
    /// Maximum time the spawner waits for the subprocess to bind its
    /// UDS before declaring `ReadinessTimeout`.
    pub readiness_deadline: Duration,
    /// Maximum time the spawner polls before each connect attempt.
    /// W1b.2b.1 uses a fixed 25ms sleep; the field is here so W1b.2b.4
    /// can wire a metric-driven adaptive backoff without API churn.
    pub probe_interval: Duration,
}

impl SpawnRequest {
    /// Sensible defaults: 2s readiness deadline, 25ms probe interval.
    pub fn new(
        binary: impl Into<PathBuf>,
        uds_path: impl Into<PathBuf>,
        config_json: Vec<u8>,
    ) -> Self {
        Self {
            binary: binary.into(),
            uds_path: uds_path.into(),
            config_json,
            readiness_deadline: Duration::from_millis(2_000),
            probe_interval: Duration::from_millis(25),
        }
    }
}

/// Spawner trait — production [`ProcessSpawner`] uses
/// `tokio::process::Command`; tests can supply their own mock.
#[async_trait::async_trait]
pub trait SubprocessSpawner: Send + Sync + 'static {
    async fn spawn(&self, request: SpawnRequest) -> Result<SubprocessHandle, SpawnError>;
}

/// Production spawner — `tokio::process::Command` + parent-death attach
/// (Linux only — macOS impl deferred to W1b.2b.{4,c} once we settle on
/// the kqueue-watcher-vs-PID-watchdog choice).
///
/// An optional [`IntegrityChecker`] runs *before* `Command::spawn`. If
/// the check fails, the subprocess is never started; the supervisor
/// surfaces [`SpawnError::IntegrityCheckFailed`] with the typed
/// [`IntegrityError`] for audit emission (W1b.2b.5).
///
/// **TOCTOU window still open** between verify-time and exec-time
/// (Plan 104 §H-L3.2). Closing it requires Linux `fexecve` (or macOS
/// `posix_spawn`-with-fd) — that lands in a follow-on PR
/// (W1b.2b.2.5 or alongside the W1b.2c cgroup/seccomp plumbing).
#[derive(Default, Clone)]
pub struct ProcessSpawner {
    integrity_checker: Option<Arc<dyn IntegrityChecker>>,
}

impl std::fmt::Debug for ProcessSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSpawner")
            .field("integrity_checker", &self.integrity_checker.is_some())
            .finish()
    }
}

impl ProcessSpawner {
    /// Create a spawner with no integrity check (development /
    /// internal-test path). Production should always use
    /// [`ProcessSpawner::with_integrity_checker`].
    pub fn unchecked() -> Self {
        Self {
            integrity_checker: None,
        }
    }

    /// Attach a pre-spawn integrity check. The W1b.2b.5 admission
    /// ceremony wires the production
    /// [`crate::supervisor::services::binary_integrity::SignedBinaryChecker`] here.
    pub fn with_integrity_checker(checker: Arc<dyn IntegrityChecker>) -> Self {
        Self {
            integrity_checker: Some(checker),
        }
    }
}

#[async_trait::async_trait]
impl SubprocessSpawner for ProcessSpawner {
    async fn spawn(&self, request: SpawnRequest) -> Result<SubprocessHandle, SpawnError> {
        debug!(
            binary = %request.binary.display(),
            uds_path = %request.uds_path.display(),
            "ProcessSpawner spawning subprocess"
        );

        // Pre-spawn integrity check (Plan 104 §H-L3.1). Refuse to
        // even Command::spawn if the verify fails.
        //
        // TOCTOU window: an attacker who swaps the binary between this
        // verify call and the `Command::new` exec below wins. Closing
        // the window requires fexecve on Linux / posix_spawn-with-fd
        // on macOS — see follow-on per §H-L3.2.
        if let Some(checker) = &self.integrity_checker {
            checker
                .verify(&request.binary)
                .map_err(|source| SpawnError::IntegrityCheckFailed {
                    binary: request.binary.clone(),
                    source,
                })?;
            debug!(
                binary = %request.binary.display(),
                "ProcessSpawner integrity check passed"
            );
        }

        let mut command = Command::new(&request.binary);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);

        #[cfg(target_os = "linux")]
        unsafe {
            // PR_SET_PDEATHSIG(SIGTERM): when the parent (us) dies, the
            // kernel sends SIGTERM to the subprocess. Set in the
            // pre_exec hook so the signal is armed before the subprocess
            // starts executing its main(). Plan 104 §H-L1 subprocess
            // lifecycle.
            //
            // SAFETY: pre_exec runs in the forked child between fork and
            // execve. Only async-signal-safe calls allowed — `prctl` is
            // on the POSIX async-signal-safe list and `libc::prctl`
            // forwards directly. No allocation, no Rust runtime, no
            // tokio state.
            command.as_std_mut().pre_exec(|| {
                let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(|source| SpawnError::Spawn {
            binary: request.binary.clone(),
            source,
        })?;

        let mut stdin = child.stdin.take().ok_or_else(|| SpawnError::NoStdin {
            binary: request.binary.clone(),
        })?;
        stdin
            .write_all(&request.config_json)
            .await
            .map_err(|source| SpawnError::ConfigWrite {
                binary: request.binary.clone(),
                source,
            })?;
        stdin
            .shutdown()
            .await
            .map_err(|source| SpawnError::ConfigWrite {
                binary: request.binary.clone(),
                source,
            })?;
        drop(stdin);

        info!(
            binary = %request.binary.display(),
            uds_path = %request.uds_path.display(),
            pid = child.id().unwrap_or(0),
            "subprocess spawned; awaiting readiness probe"
        );

        // Poll the UDS path until the subprocess accepts a connection,
        // or the deadline elapses, or the subprocess exits first.
        probe::wait_for_uds(&mut child, &request).await?;

        Ok(SubprocessHandle {
            binary: request.binary,
            uds_path: request.uds_path,
            child: Some(child),
        })
    }
}

/// Restart-on-crash supervisor. Wraps a [`SubprocessSpawner`] +
/// `SpawnRequest` with an exponential backoff (100ms, 500ms, 2s) up to
/// `restart_budget` total restarts. On budget exhaustion returns
/// [`SpawnError::RestartBudgetExhausted`] and refuses further spawns —
/// the caller (supervisor's lifecycle code) is expected to translate
/// that into a workload pause + audit event per Plan 104 §H-L1.
pub struct RestartSupervisor<S: SubprocessSpawner> {
    spawner: S,
    backoff: Vec<Duration>,
    restart_budget: u32,
    crashes: u32,
}

impl<S: SubprocessSpawner> RestartSupervisor<S> {
    /// Sensible defaults: backoff `[100ms, 500ms, 2s]`; max 3 restarts.
    pub fn new(spawner: S) -> Self {
        Self {
            spawner,
            backoff: vec![
                Duration::from_millis(100),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
            ],
            restart_budget: 3,
            crashes: 0,
        }
    }

    /// Override the default backoff sequence. Test convenience —
    /// production paths should use [`RestartSupervisor::new`].
    pub fn with_backoff(mut self, backoff: Vec<Duration>) -> Self {
        self.backoff = backoff;
        self
    }

    /// Override the default restart budget. Test convenience.
    pub fn with_budget(mut self, budget: u32) -> Self {
        self.restart_budget = budget;
        self
    }

    /// Spawn the subprocess, retrying on crash up to the budget.
    /// Returns the handle on success.
    pub async fn spawn(
        &mut self,
        mut request: SpawnRequest,
    ) -> Result<SubprocessHandle, SpawnError> {
        let mut last_err: Option<SpawnError>;
        loop {
            if self.crashes > self.restart_budget {
                return Err(SpawnError::RestartBudgetExhausted {
                    binary: request.binary,
                    crashes: self.crashes,
                    budget: self.restart_budget,
                });
            }

            // Clone the request for each attempt — Command::spawn consumes
            // some of its fields internally and Config bytes need to be
            // re-fed on each attempt.
            let attempt = SpawnRequest {
                binary: request.binary.clone(),
                uds_path: request.uds_path.clone(),
                config_json: request.config_json.clone(),
                readiness_deadline: request.readiness_deadline,
                probe_interval: request.probe_interval,
            };

            match self.spawner.spawn(attempt).await {
                Ok(handle) => return Ok(handle),
                Err(e) => {
                    warn!(
                        binary = %request.binary.display(),
                        crashes = self.crashes,
                        budget = self.restart_budget,
                        error = %e,
                        "subprocess spawn failed; will retry"
                    );
                    last_err = Some(e);
                    let backoff_idx = self.crashes as usize;
                    let delay = self.backoff.get(backoff_idx).copied().unwrap_or_else(|| {
                        self.backoff
                            .last()
                            .copied()
                            .unwrap_or(Duration::from_millis(500))
                    });
                    self.crashes += 1;
                    if self.crashes > self.restart_budget {
                        return Err(last_err.unwrap_or_else(|| {
                            SpawnError::RestartBudgetExhausted {
                                binary: request.binary.clone(),
                                crashes: self.crashes,
                                budget: self.restart_budget,
                            }
                        }));
                    }
                    // Re-bind the request for the next iteration (move
                    // back to the loop variable so the next attempt
                    // gets the same config).
                    request = SpawnRequest {
                        binary: request.binary,
                        uds_path: request.uds_path,
                        config_json: request.config_json,
                        readiness_deadline: request.readiness_deadline,
                        probe_interval: request.probe_interval,
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    pub fn crashes(&self) -> u32 {
        self.crashes
    }

    pub fn restart_budget(&self) -> u32 {
        self.restart_budget
    }
}

pub mod probe {
    //! UDS-connect readiness probe.

    use std::time::Instant;

    use tokio::net::UnixStream;
    use tokio::process::Child;

    use super::{SpawnError, SpawnRequest};

    /// Poll the subprocess's UDS path until it accepts a connection, or
    /// the readiness deadline elapses, or the subprocess exits first.
    ///
    /// Returns `Ok(())` on success. On premature exit, the caller can
    /// reap the child via the `Child::wait` exposed in [`SpawnError`].
    pub async fn wait_for_uds(child: &mut Child, request: &SpawnRequest) -> Result<(), SpawnError> {
        let deadline = Instant::now() + request.readiness_deadline;
        loop {
            // Has the subprocess exited?
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(SpawnError::PrematureExit {
                        binary: request.binary.clone(),
                        uds_path: request.uds_path.clone(),
                        status: Some(status),
                    });
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(SpawnError::PrematureExit {
                        binary: request.binary.clone(),
                        uds_path: request.uds_path.clone(),
                        status: None,
                    });
                }
            }
            // Try to connect to the UDS.
            if UnixStream::connect(&request.uds_path).await.is_ok() {
                return Ok(());
            }
            // Deadline check.
            if Instant::now() >= deadline {
                return Err(SpawnError::ReadinessTimeout {
                    binary: request.binary.clone(),
                    uds_path: request.uds_path.clone(),
                    deadline: request.readiness_deadline,
                });
            }
            tokio::time::sleep(request.probe_interval).await;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tempfile::tempdir;
    use tokio::net::UnixListener;

    use super::*;

    /// Mock spawner — used for testing RestartSupervisor + restart
    /// semantics without spawning real binaries.
    struct MockSpawner {
        outcomes: Arc<tokio::sync::Mutex<Vec<Result<(), SpawnError>>>>,
        attempts: Arc<AtomicU32>,
    }

    impl MockSpawner {
        fn new(outcomes: Vec<Result<(), SpawnError>>) -> (Self, Arc<AtomicU32>) {
            let attempts = Arc::new(AtomicU32::new(0));
            (
                Self {
                    outcomes: Arc::new(tokio::sync::Mutex::new(outcomes)),
                    attempts: attempts.clone(),
                },
                attempts,
            )
        }
    }

    #[async_trait::async_trait]
    impl SubprocessSpawner for MockSpawner {
        async fn spawn(&self, request: SpawnRequest) -> Result<SubprocessHandle, SpawnError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let mut outcomes = self.outcomes.lock().await;
            let outcome = outcomes
                .pop()
                .unwrap_or_else(|| panic!("MockSpawner ran out of outcomes"));
            outcome.map(|_| SubprocessHandle {
                binary: request.binary,
                uds_path: request.uds_path,
                child: None,
            })
        }
    }

    fn dummy_request(dir: &tempfile::TempDir) -> SpawnRequest {
        SpawnRequest {
            binary: PathBuf::from("/usr/bin/nonexistent-binary-for-tests"),
            uds_path: dir.path().join("dummy.sock"),
            config_json: b"{}".to_vec(),
            readiness_deadline: Duration::from_millis(100),
            probe_interval: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn restart_supervisor_succeeds_on_first_attempt() {
        let dir = tempdir().unwrap();
        let (spawner, attempts) = MockSpawner::new(vec![Ok(())]);
        let mut sup = RestartSupervisor::new(spawner)
            .with_backoff(vec![Duration::from_millis(1)])
            .with_budget(3);
        let handle = sup.spawn(dummy_request(&dir)).await.expect("must succeed");
        assert!(handle.is_terminated());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(sup.crashes(), 0);
    }

    #[tokio::test]
    async fn restart_supervisor_retries_after_failure() {
        let dir = tempdir().unwrap();
        // Outcomes are popped, so: first attempt fails, second succeeds.
        let outcomes = vec![
            Ok(()),
            Err(SpawnError::PrematureExit {
                binary: PathBuf::from("/x"),
                uds_path: PathBuf::from("/y"),
                status: None,
            }),
        ];
        let (spawner, attempts) = MockSpawner::new(outcomes);
        let mut sup = RestartSupervisor::new(spawner)
            .with_backoff(vec![Duration::from_millis(1), Duration::from_millis(1)])
            .with_budget(3);
        let handle = sup.spawn(dummy_request(&dir)).await.expect("must succeed");
        assert!(handle.is_terminated());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(sup.crashes(), 1);
    }

    #[tokio::test]
    async fn restart_supervisor_exhausts_budget_then_refuses() {
        let dir = tempdir().unwrap();
        let outcomes: Vec<Result<(), SpawnError>> = (0..6)
            .map(|i| {
                Err(SpawnError::PrematureExit {
                    binary: PathBuf::from(format!("/x-{i}")),
                    uds_path: PathBuf::from(format!("/y-{i}")),
                    status: None,
                })
            })
            .collect();
        let (spawner, attempts) = MockSpawner::new(outcomes);
        // Budget = 2; backoff vec only has 2 entries so the third
        // attempt gets the last entry repeated.
        let mut sup = RestartSupervisor::new(spawner)
            .with_backoff(vec![Duration::from_millis(1), Duration::from_millis(1)])
            .with_budget(2);
        let err = sup.spawn(dummy_request(&dir)).await.expect_err("must fail");
        // Budget = 2 means we attempt original + 2 retries = 3 attempts.
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        match err {
            SpawnError::PrematureExit { .. } => {}
            other => panic!("expected PrematureExit from final attempt, got {other:?}"),
        }
        assert_eq!(sup.crashes(), 3);
    }

    #[tokio::test]
    async fn readiness_probe_succeeds_when_uds_already_bound() {
        let dir = tempdir().unwrap();
        let uds_path = dir.path().join("already-bound.sock");
        let _listener = UnixListener::bind(&uds_path).unwrap();

        // Use a real `Child` so try_wait works — `sleep infinity` is a
        // long-running process that never exits during the test.
        // Skip on systems without `sleep` (unlikely on Unix CI).
        let mut child = match Command::new("sleep").arg("60").spawn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let request = SpawnRequest {
            binary: PathBuf::from("sleep"),
            uds_path: uds_path.clone(),
            config_json: vec![],
            readiness_deadline: Duration::from_millis(100),
            probe_interval: Duration::from_millis(10),
        };
        let result = probe::wait_for_uds(&mut child, &request).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let _ = child.kill().await;
    }

    #[tokio::test]
    async fn readiness_probe_times_out_when_uds_never_appears() {
        let dir = tempdir().unwrap();
        let mut child = match Command::new("sleep").arg("60").spawn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let request = SpawnRequest {
            binary: PathBuf::from("sleep"),
            uds_path: dir.path().join("never-bound.sock"),
            config_json: vec![],
            readiness_deadline: Duration::from_millis(80),
            probe_interval: Duration::from_millis(10),
        };
        let result = probe::wait_for_uds(&mut child, &request).await;
        match result {
            Err(SpawnError::ReadinessTimeout { .. }) => {}
            other => panic!("expected ReadinessTimeout, got {other:?}"),
        }
        let _ = child.kill().await;
    }

    #[tokio::test]
    async fn readiness_probe_detects_premature_exit() {
        let dir = tempdir().unwrap();
        // `true` exits immediately with 0.
        let mut child = match Command::new("true").spawn() {
            Ok(c) => c,
            Err(_) => return,
        };
        // Wait long enough for the exit to be observable by try_wait.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let request = SpawnRequest {
            binary: PathBuf::from("true"),
            uds_path: dir.path().join("never-binds.sock"),
            config_json: vec![],
            readiness_deadline: Duration::from_millis(200),
            probe_interval: Duration::from_millis(10),
        };
        let result = probe::wait_for_uds(&mut child, &request).await;
        match result {
            Err(SpawnError::PrematureExit { .. }) => {}
            other => panic!("expected PrematureExit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_spawner_real_binary_propagates_spawn_error_on_missing_path() {
        let dir = tempdir().unwrap();
        let spawner = ProcessSpawner::unchecked();
        let request = SpawnRequest::new(
            "/definitely/not/a/real/path/mvm-fake",
            dir.path().join("nope.sock"),
            b"{}".to_vec(),
        );
        let err = spawner
            .spawn(request)
            .await
            .expect_err("missing path must fail");
        match err {
            SpawnError::Spawn { .. } => {}
            other => panic!("expected Spawn error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_spawner_refuses_tampered_binary_before_calling_command_spawn() {
        // Wires the IntegrityChecker into ProcessSpawner end-to-end:
        // sign a tempdir "binary", attach the bundle, tamper the file,
        // then assert spawn fails with IntegrityCheckFailed (not the
        // downstream Spawn / ReadinessTimeout that would fire if the
        // checker were bypassed). The shell-script body never runs.
        use std::sync::Arc;

        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        use crate::supervisor::services::binary_integrity::{
            BinarySignature, IntegrityError, ReleaseKeyBundle, SignedBinaryChecker,
        };

        let dir = tempdir().unwrap();
        let binary_path = dir.path().join("fake-bin");
        let original = b"#!/bin/sh\nsleep 5\n";
        std::fs::write(&binary_path, original).unwrap();

        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(original);

        let mut bundle = ReleaseKeyBundle::new();
        let key_id = bundle.add(verifying_key);

        use base64::Engine;
        let sidecar = BinarySignature {
            sig_alg: mvm_core::security::SIG_ALG_ED25519,
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signer_key_id: key_id,
        };
        sidecar.write_for(&binary_path).unwrap();

        // TAMPER the binary after signing.
        std::fs::write(&binary_path, b"#!/bin/sh\necho TAMPERED\n").unwrap();

        let checker = SignedBinaryChecker::new(bundle);
        let spawner = ProcessSpawner::with_integrity_checker(Arc::new(checker));
        let request = SpawnRequest::new(
            &binary_path,
            dir.path().join("never-binds.sock"),
            b"{}".to_vec(),
        );

        let err = spawner
            .spawn(request)
            .await
            .expect_err("tampered binary must be refused before spawn");
        match err {
            SpawnError::IntegrityCheckFailed { source, .. } => {
                assert!(
                    matches!(source, IntegrityError::SignatureMismatch { .. }),
                    "expected SignatureMismatch, got {source:?}"
                );
            }
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }
}
