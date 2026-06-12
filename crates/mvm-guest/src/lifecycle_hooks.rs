//! In-guest lifecycle-hook runner. SDK port Phase 10c.
//!
//! Phase 10b's Nix factory bakes one shell script per phase into the
//! rootfs at `/etc/mvm/hooks/<phase>.sh` (`before_start.sh`,
//! `after_start.sh`, `before_stop.sh`, …). The bootscript already
//! runs `before_start.sh` synchronously before dispatch. This module
//! covers the *active* lifecycle behavior:
//!
//! - [`poll_readiness`] — runs `after_start.sh` repeatedly with a
//!   bounded retry budget until it exits 0. The worker pool calls
//!   this *before* accepting `mvmctl invoke` so a slow-warming
//!   workload doesn't take traffic until it says it's ready. Times
//!   out if the script never succeeds.
//!
//! - [`run_shutdown_hook`] — runs `before_stop.sh` once on shutdown,
//!   with a grace deadline. Best-effort: on SIGKILL we get no
//!   notice, but for clean termination this lets the workload flush
//!   buffers / sync state.
//!
//! Both functions take an absolute script path so the caller can
//! point them at any path (production: the baked-in
//! `/etc/mvm/hooks/<phase>.sh`; tests: a tempdir fixture). No
//! dependency on the IR `HookCmd` enum — Phase 10b already lowered
//! those to shell scripts on disk, so this layer just runs files.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HookExit {
    success: bool,
    code: Option<i32>,
}

#[cfg(test)]
impl HookExit {
    const fn success() -> Self {
        Self {
            success: true,
            code: Some(0),
        }
    }

    const fn failure(code: i32) -> Self {
        Self {
            success: false,
            code: Some(code),
        }
    }
}

impl From<ExitStatus> for HookExit {
    fn from(status: ExitStatus) -> Self {
        Self {
            success: status.success(),
            code: status.code(),
        }
    }
}

trait HookChild {
    fn try_wait(&mut self) -> io::Result<Option<HookExit>>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<HookExit>;
}

trait HookRunner {
    type Child: HookChild;

    fn status(&self, script_path: &Path) -> io::Result<HookExit>;
    fn spawn(&self, script_path: &Path) -> io::Result<Self::Child>;

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct RealHookRunner;

impl HookRunner for RealHookRunner {
    type Child = RealHookChild;

    fn status(&self, script_path: &Path) -> io::Result<HookExit> {
        Command::new(script_path).status().map(HookExit::from)
    }

    fn spawn(&self, script_path: &Path) -> io::Result<Self::Child> {
        Command::new(script_path).spawn().map(RealHookChild)
    }
}

struct RealHookChild(Child);

impl HookChild for RealHookChild {
    fn try_wait(&mut self) -> io::Result<Option<HookExit>> {
        self.0.try_wait().map(|status| status.map(HookExit::from))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.0.kill()
    }

    fn wait(&mut self) -> io::Result<HookExit> {
        self.0.wait().map(HookExit::from)
    }
}

/// Tuning for the readiness probe. Defaults are reasonable for a
/// typical function-service warm-up; the worker pool can override
/// per workload.
#[derive(Debug, Clone)]
pub struct ReadinessConfig {
    /// Path to the script the bootscript baked in. Resolved via
    /// `execve` directly; the script must be executable.
    pub script_path: PathBuf,
    /// Hard wall-clock deadline. The probe returns
    /// [`ReadinessError::Timeout`] if it elapses without an exit-0.
    pub timeout: Duration,
    /// Sleep between attempts. Smaller = faster ready detection,
    /// larger = less CPU on the probe.
    pub interval: Duration,
}

impl ReadinessConfig {
    /// Build a config pointing at `script_path` with the default
    /// 30s timeout + 200ms interval the plan calls for.
    pub fn new(script_path: impl Into<PathBuf>) -> Self {
        Self {
            script_path: script_path.into(),
            timeout: Duration::from_secs(30),
            interval: Duration::from_millis(200),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

/// Errors surfaced by [`poll_readiness`].
#[derive(Debug, thiserror::Error)]
pub enum ReadinessError {
    /// The script never exited 0 within the deadline.
    #[error(
        "after_start readiness probe `{}` did not succeed within {elapsed:?}",
        script.display()
    )]
    Timeout { script: PathBuf, elapsed: Duration },

    /// The script path doesn't exist or isn't executable. Surface
    /// distinct from `ExecError` so the caller can fall through
    /// without polling.
    #[error("after_start readiness script `{}` is missing or not executable", script.display())]
    ScriptMissing { script: PathBuf },

    /// Some other I/O error spawning the script.
    #[error("failed to spawn readiness script `{}`: {source}", script.display())]
    ExecError {
        script: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Run `cfg.script_path` repeatedly until it exits 0 or the
/// timeout elapses. Returns `Ok(())` on first success; otherwise
/// the relevant [`ReadinessError`].
///
/// The script is expected to be self-contained — the worker pool
/// captures its exit code, not its output, so anything the script
/// wants to log should go to stderr.
pub fn poll_readiness(cfg: &ReadinessConfig) -> Result<(), ReadinessError> {
    poll_readiness_with_runner(cfg, &RealHookRunner)
}

fn poll_readiness_with_runner<R>(cfg: &ReadinessConfig, runner: &R) -> Result<(), ReadinessError>
where
    R: HookRunner,
{
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= cfg.timeout {
            return Err(ReadinessError::Timeout {
                script: cfg.script_path.clone(),
                elapsed,
            });
        }
        match runner.status(&cfg.script_path) {
            Ok(status) if status.success => return Ok(()),
            Ok(_) => {
                // Non-zero exit: try again after the interval, but
                // first guard against busy-looping right up against
                // the deadline.
                let remaining = cfg.timeout.checked_sub(elapsed).unwrap_or_default();
                let sleep_for = std::cmp::min(cfg.interval, remaining);
                if sleep_for.is_zero() {
                    return Err(ReadinessError::Timeout {
                        script: cfg.script_path.clone(),
                        elapsed,
                    });
                }
                runner.sleep(sleep_for);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(ReadinessError::ScriptMissing {
                    script: cfg.script_path.clone(),
                });
            }
            Err(e) => {
                return Err(ReadinessError::ExecError {
                    script: cfg.script_path.clone(),
                    source: e,
                });
            }
        }
    }
}

/// Errors surfaced by [`run_shutdown_hook`].
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// The script exceeded `grace` and was killed.
    #[error(
        "before_stop hook `{}` exceeded grace deadline {grace:?}; killed",
        script.display()
    )]
    GraceExceeded { script: PathBuf, grace: Duration },

    /// Script ran to completion but exited non-zero.
    #[error("before_stop hook `{}` exited {code:?}", script.display())]
    NonZeroExit { script: PathBuf, code: Option<i32> },

    #[error("before_stop hook `{}` is missing or not executable", script.display())]
    ScriptMissing { script: PathBuf },

    #[error("failed to spawn before_stop hook `{}`: {source}", script.display())]
    ExecError {
        script: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Run the shutdown hook script once with a wall-clock grace
/// deadline. Best-effort: the caller is already in a teardown
/// path, so a missing script or non-zero exit is logged but the VM
/// continues shutting down.
///
/// Polls the spawned child's status at `poll_interval` until the
/// `grace` deadline; if it hasn't exited by then, `SIGKILL` it and
/// return [`ShutdownError::GraceExceeded`]. Mirrors what the
/// init's `KillSignal=SIGTERM` + `TimeoutStopSec=...` would do, but
/// in-process for the Rust agent.
pub fn run_shutdown_hook(
    script_path: &Path,
    grace: Duration,
    poll_interval: Duration,
) -> Result<(), ShutdownError> {
    run_shutdown_hook_with_runner(script_path, grace, poll_interval, &RealHookRunner)
}

fn run_shutdown_hook_with_runner<R>(
    script_path: &Path,
    grace: Duration,
    poll_interval: Duration,
    runner: &R,
) -> Result<(), ShutdownError>
where
    R: HookRunner,
{
    let mut child = match runner.spawn(script_path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(ShutdownError::ScriptMissing {
                script: script_path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(ShutdownError::ExecError {
                script: script_path.to_path_buf(),
                source: e,
            });
        }
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success {
                    return Ok(());
                }
                return Err(ShutdownError::NonZeroExit {
                    script: script_path.to_path_buf(),
                    code: status.code,
                });
            }
            Ok(None) => {
                if start.elapsed() >= grace {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ShutdownError::GraceExceeded {
                        script: script_path.to_path_buf(),
                        grace,
                    });
                }
                runner.sleep(poll_interval);
            }
            Err(e) => {
                return Err(ShutdownError::ExecError {
                    script: script_path.to_path_buf(),
                    source: e,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct FakeStatusRunner {
        exits: Mutex<VecDeque<HookExit>>,
        fallback: HookExit,
    }

    impl FakeStatusRunner {
        fn new(exits: impl IntoIterator<Item = HookExit>, fallback: HookExit) -> Self {
            Self {
                exits: Mutex::new(exits.into_iter().collect()),
                fallback,
            }
        }
    }

    impl HookRunner for FakeStatusRunner {
        type Child = FakeChild;

        fn status(&self, _script_path: &Path) -> io::Result<HookExit> {
            Ok(self
                .exits
                .lock()
                .expect("fake status mutex poisoned")
                .pop_front()
                .unwrap_or(self.fallback))
        }

        fn spawn(&self, _script_path: &Path) -> io::Result<Self::Child> {
            Err(io::Error::other("fake status runner does not spawn"))
        }

        fn sleep(&self, _duration: Duration) {}
    }

    #[derive(Debug, Default)]
    struct FakeChildState {
        polls: usize,
        killed: bool,
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeChildBehavior {
        ExitAfter { polls: usize, exit: HookExit },
        NeverExit,
    }

    struct FakeChild {
        behavior: FakeChildBehavior,
        state: Arc<Mutex<FakeChildState>>,
    }

    impl HookChild for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<HookExit>> {
            let mut state = self.state.lock().expect("fake child mutex poisoned");
            state.polls += 1;
            match self.behavior {
                FakeChildBehavior::ExitAfter { polls, exit } if state.polls >= polls => {
                    Ok(Some(exit))
                }
                _ => Ok(None),
            }
        }

        fn kill(&mut self) -> io::Result<()> {
            self.state.lock().expect("fake child mutex poisoned").killed = true;
            Ok(())
        }

        fn wait(&mut self) -> io::Result<HookExit> {
            Ok(HookExit {
                success: false,
                code: None,
            })
        }
    }

    struct FakeSpawnRunner {
        child: Mutex<Option<FakeChild>>,
    }

    impl FakeSpawnRunner {
        fn new(behavior: FakeChildBehavior) -> (Self, Arc<Mutex<FakeChildState>>) {
            let state = Arc::new(Mutex::new(FakeChildState::default()));
            let child = FakeChild {
                behavior,
                state: Arc::clone(&state),
            };
            (
                Self {
                    child: Mutex::new(Some(child)),
                },
                state,
            )
        }
    }

    impl HookRunner for FakeSpawnRunner {
        type Child = FakeChild;

        fn status(&self, _script_path: &Path) -> io::Result<HookExit> {
            Err(io::Error::other("fake spawn runner does not poll status"))
        }

        fn spawn(&self, _script_path: &Path) -> io::Result<Self::Child> {
            self.child
                .lock()
                .expect("fake child slot mutex poisoned")
                .take()
                .ok_or_else(|| io::Error::other("fake child already spawned"))
        }

        fn sleep(&self, _duration: Duration) {}
    }

    #[test]
    fn poll_readiness_succeeds_when_script_exits_zero() {
        let runner = FakeStatusRunner::new([HookExit::success()], HookExit::failure(1));
        let cfg = ReadinessConfig::new(PathBuf::from("/fake/ok.sh"))
            .with_timeout(Duration::from_secs(1))
            .with_interval(Duration::from_millis(50));
        poll_readiness_with_runner(&cfg, &runner).expect("ready");
    }

    #[test]
    fn poll_readiness_times_out_when_script_always_fails() {
        let runner = FakeStatusRunner::new([], HookExit::failure(1));
        let cfg = ReadinessConfig::new(PathBuf::from("/fake/fail.sh"))
            .with_timeout(Duration::from_millis(5))
            .with_interval(Duration::from_millis(50));
        let err = poll_readiness_with_runner(&cfg, &runner).unwrap_err();
        assert!(matches!(err, ReadinessError::Timeout { .. }));
    }

    #[test]
    fn poll_readiness_succeeds_after_initial_failures() {
        let runner = FakeStatusRunner::new(
            [
                HookExit::failure(1),
                HookExit::failure(1),
                HookExit::success(),
            ],
            HookExit::failure(1),
        );
        let cfg = ReadinessConfig::new(PathBuf::from("/fake/warmup.sh"))
            .with_timeout(Duration::from_secs(1))
            .with_interval(Duration::from_millis(50));
        poll_readiness_with_runner(&cfg, &runner).expect("warmed up");
    }

    #[test]
    fn poll_readiness_reports_missing_script() {
        let cfg = ReadinessConfig::new(PathBuf::from("/nonexistent/probe.sh"))
            .with_timeout(Duration::from_millis(100))
            .with_interval(Duration::from_millis(50));
        let err = poll_readiness(&cfg).unwrap_err();
        assert!(matches!(err, ReadinessError::ScriptMissing { .. }));
    }

    #[test]
    fn run_shutdown_hook_succeeds_for_fast_script() {
        let (runner, _state) = FakeSpawnRunner::new(FakeChildBehavior::ExitAfter {
            polls: 1,
            exit: HookExit::success(),
        });
        run_shutdown_hook_with_runner(
            Path::new("/fake/stop.sh"),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &runner,
        )
        .expect("clean shutdown");
    }

    #[test]
    fn run_shutdown_hook_reports_non_zero_exit() {
        let (runner, _state) = FakeSpawnRunner::new(FakeChildBehavior::ExitAfter {
            polls: 1,
            exit: HookExit::failure(7),
        });
        let err = run_shutdown_hook_with_runner(
            Path::new("/fake/stop.sh"),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &runner,
        )
        .unwrap_err();
        match err {
            ShutdownError::NonZeroExit { code, .. } => assert_eq!(code, Some(7)),
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn run_shutdown_hook_kills_after_grace_deadline() {
        let (runner, state) = FakeSpawnRunner::new(FakeChildBehavior::NeverExit);
        let err = run_shutdown_hook_with_runner(
            Path::new("/fake/slow.sh"),
            Duration::from_millis(5),
            Duration::from_millis(1),
            &runner,
        )
        .unwrap_err();
        assert!(matches!(err, ShutdownError::GraceExceeded { .. }));
        assert!(state.lock().expect("fake child mutex poisoned").killed);
    }

    #[test]
    fn run_shutdown_hook_reports_missing_script() {
        let err = run_shutdown_hook(
            Path::new("/nonexistent/stop.sh"),
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(err, ShutdownError::ScriptMissing { .. }));
    }
}
