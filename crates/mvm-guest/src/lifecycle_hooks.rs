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
use std::process::Command;
use std::time::{Duration, Instant};

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
    Timeout {
        script: PathBuf,
        elapsed: Duration,
    },

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
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= cfg.timeout {
            return Err(ReadinessError::Timeout {
                script: cfg.script_path.clone(),
                elapsed,
            });
        }
        match Command::new(&cfg.script_path).status() {
            Ok(status) if status.success() => return Ok(()),
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
                std::thread::sleep(sleep_for);
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
    let mut child = match Command::new(script_path).spawn() {
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
                if status.success() {
                    return Ok(());
                }
                return Err(ShutdownError::NonZeroExit {
                    script: script_path.to_path_buf(),
                    code: status.code(),
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
                std::thread::sleep(poll_interval);
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
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
        p
    }

    #[test]
    fn poll_readiness_succeeds_when_script_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let s = write_script(tmp.path(), "ok.sh", "#!/bin/sh\nexit 0\n");
        let cfg = ReadinessConfig::new(s)
            .with_timeout(Duration::from_secs(1))
            .with_interval(Duration::from_millis(50));
        poll_readiness(&cfg).expect("ready");
    }

    #[test]
    fn poll_readiness_times_out_when_script_always_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let s = write_script(tmp.path(), "fail.sh", "#!/bin/sh\nexit 1\n");
        let cfg = ReadinessConfig::new(s)
            .with_timeout(Duration::from_millis(250))
            .with_interval(Duration::from_millis(50));
        let err = poll_readiness(&cfg).unwrap_err();
        assert!(matches!(err, ReadinessError::Timeout { .. }));
    }

    #[test]
    fn poll_readiness_succeeds_after_initial_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let counter = tmp.path().join("count");
        fs::write(&counter, "0").unwrap();
        let body = format!(
            "#!/bin/sh\nc=$(cat {ctr})\nc=$((c+1))\necho $c > {ctr}\n[ $c -ge 3 ] && exit 0\nexit 1\n",
            ctr = counter.display()
        );
        let s = write_script(tmp.path(), "warmup.sh", &body);
        let cfg = ReadinessConfig::new(s)
            .with_timeout(Duration::from_secs(3))
            .with_interval(Duration::from_millis(50));
        poll_readiness(&cfg).expect("warmed up");
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
        let tmp = tempfile::tempdir().unwrap();
        let s = write_script(tmp.path(), "stop.sh", "#!/bin/sh\nexit 0\n");
        run_shutdown_hook(&s, Duration::from_secs(2), Duration::from_millis(50))
            .expect("clean shutdown");
    }

    #[test]
    fn run_shutdown_hook_reports_non_zero_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let s = write_script(tmp.path(), "stop.sh", "#!/bin/sh\nexit 7\n");
        let err =
            run_shutdown_hook(&s, Duration::from_secs(2), Duration::from_millis(50)).unwrap_err();
        match err {
            ShutdownError::NonZeroExit { code, .. } => assert_eq!(code, Some(7)),
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn run_shutdown_hook_kills_after_grace_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let s = write_script(tmp.path(), "slow.sh", "#!/bin/sh\nsleep 5\n");
        let err = run_shutdown_hook(&s, Duration::from_millis(200), Duration::from_millis(50))
            .unwrap_err();
        assert!(matches!(err, ShutdownError::GraceExceeded { .. }));
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
