//! Idle-registration self-termination logic for `mvm-host-agent`.
//!
//! A detached host-agent worker (setsid, ppid=1) leaks when its VMs are gone
//! and the CLI that would ordinarily reap it dies abnormally. This module
//! implements the decision logic: once zero VM registrations have persisted for
//! the configured idle timeout the worker exits with [`IDLE_SHUTDOWN_EXIT_CODE`]
//! so the wrapper can tear down the tree rather than restart it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::broker::daemon::HostAgentDaemon;

/// Exit code the worker uses when it self-terminates due to idle timeout.
///
/// A distinct value lets the wrapper distinguish "idle — tear down the tree"
/// from a crash (non-zero) or a clean stop (0). The wrapper must not restart
/// on this code.
pub const IDLE_SHUTDOWN_EXIT_CODE: i32 = 42;

/// Map the raw `MVM_HOST_AGENT_IDLE_TIMEOUT` env value to a `Duration`.
///
/// - `None` (env var unset) → `Some(300s)` — the default 5-minute warm window
///   keeps short-lived dev workflows from racing against idle reap.
/// - `Some("0")` → `None` — disables idle-exit entirely.
/// - `Some(positive integer)` → `Some(n seconds)`.
/// - `Some(unparseable / negative)` → `Some(300s)` — safe fallback to default.
pub fn parse_idle_timeout(raw: Option<&str>) -> Option<Duration> {
    const DEFAULT: Duration = Duration::from_secs(300);
    match raw {
        None => Some(DEFAULT),
        Some("0") => None,
        Some(s) => match s.trim().parse::<i64>() {
            Ok(n) if n > 0 => Some(Duration::from_secs(n as u64)),
            _ => Some(DEFAULT),
        },
    }
}

/// Read `MVM_HOST_AGENT_IDLE_TIMEOUT` from the environment and return the
/// resolved idle timeout.
pub fn idle_timeout() -> Option<Duration> {
    parse_idle_timeout(std::env::var("MVM_HOST_AGENT_IDLE_TIMEOUT").ok().as_deref())
}

/// Return `true` when the daemon should self-exit due to idleness.
///
/// All four conditions must hold simultaneously:
/// - `timeout` is `Some` (idle-exit is enabled),
/// - `count == 0` (no live registrations),
/// - `zero_since` is `Some` (we have been at zero continuously since that
///   instant — a transient dip that recovered resets the clock),
/// - the elapsed time since `zero_since` has reached `timeout`.
pub fn should_idle_exit(
    count: usize,
    zero_since: Option<Instant>,
    now: Instant,
    timeout: Option<Duration>,
) -> bool {
    timeout.is_some_and(|t| count == 0 && zero_since.is_some_and(|z| now.duration_since(z) >= t))
}

/// Return `true` when the worker exit code signals an idle self-termination.
///
/// The wrapper uses this to distinguish idle teardown (no restart) from a
/// crash (back off + restart).
pub fn is_idle_shutdown(code: Option<i32>) -> bool {
    code == Some(IDLE_SHUTDOWN_EXIT_CODE)
}

/// Watcher task that calls `process::exit(IDLE_SHUTDOWN_EXIT_CODE)` once the
/// daemon has had zero VM registrations for `timeout`.
///
/// Spawn this as a sibling task alongside the daemon's main serve loop. If
/// `timeout` is `None` (idle-exit disabled) the function returns immediately
/// without blocking.
///
/// The lock over `daemon` is held only for the `registration_count()` read and
/// is dropped before every sleep, so it never serialises against broker request
/// handling.
pub async fn run_idle_watcher(daemon: Arc<Mutex<HostAgentDaemon>>, timeout: Option<Duration>) {
    let Some(timeout) = timeout else {
        return;
    };
    const PROBE: Duration = Duration::from_millis(500);
    let mut zero_since: Option<Instant> = None;
    loop {
        let count = daemon.lock().await.registration_count();
        if count > 0 {
            zero_since = None;
        } else if zero_since.is_none() {
            zero_since = Some(Instant::now());
        }
        if should_idle_exit(count, zero_since, Instant::now(), Some(timeout)) {
            std::process::exit(IDLE_SHUTDOWN_EXIT_CODE);
        }
        tokio::time::sleep(PROBE).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_idle_timeout ---

    #[test]
    fn parse_none_gives_default() {
        assert_eq!(parse_idle_timeout(None), Some(Duration::from_secs(300)));
    }

    #[test]
    fn parse_zero_disables() {
        assert_eq!(parse_idle_timeout(Some("0")), None);
    }

    #[test]
    fn parse_positive_integer() {
        assert_eq!(parse_idle_timeout(Some("5")), Some(Duration::from_secs(5)));
    }

    #[test]
    fn parse_unparseable_falls_back_to_default() {
        assert_eq!(
            parse_idle_timeout(Some("abc")),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_negative_falls_back_to_default() {
        assert_eq!(
            parse_idle_timeout(Some("-3")),
            Some(Duration::from_secs(300))
        );
    }

    // --- should_idle_exit ---

    #[test]
    fn disabled_timeout_never_exits() {
        let base = Instant::now();
        // Simulate count == 0 with an old zero_since: disabled means no exit.
        let zero_since = base.checked_sub(Duration::from_secs(600));
        assert!(!should_idle_exit(0, zero_since, base, None));
    }

    #[test]
    fn nonzero_count_never_exits() {
        let base = Instant::now();
        let timeout = Some(Duration::from_secs(10));
        let zero_since = base.checked_sub(Duration::from_secs(600));
        assert!(!should_idle_exit(1, zero_since, base, timeout));
    }

    #[test]
    fn zero_count_no_zero_since_does_not_exit() {
        let base = Instant::now();
        let timeout = Some(Duration::from_secs(10));
        assert!(!should_idle_exit(0, None, base, timeout));
    }

    #[test]
    fn zero_count_idle_under_timeout_does_not_exit() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is only 1 second ago — still under the 60s threshold.
        let zero_since = base.checked_sub(Duration::from_secs(1));
        assert!(!should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    #[test]
    fn zero_count_idle_over_timeout_exits() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is 120 seconds ago — well past the threshold.
        let zero_since = base.checked_sub(Duration::from_secs(120));
        assert!(should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    #[test]
    fn zero_count_idle_exactly_at_timeout_exits() {
        let timeout = Duration::from_secs(60);
        let base = Instant::now();
        // zero_since is exactly `timeout` ago — boundary inclusive.
        let zero_since = base.checked_sub(timeout);
        assert!(should_idle_exit(0, zero_since, base, Some(timeout)));
    }

    // --- is_idle_shutdown ---

    #[test]
    fn idle_shutdown_code_is_recognized() {
        assert!(is_idle_shutdown(Some(IDLE_SHUTDOWN_EXIT_CODE)));
    }

    #[test]
    fn zero_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(Some(0)));
    }

    #[test]
    fn one_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(Some(1)));
    }

    #[test]
    fn none_exit_is_not_idle_shutdown() {
        assert!(!is_idle_shutdown(None));
    }
}
