//! Integration health monitoring: per-integration health-check commands run
//! on a background loop, cached, and surfaced as `IntegrationStateReport`s.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mvm_agentd::integrations::{
    IntegrationEntry, IntegrationHealthResult, IntegrationStateReport, IntegrationStatus,
};

use crate::monitoring::utc_now;
use crate::state::IntegrationState;

// ============================================================================
// Shell command execution
// ============================================================================

/// Run a shell command with a timeout, returning the captured output.
///
/// Uses `/bin/sh -c` (absolute path — NixOS systemd services may not have
/// `/bin` in PATH, but `/bin/sh` always exists as a symlink to bash).
/// Timeout is enforced natively via `try_wait` polling to avoid depending
/// on the `timeout` binary from coreutils being in PATH.
pub(crate) fn run_shell_with_timeout(
    cmd: &str,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Poll until the child exits or the timeout fires.
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if start.elapsed() >= timeout => {
                if let Err(e) = child.kill() {
                    eprintln!("failed to kill child process: {e}");
                }
                if let Err(e) = child.wait() {
                    eprintln!("failed to wait child process: {e}");
                }
                return Ok(std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: Vec::new(),
                    stderr: format!("timed out after {}s", timeout.as_secs()).into_bytes(),
                });
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    // Child has exited — read remaining pipe output.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut r) = child.stdout.take()
        && let Err(e) = r.read_to_end(&mut stdout)
    {
        eprintln!("failed to read child stdout: {e}");
    }
    if let Some(mut r) = child.stderr.take()
        && let Err(e) = r.read_to_end(&mut stderr)
    {
        eprintln!("failed to read child stderr: {e}");
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

// ============================================================================
// Integration health monitoring
// ============================================================================

/// Run a single health check command for an integration.
fn run_health_check(entry: &IntegrationEntry) -> IntegrationHealthResult {
    let Some(ref cmd) = entry.health_cmd else {
        return IntegrationHealthResult {
            healthy: true,
            detail: "no health_cmd configured".to_string(),
            checked_at: utc_now(),
        };
    };

    let timeout = Duration::from_secs(entry.health_timeout_secs);
    match run_shell_with_timeout(cmd, timeout) {
        Ok(out) if out.status.success() => IntegrationHealthResult {
            healthy: true,
            detail: "ok".to_string(),
            checked_at: utc_now(),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("exit code {}", out.status.code().unwrap_or(-1))
            } else {
                stderr.trim().to_string()
            };
            IntegrationHealthResult {
                healthy: false,
                detail,
                checked_at: utc_now(),
            }
        }
        Err(e) => IntegrationHealthResult {
            healthy: false,
            detail: format!("failed to execute: {}", e),
            checked_at: utc_now(),
        },
    }
}

/// Background loop that periodically runs health checks for all integrations.
pub(crate) fn integration_health_loop(state: Arc<Mutex<IntegrationState>>) {
    let count = state.lock().map(|s| s.integrations.len()).unwrap_or(0);
    let mut last_checked: Vec<Option<std::time::Instant>> = vec![None; count];
    let boot_time = std::time::Instant::now();

    loop {
        let entries: Vec<(usize, IntegrationEntry)> = {
            let Ok(s) = state.lock() else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            s.integrations
                .iter()
                .enumerate()
                .map(|(i, ih)| (i, ih.entry.clone()))
                .collect()
        };

        for (idx, entry) in &entries {
            if entry.health_cmd.is_none() {
                continue;
            }
            let interval = Duration::from_secs(entry.health_interval_secs);
            let should_check = match last_checked.get(*idx).copied().flatten() {
                Some(last) => last.elapsed() >= interval,
                None => true,
            };
            if !should_check {
                continue;
            }

            let result = run_health_check(entry);
            // During the startup grace period, still store results (so the host
            // can poll via vsock) but don't log failures to console.
            let in_grace = entry.startup_grace_secs > 0
                && boot_time.elapsed() < Duration::from_secs(entry.startup_grace_secs);
            if !result.healthy && !in_grace {
                eprintln!(
                    "mvm-guest-agent: health check failed for '{}': {}",
                    entry.name, result.detail
                );
            }
            if let Ok(mut s) = state.lock()
                && let Some(ih) = s.integrations.get_mut(*idx)
            {
                ih.last_result = Some(result);
            }
            last_checked[*idx] = Some(std::time::Instant::now());
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Build an IntegrationStateReport from cached health data.
///
/// `boot_at` is the time the agent started; used to determine whether a
/// service is still within its `startup_grace_secs` window.  During that
/// window, unhealthy or not-yet-checked integrations report `starting`
/// instead of `error` / `pending` so the host knows the VM is still
/// initialising rather than broken.
pub(crate) fn build_integration_reports(
    integration_state: &Arc<Mutex<IntegrationState>>,
    boot_at: std::time::Instant,
) -> Vec<IntegrationStateReport> {
    let Ok(s) = integration_state.lock() else {
        return vec![];
    };
    s.integrations
        .iter()
        .map(|ih| {
            let in_grace = ih.entry.startup_grace_secs > 0
                && boot_at.elapsed() < Duration::from_secs(ih.entry.startup_grace_secs);
            let status = match &ih.last_result {
                Some(r) if r.healthy => IntegrationStatus::Active,
                Some(_) if in_grace => IntegrationStatus::Starting,
                Some(r) => IntegrationStatus::Error(r.detail.clone()),
                None if in_grace => IntegrationStatus::Starting,
                None => IntegrationStatus::Pending,
            };
            IntegrationStateReport {
                name: ih.entry.name.clone(),
                status,
                last_checkpoint_at: None,
                state_size_bytes: 0,
                health: ih.last_result.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::IntegrationHealth;

    fn make_state(
        entries: Vec<(IntegrationEntry, Option<IntegrationHealthResult>)>,
    ) -> Arc<Mutex<IntegrationState>> {
        let integrations = entries
            .into_iter()
            .map(|(entry, last_result)| IntegrationHealth { entry, last_result })
            .collect();
        Arc::new(Mutex::new(IntegrationState { integrations }))
    }

    fn entry_with_grace(name: &str, grace_secs: u64) -> IntegrationEntry {
        IntegrationEntry {
            name: name.to_string(),
            checkpoint_cmd: None,
            restore_cmd: None,
            critical: false,
            health_cmd: Some("true".to_string()),
            health_interval_secs: 10,
            health_timeout_secs: 5,
            startup_grace_secs: grace_secs,
        }
    }

    fn unhealthy_result() -> IntegrationHealthResult {
        IntegrationHealthResult {
            healthy: false,
            detail: "connection refused".to_string(),
            checked_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn healthy_result() -> IntegrationHealthResult {
        IntegrationHealthResult {
            healthy: true,
            detail: "ok".to_string(),
            checked_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_grace_period_unhealthy_returns_starting() {
        // Boot happened 5 seconds ago, grace period is 60 seconds
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(
            entry_with_grace("app", 60),
            Some(unhealthy_result()),
        )]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Starting),
            "Expected Starting during grace period, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_grace_period_expired_returns_error() {
        // Boot happened 120 seconds ago, grace period is 60 seconds
        let boot_at = std::time::Instant::now() - Duration::from_secs(120);
        let state = make_state(vec![(
            entry_with_grace("app", 60),
            Some(unhealthy_result()),
        )]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Error(_)),
            "Expected Error after grace period, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_grace_period_no_result_returns_starting() {
        // Boot happened 5 seconds ago, no health check result yet
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 60), None)]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Starting),
            "Expected Starting for no-result during grace, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_no_grace_period_no_result_returns_pending() {
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 0), None)]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Pending),
            "Expected Pending with no grace and no result, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_healthy_returns_active_regardless_of_grace() {
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 60), Some(healthy_result()))]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Active),
            "Expected Active for healthy integration, got {:?}",
            reports[0].status
        );
    }
}
