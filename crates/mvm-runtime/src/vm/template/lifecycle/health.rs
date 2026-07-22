//! Vsock health polling: guest agent readiness and per-integration
//! health checks, both driven from the host side against a booted VM.

use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::instrument;

use crate::ui;

/// Poll the guest agent via vsock until it responds, or timeout.
#[instrument(skip_all, fields(timeout_secs, interval_ms))]
pub fn wait_for_healthy(vsock_uds_path: &str, timeout_secs: u64, interval_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempts = 0u32;
    loop {
        if mvm_agentd::vsock::ping_at(vsock_uds_path).unwrap_or(false) {
            ui::success(&format!(
                "Guest agent healthy after {} attempts",
                attempts + 1
            ));
            return Ok(());
        }
        attempts += 1;
        if attempts.is_multiple_of(10) {
            ui::info(&format!(
                "Waiting for guest agent... ({} attempts, {}s remaining)",
                attempts,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            ));
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "VM did not become healthy within {}s ({} attempts)",
                timeout_secs,
                attempts
            );
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

/// Check whether all integrations with health checks are healthy.
/// Returns `(all_healthy, unhealthy_names)`.
///
/// Integrations without a `health_cmd` (i.e., `health: None`) are skipped.
/// If there are no integrations or none have health checks, returns `(true, [])`.
fn check_integration_health(
    integrations: &[mvm_agentd::integrations::IntegrationStateReport],
) -> (bool, Vec<String>) {
    let with_health: Vec<_> = integrations.iter().filter(|i| i.health.is_some()).collect();

    if with_health.is_empty() {
        return (true, vec![]);
    }

    let unhealthy: Vec<String> = with_health
        .iter()
        .filter(|i| !i.health.as_ref().is_some_and(|h| h.healthy))
        .map(|i| i.name.clone())
        .collect();

    (unhealthy.is_empty(), unhealthy)
}

/// Poll integration health status via vsock until all integrations with
/// health checks report healthy, or timeout.
///
/// If there are no integrations or none have `health_cmd` configured, returns
/// immediately (no-op).
#[instrument(skip_all, fields(timeout_secs, interval_ms))]
pub fn wait_for_integrations_healthy(
    vsock_uds_path: &str,
    timeout_secs: u64,
    interval_ms: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempts = 0u32;

    loop {
        let integrations = match mvm_agentd::vsock::query_integration_status_at(vsock_uds_path) {
            Ok(list) => list,
            Err(e) => {
                attempts += 1;
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "Timed out querying integration status after {}s ({} attempts): {}",
                        timeout_secs,
                        attempts,
                        e
                    );
                }
                if attempts.is_multiple_of(10) {
                    ui::warn(&format!(
                        "Failed to query integration status (attempt {}): {}",
                        attempts, e
                    ));
                }
                std::thread::sleep(Duration::from_millis(interval_ms));
                continue;
            }
        };

        if integrations.is_empty() {
            ui::info("No integrations registered, skipping integration health wait");
            return Ok(());
        }

        let (all_healthy, unhealthy) = check_integration_health(&integrations);

        if all_healthy {
            let names: Vec<&str> = integrations
                .iter()
                .filter(|i| i.health.is_some())
                .map(|i| i.name.as_str())
                .collect();
            ui::success(&format!(
                "All integrations healthy after {} attempts: [{}]",
                attempts + 1,
                names.join(", ")
            ));
            return Ok(());
        }

        attempts += 1;

        if attempts.is_multiple_of(10) {
            ui::info(&format!(
                "Waiting for integrations... ({} attempts, {}s remaining) unhealthy: [{}]",
                attempts,
                deadline.saturating_duration_since(Instant::now()).as_secs(),
                unhealthy.join(", ")
            ));
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "Integrations did not become healthy within {}s ({} attempts). Unhealthy: [{}]",
                timeout_secs,
                attempts,
                unhealthy.join(", ")
            );
        }

        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::integrations::{
        IntegrationHealthResult, IntegrationStateReport, IntegrationStatus,
    };

    fn healthy_report(name: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Active,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: true,
                detail: "ok".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }
    }

    fn unhealthy_report(name: &str, detail: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Error(detail.to_string()),
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: false,
                detail: detail.to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }
    }

    fn no_health_report(name: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Active,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: None,
        }
    }

    #[test]
    fn test_check_integration_health_all_healthy() {
        let integrations = vec![healthy_report("openclaw"), healthy_report("redis")];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_some_unhealthy() {
        let integrations = vec![
            unhealthy_report("openclaw", "exit code 1"),
            healthy_report("redis"),
        ];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(!all_healthy);
        assert_eq!(unhealthy, vec!["openclaw"]);
    }

    #[test]
    fn test_check_integration_health_empty_list() {
        let (all_healthy, unhealthy) = check_integration_health(&[]);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_no_health_cmds() {
        let integrations = vec![no_health_report("plain-service")];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_mixed_health_and_no_health() {
        let integrations = vec![
            healthy_report("with-health"),
            no_health_report("without-health"),
        ];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_pending_not_yet_checked() {
        let integrations = vec![IntegrationStateReport {
            name: "starting-up".to_string(),
            status: IntegrationStatus::Pending,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: false,
                detail: "connection refused".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(!all_healthy);
        assert_eq!(unhealthy, vec!["starting-up"]);
    }

    #[test]
    fn test_check_integration_health_error_status_but_healthy_check() {
        // Edge case: integration status is Error but health check passed.
        // We check health.healthy, not status — the health_cmd result is
        // the source of truth for readiness.
        let integrations = vec![IntegrationStateReport {
            name: "recovering".to_string(),
            status: IntegrationStatus::Error("previous crash".to_string()),
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: true,
                detail: "ok".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }
}
