use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::server::CoordinatorState;
use super::wake::GatewayState;

/// Run periodic health checks against all routes.
///
/// For each route whose gateway is marked Running, periodically verify it's
/// still alive via the agent API. If the gateway is gone, mark it idle so the
/// next connection triggers a wake.
pub async fn health_check_loop(state: Arc<CoordinatorState>) {
    let interval = Duration::from_secs(state.config.coordinator.health_interval_secs);

    loop {
        tokio::time::sleep(interval).await;

        let routes = state.route_table.routes().await;
        for (_, route) in routes {
            let current = state.wake_manager.gateway_state(&route.tenant_id).await;
            if let GatewayState::Running { addr } = current {
                if let Err(e) = check_gateway_alive(addr).await {
                    warn!(
                        tenant = %route.tenant_id,
                        addr = %addr,
                        error = %e,
                        "Gateway health check failed, marking idle"
                    );
                    state.wake_manager.mark_idle(&route.tenant_id).await;
                } else {
                    debug!(
                        tenant = %route.tenant_id,
                        addr = %addr,
                        "Gateway health check passed"
                    );
                }
            }
        }
    }
}

/// Check if a gateway is still alive by attempting a TCP connection.
///
/// This is a simple L4 probe — connect to the gateway's service port and
/// immediately close. If the connect succeeds, the gateway is alive.
async fn check_gateway_alive(addr: SocketAddr) -> Result<()> {
    let timeout = Duration::from_secs(5);
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("Health check timed out for {}", addr))?
        .with_context(|| format!("Health check connection failed for {}", addr))?;
    Ok(())
}

/// After a wake operation completes, wait until the gateway is actually ready
/// to accept connections by probing its service port.
///
/// Returns once the probe succeeds or the timeout expires.
pub async fn wait_for_readiness(addr: SocketAddr, timeout_secs: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let probe_interval = Duration::from_millis(200);

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Gateway at {} did not become ready within {}s",
                addr,
                timeout_secs
            );
        }

        match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                info!(addr = %addr, "Gateway is ready to accept connections");
                return Ok(());
            }
            _ => {
                debug!(addr = %addr, "Gateway not ready yet, retrying...");
                tokio::time::sleep(probe_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::net::TcpListener;

    async fn bind_or_skip(addr: &str) -> Option<TcpListener> {
        match TcpListener::bind(addr).await {
            Ok(l) => Some(l),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                // Running in a sandbox without socket permissions; skip test.
                eprintln!("skipping test: PermissionDenied binding to {}", addr);
                None
            }
            Err(e) => panic!("failed to bind {}: {}", addr, e),
        }
    }

    #[tokio::test]
    async fn test_check_gateway_alive_success() {
        let Some(listener) = bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let addr = listener.local_addr().unwrap();

        // Accept in background so the connect succeeds
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = check_gateway_alive(addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_gateway_alive_failure() {
        // Use a port that's definitely not listening
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = check_gateway_alive(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wait_for_readiness_success() {
        let Some(listener) = bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let addr = listener.local_addr().unwrap();

        // Accept connections in background
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let result = wait_for_readiness(addr, 5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_readiness_timeout() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = wait_for_readiness(addr, 1).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("did not become ready"));
    }
}
