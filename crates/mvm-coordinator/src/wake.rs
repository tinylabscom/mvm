use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, watch};
use tracing::info;

use super::config::CoordinatorConfig;
use super::routing::ResolvedRoute;
use crate::client::CoordinatorClient;
use mvm_core::agent::{AgentRequest, AgentResponse};
use mvm_core::instance::InstanceStatus;

use serde::{Deserialize, Serialize};

/// Per-tenant gateway state as seen by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayState {
    /// Gateway is running and ready to accept connections.
    Running {
        /// The gateway VM's guest IP + service port for TCP proxying.
        addr: SocketAddr,
    },
    /// A wake operation is in progress. Waiters subscribe to the channel.
    Waking,
    /// Gateway is warm (snapshot ready) or status unknown. Needs wake.
    Idle,
}

use crate::state::StateStore;

type WakeResult = Option<Result<SocketAddr, String>>;
type WakeReceiver = watch::Receiver<WakeResult>;

/// Manages on-demand gateway wake/sleep lifecycle across tenants.
pub struct WakeManager {
    store: Arc<dyn StateStore>,
    /// Local inflight wakes (for coalescing requests on this node).
    /// Maps tenant_id -> notification channel.
    local_inflight: Arc<Mutex<HashMap<String, WakeReceiver>>>,
    gateway_service_port: u16,
}

impl WakeManager {
    pub fn new(store: Arc<dyn StateStore>, _config: &CoordinatorConfig) -> Self {
        Self {
            store,
            local_inflight: Arc::new(Mutex::new(HashMap::new())),
            gateway_service_port: 8080,
        }
    }

    /// Ensure the gateway for this route is running. Returns the gateway's
    /// address for TCP proxying.
    pub async fn ensure_running(
        &self,
        route: &ResolvedRoute,
        config: &CoordinatorConfig,
    ) -> Result<SocketAddr> {
        let tenant_id = &route.tenant_id;

        // 1. Check persistent state
        if let Some(GatewayState::Running { addr }) =
            self.store.get_gateway_state(tenant_id).await?
        {
            return Ok(addr);
        }

        // 2. Check local inflight (coalescing)
        let rx = {
            let mut inflight = self.local_inflight.lock().await;

            // Clean up closed channels (optional optimization)
            // inflight.retain(|_, rx| rx.has_changed().is_ok());

            if let Some(rx) = inflight.get(tenant_id) {
                rx.clone()
            } else {
                // 3. Initiate new wake
                // Mark as waking in store
                self.store
                    .set_gateway_state(tenant_id, &GatewayState::Waking)
                    .await?;

                let (tx, rx) = watch::channel(None);
                inflight.insert(tenant_id.clone(), rx.clone());

                let tenant_id = tenant_id.clone();
                let route = route.clone();
                let wake_timeout = config.coordinator.wake_timeout_secs;
                let service_port = self.gateway_service_port;
                let store = Arc::clone(&self.store);
                let inflight_map = Arc::clone(&self.local_inflight);

                tokio::spawn(async move {
                    let result = do_wake(&route, wake_timeout, service_port).await;

                    // Update store
                    match &result {
                        Ok(addr) => {
                            let _ = store
                                .set_gateway_state(
                                    &tenant_id,
                                    &GatewayState::Running { addr: *addr },
                                )
                                .await;
                        }
                        Err(_) => {
                            let _ = store
                                .set_gateway_state(&tenant_id, &GatewayState::Idle)
                                .await;
                        }
                    }

                    // Notify waiters
                    let _ = tx.send(Some(result.map_err(|e| e.to_string())));

                    // Cleanup local inflight
                    let mut map = inflight_map.lock().await;
                    map.remove(&tenant_id);
                });

                rx
            }
        };

        // 4. Wait for result
        wait_for_wake(rx, config.coordinator.wake_timeout_secs).await
    }

    /// Mark a tenant's gateway as idle (e.g., after sleep).
    pub async fn mark_idle(&self, tenant_id: &str) {
        let _ = self
            .store
            .set_gateway_state(tenant_id, &GatewayState::Idle)
            .await;
    }

    /// Mark a tenant's gateway as running with a known address.
    pub async fn mark_running(&self, tenant_id: &str, addr: SocketAddr) {
        let _ = self
            .store
            .set_gateway_state(tenant_id, &GatewayState::Running { addr })
            .await;
    }

    /// Get the current state of a tenant's gateway.
    pub async fn gateway_state(&self, tenant_id: &str) -> GatewayState {
        self.store
            .get_gateway_state(tenant_id)
            .await
            .unwrap_or(None)
            .unwrap_or(GatewayState::Idle)
    }
}

/// Wait for a wake operation to complete (either ours or someone else's).
async fn wait_for_wake(mut rx: WakeReceiver, timeout_secs: u64) -> Result<SocketAddr> {
    let deadline = tokio::time::Duration::from_secs(timeout_secs);
    match tokio::time::timeout(deadline, async {
        loop {
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!("Wake channel closed unexpectedly"))?;
            let val = rx.borrow().clone();
            if let Some(result) = val {
                return result.map_err(|e| anyhow::anyhow!("Wake failed: {}", e));
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => anyhow::bail!("Gateway wake timed out after {}s", timeout_secs),
    }
}

/// Execute the actual wake sequence: send WakeInstance to agent, poll until
/// the gateway instance is Running, return its address.
async fn do_wake(
    route: &ResolvedRoute,
    timeout_secs: u64,
    service_port: u16,
) -> Result<SocketAddr> {
    info!(
        tenant = %route.tenant_id,
        pool = %route.pool_id,
        node = %route.node,
        "Waking gateway"
    );

    let client =
        CoordinatorClient::new().with_context(|| "Failed to create QUIC client for wake")?;

    // First, find the gateway instance to wake by listing instances
    let response = client
        .send(
            route.node,
            &AgentRequest::InstanceList {
                tenant_id: route.tenant_id.clone(),
                pool_id: Some(route.pool_id.clone()),
            },
        )
        .await
        .with_context(|| "Failed to query instances for wake")?;

    let instances = match response {
        AgentResponse::InstanceList(list) => list,
        AgentResponse::Error { code, message } => {
            anyhow::bail!("Agent error ({}): {}", code, message);
        }
        _ => anyhow::bail!("Unexpected response from agent"),
    };

    // Find a warm or sleeping instance to wake
    let target = instances
        .iter()
        .find(|i| i.status == InstanceStatus::Warm || i.status == InstanceStatus::Sleeping)
        .or_else(|| {
            instances
                .iter()
                .find(|i| i.status == InstanceStatus::Stopped)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No wakeable instance found for {}/{}",
                route.tenant_id,
                route.pool_id
            )
        })?;

    let instance_id = &target.instance_id;
    let guest_ip = &target.net.guest_ip;

    info!(
        instance = %instance_id,
        guest_ip = %guest_ip,
        "Sending WakeInstance"
    );

    // Send wake request
    let wake_response = client
        .send(
            route.node,
            &AgentRequest::WakeInstance {
                tenant_id: route.tenant_id.clone(),
                pool_id: route.pool_id.clone(),
                instance_id: instance_id.clone(),
            },
        )
        .await
        .with_context(|| format!("Failed to wake instance {}", instance_id))?;

    match wake_response {
        AgentResponse::WakeResult { success } if success => {
            info!(instance = %instance_id, "Wake acknowledged");
        }
        AgentResponse::WakeResult { success: false } => {
            anyhow::bail!("Agent refused to wake instance {}", instance_id);
        }
        AgentResponse::Error { code, message } => {
            anyhow::bail!("Wake error ({}): {}", code, message);
        }
        _ => anyhow::bail!("Unexpected wake response"),
    }

    // Poll until the instance is Running
    let poll_interval = tokio::time::Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Gateway instance {} did not become Running within {}s",
                instance_id,
                timeout_secs
            );
        }

        tokio::time::sleep(poll_interval).await;

        let status_response = client
            .send(
                route.node,
                &AgentRequest::InstanceList {
                    tenant_id: route.tenant_id.clone(),
                    pool_id: Some(route.pool_id.clone()),
                },
            )
            .await;

        if let Ok(AgentResponse::InstanceList(list)) = status_response
            && let Some(inst) = list.iter().find(|i| i.instance_id == *instance_id)
            && inst.status == InstanceStatus::Running
        {
            let addr: SocketAddr = format!("{}:{}", guest_ip, service_port)
                .parse()
                .with_context(|| {
                    format!("Invalid gateway address: {}:{}", guest_ip, service_port)
                })?;
            info!(
                instance = %instance_id,
                addr = %addr,
                "Gateway is Running"
            );
            return Ok(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MemStateStore;

    fn test_config() -> CoordinatorConfig {
        CoordinatorConfig::parse(
            r#"
[coordinator]
wake_timeout_secs = 5

[[routes]]
tenant_id = "alice"
pool_id = "gateways"
listen = "0.0.0.0:8443"
node = "127.0.0.1:4433"
"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_gateway_state_default_is_idle() {
        let config = test_config();
        let store = Arc::new(MemStateStore::new());
        let wm = WakeManager::new(store, &config);
        match wm.gateway_state("alice").await {
            GatewayState::Idle => {}
            _ => panic!("Expected Idle"),
        }
    }

    #[tokio::test]
    async fn test_mark_running() {
        let config = test_config();
        let store = Arc::new(MemStateStore::new());
        let wm = WakeManager::new(store, &config);
        let addr: SocketAddr = "10.240.1.5:8080".parse().unwrap();
        wm.mark_running("alice", addr).await;

        match wm.gateway_state("alice").await {
            GatewayState::Running { addr: a } => assert_eq!(a, addr),
            _ => panic!("Expected Running"),
        }
    }

    #[tokio::test]
    async fn test_mark_idle() {
        let config = test_config();
        let store = Arc::new(MemStateStore::new());
        let wm = WakeManager::new(store, &config);
        let addr: SocketAddr = "10.240.1.5:8080".parse().unwrap();
        wm.mark_running("alice", addr).await;
        wm.mark_idle("alice").await;

        match wm.gateway_state("alice").await {
            GatewayState::Idle => {}
            _ => panic!("Expected Idle"),
        }
    }

    #[tokio::test]
    async fn test_ensure_running_fast_path() {
        let config = test_config();
        let store = Arc::new(MemStateStore::new());
        let wm = WakeManager::new(store, &config);
        let addr: SocketAddr = "10.240.1.5:8080".parse().unwrap();
        wm.mark_running("alice", addr).await;

        let route = ResolvedRoute {
            tenant_id: "alice".to_string(),
            pool_id: "gateways".to_string(),
            node: "127.0.0.1:4433".parse().unwrap(),
            idle_timeout_secs: 300,
        };

        let result = wm.ensure_running(&route, &config).await.unwrap();
        assert_eq!(result, addr);
    }
}
