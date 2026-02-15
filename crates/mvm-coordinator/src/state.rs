use std::collections::HashMap;
use std::net::SocketAddr;
// Arc not needed in current implementation; keep imports minimal.

use anyhow::{Context, Result};
use async_trait::async_trait;
use etcd_client::{Client, GetOptions};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;

use crate::routing::ResolvedRoute;
use crate::wake::GatewayState;

/// Abstract interface for coordinator state storage.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Get a route by its listen address.
    async fn get_route(&self, listen_addr: &SocketAddr) -> Result<Option<ResolvedRoute>>;

    /// Set a route.
    async fn set_route(&self, listen_addr: &SocketAddr, route: &ResolvedRoute) -> Result<()>;

    /// List all routes.
    async fn list_routes(&self) -> Result<Vec<(SocketAddr, ResolvedRoute)>>;

    /// Get the current gateway state for a tenant.
    async fn get_gateway_state(&self, tenant_id: &str) -> Result<Option<GatewayState>>;

    /// Set the gateway state for a tenant.
    async fn set_gateway_state(&self, tenant_id: &str, state: &GatewayState) -> Result<()>;
}

// ============================================================================
// In-Memory Implementation (Legacy / Dev / Test)
// ============================================================================

pub struct MemStateStore {
    routes: RwLock<HashMap<SocketAddr, ResolvedRoute>>,
    gateways: RwLock<HashMap<String, GatewayState>>,
}

impl MemStateStore {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            gateways: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StateStore for MemStateStore {
    async fn get_route(&self, listen_addr: &SocketAddr) -> Result<Option<ResolvedRoute>> {
        let routes = self.routes.read().await;
        Ok(routes.get(listen_addr).cloned())
    }

    async fn set_route(&self, listen_addr: &SocketAddr, route: &ResolvedRoute) -> Result<()> {
        let mut routes = self.routes.write().await;
        routes.insert(*listen_addr, route.clone());
        Ok(())
    }

    async fn list_routes(&self) -> Result<Vec<(SocketAddr, ResolvedRoute)>> {
        let routes = self.routes.read().await;
        Ok(routes.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    async fn get_gateway_state(&self, tenant_id: &str) -> Result<Option<GatewayState>> {
        let gateways = self.gateways.read().await;
        Ok(gateways.get(tenant_id).cloned())
    }

    async fn set_gateway_state(&self, tenant_id: &str, state: &GatewayState) -> Result<()> {
        let mut gateways = self.gateways.write().await;
        gateways.insert(tenant_id.to_string(), state.clone());
        Ok(())
    }
}

// ============================================================================
// Etcd Implementation (Distributed)
// ============================================================================

pub struct EtcdStateStore {
    client: Client,
    prefix: String,
}

impl EtcdStateStore {
    pub async fn connect(endpoints: &[String], prefix: &str) -> Result<Self> {
        let client = Client::connect(endpoints, None)
            .await
            .with_context(|| format!("Failed to connect to etcd endpoints: {:?}", endpoints))?;
        Ok(Self {
            client,
            prefix: prefix.trim_end_matches('/').to_string(),
        })
    }

    fn key_route(&self, addr: &SocketAddr) -> String {
        format!("{}/routes/{}", self.prefix, addr)
    }

    fn key_gateway(&self, tenant_id: &str) -> String {
        format!("{}/gateways/{}", self.prefix, tenant_id)
    }

    async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut client = self.client.clone();
        let resp = client.get(key, None).await?;
        if let Some(kv) = resp.kvs().first() {
            let val = serde_json::from_slice(kv.value())
                .with_context(|| format!("Failed to deserialize value for key {}", key))?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    async fn put_json<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let mut client = self.client.clone();
        let json = serde_json::to_vec(value)?;
        client.put(key, json, None).await?;
        Ok(())
    }
}

#[async_trait]
impl StateStore for EtcdStateStore {
    async fn get_route(&self, listen_addr: &SocketAddr) -> Result<Option<ResolvedRoute>> {
        self.get_json(&self.key_route(listen_addr)).await
    }

    async fn set_route(&self, listen_addr: &SocketAddr, route: &ResolvedRoute) -> Result<()> {
        self.put_json(&self.key_route(listen_addr), route).await
    }

    async fn list_routes(&self) -> Result<Vec<(SocketAddr, ResolvedRoute)>> {
        let mut client = self.client.clone();
        let prefix = format!("{}/routes/", self.prefix);
        let resp = client
            .get(prefix.as_str(), Some(GetOptions::new().with_prefix()))
            .await?;

        let mut routes = Vec::new();
        for kv in resp.kvs() {
            let key_str = kv.key_str()?;
            // Key format: prefix/IP:PORT
            if let Some(addr_str) = key_str.strip_prefix(&prefix)
                && let Ok(addr) = addr_str.parse::<SocketAddr>()
            {
                match serde_json::from_slice::<ResolvedRoute>(kv.value()) {
                    Ok(route) => routes.push((addr, route)),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize route at {}: {}", key_str, e);
                    }
                }
            }
        }
        Ok(routes)
    }

    async fn get_gateway_state(&self, tenant_id: &str) -> Result<Option<GatewayState>> {
        self.get_json(&self.key_gateway(tenant_id)).await
    }

    async fn set_gateway_state(&self, tenant_id: &str, state: &GatewayState) -> Result<()> {
        self.put_json(&self.key_gateway(tenant_id), state).await
    }
}
