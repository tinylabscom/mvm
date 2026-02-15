use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Resolved route for a tenant's gateway pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedRoute {
    pub tenant_id: String,
    pub pool_id: String,
    pub node: SocketAddr,
    pub idle_timeout_secs: u64,
}

use crate::state::StateStore;
/// Lookup table: listen address -> tenant route.
///
/// In port-based mode, each tenant gets its own listen port. The coordinator
/// runs one TCP listener per route and uses the listener's address to determine
/// which tenant the connection belongs to.
use std::sync::Arc;

/// Lookup table: listen address -> tenant route.
///
/// Wraps the async StateStore to provide route lookups.
#[derive(Clone)]
pub struct RouteTable {
    store: Arc<dyn StateStore>,
}

impl RouteTable {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// Look up a route by the listen address.
    pub async fn lookup(&self, listen_addr: &SocketAddr) -> Option<ResolvedRoute> {
        self.store.get_route(listen_addr).await.ok().flatten()
    }

    /// List all unique listen addresses.
    pub async fn listen_addrs(&self) -> Vec<SocketAddr> {
        match self.store.list_routes().await {
            Ok(routes) => routes.into_iter().map(|(k, _)| k).collect(),
            Err(_) => vec![],
        }
    }

    /// List all routes.
    pub async fn routes(&self) -> Vec<(SocketAddr, ResolvedRoute)> {
        self.store.list_routes().await.unwrap_or_default()
    }

    /// Check if table is empty.
    pub async fn is_empty(&self) -> bool {
        self.listen_addrs().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CoordinatorConfig;
    use crate::state::{MemStateStore, StateStore};

    fn test_config() -> CoordinatorConfig {
        let toml = r#"
[coordinator]
idle_timeout_secs = 300

[[nodes]]
address = "127.0.0.1:4433"
name = "node-1"

[[routes]]
tenant_id = "alice"
pool_id = "gateways"
listen = "0.0.0.0:8443"
node = "127.0.0.1:4433"

[[routes]]
tenant_id = "bob"
pool_id = "gateways"
listen = "0.0.0.0:8444"
node = "127.0.0.1:4433"
idle_timeout_secs = 600
"#;
        CoordinatorConfig::parse(toml).unwrap()
    }

    async fn create_table(config: &CoordinatorConfig) -> RouteTable {
        let store = Arc::new(MemStateStore::new());
        for route in &config.routes {
            let resolved = ResolvedRoute {
                tenant_id: route.tenant_id.clone(),
                pool_id: route.pool_id.clone(),
                node: route.node,
                idle_timeout_secs: route.idle_timeout(&config.coordinator),
            };
            store.set_route(&route.listen, &resolved).await.unwrap();
        }
        RouteTable::new(store)
    }

    #[tokio::test]
    async fn test_route_table_len() {
        let config = test_config();
        let table = create_table(&config).await;
        assert_eq!(table.listen_addrs().await.len(), 2);
    }

    #[tokio::test]
    async fn test_lookup_by_listen_addr() {
        let config = test_config();
        let table = create_table(&config).await;

        let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let route = table.lookup(&addr).await.unwrap();
        assert_eq!(route.tenant_id, "alice");
        assert_eq!(route.pool_id, "gateways");
        assert_eq!(route.idle_timeout_secs, 300); // global default
    }

    #[tokio::test]
    async fn test_lookup_with_override() {
        let config = test_config();
        let table = create_table(&config).await;

        let addr: SocketAddr = "0.0.0.0:8444".parse().unwrap();
        let route = table.lookup(&addr).await.unwrap();
        assert_eq!(route.tenant_id, "bob");
        assert_eq!(route.idle_timeout_secs, 600); // per-route override
    }

    #[tokio::test]
    async fn test_lookup_missing() {
        let config = test_config();
        let table = create_table(&config).await;

        let addr: SocketAddr = "0.0.0.0:9999".parse().unwrap();
        assert!(table.lookup(&addr).await.is_none());
    }

    #[tokio::test]
    async fn test_listen_addrs() {
        let config = test_config();
        let table = create_table(&config).await;

        let mut addrs = table.listen_addrs().await;
        addrs.sort();
        assert_eq!(addrs.len(), 2);
    }
}
