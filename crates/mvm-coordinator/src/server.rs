use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::config::CoordinatorConfig;
use super::idle::IdleTracker;
use super::routing::RouteTable;
use super::wake::WakeManager;

/// Shared state accessible by all connection handlers.
pub struct CoordinatorState {
    pub config: CoordinatorConfig,
    pub route_table: RouteTable,
    pub wake_manager: WakeManager,
    pub idle_tracker: IdleTracker,
}

use super::routing::ResolvedRoute;
/// Run the coordinator server.
///
/// Binds TCP listeners for each route, accepts connections, and dispatches
/// them through the wake manager and proxy pipeline. Also runs background
/// health check and idle sweep tasks.
use super::state::{MemStateStore, StateStore};

// ...

pub async fn serve(config: CoordinatorConfig) -> Result<()> {
    // Default to in-memory store for now.
    // TODO: Add config support for EtcdStateStore.
    let store: Arc<dyn StateStore> = Arc::new(MemStateStore::new());

    // Bootstrap routes from config into the store
    for route in &config.routes {
        let resolved = ResolvedRoute {
            tenant_id: route.tenant_id.clone(),
            pool_id: route.pool_id.clone(),
            node: route.node,
            idle_timeout_secs: route.idle_timeout(&config.coordinator),
        };
        store.set_route(&route.listen, &resolved).await?;
    }

    let route_table = RouteTable::new(store.clone());
    let wake_manager = WakeManager::new(store.clone(), &config);
    let idle_tracker = IdleTracker::new();

    info!(
        routes = route_table.listen_addrs().await.len(),
        "Coordinator starting"
    );

    let state = Arc::new(CoordinatorState {
        config: config.clone(),
        route_table,
        wake_manager,
        idle_tracker,
    });

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn background health check loop
    let health_state = Arc::clone(&state);
    tokio::spawn(async move {
        super::health::health_check_loop(health_state).await;
    });

    // Spawn background idle sweep loop
    let idle_state = Arc::clone(&state);
    tokio::spawn(async move {
        idle_sweep_loop(idle_state).await;
    });

    // Spawn a TCP listener for each route
    let mut listener_handles = Vec::new();
    let listen_addrs = state.route_table.listen_addrs().await;

    for addr in &listen_addrs {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind TCP listener on {}", addr))?;
        info!(listen = %addr, "Listening for connections");

        let state = Arc::clone(&state);
        let bound_addr = *addr;
        let mut shutdown = shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer)) => {
                                let state = Arc::clone(&state);
                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(
                                        stream, peer, bound_addr, &state
                                    ).await {
                                        warn!(
                                            peer = %peer,
                                            error = %e,
                                            "Connection handler error"
                                        );
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "Accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        info!(listen = %bound_addr, "Listener shutting down");
                        break;
                    }
                }
            }
        });
        listener_handles.push(handle);
    }

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .with_context(|| "Failed to listen for ctrl-c")?;

    info!("Shutdown signal received, stopping listeners...");
    let _ = shutdown_tx.send(true);

    for handle in listener_handles {
        let _ = handle.await;
    }

    info!("Coordinator stopped");
    Ok(())
}

/// Handle a single inbound TCP connection.
///
/// 1. Look up the route by the listener address
/// 2. Track the connection in the idle tracker
/// 3. Check/wake the gateway via WakeManager
/// 4. Proxy the connection to the gateway VM
/// 5. Untrack the connection when done
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    listen_addr: SocketAddr,
    state: &CoordinatorState,
) -> Result<()> {
    let route = state
        .route_table
        .lookup(&listen_addr)
        .await
        .ok_or_else(|| anyhow::anyhow!("No route for listen address {}", listen_addr))?;

    info!(
        peer = %peer,
        tenant = %route.tenant_id,
        pool = %route.pool_id,
        "Inbound connection"
    );

    // Track connection for idle detection
    state.idle_tracker.connection_opened(&route.tenant_id).await;

    // Wake gateway if needed, get its address
    let result = async {
        let gateway_addr = state
            .wake_manager
            .ensure_running(&route, &state.config)
            .await?;

        // Proxy connection
        super::proxy::proxy_connection(stream, gateway_addr, &route.tenant_id).await
    }
    .await;

    // Always untrack the connection, even on error
    state.idle_tracker.connection_closed(&route.tenant_id).await;

    result
}

/// Periodically sweep for idle tenants and sleep their gateways.
async fn idle_sweep_loop(state: Arc<CoordinatorState>) {
    let interval =
        tokio::time::Duration::from_secs(state.config.coordinator.idle_timeout_secs.min(30));

    loop {
        tokio::time::sleep(interval).await;

        let routes = state.route_table.routes().await;
        for (_, route) in routes {
            let idle_tenants = state
                .idle_tracker
                .idle_tenants(route.idle_timeout_secs)
                .await;

            for tenant_id in &idle_tenants {
                if *tenant_id != route.tenant_id {
                    continue;
                }

                let current = state.wake_manager.gateway_state(tenant_id).await;
                if let super::wake::GatewayState::Running { .. } = current {
                    info!(
                        tenant = %tenant_id,
                        timeout_secs = route.idle_timeout_secs,
                        "Tenant idle, marking gateway for sleep"
                    );
                    state.wake_manager.mark_idle(tenant_id).await;
                    state.idle_tracker.reset(tenant_id).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CoordinatorState>();
    }
}
