// mvm-coordinator: Gateway load-balancer, TCP proxy, wake manager
// Depends on mvm-core (types) and mvm-runtime (cert loading)

pub mod client;
pub mod config;
pub mod health;
pub mod idle;
pub mod proxy;
pub mod routing;
pub mod server;
pub mod state;
pub mod wake;
