//! Entity types — agents, instances, nodes, pools, sessions, tenants, templates, volumes.

pub mod agent;
pub mod instance;
// The `mvm.toml` workload manifest is authored and read on the host.
#[cfg(feature = "host-state")]
pub mod manifest;
pub mod node;
pub mod pool;
pub mod session;
pub mod template;
pub mod template_tags;
pub mod tenant;
pub mod volume;
