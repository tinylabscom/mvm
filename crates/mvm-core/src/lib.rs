// mvm-core: Pure types, IDs, config, utilities
// No internal mvm dependencies — this is the foundation crate.

pub mod build_env;
pub mod catalog;
pub mod config;
pub mod dev_network;
pub mod migration;
pub mod naming;
pub mod observability;
pub mod user_config;

pub mod domain;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod util;

// ----------------------------------------------------------------------------
// Legacy flat re-exports — preserve `mvm_core::tenant::*`, `mvm_core::audit::*`,
// etc. paths so downstream crates don't need to migrate. New code should
// prefer the canonical `mvm_core::<group>::<module>::*` paths.
//
// Note: for groups where the inner module shares the group name (platform,
// protocol, util), the inner content is flattened up to the group level via
// `pub use self::platform::*;` inside the group's `mod.rs` — so callers
// like `mvm_core::platform::current()` and `mvm_core::util::parse_human_size()`
// continue to resolve.
// ----------------------------------------------------------------------------

pub use domain::{agent, instance, node, pool, template, tenant};
pub use platform::linux_env;
pub use policy::{audit, network_policy, secret_binding, security};
pub use protocol::{routing, signing, vm_backend};
pub use util::{atomic_io, idle_metrics, retry, time};
