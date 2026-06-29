// mvm-core: Pure types, IDs, config, utilities
// No internal mvm dependencies — this is the foundation crate.

pub mod arch;
pub mod build_env;
pub mod catalog;
pub mod checkpoint;
pub mod config;
pub mod dev_network;
/// Host egress-broker decision logic (closed-by-default allow/deny per request).
pub mod egress_broker;
/// Egress-broker handler: compose decision + trace into an audit record.
pub mod egress_handler;
pub mod entrypoint_policy;
pub mod exit_capture;
/// Guest `mvm-netd` helpers (proxy env-var injection for cooperative apps).
pub mod guest_netd;
/// Host ingress-broker decision logic (host listener only by explicit policy).
pub mod ingress_broker;
/// `mvm-init` supervisor core logic: metadata → exec spec, marker progression.
pub mod init_supervisor;
pub mod kernel_advisory;
pub mod kernel_artifact;
pub mod kernel_format;
/// Flat launch-metadata parsers for `mvm-init` (no JSON in PID 1).
pub mod launch_metadata;
/// Guest lifecycle markers + snapshot timing (the `mvm-init` ↔ host contract).
pub mod lifecycle;
/// Resident-memory accounting for warm pools (learned charge + admission).
pub mod memory_budget;
pub mod metering;
pub mod migration;
pub mod naming;
pub mod observability;
pub mod packs;
pub mod user_config;

/// Cryptographic primitives — attestation, key rotation, keystore,
/// secret store, snapshot encryption/HMAC, image (cosign) verification,
/// seccomp, fs/mount/path/ttl policy. Folded in from the former
/// `mvm-security` crate; named `crypto` to avoid clashing
/// with `policy::security` (the session-policy type). All sync; the
/// only opt-in async surface is the off-by-default `manifest-verify`
/// (sigstore) feature, so the default build stays runtime-free.
pub mod crypto;
pub mod domain;
pub mod mvmd_iface;
/// The typed, signed `ExecutionPlan` contract. Folded in from the
/// former `mvm-plan` crate; it depended only on `mvm-core`, so the
/// fold adds no async/runtime dep (just `tar`).
pub mod plan;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod residency;
/// Hardened snapshot frame v0: cap-bounded, fail-closed parsing of the
/// snapshot container mvm controls (eager-CoW / raw-hypervisor path).
pub mod snapshot_frame;
/// The guest↔host substitution-endpoint wire contract, shared so the
/// in-guest client and the host server serialize identical bytes.
pub mod substitution_wire;
/// W3C-shaped distributed trace context for end-to-end audit correlation.
pub mod trace_context;
pub mod transcript;
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

pub use domain::{agent, instance, manifest, node, pool, session, template, tenant, volume};
pub use platform::linux_env;
pub use policy::{audit, network_policy, secret_binding, security};
pub use protocol::{routing, signing, vm_backend};
pub use util::{atomic_io, idle_metrics, retry, time};
