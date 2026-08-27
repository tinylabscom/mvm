#![deny(unsafe_code)]
// mvm-core: Pure types, IDs, config, utilities
// Depends only on the smaller canonical volume-contract leaf plus the
// no_std protocol foundation; it does not depend on a runtime or provider.
// `deny` (not `forbid`) so `util::test_env` can carry the one narrow
// unsafe carve-out for process-wide env mutation in tests.

/// Content-addressed build-action cache records: a typed identity for one
/// cached action's output artifacts, and a verify-on-read helper that
/// recomputes each artifact's digest before a cache entry is trusted.
pub mod action;
/// SCITT-compatible action state capsules with hash chaining and evidence binding.
pub mod action_state;
pub mod arch;
pub mod at_rest;
pub mod build_env;
pub mod catalog;
pub mod checkpoint;
pub mod runtime_catalog;
// The `MvmClient` machine-driving facade (trait + DTOs + mock + remote gateway).
// Off by default so the runtime-free closure never pulls `async-trait`; enabled
// by `mvm-client` (which adds the in-process `LocalBackend`) and by `mvm-sdk`'s
// `client-facade`.
#[cfg(feature = "client")]
pub mod client;
pub mod config;
pub mod conformance_badge;
/// Per-VM CPU bounds through a transient systemd scope on the user's own
/// manager — the one mechanism that both places an unprivileged process under a
/// cgroup v2 `cpu.max` quota and reports back what is actually in effect. Lives
/// here, beside the [`vm_backend::VmBackend`] trait it serves, so the backend
/// crates that spawn per-VM processes can reach it.
pub mod cpu_scope;
pub mod dev_network;
pub mod did_key;
/// The single `sha256:<64 lowercase hex>` shape check every prefixed
/// content-address newtype in this crate shares (crate-private).
pub(crate) mod digest_shape;
/// Real on-disk footprint of a path — the one measurement behind every
/// "how much would this reclaim" counter in the CLI.
pub mod disk_usage;
/// Host egress-broker decision logic (closed-by-default allow/deny per request).
pub mod egress_broker;
/// Egress-broker handler: compose decision + trace into an audit record.
pub mod egress_handler;
/// Host-side egress secret substitution (destination-bound; closed by default).
/// Secrets are substituted into outbound requests host-side and never enter the
/// guest.
pub mod exit_capture;
pub mod extension_admission;
/// Per-dimension resolution of a workload's grants across the CLI, a JSON
/// grants file, the project manifest, and the operator's host config.
pub mod grants_resolve;
/// Shared guest loopback-egress helpers (proxy env-var injection for cooperative apps).
pub mod guest_netd;
/// Pure health-state reducer: fold probe results into a health state and
/// decide restart/give-up actions. No I/O.
pub mod health;
pub mod icmp_wire;
/// Content-addressed image version-lineage nodes (the image analog of
/// [`checkpoint`]). Provenance metadata, never authorization.
pub mod image_lineage;
/// Ingress secret redaction (mask known secret values before they reach the guest).
pub mod ingress_redaction;
/// `mvm-init` supervisor core logic: metadata → exec spec, marker progression.
pub mod init_supervisor;
pub mod kernel_advisory;
pub mod kernel_artifact;
pub mod kernel_format;
/// Flat launch-metadata parsers for `mvm-init` (no JSON in PID 1).
pub mod launch_metadata;
/// Backend-recorded launch phases, so a caller can see inside `start`.
pub mod launch_trace;
/// Shared backoff for polls that wait on a condition.
pub mod poll_backoff;
pub mod vcpu_quota;
// Guest lifecycle markers + snapshot timing (the `mvm-init` ↔ host
// contract) are a pure-DTO leaf that now lives in `mvm-contract`;
// re-exported here as a module alias so every existing
// `crate::lifecycle::X` path keeps resolving unchanged.
pub use mvm_contract::lifecycle;
/// Resident-memory accounting for warm pools (learned charge + admission).
pub mod memory_budget;
pub mod metering;
pub mod migration;
pub mod naming;
pub mod net;
pub mod observability;
pub mod pack_cache;
pub mod pack_revocation;
pub mod pack_trust;
pub mod packs;
/// Same-page-merge confinement policy: whether two guest-memory merge
/// candidates (tenant + sealed image + fork family) may be host-wide
/// same-page merged. Pure decision only, fails closed to `Refuse`; no
/// kernel/`madvise` enforcement lives here.
pub mod page_merge;
pub mod pii;
/// Compiled-in release-signing identity: the OIDC issuer and identity
/// templates a stock binary trusts for its own release packs, with
/// version interpolation.
pub mod release_trust;
/// UOR-ADDR-compatible canonical content identity for the Workload IR,
/// distinct from every exact-byte, trust, and replay identity type.
pub mod workload_address;
pub use workload_address::{
    WorkloadAddress, WorkloadAddressError, WorkloadAddressParseError, workload_address,
};
pub mod user_config;

/// Test-only drift-lock proving `mvm_contract::ir::canonicalize` and
/// `serde_jcs` emit byte-identical canonical form for the same workload.
#[cfg(test)]
mod canonicalizer_equivalence;

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
#[cfg(feature = "provenance")]
pub mod provenance;
pub mod rate_limit;
pub mod receipt;
/// The signed index of an evidence archive: manifest, citations, and the
/// checked-versus-asserted completeness distinction.
pub mod receipt_archive;
pub mod residency;
/// What a caller declared a machine should boot from — the one type both the
/// declaration boundary and the build side name.
pub mod rootfs_source;
/// Hardened snapshot frame v0: cap-bounded, fail-closed parsing of the
/// snapshot container mvm controls (eager-CoW / raw-hypervisor path).
pub mod snapshot_frame;
/// Shared SOCKS5 UDP datagram wire codec for the guest proxy and host relay.
pub mod socks5_udp;
/// Read side of the workload stream plane: the consumer trait, its filters,
/// and the framed transport to a VM's host-side broker. Lives here rather
/// than in `mvm-client` so `mvm-sdk` — which sits below `mvm-hostd`, which
/// `mvm-client` depends on — can expose the same reader without a cycle.
pub mod stream_client;
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
pub use policy::{audit, network_policy, security};
pub use protocol::{routing, signing, vm_backend};
pub use util::{atomic_io, idle_metrics, retry, time};
