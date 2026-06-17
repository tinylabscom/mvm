//! mvm-backend — concrete `VmBackend` implementations.
//!
//! This crate is no longer a re-export façade — every concrete backend
//! now lives here:
//!
//! - **Firecracker** (`backend::FirecrackerBackend`) + the `AnyBackend`
//!   dispatch enum + `FirecrackerConfig` — the production Tier 1 path.
//! - **Vz** (`vz::VzBackend`) — the one Apple Virtualization.framework
//!   backend (per-VM Rust objc2 supervisor); macOS-26 auto-default.
//! - **libkrun** (`libkrun::LibkrunBackend`) — raw libkrun shim
//!   (Linux KVM / macOS HVF).
//!
//! Plus the FC support modules: `firecracker` (installer helpers),
//! `microvm` (lifecycle), `image` (Mvmfile.toml), `network` (TAP/
//! bridge wiring).
//!
//! ## Dependency direction
//!
//!   mvm-core              ← VmBackend trait + types
//!   base (module)         ← config + shell + linux_env + ui +
//!                           runtime_meta + cow (substrate, was mvm-base)
//!   providers (module)    ← libkrun/Apple-VZ FFI shims (was mvm-providers)
//!     ↓                     ↓                     ↓
//!     └─────── mvm-backend (this crate) ────────┘
//!                          ↑
//!                     mvm
//!                     (consumes us via `vm::backend::AnyBackend`)
//!                     mvm-cli
//!                     (consumes us directly)

pub mod artifacts;
pub mod audit_substrate;
pub mod backend;
pub mod catalog;
pub mod checkpoint;
pub mod codesign;
// Shared host-side substrate (config + shell + linux_env + ui +
// runtime_meta + cow + snapshot_integrity) — folded in from the
// former Lima-era `mvm-base` crate. It lives here, not in `mvm`,
// because `mvm-backend`'s concrete backends are its heaviest
// consumer and sit below `mvm`; folding it up into `mvm` would cycle
// (`mvm → mvm-backend → mvm`). `mvm` re-exports these at their old
// paths so the mvmd `mvmctl::runtime::{shell,ui,shell_mock}` contract
// surface keeps resolving.
pub mod base;
/// Per-VM broker-services (`mvm-broker` / `mvm-audit-signer`) subprocess
/// spawn/reap helpers, mirroring [`substitution_spawn`].
pub(crate) mod broker_services_spawn;
pub mod compat;
/// Per-VM transparent egress redirect (nft prerouting REDIRECT scoped
/// to the guest TAP) steering guest :80 to the host-side substitution
/// terminator. Linux-only mechanism; consumed by the FC path.
pub mod egress_redirect;
/// Cfg-free decode of the admitted plan's egress secret bindings, shared by
/// the libkrun + Firecracker substitution-endpoint spawn paths.
pub(crate) mod egress_shared;
pub mod firecracker;
pub mod handle_registry;
pub(crate) mod host_agent_spawn;
pub mod image;
pub mod libkrun;
pub mod microvm;
pub mod mock;
pub mod mock_guest_agent;
pub mod netinit_audit;
pub mod network;
/// `NetworkProvider` impl over the bridge+TAP path.
pub mod network_provider;
/// QEMU workload runtime backend (dev/test).
pub mod qemu;
/// Backend-agnostic supervisor standby pool registry (`~/.mvm/pool/`
/// state-dir; record/select-idle-by-kernel/remove/reap).
pub mod standby_pool;
/// Shared per-VM substitution-endpoint spawn/reap helpers used by the
/// QEMU + Firecracker launch paths (one impl, no drift).
pub(crate) mod substitution_spawn;
// Vz (Apple Virtualization.framework) backend. Currently a skeleton:
// trait surface + capabilities + security profile + availability
// probe; lifecycle methods land in a follow-up slice.
pub mod vz;
// Rust client for the Vz supervisor's control socket
// (PAUSE / RESUME / BALLOON / SAVE). Used by VzBackend.
pub mod vz_control;
/// `WorkloadBackend` marker trait — the type-level permission to carry an
/// untrusted workload. The admitted launch path accepts `&dyn WorkloadBackend`
/// only, so a non-workload backend (QEMU dev/test, mock) cannot reach it.
pub mod workload_backend;

pub use backend::{AnyBackend, FirecrackerBackend, FirecrackerConfig};
pub use libkrun::LibkrunBackend;
pub use mock::MockBackend;
pub use qemu::QemuBackend;
pub use vz::VzBackend;
pub use workload_backend::{EgressSubstitutionTransport, WorkloadBackend};

/// The per-VM egress-TLS cert/key split helper. `mvmctl up`
/// (mvm-cli) calls this while assembling the guest secrets drive: the cert is
/// pushed onto the drive, the key is persisted host-side for the terminator
/// endpoint. See [`substitution_spawn::build_egress_tls_delivery`].
pub use substitution_spawn::{
    EGRESS_CERT_DRIVE_NAME, EgressTlsDelivery, EndpointTransport, build_egress_tls_delivery,
};

/// Per-VM broker-services spawn/reap, called from the workload backends' launch
/// path (E5.3b-2 wiring). Exposed so the backends and tests share one impl.
pub use broker_services_spawn::{
    AuditSignerHandle, AuditSignerSpawnParams, BrokerHandle, BrokerServicesGuard,
    BrokerServicesSpawnParams, BrokerSpawnParams, reap_audit_signer, reap_broker,
    reap_broker_services, spawn_audit_signer, spawn_broker, spawn_broker_services_if_admitted,
};

/// Per-tenant host-agent daemon seam: register/deregister VMs with one
/// resident daemon instead of forking a per-VM broker. Exposed so the backend
/// start/stop paths (and tests) share one impl. Not yet wired into `start()` —
/// that lands behind a flag next.
pub use host_agent_spawn::{
    HostAgentServicesGuard, HostAgentServicesParams, ServicesGuard, deregister_vm,
    ensure_host_agent_daemon, host_agent_daemon_enabled, load_host_signing_key,
    reap_host_agent_services_from_state, register_host_agent_services_if_admitted, register_vm,
};

/// Crate-wide test serialization for tests that mutate `HOME` or
/// other process-global env vars. Re-exported from
/// [`crate::base::runtime_meta::HOME_TEST_LOCK`] so the
/// alt-backend tests share the same mutex with `mvm` tests
/// — without sharing one lock the modules race each other when
/// their tests run on the same `cargo test` binary.
///
/// Tests import from `mvm_base` directly; keep this note near the
/// module list so future process-global tests reuse the same lock.
#[cfg(any())]
pub(crate) use crate::base::runtime_meta::HOME_TEST_LOCK;
