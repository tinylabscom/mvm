// mvm-runtime — VM lifecycle orchestration + concrete `VmBackend` implementations.
//
// The leaf substrate (`config`, `shell`, `linux_env`, `ui`, `runtime_meta`,
// `cow`) lives under `base` (folded in from the former Lima-era `mvm-base`
// crate). The `pub use base::*` re-exports below preserve the old
// `mvm::{config, shell, linux_env, ui, shell_mock}` paths so the mvmd
// contract surface (consumed via `mvmctl::runtime::*`) keeps resolving.
//
// Concrete `VmBackend` implementations:
//
// - **Firecracker** (`backend::FirecrackerBackend`) + the `AnyBackend`
//   dispatch enum — the production Tier 1 path.
// - **HVF** (`hvf_backend::HvfBackend`) — the in-house Hypervisor.framework
//   VMM; the macOS-26 workload default.
// - **libkrun** (`libkrun::LibkrunBackend`) — raw libkrun shim
//   (Linux KVM / macOS HVF).
//
// Plus the FC support modules: `firecracker` (installer helpers),
// `microvm` (control/lifecycle), and `image` (Mvmfile.toml); and the
// Machine product abstraction (`machine`) — the
// construction + capability-gate seam the CLI, mvmd, and the SDKs share.

pub mod build_env;
pub mod machine;
pub mod sdk_sidecar;
pub mod security;
pub mod storage;
pub mod vsock_transport;

pub mod vm;

pub mod apple_container;
pub mod apple_container_backend;
pub mod artifacts;
pub mod audit_substrate;
/// Shared resolve-or-build for the per-VM helper binaries `mvmctl` spawns
/// (supervisors + the substitution endpoint); one impl, no drift.
pub(crate) mod aux_bin;
pub mod backend;
pub mod base;
/// Per-VM broker-services (`mvm-broker` / `mvm-audit-signer`) subprocess
/// spawn/reap helpers, mirroring [`substitution_spawn`].
pub(crate) mod broker_services_spawn;
/// The builder role layer: boots a builder VM over the `VmmDriver` seam with the
/// disk-only job/artifact transport (trusted, no egress endpoint, no virtio-fs).
pub mod builder_runner;
pub mod catalog;
pub mod checkpoint;
pub mod codesign;
pub mod compat;
pub mod docker_backend;
pub mod driver;
/// Per-VM transparent egress redirect used by the legacy libkrun gateway path.
pub mod egress_redirect;
/// Cfg-free decode of the admitted plan's egress secret bindings, shared by
/// the libkrun + Firecracker substitution-endpoint spawn paths.
pub mod egress_shared;
pub mod firecracker;
pub mod handle_registry;
pub(crate) mod host_agent_spawn;
/// Raw HVF (`Hypervisor.framework`) backend spike — drives [`vmm`] on macOS /
/// Apple silicon. Links the system framework, so
/// it is cfg-gated off every other target.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod hvf;
/// `HvfBackend` — the `VmBackend` for the raw-HVF macOS path. Compiles
/// on every target (lifecycle = spawn the detached `mvm-hvf-supervisor` + track
/// PID files; only availability probing is macOS-specific), so it registers in
/// `AnyBackend`/the catalog without cfg-gymnastics.
pub mod hvf_backend;
pub(crate) mod hvf_bootargs;
pub mod image;
/// Content-addressed image version-lineage store + chain-anchored verification
/// (the image analog of [`checkpoint`]). Reuses the shared `lineage` walk.
pub mod image_lineage;
/// KVM (Linux) backend — drives [`vmm`] on Linux via `kvm-ioctls`, implementing
/// the [`vmm::hv`] seam. `kvm::x86_boot` is pure logic
/// (compiles + tests everywhere); the ioctl glue is Linux-only.
pub mod kvm;
pub mod libkrun;
/// Namespace-agnostic hash-linked lineage walk + read-only enumeration shared by
/// [`checkpoint`] and [`image_lineage`]. The walk traits stay crate-private (the
/// stores provide concrete wrappers); the enumeration result types
/// ([`lineage::Ancestry`], [`lineage::VerifiedNode`], [`lineage::HopStatus`]) are
/// public so a navigator can name what the wrappers return.
pub mod lineage;
pub mod microvm;
/// The hermetic in-memory `MockBackend` — see its module docs for the
/// security posture. Gated behind `test-support` so it never compiles into
/// a production `mvmctl` binary.
#[cfg(feature = "test-support")]
pub mod mock;
/// In-process mock of the in-guest vsock agent, paired with [`mock`].
/// Gated the same way — test-only, never in a production build.
#[cfg(feature = "test-support")]
pub mod mock_guest_agent;
pub mod netinit_audit;
/// QEMU workload runtime backend (dev/test).
pub mod qemu;
/// Capability-aware backend selection (fail-closed, no silent downgrade).
pub mod selection;
/// Backend-agnostic supervisor standby pool registry (`~/.mvm/pool/`
/// state-dir; record/select-idle-by-kernel/remove/reap).
pub mod standby_pool;
/// Shared per-VM substitution-endpoint spawn/reap helpers used by the
/// QEMU + Firecracker launch paths (one impl, no drift).
pub(crate) mod substitution_spawn;
#[cfg(test)]
pub(crate) mod test_support;
/// Portable, hypervisor-agnostic VMM device model (guest memory, FDT, kernel
/// loading, virtio-mmio block/vsock). Compiles on every target; the per-platform
/// backends (HVF/KVM/WHP) drive it. The "no VMM lock-in" seam.
pub mod vmm;
/// Shared host-side vsock egress support. Backend-agnostic; every VMM path uses
/// the same gate/relay substrate while policy remains in the host endpoint.
pub mod vsock_egress_bridge;
/// Plugs `mvm_fs`'s content-addressed `SnapshotStore` beneath the existing
/// checkpoint lineage: stage a checkpoint's bytes into the snapshot store,
/// then clone them only after the checkpoint's fail-closed lineage
/// verification (`verify_content` + `verify_lineage`) passes.
pub mod warm_snapshot;
/// `WasmBackend` — host-`wasmtime` claim-free portability tier running a
/// user-supplied WASI module. Always constructible; the real engine only
/// compiles in behind the opt-in `wasm-backend` feature.
pub mod wasm_backend;
/// `WorkloadBackend` marker trait — the type-level permission to carry an
/// untrusted workload. The admitted launch path accepts `&dyn WorkloadBackend`
/// only, so a non-workload backend (QEMU dev/test, mock) cannot reach it.
pub mod workload_backend;
pub mod workload_runner;
mod workload_wait;

// Embedded-library surface for the warm-lease ergonomics.
pub use vm::exec_builder::{ExecBuilder, ExecOutcome};
pub use vm::lease::{AcquireSpec, WarmLease};

// The Machine product abstraction — the construction + capability-gate seam
// the CLI, mvmd, and the SDKs share.
pub use machine::{
    CapabilityError, LaunchInputs, Machine, MachineBuilder, MachineError, MachineSpec, NetworkMode,
};

// Substrate re-exports — see crate doc comment.
pub use base::{config, linux_env, shell, ui};

// Legacy re-export — preserves `mvm_runtime::shell_mock::*` (used by
// mvmd's `mvmd-agent::quic_integration` test and a handful of
// `mvmd-runtime` security modules).
pub use base::shell_mock;

pub use backend::{AnyBackend, FirecrackerBackend, FirecrackerConfig};
pub use libkrun::LibkrunBackend;
#[cfg(feature = "test-support")]
pub use mock::MockBackend;
pub use qemu::QemuBackend;
pub use workload_backend::{EgressSubstitutionTransport, WorkloadBackend};

/// The per-VM egress-TLS cert/key split helper. `mvmctl up`
/// (mvm-cli) calls this while assembling the guest secrets drive: the cert is
/// pushed onto the drive, the key is persisted host-side for the terminator
/// endpoint. See [`substitution_spawn::build_egress_tls_delivery`].
pub use substitution_spawn::{
    EGRESS_CERT_DRIVE_NAME, EgressTlsDelivery, EndpointTransport, build_egress_tls_delivery,
};

/// Per-VM broker-services spawn/reap, called from the workload backends' launch
/// path. Exposed so the backends and tests share one impl.
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
/// alt-backend tests share the same mutex with the VM lifecycle tests
/// — without sharing one lock the modules race each other when
/// their tests run on the same `cargo test` binary.
///
/// Tests import from `mvm_base` directly; keep this note near the
/// module list so future process-global tests reuse the same lock.
#[cfg(any())]
pub(crate) use crate::base::runtime_meta::HOME_TEST_LOCK;
