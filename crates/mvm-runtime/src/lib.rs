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
// - **Firecracker** (`backend::AnyBackend::Firecracker`) — the Linux KVM
//   production Tier 1 path, driven through `WorkloadRunner<FcDriver>`.
// - **HVF** (`backend::AnyBackend::Hvf`) — the in-house Hypervisor.framework
//   path, driven through `WorkloadRunner<HvfDriver>`.
// - **libkrun** (`backend::AnyBackend::Libkrun`) — driven through
//   `WorkloadRunner<LibkrunDriver>`.
// - **QEMU** (`backend::AnyBackend::Qemu`) — Tier-2 dev/test substrate only.
// - **Wasm** (`wasm_backend::WasmBackend`) — claim-free portability/demo
//   exception; direct `VmBackend` implementation.
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
pub mod warm_artifact_builder;
pub mod warm_artifacts;
pub mod warm_readiness;

/// Filesystem-backed store for durable agent sessions (see [`checkpoint`]
/// for the analogous per-checkpoint store).
pub mod agent_session;
pub mod apple_container;
pub mod apple_container_backend;
pub mod artifacts;
/// Shared resolve-or-build for the per-VM helper binaries `mvmctl` spawns
/// (supervisors + the substitution endpoint); one impl, no drift.
pub mod backend;
/// Concrete hypervisor backend implementations.
pub mod backends;
pub mod base;
/// Per-VM broker-services (`mvm-broker` / `mvm-audit-signer`) subprocess
/// spawn/reap helpers, mirroring [`network_endpoint_spawn`].
/// The builder role layer: boots a builder VM over the `VmmDriver` seam with the
/// disk-only job/artifact transport (trusted, no egress endpoint, no virtio-fs).
pub mod builder_runner;
pub mod catalog;
pub mod checkpoint;
pub mod codesign;
pub mod compat;
pub mod driver;
/// Per-VM transparent egress redirect used by the legacy libkrun gateway path.
/// Cfg-free decode of the admitted plan's egress secret bindings, shared by
/// the libkrun + Firecracker substitution-endpoint spawn paths.
// Firecracker host mechanics moved to mvm-backends::fc; re-exported so
// `mvm_runtime::firecracker::<name>` keeps resolving for mvm-cli.
pub use mvm_backends::fc::host as firecracker;
pub mod handle_registry;
/// The HVF end of the checkpoint restore seams (fork into a fresh identity,
/// same-identity resume) — the counterpart of the capture control the HVF
/// driver hands back through `vm_full_control`.
pub mod hvf_restore;
pub mod image;
/// Content-addressed image version-lineage store + chain-anchored verification
/// (the image analog of [`checkpoint`]). Reuses the shared `lineage` walk.
pub mod image_lineage;
/// KVM (Linux) backend — drives [`vmm`] on Linux via `kvm-ioctls`, implementing
/// the [`vmm::hv`] seam. `kvm::x86_boot` is pure logic
/// (compiles + tests everywhere); the ioctl glue is Linux-only.
pub mod kvm;
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
/// Process-local reservation and rollback for resident warm parents.
pub mod resident_pool;
/// Capability-aware backend selection (fail-closed, no silent downgrade).
pub mod selection;
/// Backend-agnostic supervisor standby pool registry (`~/.mvm/pool/`
/// state-dir; record/select-idle-by-kernel/remove/reap).
pub mod standby_pool;
/// Shared per-VM substitution-endpoint spawn/reap helpers used by the
/// QEMU + Firecracker launch paths (one impl, no drift).
#[cfg(test)]
pub(crate) mod test_support;
/// Resident owner for opaque trusted-snapshot publications.
pub mod trusted_snapshot_service;
/// Portable, hypervisor-agnostic VMM device model (guest memory, FDT, kernel
/// loading, virtio-mmio block/vsock). Compiles on every target; the per-platform
/// backends (HVF/KVM/WHP) drive it. The "no VMM lock-in" seam.
/// Shared host-side vsock egress support. Backend-agnostic; every VMM path uses
/// the same gate/relay substrate while policy remains in the host endpoint.
/// In-process Claim/Release/Prewarm ownership boundary for resident warm launches.
pub mod warm_service;
/// Plugs `mvm_fs`'s content-addressed `SnapshotStore` beneath the existing
/// checkpoint lineage: stage a checkpoint's bytes into the snapshot store,
/// then clone them only after the checkpoint's fail-closed lineage
/// verification (`verify_content` + `verify_lineage`) passes.
pub mod warm_snapshot;
/// The Wasm tier's activation analog: the capability handshake (preopens,
/// env, activation file) delivered to a WASI run, adapted from the
/// microVM/container tiers' environment activation. Pure data + mapping,
/// independent of the `wasm-backend` engine feature.
pub mod wasm_activation;
/// `WasmBackend` — host-`wasmtime` claim-free portability tier running a
/// user-supplied WASI module. Always constructible; the real engine only
/// compiles in behind the opt-in `wasm-backend` feature.
pub mod wasm_backend;
pub mod web_linux_backend;
/// `WorkloadBackend` marker trait — the type-level permission to carry an
/// untrusted workload. The admitted launch path accepts `&dyn WorkloadBackend`
/// only, so a non-workload backend (QEMU dev/test, mock) cannot reach it.
pub mod workload_backend;
pub mod workload_runner;

/// Re-export the backend-agnostic VMM device model from `mvm-vmm`.
pub use mvm_vmm::vmm;
/// Re-export the shared vsock egress bridge from `mvm-vmm`.
pub use mvm_vmm::vsock_egress_bridge;

// Embedded-library surface for the warm-lease ergonomics.
pub use mvm_core::vm_backend::WarmPrewarmSource;
pub use resident_pool::{ResidentPoolError, ResidentWarmLease, ResidentWarmPool};
pub use vm::exec_builder::{ExecBuilder, ExecOutcome};
pub use vm::lease::{AcquireSpec, WarmLease, WarmLeaseOrigin};
pub use warm_artifact_builder::{
    WarmArtifactBuildPlan, WarmArtifactPlanResolver, WarmArtifactSupportPaths, WarmArtifactWorker,
    WarmGoldenVmReadinessVerifier,
};
pub use warm_artifacts::{
    PrewarmJob, PrewarmJobState, PrewarmQueue, WarmArtifactFile, WarmArtifactInput,
    WarmArtifactKey, WarmArtifactManifest, WarmArtifactSet, WarmArtifactStore,
};
pub use warm_readiness::{AuthenticatedWarmGoldenVmVerifier, WarmGoldenVmFactory};

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

pub use backend::{AnyBackend, FirecrackerConfig};
#[cfg(feature = "test-support")]
pub use mock::MockBackend;
pub use warm_service::{PrewarmFn, WarmLaunchService};
pub use workload_backend::{EgressSubstitutionTransport, WorkloadBackend};

/// The per-VM egress-TLS cert/key split helper. `mvmctl up`
/// (mvm-cli) calls this while assembling the guest secrets drive: the cert is
/// pushed onto the drive, the key is persisted host-side for the terminator
/// Per-VM egress-substitution spawn helpers. Re-exported from `mvm-vmm::host`.
pub use mvm_vmm::host::network_endpoint_spawn;

/// Per-VM broker-services spawn/reap. Re-exported from `mvm-vmm::host`.
pub use mvm_vmm::host::broker_services_spawn;

/// Per-tenant host-agent daemon seam. Re-exported from `mvm-vmm::host`.
pub use mvm_vmm::host::host_agent_spawn;

/// Host-agent registration helpers used by integration tests and the
/// `mvmctl` host-agent path. Re-exported from `mvm-vmm::host::host_agent_spawn`.
pub use mvm_vmm::host::host_agent_spawn::{
    HostAgentServicesParams, deregister_vm, ensure_host_agent_daemon, load_host_signing_key,
    reap_host_agent_services_from_state, register_host_agent_services_if_admitted, register_vm,
};

/// Substitution-endpoint helpers used by integration tests and the
/// `mvmctl` secrets-drive path. Re-exported from `mvm-vmm::host::network_endpoint_spawn`.
pub use mvm_vmm::host::network_endpoint_spawn::{EndpointHandshake, record_secret_fingerprints};

/// Spawn/reap the per-VM substitution-endpoint moat, its params, and the
/// remote-resolver spawn config — re-exported at the crate root so fleet
/// callers outside this crate (mvmd's tenant-secrets vault, Phase 1 egress
/// broker / D8 spawn-wiring, reaching them via `mvmctl::backend`) can drive the
/// same per-VM endpoint the libkrun/HVF/Firecracker backends use, instead of
/// duplicating the subprocess spawn/handshake/PID-file logic. The
/// `network_endpoint_spawn` module is also re-exported above; these root aliases
/// mirror the original `mvm-backend` crate-root surface those callers named.
pub use mvm_vmm::host::network_endpoint_spawn::{
    RemoteResolverSpawnConfig, SubstitutionSpawnParams, reap_network_endpoint,
    spawn_network_endpoint,
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
