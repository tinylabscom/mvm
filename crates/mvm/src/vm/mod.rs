// Plan-60 W7+W8 split:
//
//   * Every concrete `VmBackend` impl + the FC support modules
//     (apple_container, libkrun, firecracker, microvm,
//     image, network, backend) live in `mvm-backend`.
//   * The leaf substrate (`ui`, `runtime_meta`, `cow`,
//     `snapshot_integrity`) lives in `mvm-base`.
//
// What's left here is the orchestration layer — instance/pool/
// template/tenant lifecycle, name + volume registries, the egress
// proxy, vminitd client, and the host-side rootfs snapshot helper.

pub mod egress_proxy;
pub mod instance_snapshot;
pub mod name_registry;
pub mod overlay;
pub mod reconcile;
pub mod template;
pub mod vminitd_client;
pub mod volume_registry;

// Substrate re-exports — preserve the `mvm::vm::{cow,
// runtime_meta}::*` paths. These have external consumers (mvmd's
// `mvmctl::runtime` surface and the W6.2 console gate) so the
// re-exports stay even after W8.B.3 migrated in-tree consumers.
pub use mvm_backend::base::{cow, runtime_meta};

/// Crate-wide test serialization for tests that mutate
/// `MVM_DATA_DIR` (and thus rely on a process-global env var).
/// Tests that mutate `HOME` use
/// [`mvm_backend::base::runtime_meta::HOME_TEST_LOCK`] instead.
/// Tests that mutate other process-globals can grab their own lock
/// or pile onto one of these — the goal is "no two tests touch the
/// same env var concurrently."
#[cfg(test)]
pub(crate) static DATA_DIR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
