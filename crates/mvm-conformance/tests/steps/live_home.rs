//! Preparation of the home a live scenario boots from.
//!
//! A launch is cache-only: it refuses a missing workload kernel, guest
//! runtime, runtime overlay, initramfs or OCI image instead of acquiring one.
//! A live scenario therefore prepares its home before it launches, from bytes
//! the suite has already verified, and never relies on the launch to fetch or
//! compile anything.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

#[path = "../support/live_runtime.rs"]
mod live_runtime;

/// The guest runtime a live home is seeded with is built from this checkout,
/// so every `mvmctl` run against that home resolves it in source-build mode.
/// In the published-artifact mode the same seeded runtime reads as missing.
pub(crate) const RUNTIME_ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";
pub(crate) const RUNTIME_ACQUIRE_MODE: &str = "build";

/// Select the source-built guest runtime the live home was seeded with.
pub(crate) fn use_seeded_runtime(command: &mut Command) -> &mut Command {
    command.env(RUNTIME_ACQUIRE_MODE_ENV, RUNTIME_ACQUIRE_MODE)
}

fn prepared_homes() -> std::sync::MutexGuard<'static, HashSet<PathBuf>> {
    static PREPARED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    PREPARED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Prepare `home` once per process: the verified workload kernel, the
/// source-built guest runtime, and the runtime overlay and initramfs
/// assembled from that runtime. Every later launch against the home resolves
/// them from its own cache.
pub(crate) fn prepare_live_home(home: &Path) {
    let mut prepared = prepared_homes();
    if prepared.contains(home) {
        return;
    }
    seed_workload_kernel(home);
    prepare_live_runtime(home);
    prepared.insert(home.to_path_buf());
}

/// Whether `home` was prepared for live launches. A lifecycle verb that runs
/// against such a home after the launch (`machine restart`, say) must resolve
/// the same seeded runtime the launch did.
pub(crate) fn is_prepared_live_home(home: &Path) -> bool {
    prepared_homes().contains(home)
}

/// Copy the suite's verified workload kernel into `home` and record its
/// digest, so the launch resolves it from the home's own verified cache.
pub(crate) fn seed_workload_kernel(home: &Path) {
    let cache = home.join("cache");
    let arch = std::env::consts::ARCH;
    if matches!(
        mvm_build::kernel_fetch::resolve_kernel(&cache, arch, "workload", false),
        mvm_build::kernel_fetch::KernelResolution::Cached(_)
    ) {
        return;
    }
    let source = crate::workload_kernel_path().expect(
        "a live scenario needs a prepared workload kernel; run \
         `mvmctl kernel build --which workload --source download` before the live suite",
    );
    let destination = mvm_build::kernel_fetch::cached_kernel_path(&cache, arch, "workload");
    fs::create_dir_all(
        destination
            .parent()
            .expect("workload kernel cache path has a parent"),
    )
    .expect("create isolated workload kernel cache");
    fs::copy(&source, &destination).unwrap_or_else(|error| {
        panic!("copy live workload kernel {source:?} to {destination:?}: {error}")
    });
    mvm_build::kernel_fetch::record_kernel_digest(&destination)
        .expect("record isolated workload kernel digest");
    assert!(
        matches!(
            mvm_build::kernel_fetch::resolve_kernel(&cache, arch, "workload", false),
            mvm_build::kernel_fetch::KernelResolution::Cached(ref kernel)
                if kernel.path() == destination
        ),
        "isolated workload kernel must resolve from the verified cache"
    );
}

fn prepare_live_runtime(home: &Path) {
    use mvm_vmm::host::aux_bin::{self, AuxBin, HostProcess};

    let cache = home.join("cache");
    let cli = super::cli::mvmctl_path();
    let host = HostProcess::undeclared()
        .with_binary_dir(cli.parent().expect("mvmctl has a binary directory"));
    // These daemon binaries do not implement the endpoint's contract probe.
    // Resolve them without granting permission to compile at launch.
    for name in ["mvm-host-agent", "mvm-signer-helper"] {
        assert!(
            host.binary_named(name).is_some(),
            "prebuild {name} beside the live mvmctl"
        );
    }
    aux_bin::resolve_verified_for(
        &AuxBin::new(
            "mvm-network-endpoint",
            "MVM_SUBSTITUTION_ENDPOINT_PATH",
            "mvm-hostd",
        ),
        &host,
    )
    .expect("prebuilt network endpoint must satisfy the launch contract");
    // Admit one independently verified archive, not loose executables. Both
    // assemblers record that archive's digest, including the distinct PID 1
    // agent that the universal initramfs needs.
    let runtime = super::cli::seed_live_guest_runtime(home);
    let (overlay, initramfs) = live_runtime::prepare(&cache, &runtime)
        .expect("prepare both isolated verified boot artifacts");

    // Exercise the launch's cache-only boundaries before creating a machine.
    // A missing artifact or stale source fingerprint is a fixture failure,
    // rather than a request to acquire anything during machine start.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home);
    env.set(RUNTIME_ACQUIRE_MODE_ENV, RUNTIME_ACQUIRE_MODE);
    mvm_client::launch::runtime_overlay::require_prepared_oci_guest_runtime(&cache.join("oci"))
        .expect("isolated OCI guest runtime must already be prepared");
    let mut config = mvm_core::vm_backend::VmStartConfig {
        kernel_path: Some("prepared-workload-kernel".to_string()),
        rootfs_path: "prepared-workload-rootfs".to_string(),
        ..Default::default()
    };
    mvm_client::launch::runtime_source::attach_runtime_overlay_if_cached(
        &mut config,
        "firecracker",
    )
    .expect("isolated runtime overlay must attach without acquisition");
    mvm_runtime::universal_initramfs::attach_universal_initramfs_if_cached(
        &mut config,
        "firecracker",
    )
    .expect("isolated universal initramfs must attach without acquisition");
    assert_eq!(config.initrd_path.as_deref(), initramfs.image_path.to_str());
    assert_eq!(
        config.runtime_overlay_path.as_deref(),
        overlay.overlay_ext4.to_str()
    );
    assert_eq!(
        config.runtime_overlay_verity_path.as_deref(),
        overlay.sidecar.to_str()
    );
    assert_eq!(
        config.runtime_overlay_roothash.as_deref(),
        Some(overlay.roothash.as_str())
    );
}
