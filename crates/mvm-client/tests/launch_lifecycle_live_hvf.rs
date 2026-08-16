//! Live HVF E2E for the in-process launch lifecycle.
//!
//! macOS twin of `launch_lifecycle_live`: proves both lifecycle modes reach
//! the real admitted boot path on an Apple Silicon host through the HVF
//! backend — no `mvmctl` subprocess. Ignored by default: an operator or CI
//! lane drives it with `-- --ignored` after exporting `MVM_E2E_KERNEL` (a
//! verified arm64 workload kernel, present in the kernel cache) and
//! `MVM_E2E_ROOTFS` (a bootable ext4 workload rootfs), with
//! `mvm-hvf-supervisor` built in the workspace target dir or named via
//! `MVM_HVF_SUPERVISOR_PATH`. Without those the test skips cleanly so the
//! suite stays green everywhere else.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, MvmClient, RemoveOptions};
use mvm_core::client::dto::{MachineId, MachineStatus};
use mvm_core::rootfs_source::RootfsSource;

/// Resolve the live-lane prerequisites, or explain the clean skip.
fn live_env() -> Option<(String, RootfsSource)> {
    let kernel = std::env::var("MVM_E2E_KERNEL").ok()?;
    let rootfs = std::env::var("MVM_E2E_ROOTFS").ok()?;
    if !std::path::Path::new(&kernel).exists() || !std::path::Path::new(&rootfs).exists() {
        eprintln!("skipping: MVM_E2E_KERNEL / MVM_E2E_ROOTFS do not name existing files");
        return None;
    }
    // Declared as a path outright: the env var may hold a relative one, which
    // the string grammar would (correctly) read as a registry reference.
    Some((
        kernel,
        RootfsSource::LocalPath(std::path::PathBuf::from(rootfs)),
    ))
}

/// Optional dwell between launch and stop (`MVM_E2E_LINGER_SECS`), so an
/// operator can let the guest reach userspace and inspect its console log.
fn linger() {
    if let Some(secs) = std::env::var("MVM_E2E_LINGER_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

#[tokio::test]
#[ignore = "live HVF E2E: needs Apple Silicon + mvm-hvf-supervisor + MVM_E2E_KERNEL/MVM_E2E_ROOTFS; run with -- --ignored"]
async fn transient_and_persistent_lifecycle_over_hvf() {
    let Some((_kernel, rootfs)) = live_env() else {
        return;
    };
    let client = LocalBackend::with_hypervisor("hvf");

    // Transient: boots through the signed admission path, then cleans up.
    let transient = LaunchRequest::builder(LifecycleMode::Transient, rootfs.clone())
        .name("e2e-hvf-transient")
        .build()
        .expect("transient request");
    let outcome = client.launch(transient).await.expect("transient launch");
    assert_eq!(outcome.machine.status, MachineStatus::Running);
    assert!(outcome.plan_id.starts_with("sha256:"), "admitted plan id");
    linger();
    client
        .stop_machine(&outcome.machine.id)
        .await
        .expect("stop transient");
    client
        .cleanup_transient("e2e-hvf-transient")
        .expect("idempotent cleanup");

    // Persistent: create + start + stop keeps the spec; remove deletes it.
    let persistent = LaunchRequest::builder(LifecycleMode::Persistent, rootfs)
        .name("e2e-hvf-persistent")
        .build()
        .expect("persistent request");
    let outcome = client.launch(persistent).await.expect("persistent launch");
    assert_eq!(outcome.machine.status, MachineStatus::Running);
    linger();

    let id = MachineId("e2e-hvf-persistent".into());
    client.stop_machine(&id).await.expect("stop persistent");
    assert!(
        mvm_core::config::machine_spec_path("e2e-hvf-persistent").exists(),
        "stop keeps the persisted definition"
    );
    client
        .remove_machine_with(&id, RemoveOptions { force: false })
        .await
        .expect("remove stopped persistent");
    assert!(!mvm_core::config::machine_spec_path("e2e-hvf-persistent").exists());
}
