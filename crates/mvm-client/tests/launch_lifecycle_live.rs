//! Live KVM E2E for the in-process launch lifecycle.
//!
//! Proves both lifecycle modes reach the real admitted boot path on a Linux
//! host with `/dev/kvm` and a `firecracker` binary — no `mvmctl` subprocess.
//! Ignored by default (same pattern as the jailer-lite property lanes): a CI
//! lane or an operator drives it with `-- --ignored` after exporting
//! `MVM_E2E_KERNEL` (an uncompressed workload kernel) and `MVM_E2E_ROOTFS`
//! (a bootable ext4 workload rootfs). Without those, or without KVM, the
//! test skips cleanly so the suite stays green everywhere else.

#![cfg(target_os = "linux")]

use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, MvmClient, RemoveOptions};
use mvm_core::client::dto::{MachineId, MachineStatus};

/// Resolve the live-lane prerequisites, or explain the clean skip.
fn live_env() -> Option<(String, String)> {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("skipping: /dev/kvm not present");
        return None;
    }
    let kernel = std::env::var("MVM_E2E_KERNEL").ok()?;
    let rootfs = std::env::var("MVM_E2E_ROOTFS").ok()?;
    if !std::path::Path::new(&kernel).exists() || !std::path::Path::new(&rootfs).exists() {
        eprintln!("skipping: MVM_E2E_KERNEL / MVM_E2E_ROOTFS do not name existing files");
        return None;
    }
    Some((kernel, rootfs))
}

#[tokio::test]
#[ignore = "live KVM E2E: needs /dev/kvm + firecracker + MVM_E2E_KERNEL/MVM_E2E_ROOTFS; run with -- --ignored"]
async fn transient_and_persistent_lifecycle_over_firecracker() {
    let Some((_kernel, rootfs)) = live_env() else {
        return;
    };
    let client = LocalBackend::with_hypervisor("firecracker");

    // Transient: boots through the signed admission path, then cleans up.
    let transient = LaunchRequest::builder(LifecycleMode::Transient, rootfs.clone())
        .name("e2e-transient")
        .build()
        .expect("transient request");
    let outcome = client.launch(transient).await.expect("transient launch");
    assert_eq!(outcome.machine.status, MachineStatus::Running);
    assert!(outcome.plan_id.starts_with("sha256:"), "admitted plan id");
    client
        .stop_machine(&outcome.machine.id)
        .await
        .expect("stop transient");
    client
        .cleanup_transient("e2e-transient")
        .expect("idempotent cleanup");

    // Persistent: create + start + stop keeps the spec; remove deletes it.
    let persistent = LaunchRequest::builder(LifecycleMode::Persistent, rootfs)
        .name("e2e-persistent")
        .build()
        .expect("persistent request");
    let outcome = client.launch(persistent).await.expect("persistent launch");
    assert_eq!(outcome.machine.status, MachineStatus::Running);

    let id = MachineId("e2e-persistent".into());
    client.stop_machine(&id).await.expect("stop persistent");
    assert!(
        mvm_core::config::machine_spec_path("e2e-persistent").exists(),
        "stop keeps the persisted definition"
    );
    client
        .remove_machine_with(&id, RemoveOptions { force: false })
        .await
        .expect("remove stopped persistent");
    assert!(!mvm_core::config::machine_spec_path("e2e-persistent").exists());
}
