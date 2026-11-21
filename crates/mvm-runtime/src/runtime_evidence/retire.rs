//! Removing a VM's per-VM runtime evidence once nothing can read it again.

use super::{RuntimeLifecycleLease, namespace};
use anyhow::Result;
use mvm_core::protocol::runtime_release::RuntimeLaunchBinding;
use mvm_core::vm_backend::VmStartConfig;
use std::path::Path;

/// Whether a retained checkpoint binding reads anything under `directory`.
fn binding_reads(binding: &RuntimeLaunchBinding, directory: &Path) -> bool {
    let mut config = VmStartConfig::default();
    binding.apply_to_config(&mut config);
    [
        Some(&config.rootfs_path),
        config.initrd_path.as_ref(),
        config.runtime_overlay_path.as_ref(),
        config.runtime_overlay_verity_path.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|path| Path::new(path).starts_with(directory))
}

/// Remove `vm_name`'s `runtime-evidence/<vm>` directory after its name is gone
/// for good (`machine rm`, a finished transient run). Content shared across VMs
/// lives in `shared_content` as hard links, so other VMs keep their bytes.
///
/// Kept, returning `false`, while anything can still read the generation: a
/// retained kernel or installed-bundle record (stop not proven), or a
/// checkpoint whose binding names a file in it. Absent evidence is not an error.
pub fn remove_retired_vm_evidence(vm_name: &str) -> Result<bool> {
    mvm_core::naming::validate_vm_name(vm_name)?;
    let Ok(root) = namespace::root(false) else {
        return Ok(false);
    };
    let directory = root.join(vm_name);
    if std::fs::symlink_metadata(&directory).is_err() {
        return Ok(false);
    }
    let lease = RuntimeLifecycleLease::acquire(vm_name)?;
    if crate::kernel_custody::has_retained_kernel(&lease)?
        || std::fs::symlink_metadata(lease.bundle_use_record()).is_ok()
    {
        return Ok(false);
    }
    let checkpoints = crate::checkpoint::CheckpointStore::open().list_for_removal()?;
    if checkpoints
        .iter()
        .filter_map(|meta| meta.runtime_launch_binding.as_ref())
        .any(|binding| binding_reads(binding, &directory))
    {
        return Ok(false);
    }
    std::fs::remove_dir_all(&directory)?;
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn removal_drops_one_vms_dir_and_keeps_shared_content_and_other_vms() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let root = namespace::root(true).unwrap();
        let shared = root.join(super::super::SHARED_CONTENT_DIR);
        namespace::private_directory(&shared).unwrap();
        std::fs::write(shared.join("blob"), b"bytes").unwrap();
        for vm in ["gone", "kept"] {
            namespace::private_directory(&root.join(vm)).unwrap();
            std::fs::hard_link(shared.join("blob"), root.join(vm).join("blob")).unwrap();
        }

        assert!(remove_retired_vm_evidence("gone").unwrap());
        assert!(!root.join("gone").exists());
        assert_eq!(std::fs::read(root.join("kept/blob")).unwrap(), b"bytes");
        assert_eq!(std::fs::read(shared.join("blob")).unwrap(), b"bytes");
        assert!(!remove_retired_vm_evidence("gone").unwrap(), "already gone");
    }

    #[test]
    fn a_pending_bundle_use_record_keeps_the_evidence() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("pending").unwrap();
        std::fs::write(lease.bundle_use_record(), "a".repeat(64)).unwrap();
        drop(lease);
        assert!(!remove_retired_vm_evidence("pending").unwrap());
        assert!(
            namespace::root(false)
                .unwrap()
                .join("pending/bundle-use.sha256")
                .exists()
        );
    }

    #[test]
    fn a_checkpoint_binding_inside_the_directory_is_detected() {
        let dir = Path::new("/h/runtime-evidence/vm");
        use mvm_core::protocol::runtime_release::{
            CliRuntimeLaunchBinding, RuntimeBindingProvenance,
        };
        let binding = |generation: &str| {
            let at = |name: &str| std::path::PathBuf::from(format!("{generation}/{name}"));
            RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
                provenance: RuntimeBindingProvenance::Source {
                    version: "0".into(),
                    arch: mvm_core::arch::GuestArch::host(),
                    archive_sha256: String::new(),
                },
                overlay_path: at("overlay.ext4"),
                overlay_verity_path: at("overlay.verity"),
                initramfs_path: at("initramfs.cpio.gz"),
                overlay_roothash: String::new(),
            })
        };
        assert!(binding_reads(&binding("/h/runtime-evidence/vm/g"), dir));
        assert!(!binding_reads(&binding("/h/runtime-evidence/vm2/g"), dir));
    }
}
