//! Boot-time mounts for host-admitted extension artifacts.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use super::mount;
use super::{MountError, Result, ensure_dir, validate_virtio_block_device};
use crate::vsock::ExtensionConfig;

/// Mount host-admitted extension artifacts in their reserved runtime namespace.
///
/// These are not user volumes: the authenticated activation message binds each
/// device to a signed extension identity, and the only accepted target is the
/// path derived from that identity's pack digest. Call this after the root pivot
/// so the `/run` tmpfs carried out of the initramfs remains the visible mount.
pub fn mount_extensions(extensions: &[ExtensionConfig], root: &Path) -> Result<()> {
    for extension in extensions {
        let target = validated_extension_mount_target(extension, root)?;
        ensure_dir(&target.to_string_lossy())?;
        #[cfg(target_os = "linux")]
        mount(
            &extension.device,
            &target.to_string_lossy(),
            "ext4",
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            "",
        )?;
    }
    Ok(())
}

fn validated_extension_mount_target(extension: &ExtensionConfig, root: &Path) -> Result<PathBuf> {
    extension.binding.validate().map_err(|error| {
        MountError::InvalidConfig(format!("invalid extension binding: {error}"))
    })?;
    validate_virtio_block_device(&extension.device, "extension")?;
    let digest = extension
        .binding
        .pack_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let expected = format!("/run/mvm/extensions/{digest}");
    if extension.mountpoint != expected {
        return Err(MountError::InvalidConfig(
            "extension activation identity does not match its mount".into(),
        ));
    }
    Ok(root.join(expected.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_mount::validate_volume_mountpoint;

    #[test]
    fn extension_mount_target_is_derived_from_the_signed_pack_digest() {
        use mvm_contract::assurance::AssuranceId;
        use mvm_contract::protocol::extension_pack::{
            ExtensionBudgets, ExtensionId, ExtensionPlacement, ExtensionPlanBinding,
            ExtensionVersion,
        };

        let expected = format!("/run/mvm/extensions/{}", "01".repeat(32));
        let mut extension = ExtensionConfig {
            binding: ExtensionPlanBinding {
                extension_id: ExtensionId::parse("org.example.extension").expect("id"),
                version: ExtensionVersion::parse("1.0.0").expect("version"),
                pack_digest: [1; 32],
                contract_digest: [2; 32],
                placement: ExtensionPlacement::GuestWorkload,
                artifact: "extension.ext4".into(),
                entrypoint: "bin/extension".into(),
                capabilities: Vec::new(),
                budgets: ExtensionBudgets {
                    cpu_millis: 100,
                    memory_bytes: 1024,
                    duration_ms: 1000,
                    max_steps: 1,
                    max_concurrency: 1,
                    max_payload_bytes: 1024,
                    max_output_bytes: 1024,
                    max_artifact_bytes: 1024,
                },
            },
            plan_id: AssuranceId::parse("plan-1").expect("plan id"),
            mountpoint: expected.clone(),
            device: "/dev/vde".into(),
        };

        assert_eq!(
            validated_extension_mount_target(&extension, Path::new("/")).unwrap(),
            PathBuf::from(&expected)
        );
        assert!(validate_volume_mountpoint(&expected).is_err());

        extension.mountpoint = "/run/mvm/extensions/attacker".into();
        assert!(validated_extension_mount_target(&extension, Path::new("/")).is_err());
    }
}
