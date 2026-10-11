//! Local named-machine launch providers. They never acquire boot artifacts.

use anyhow::{Context, Result};

use super::machine_start::{BootImage, StartHost, prepared_machine_image, prepared_machine_kernel};
use crate::volume::{
    AdmittedProfile, ExplicitVolume, LaunchLeaseRequest, LaunchPreparation, VolumeService,
};

/// Parsed volume intent and the profile of the definition being started.
/// Frontends parse their argument grammar; this provider owns materialization,
/// encrypted-host checks, registration refresh and launch leases.
pub struct PreparedStartHost {
    kernel_pinned: bool,
    profile: AdmittedProfile,
    volumes: Vec<ExplicitVolume>,
}

impl PreparedStartHost {
    pub fn new(profile: &str, kernel_pinned: bool, volumes: Vec<ExplicitVolume>) -> Self {
        Self {
            kernel_pinned,
            profile: AdmittedProfile::from_profile_name(profile),
            volumes,
        }
    }
}

impl StartHost for PreparedStartHost {
    fn workload_kernel(&self, backend: &str) -> Result<Option<String>> {
        prepared_machine_kernel(backend, self.kernel_pinned)
    }

    fn resolve_image(&self, reference: &str) -> Result<BootImage> {
        prepared_machine_image(reference)
    }

    fn prepare_volumes(&self, name: &str, volume_specs: &[String]) -> Result<LaunchPreparation> {
        anyhow::ensure!(
            volume_specs.len() == self.volumes.len(),
            "all persisted volume declarations must be parsed before a named machine start"
        );
        let service = crate::volume::wire::service();
        let mut creation_locks = Vec::with_capacity(self.volumes.len());
        for volume in &self.volumes {
            let profile = self
                .profile
                .profile()
                .context("machine spec carries an unrecognised profile for explicit volumes")?;
            anyhow::ensure!(
                profile.grants().host_shares,
                "--profile {} does not allow volumes (--mount/--volume)",
                profile.as_str()
            );
            if !volume.read_only {
                self.profile.require_read_write("explicit disk volume")?;
            }
            let path = std::path::Path::new(&volume.host);
            anyhow::ensure!(
                !path.is_dir() && !volume.size.is_empty(),
                "persistent machines require disk images or registered host snapshots"
            );
            mvm_core::crypto::policy::validate_mount_path(&volume.guest)
                .map_err(anyhow::Error::msg)?;
            let size_mib = mvm_core::util::parse_human_size(&volume.size)?;
            creation_locks.push(
                mvm_build::builder_vm_runtime::ensure_persistent_volume_image(
                    path,
                    u64::from(size_mib) * 1024 * 1024,
                    volume.read_only,
                )
                .with_context(|| format!("materializing disk volume image '{}'", volume.host))?,
            );
        }
        service
            .refresh_host_snapshots(name, crate::workspace_apply::cache::MountImageCache::new)?;
        let request = LaunchLeaseRequest::builder(name)?
            .explicit_specs(self.volumes.clone())
            .profile(self.profile)
            .build();
        service
            .acquire_launch_lease(&request)
            .context("resolving registered local volumes for launch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn explicit_volume_policy_refuses_before_creating_a_disk() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let image = home.path().join("state.ext4");
        let volume = ExplicitVolume {
            host: image.display().to_string(),
            guest: "/data".into(),
            size: "16M".into(),
            read_only: false,
            materialized_image: None,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        };
        for profile in ["restrictive", "unknown"] {
            let host = PreparedStartHost::new(profile, false, vec![volume.clone()]);
            assert!(host.prepare_volumes("web", &["disk".into()]).is_err());
            assert!(!image.exists());
        }
    }

    #[test]
    fn unparsed_persisted_volumes_cannot_be_dropped() {
        let host = PreparedStartHost::new("dev", false, Vec::new());
        let error = host.prepare_volumes("web", &["disk".into()]).unwrap_err();
        assert!(error.to_string().contains("must be parsed"));
    }

    #[test]
    fn empty_named_volume_preparation_needs_no_mount_cache() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let host = PreparedStartHost::new("dev", false, Vec::new());
        let prepared = host.prepare_volumes("web", &[]).unwrap();
        assert!(prepared.volumes.is_empty());
    }
}
