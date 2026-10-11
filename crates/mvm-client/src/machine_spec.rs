//! Persisted named-machine specs: the registry every surface reaches through
//! the client.
//!
//! The storage engine lives in `mvm_runtime::machine::persist` — `mvm-hostd`'s
//! health probe reads it below the client, so the module itself cannot move
//! here without a dependency cycle. The client re-exports the registry surface
//! as the one import point above the runtime and owns the spec-to-launch
//! volume validation that turns persisted declarations into attachable
//! volumes.

use anyhow::{Context, Result, bail};

use crate::mounts::{self, VolumeSpec};
use crate::volume::ExplicitVolume;

pub use mvm_runtime::machine::persist::{
    MACHINE_SPEC_SCHEMA_VERSION, MachineSpec, ReconfigurePatch, SpecReconcile, apply_patch,
    list_machine_specs, load_machine_spec, machine_config_diff, overwrite_machine_spec,
    reconcile_machine_spec, save_machine_spec, validate_machine_memory,
};

/// Parse and validate a persisted machine's volume declarations into the
/// explicit volumes a launch provider attaches.
///
/// A persistent machine has no live host-directory share: a directory reaches
/// the guest only as a registered snapshot, so a `DirShare` is refused even in
/// a spec saved before the gate existed. Wording comes from
/// [`mounts::persistent_dir_share_refusal`] so every entry point says the same
/// thing.
pub fn explicit_volumes_for_specs(volume_specs: &[String]) -> Result<Vec<ExplicitVolume>> {
    let mut volumes = Vec::with_capacity(volume_specs.len());
    for volume in volume_specs {
        let spec = mounts::parse_volume_spec(volume)?;
        if let VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            ..
        } = &spec
        {
            bail!(mounts::persistent_dir_share_refusal(host_dir, guest_mount));
        }
        let vmv = mounts::vm_volume_from_spec_validated(&spec)
            .with_context(|| format!("volume {volume:?}"))?;
        volumes.push(ExplicitVolume {
            host: vmv.host,
            guest: vmv.guest,
            size: vmv.size,
            read_only: vmv.read_only,
            materialized_image: vmv.materialized_image,
            kind: vmv.kind,
            encrypted: vmv.encrypted,
        });
    }
    Ok(volumes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boot-time check stays as defense in depth for a spec that reached
    /// `machine start` without passing the spec-time gate, and it says exactly
    /// what the gate says.
    #[test]
    fn persistent_directory_volume_refuses_with_the_snapshot_registration_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let volume = format!("{}:/work:ro", dir.path().display());
        let at_boot = explicit_volumes_for_specs(std::slice::from_ref(&volume))
            .expect_err("a persistent machine cannot carry a live directory share")
            .to_string();
        assert!(
            at_boot.contains("cannot attach a live host directory"),
            "message: {at_boot}"
        );
        assert!(
            at_boot.contains("machine volume mount"),
            "message: {at_boot}"
        );
    }

    #[test]
    fn disk_volumes_parse_into_explicit_volumes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let image = dir.path().join("state.ext4");
        let spec = format!("{}:/data:16M:rw", image.display());
        let volumes = explicit_volumes_for_specs(&[spec]).expect("disk volume");
        let canonical_image = std::fs::canonicalize(dir.path())
            .expect("canonicalize tmpdir")
            .join("state.ext4");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].host, canonical_image.display().to_string());
        assert_eq!(volumes[0].guest, "/data");
        assert!(!volumes[0].read_only);
    }
}
