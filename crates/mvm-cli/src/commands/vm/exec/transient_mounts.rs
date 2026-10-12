//! The `--mount` specs of a transient run, split into the directory shares
//! and the disk volumes it attaches.

use anyhow::Result;

pub(super) struct TransientMounts {
    pub(super) dir_shares: Vec<crate::commands::DirShareSpec>,
    pub(super) disk_volumes: Vec<mvm_core::vm_backend::VmVolume>,
}

pub(super) fn parse_transient_mounts(specs: &[String]) -> Result<TransientMounts> {
    let mut dir_shares = Vec::new();
    let mut disk_volumes = Vec::new();
    for raw in specs {
        let parsed = crate::commands::vm::shared::parse_volume_spec(raw)?;
        match parsed {
            crate::commands::vm::shared::VolumeSpec::DirShare { .. } => {
                dir_shares.push(crate::commands::parse_dir_share_spec(raw)?);
            }
            crate::commands::vm::shared::VolumeSpec::Disk { .. } => {
                disk_volumes.push(crate::commands::vm::shared::vm_volume_from_spec_validated(
                    &parsed,
                )?);
            }
        }
    }
    Ok(TransientMounts {
        dir_shares,
        disk_volumes,
    })
}
