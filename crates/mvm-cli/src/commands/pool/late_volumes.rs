//! The volume half of warm eligibility: which volumes a restored child can
//! take over the parent's late-volume slots.

use mvm_core::vm_backend::VmStartConfig;

/// Whether every volume of this launch can be attached to a claimed child
/// through the backend's late-volume slots.
pub(super) fn late_volumes_attachable(cfg: &VmStartConfig, late_volume_slots: u8) -> bool {
    cfg.volumes.len() <= usize::from(late_volume_slots)
        && cfg
            .volumes
            .iter()
            .all(|volume| volume.read_only && volume.materialized_image.is_some())
}
