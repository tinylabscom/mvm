//! Match a volume against the signed share grant before attachment.

use mvm_core::plan::{HostShareGrant, ShareKind};
use mvm_core::vm_backend::VmVolume;

pub(super) fn matches_grant(grant: &HostShareGrant, volume: &VmVolume, kind: ShareKind) -> bool {
    grant.host_path == volume.host
        && grant.guest_path == volume.guest
        && grant.kind == kind
        && grant.read_only == volume.read_only
        && grant.encrypted == volume.encrypted
        // Bind the deny set at claim time: a re-bind cannot hand the guest a
        // different tree from the one the signed plan admitted.
        && grant.include == volume.share_include
        && grant.exclude == volume.share_exclude
}
