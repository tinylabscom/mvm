//! Which `--mount`/`--volume` specs a machine's profile grants.

use anyhow::{Result, bail};

use super::RunProfile;
use crate::commands::shared::{VolumeSpec, parse_volume_spec};

/// Refuse any volume the profile does not grant. `machine run` and
/// `machine create` both call this, so the two entry points accept exactly the
/// same specs.
///
/// Writability is split by what the guest writes into. A disk image
/// (`HOST.img:/GUEST:SIZE:rw`) is the guest's own ext4 file, so any profile
/// that accepts volumes accepts it writable; a host directory is the host's
/// filesystem, so writing into one stays with the dev-capable profiles. Where
/// in the guest either may mount is the guest mount allow-list's decision, not
/// this one's: it is checked separately for every spec.
pub(super) fn enforce_volume_profile(profile: RunProfile, raw_specs: &[String]) -> Result<()> {
    let grants = profile.grants();
    let name = profile.as_str();
    if !grants.host_shares && !raw_specs.is_empty() {
        bail!("--profile {name} does not allow volumes (--mount/--volume)");
    }
    for raw in raw_specs {
        match parse_volume_spec(raw)? {
            VolumeSpec::DirShare {
                read_only: false, ..
            } if !grants.writable_host_dirs_when_persistent => bail!(
                "volume {raw:?} requests ':rw' on a host directory, which needs --profile dev \
                 or --profile permissive. A disk image (`HOST.img:/GUEST:SIZE:rw`) is writable \
                 under any profile that accepts volumes"
            ),
            VolumeSpec::Disk {
                read_only: false, ..
            } if !grants.writable_disk_images => bail!(
                "volume {raw:?} requests a writable disk image, which --profile {name} does not grant"
            ),
            VolumeSpec::DirShare { .. } | VolumeSpec::Disk { .. } => {}
        }
    }
    Ok(())
}
