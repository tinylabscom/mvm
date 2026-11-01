//! Pure Firecracker drive configuration recipes.

use mvm_vmm::driver::spec::BlockDev;
use mvm_vmm::host::boot_config::FcDrive;

use crate::fc::FcCapabilities;

/// One Firecracker API configuration call: an HTTP PUT of `body` to `path` on
/// the per-VM API socket. Kept as data so the whole NIC-less config sequence is
/// a pure, testable value the driver replays through `api_put_socket`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcApiPut {
    pub path: String,
    pub body: String,
}

/// Map slot-ordered blocks to `/drives/*` PUTs in the order Firecracker assigns
/// device letters (first PUT → `/dev/vda`, next → `/dev/vdb`, …), so the guest
/// device nodes line up with the verity slot model the cmdline names
/// (`mvm.data=/dev/vda mvm.hash=/dev/vdb …`). The lowest-slot block is the root
/// device; every block carries its own read-only policy verbatim.
///
/// Every writable block offers the guest discard when the running Firecracker
/// supports it, so a guest trim releases host blocks. That grants a guest
/// nothing it lacked: a drive it can write is one it could already zero, and a
/// punched hole is zeroes that cost no disk.
pub(super) fn fc_drive_puts(blocks: &[BlockDev], caps: FcCapabilities) -> Vec<FcApiPut> {
    let mut ordered: Vec<&BlockDev> = blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    ordered
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let drive_id = format!("blk{}", block.slot);
            // The lowest-slot block (first PUT) is the root device; each block
            // keeps its own read-only policy. Body shape shared with the raw path.
            let body = FcDrive {
                drive_id: &drive_id,
                path_on_host: &block.source.to_string_lossy(),
                is_root_device: index == 0,
                is_read_only: block.read_only,
                discard: caps.block_discard,
            }
            .body();
            FcApiPut {
                path: format!("/drives/{drive_id}"),
                body,
            }
        })
        .collect()
}
