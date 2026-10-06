//! Block-group geometry and the data-block allocator: how many groups an
//! image needs, where each group's metadata and data sit, which data blocks
//! the tree occupies, and which are left free for a guest that writes.

use super::{
    BLOCK_SIZE, BLOCKS_PER_GROUP, Ext4Error, Extent, INODE_SIZE, MAX_GROUPS, MIN_INODES_PER_GROUP,
    ceil_div_u32, round_up_8,
};

/// Resolved on-disk geometry: how many block groups, where each group's
/// metadata and data live, and how inodes map to groups. Every field is a pure
/// function of the tree's size and the requested free space, so the layout — and thus the
/// image bytes — are deterministic.
pub(super) struct Layout {
    pub(super) groups: u32,
    pub(super) inodes_per_group: u32,
    pub(super) gdt_blocks: u32,
    /// Metadata blocks at the start of every group: 1 (superblock/backup) +
    /// gdt_blocks + 1 (block bitmap) + 1 (inode bitmap) + inode-table blocks.
    pub(super) prefix: u32,
    pub(super) total_blocks: u32,
    pub(super) inode_slots: u32,
    /// Highest inode number in use (inodes `1..=used_inodes` are all occupied:
    /// the reserved 1..=10, root at 2, then our nodes contiguously).
    pub(super) used_inodes: u32,
    /// Data-region blocks the tree occupies. The allocator fills the data
    /// regions in order, so every data block past this count is free.
    pub(super) used_data_blocks: u64,
}

impl Layout {
    /// Geometry for `used_data_blocks` of tree data plus `free_blocks` left
    /// unallocated, and `inode_high` plus `free_inodes` inode slots.
    pub(super) fn plan(
        inode_high: u32,
        used_data_blocks: u64,
        free_blocks: u32,
        free_inodes: u32,
    ) -> Result<Self, Ext4Error> {
        let used_inodes = inode_high.saturating_sub(1);
        let data_blocks_total = used_data_blocks + u64::from(free_blocks);
        let inode_need = inode_high.saturating_add(free_inodes);
        for groups in 1..=MAX_GROUPS {
            let gdt_blocks = ceil_div_u32(groups.saturating_mul(32), BLOCK_SIZE);
            let per_group_need = ceil_div_u32(inode_need, groups).max(MIN_INODES_PER_GROUP);
            let inodes_per_group = round_up_8(per_group_need);
            // One inode-bitmap block addresses at most this many slots.
            if inodes_per_group > BLOCK_SIZE * 8 {
                continue;
            }
            let itb_per_group = ceil_div_u32(inodes_per_group * INODE_SIZE as u32, BLOCK_SIZE);
            let prefix = 3 + gdt_blocks + itb_per_group;
            // A group whose metadata leaves no room for data can't help; a
            // larger group count shrinks inodes_per_group and thus the prefix.
            if prefix >= BLOCKS_PER_GROUP {
                continue;
            }
            let data_per_group = (BLOCKS_PER_GROUP - prefix) as u64;
            let capacity = groups as u64 * data_per_group;
            if capacity < data_blocks_total {
                continue;
            }
            // Trim the final group to exactly the data it holds so the image is
            // no larger than the tree needs (verity hashes every byte).
            let full_groups = (groups - 1) as u64;
            let last_data = data_blocks_total - full_groups * data_per_group; // >= 1
            let total = full_groups * BLOCKS_PER_GROUP as u64 + prefix as u64 + last_data;
            if total > u32::MAX as u64 {
                break;
            }
            return Ok(Self {
                groups,
                inodes_per_group,
                gdt_blocks,
                prefix,
                total_blocks: total as u32,
                inode_slots: inodes_per_group * groups,
                used_inodes,
                used_data_blocks,
            });
        }
        Err(Ext4Error::TooLarge {
            blocks: data_blocks_total,
        })
    }

    pub(super) fn group_start(&self, g: u32) -> u32 {
        g * BLOCKS_PER_GROUP
    }
    pub(super) fn block_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 1 + self.gdt_blocks
    }
    pub(super) fn inode_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 2 + self.gdt_blocks
    }
    pub(super) fn inode_table(&self, g: u32) -> u32 {
        self.group_start(g) + 3 + self.gdt_blocks
    }
    pub(super) fn data_start(&self, g: u32) -> u32 {
        self.group_start(g) + self.prefix
    }
    pub(super) fn group_end(&self, g: u32) -> u32 {
        ((g + 1) * BLOCKS_PER_GROUP).min(self.total_blocks)
    }
    /// `(group, local index)` of an inode number (1-based).
    pub(super) fn locate_inode(&self, ino: u32) -> (u32, u32) {
        (
            (ino - 1) / self.inodes_per_group,
            (ino - 1) % self.inodes_per_group,
        )
    }
    /// Free data blocks in group `g`: the part of its data region past the
    /// blocks the allocator handed out, which fills regions in group order.
    pub(super) fn free_data_blocks(&self, g: u32) -> u32 {
        let mut used_remaining = self.used_data_blocks;
        for group in 0..self.groups {
            let len = self.group_end(group).saturating_sub(self.data_start(group));
            let used_here = used_remaining.min(u64::from(len)) as u32;
            if group == g {
                return len - used_here;
            }
            used_remaining -= u64::from(used_here);
        }
        0
    }

    /// Per-group data regions, in order, that the allocator hands out.
    pub(super) fn data_regions(&self) -> Vec<(u32, u32)> {
        (0..self.groups)
            .filter_map(|g| {
                let start = self.data_start(g);
                let end = self.group_end(g);
                (end > start).then_some((start, end - start))
            })
            .collect()
    }
}

/// Hands out physical blocks from each group's data region in order, splitting
/// a request into one [`Extent`] per region it spans (so no extent ever crosses
/// a group's metadata prefix).
pub(super) struct RegionAllocator {
    regions: Vec<(u32, u32)>,
    ridx: usize,
    roff: u32,
}

impl RegionAllocator {
    pub(super) fn new(layout: &Layout) -> Self {
        Self {
            regions: layout.data_regions(),
            ridx: 0,
            roff: 0,
        }
    }

    pub(super) fn take(&mut self, blocks: u32) -> Vec<Extent> {
        let mut out = Vec::new();
        let mut logical = 0u32;
        let mut remaining = blocks;
        while remaining > 0 {
            let (start, len) = self.regions[self.ridx];
            let avail = len - self.roff;
            let n = avail.min(remaining);
            out.push(Extent {
                logical,
                len: n,
                phys: start + self.roff,
            });
            self.roff += n;
            logical += n;
            remaining -= n;
            if self.roff == len {
                self.ridx += 1;
                self.roff = 0;
            }
        }
        out
    }
}
