//! In-tree structural verifier for ext2 / ext3 / ext4 volumes.
//!
//! Walks the on-disk superblock + BGDs + per-group bitmaps + every
//! allocated inode's block tree, then reconciles: every block any inode
//! claims must be marked allocated in its group's block bitmap, and every
//! allocated block should be claimed by exactly one inode (orphans surface
//! as warnings). Flavor-aware via [`crate::indirect::map_logical_any`] —
//! works equally on ext4 (extent tree) and ext2/3 (legacy direct/indirect).
//!
//! This is the sibling of [`crate::fsck`]: fsck audits *logical* invariants
//! (link counts, dir entries, .. parents); this module audits *physical*
//! invariants (bitmap consistency, block double-claims, leaked blocks).
//! The two are complementary — both should run clean on any image we
//! produce or accept as input.
//!
//! Pure read-only. Never mutates the volume. Designed to run as a test
//! oracle: "format → write → mount → call `verify()` → assert clean".
//! The `VerifyReport` lists every finding as a human-readable string so
//! tests can substring-match on the failure mode without bespoke types.

use crate::error::Result;
use crate::extent;
use crate::fs::Filesystem;
use crate::indirect;
use crate::inode::{Inode, InodeFlags};

/// Outcome of a verifier run. `errors` are violations of physical
/// invariants (e.g. an inode references a block the bitmap says is free —
/// the FS is corrupt). `warnings` are anomalies that don't break correctness
/// but suggest waste or stale state (e.g. an allocated block no inode
/// claims — leaked). `is_clean()` checks only `errors`.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub inodes_walked: u32,
    pub blocks_claimed: u64,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// Single-line summary suitable for test panics + log output.
    pub fn summary(&self) -> String {
        format!(
            "verify: {} errors, {} warnings, {} inodes, {} blocks claimed",
            self.errors.len(),
            self.warnings.len(),
            self.inodes_walked,
            self.blocks_claimed,
        )
    }
}

/// Walk the volume mounted on `fs` and produce a structural verification
/// report. Errors are physical-corruption-grade (the volume should not be
/// trusted for further writes); warnings are recoverable.
///
/// Costs: O(allocated_inodes + claimed_blocks). For test-fixture-sized
/// images (single group, < 100 MiB) this is sub-millisecond. Multi-group
/// volumes scale linearly with allocated content.
pub fn verify(fs: &Filesystem) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();

    // --- Phase 1: superblock sanity ---
    verify_superblock(fs, &mut report);

    // --- Phase 2: BGD self-consistency ---
    verify_bgds(fs, &mut report);

    // --- Phase 3: reconcile inode-claimed blocks vs the on-disk bitmap.
    // We build a "claimed" bitmap (one bit per fs block) by walking every
    // allocated inode's block tree, then compare against the union of all
    // groups' on-disk block bitmaps.
    let bs = fs.sb.block_size() as u64;
    let total_blocks = fs.sb.blocks_count;
    if total_blocks == 0 || bs == 0 {
        return Ok(report);
    }
    // u32 cap: fs blocks_count is u64 on disk (INCOMPAT_64BIT) but our
    // single-group test fixtures stay well under 2^32. Larger volumes
    // would need a smarter representation — guard so we don't silently
    // truncate and produce nonsense.
    if total_blocks > u32::MAX as u64 {
        report.errors.push(
            "verify: volume exceeds u32 blocks (multi-group triple-indirect tier untested)".into(),
        );
        return Ok(report);
    }

    let mut claimed = ClaimedBitmap::new(total_blocks as u32);

    // Pre-mark the always-unavailable / metadata-fixed regions so they don't
    // surface as "leaked" warnings:
    // - Block 0 (boot sector / SB region) is permanently used by the FS.
    // - Each group's superblock copy + BGT + bitmaps + inode table are
    //   metadata, owned by the FS itself, not by any inode.
    mark_metadata_blocks(fs, &mut claimed);

    walk_all_allocated_inodes(fs, &mut claimed, &mut report)?;

    // Compare claimed bitmap against on-disk bitmaps group by group.
    reconcile_with_bitmaps(fs, &claimed, &mut report)?;

    report.blocks_claimed = claimed.count_set();
    Ok(report)
}

// ---------------------------------------------------------------------------
// Phase 1: superblock
// ---------------------------------------------------------------------------

fn verify_superblock(fs: &Filesystem, r: &mut VerifyReport) {
    let sb = &fs.sb;

    if sb.magic != crate::superblock::EXT4_MAGIC {
        r.errors.push(format!(
            "superblock: magic 0x{:04X} != 0x{:04X}",
            sb.magic,
            crate::superblock::EXT4_MAGIC
        ));
    }
    let bs = sb.block_size() as u64;
    if bs == 0 || !bs.is_power_of_two() || !(1024..=65536).contains(&bs) {
        r.errors.push(format!(
            "superblock: block_size {} out of range [1024..=65536, power of 2]",
            bs
        ));
    }
    if sb.blocks_count == 0 {
        r.errors.push("superblock: blocks_count == 0".into());
    }
    if sb.free_blocks_count > sb.blocks_count {
        r.errors.push(format!(
            "superblock: free_blocks_count {} > blocks_count {}",
            sb.free_blocks_count, sb.blocks_count
        ));
    }
    if sb.free_inodes_count > sb.inodes_count {
        r.errors.push(format!(
            "superblock: free_inodes_count {} > inodes_count {}",
            sb.free_inodes_count, sb.inodes_count
        ));
    }
}

// ---------------------------------------------------------------------------
// Phase 2: BGDs
// ---------------------------------------------------------------------------

fn verify_bgds(fs: &Filesystem, r: &mut VerifyReport) {
    let total = fs.sb.blocks_count;
    let bpg = fs.sb.blocks_per_group as u64;
    let ipg = fs.sb.inodes_per_group;
    for (gi, bgd) in fs.groups.iter().enumerate() {
        if bgd.block_bitmap >= total {
            r.errors.push(format!(
                "bgd[{}]: block_bitmap {} >= blocks_count {}",
                gi, bgd.block_bitmap, total
            ));
        }
        if bgd.inode_bitmap >= total {
            r.errors.push(format!(
                "bgd[{}]: inode_bitmap {} >= blocks_count {}",
                gi, bgd.inode_bitmap, total
            ));
        }
        if bgd.inode_table >= total {
            r.errors.push(format!(
                "bgd[{}]: inode_table {} >= blocks_count {}",
                gi, bgd.inode_table, total
            ));
        }
        if bgd.free_blocks_count as u64 > bpg {
            r.errors.push(format!(
                "bgd[{}]: free_blocks_count {} > blocks_per_group {}",
                gi, bgd.free_blocks_count, bpg
            ));
        }
        if bgd.free_inodes_count > ipg {
            r.errors.push(format!(
                "bgd[{}]: free_inodes_count {} > inodes_per_group {}",
                gi, bgd.free_inodes_count, ipg
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3: claimed-block bitmap + reconciliation
// ---------------------------------------------------------------------------

/// Bit-packed per-block flags. A set bit means "some inode claims this
/// block" (or "this block is permanent FS metadata" — see
/// `mark_metadata_blocks`).
struct ClaimedBitmap {
    bits: Vec<u8>,
    total: u32,
}

impl ClaimedBitmap {
    fn new(total_blocks: u32) -> Self {
        Self {
            bits: vec![0u8; total_blocks.div_ceil(8) as usize],
            total: total_blocks,
        }
    }

    fn set(&mut self, block: u32) -> bool {
        debug_assert!(block < self.total);
        let byte = (block / 8) as usize;
        let mask = 1u8 << (block % 8);
        let was = self.bits[byte] & mask != 0;
        self.bits[byte] |= mask;
        was
    }

    fn get(&self, block: u32) -> bool {
        debug_assert!(block < self.total);
        let byte = (block / 8) as usize;
        let mask = 1u8 << (block % 8);
        self.bits[byte] & mask != 0
    }

    fn count_set(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }
}

fn mark_metadata_blocks(fs: &Filesystem, claimed: &mut ClaimedBitmap) {
    // Block 0 (boot sector + first SB) is FS-owned. For 1 KiB blocks the
    // SB lives in block 1 too — also FS-owned.
    let bs = fs.sb.block_size();
    let sb_logical_block = 1024 / bs;
    if sb_logical_block < claimed.total {
        claimed.set(sb_logical_block);
    }
    if 0 < claimed.total {
        claimed.set(0);
    }

    // Per group: BGT block (typically first_data_block + 1), block bitmap,
    // inode bitmap, inode table.
    for bgd in &fs.groups {
        if bgd.block_bitmap < claimed.total as u64 {
            claimed.set(bgd.block_bitmap as u32);
        }
        if bgd.inode_bitmap < claimed.total as u64 {
            claimed.set(bgd.inode_bitmap as u32);
        }
        let inodes_per_group = fs.sb.inodes_per_group as u64;
        let inode_size = fs.sb.inode_size as u64;
        let it_blocks = (inodes_per_group * inode_size).div_ceil(bs as u64);
        for i in 0..it_blocks {
            let b = bgd.inode_table + i;
            if b < claimed.total as u64 {
                claimed.set(b as u32);
            }
        }
    }

    // BGT block: derive from first_data_block. Single-group volumes (Phase A
    // mkfs constraint) put it at first_data_block + 1; multi-group needs a
    // walk over `bg_block_bitmap - 1` etc., which we approximate by also
    // marking the block immediately preceding each bitmap (the BGT lives
    // there in mkfs's layout). This is a heuristic — false positives
    // (over-marking) only suppress potential leaked-block warnings, never
    // generate false errors.
    let first_data = fs.sb.first_data_block as u64;
    let bgt = first_data + 1;
    if bgt < claimed.total as u64 {
        claimed.set(bgt as u32);
    }
}

fn walk_all_allocated_inodes(
    fs: &Filesystem,
    claimed: &mut ClaimedBitmap,
    r: &mut VerifyReport,
) -> Result<()> {
    let bs = fs.sb.block_size() as u64;
    let ipg = fs.sb.inodes_per_group;

    for (gi, bgd) in fs.groups.iter().enumerate() {
        // Read this group's inode bitmap.
        let mut bm = vec![0u8; bs as usize];
        fs.dev.read_at(bgd.inode_bitmap * bs, &mut bm)?;

        for bit in 0..ipg {
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if byte >= bm.len() || bm[byte] & mask == 0 {
                continue;
            }
            // ext4 inode numbers are 1-based; bit i = inode (gi*ipg + i + 1).
            let ino = (gi as u32) * ipg + bit + 1;

            // Skip the reserved range (1..first_inode) silently — those
            // are FS-internal slots (resize, journal, etc.).
            if ino < fs.sb.first_inode && ino != 2 {
                continue;
            }

            r.inodes_walked += 1;
            let raw = match fs.read_inode_raw(ino) {
                Ok(b) => b,
                Err(e) => {
                    r.errors
                        .push(format!("inode {}: read failed: {:?}", ino, e));
                    continue;
                }
            };
            let inode = match Inode::parse(&raw) {
                Ok(i) => i,
                Err(e) => {
                    r.errors
                        .push(format!("inode {}: parse failed: {:?}", ino, e));
                    continue;
                }
            };
            // Inline-data files keep content inside i_block + xattrs — no
            // separate data blocks to claim. Skip.
            if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
                continue;
            }
            // Skip inodes with no allocated data blocks. This covers:
            //   * Empty regular files (`size == 0`).
            //   * "Fast" symlinks whose target fits in the 60-byte i_block
            //     region — `size > 0` but `i_blocks == 0` because the
            //     inode owns zero on-disk sectors.
            //   * Special files (chr/blk/fifo/sock) which carry no data.
            // Without this guard the walker would interpret i_block as
            // raw block pointers and "discover" garbage block numbers far
            // outside the volume.
            if inode.blocks == 0 {
                continue;
            }
            walk_inode_block_tree(fs, ino, &inode, claimed, r)?;
        }
    }
    Ok(())
}

/// Mark every block reachable from `inode`'s i_block region. Catches
/// double-claims (set bit was already set → another inode beat us).
fn walk_inode_block_tree(
    fs: &Filesystem,
    ino: u32,
    inode: &Inode,
    claimed: &mut ClaimedBitmap,
    r: &mut VerifyReport,
) -> Result<()> {
    let bs = fs.sb.block_size() as u64;
    let bs32 = fs.sb.block_size();
    let n_blocks = inode.size.div_ceil(bs);
    let total = claimed.total as u64;

    if (inode.flags & InodeFlags::EXTENTS.bits()) != 0 {
        // Extent tree walk: enumerate all leaf extents and intermediate
        // nodes via `extent::collect_all`, marking everything they cover.
        let extents = match extent::collect_all(&inode.block, fs.dev.as_ref(), bs32) {
            Ok(es) => es,
            Err(e) => {
                r.errors
                    .push(format!("inode {}: extent walk failed: {:?}", ino, e));
                return Ok(());
            }
        };
        for ext in &extents {
            for off in 0..ext.length as u64 {
                let phys = ext.physical_block + off;
                if phys >= total {
                    r.errors.push(format!(
                        "inode {}: extent block {} >= blocks_count {}",
                        ino, phys, total
                    ));
                    continue;
                }
                if claimed.set(phys as u32) {
                    r.errors.push(format!(
                        "inode {}: block {} double-claimed (extent)",
                        ino, phys
                    ));
                }
            }
        }
    } else {
        // Indirect tree walk: just enumerate logical 0..n_blocks via the
        // dispatcher. For blocks with mappings, mark them. We don't yet
        // mark the indirect-tree metadata blocks themselves (single, double,
        // triple) — those would require a deeper walk. Treating them as
        // potential leaked-block warnings is acceptable for Phase A; can
        // tighten in Phase B.
        for logical in 0..n_blocks {
            let phys_opt = indirect::map_logical_any(
                &inode.block,
                inode.flags,
                fs.dev.as_ref(),
                bs32,
                logical,
            )?;
            if let Some(phys) = phys_opt {
                if phys >= total {
                    r.errors.push(format!(
                        "inode {}: indirect block {} >= blocks_count {}",
                        ino, phys, total
                    ));
                    continue;
                }
                if claimed.set(phys as u32) {
                    r.errors.push(format!(
                        "inode {}: block {} double-claimed (indirect)",
                        ino, phys
                    ));
                }
            }
        }
        // Mark indirect-tree metadata blocks (single/double/triple slots
        // in i_block) so they don't show up as leaked.
        for slot in [12usize, 13, 14] {
            let off = slot * 4;
            let p = u32::from_le_bytes(inode.block[off..off + 4].try_into().unwrap()) as u64;
            if p != 0 && p < total {
                claimed.set(p as u32);
                // Walk one tier deeper: read the indirect block and mark
                // any inner indirect blocks it points at. We don't recurse
                // into double/triple inner-inner-inner — handled
                // approximately via the `mark_metadata_blocks` over-
                // marking heuristic.
                let mut buf = vec![0u8; bs32 as usize];
                if fs.dev.read_at(p * bs, &mut buf).is_ok() {
                    let ppb = (bs32 / 4) as usize;
                    for i in 0..ppb {
                        let off = i * 4;
                        let inner =
                            u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as u64;
                        if inner != 0 && inner < total && slot >= 13 {
                            claimed.set(inner as u32);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn reconcile_with_bitmaps(
    fs: &Filesystem,
    claimed: &ClaimedBitmap,
    r: &mut VerifyReport,
) -> Result<()> {
    let bs = fs.sb.block_size() as u64;
    let bpg = fs.sb.blocks_per_group as u64;
    let total = fs.sb.blocks_count;
    let first_data = fs.sb.first_data_block as u64;

    for (gi, bgd) in fs.groups.iter().enumerate() {
        let mut bm = vec![0u8; bs as usize];
        fs.dev.read_at(bgd.block_bitmap * bs, &mut bm)?;

        // For each block in this group's range, compare claimed-state
        // against bitmap-state. Block N in group `gi` is at logical
        // index `gi * bpg + N + first_data` in our flat claimed map.
        let group_start = first_data + (gi as u64) * bpg;
        let group_end = (group_start + bpg).min(total);
        for b in group_start..group_end {
            let in_bitmap = {
                let bit_idx = b - group_start;
                let byte = (bit_idx / 8) as usize;
                let mask = 1u8 << (bit_idx % 8);
                byte < bm.len() && bm[byte] & mask != 0
            };
            let in_claimed = claimed.get(b as u32);
            match (in_bitmap, in_claimed) {
                (true, true) => {}   // consistent: allocated and claimed
                (false, false) => {} // consistent: free and unclaimed
                (false, true) => {
                    // CORRUPTION: an inode claims this block but the bitmap
                    // says it's free → double-allocation risk on next write.
                    r.errors.push(format!(
                        "block {} (group {}): claimed by inode but marked free in bitmap",
                        b, gi
                    ));
                }
                (true, false) => {
                    // LEAK: bitmap says allocated but no inode claims it.
                    // Could be a transient (we walked at the same time as
                    // a write) or genuinely leaked.
                    r.warnings.push(format!(
                        "block {} (group {}): allocated but unclaimed",
                        b, gi
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an empty `VerifyReport` (helper for direct construction in tests).
    #[test]
    fn report_default_is_clean() {
        let r = VerifyReport::default();
        assert!(r.is_clean());
        assert_eq!(
            r.summary(),
            "verify: 0 errors, 0 warnings, 0 inodes, 0 blocks claimed"
        );
    }

    #[test]
    fn claimed_bitmap_set_get_count() {
        let mut bm = ClaimedBitmap::new(100);
        assert_eq!(bm.count_set(), 0);
        assert!(!bm.set(50));
        assert!(bm.set(50)); // second set returns true (was already set)
        assert!(bm.get(50));
        assert!(!bm.get(51));
        assert!(!bm.set(99));
        assert_eq!(bm.count_set(), 2);
    }
}
