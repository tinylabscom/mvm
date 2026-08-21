//! Mutation primitives for the legacy direct/indirect block-pointer scheme
//! used by ext2 / ext3 (and ext4 inodes that opt out of extents).
//!
//! Two pure-data planners — neither touches the device or the global inode
//! state. The caller is responsible for: invoking the allocator, marking the
//! allocated blocks in the on-disk block bitmap, persisting the indirect
//! tree's block writes, updating BGD/SB counters, and finally publishing the
//! new inode.
//!
//! Companions to `extent_mut.rs`. Same architectural split: planning is pure
//! and unit-testable; the IO/concurrency story lives in `fs.rs`.
//!
//! Spec source: kernel.org/doc/html/latest/filesystems/ext4/blockmap.html
//! (the same scheme ext4 inherited from ext2/ext3) and Carrier,
//! *File System Forensic Analysis*, ch. 14.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};

/// Number of direct block pointers in `i_block` (slots 0..=11).
pub const DIRECT_COUNT: u32 = 12;

#[inline]
fn ppb(block_size: u32) -> u32 {
    block_size / 4
}

#[inline]
fn write_u32_le(buf: &mut [u8], idx: usize, val: u32) {
    let off = idx * 4;
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn read_u32_le(buf: &[u8], idx: usize) -> u32 {
    let off = idx * 4;
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Plan output: the new `i_block` region, plus the indirect-block writes the
/// caller MUST persist before publishing the inode, plus the list of physical
/// blocks the planner allocated for the indirect tree (which the caller must
/// mark in the block bitmap and credit against BGD/SB counters).
///
/// The data blocks themselves are NOT in `block_writes` — `plan_contiguous`
/// does not own data; it only tracks the indirect-tree metadata blocks. The
/// caller already knows the data block range and writes the payload there
/// directly.
#[derive(Debug, Clone)]
pub struct IndirectPlan {
    pub i_block: [u8; 60],
    pub block_writes: Vec<(u64, Vec<u8>)>,
    pub indirect_blocks_allocated: Vec<u64>,
}

/// Count the indirect-tree metadata blocks needed to address `data_blocks`
/// data blocks via the legacy direct/indirect scheme at `block_size`.
///
/// This lets a caller pre-allocate one contiguous run sized for both the
/// data payload AND the indirect tree, eliminating a second round-trip
/// through the block allocator.
///
/// Counts (for `ppb = block_size / 4`):
/// - 0 if `data_blocks <= 12`
/// - 1 if `data_blocks <= 12 + ppb` (one single-indirect block)
/// - `1 + 1 + ceil((data_blocks - 12 - ppb) / ppb)` for the double tier
///   (single-indirect + double-outer + double-inners)
/// - additional L1 + ceil(remaining / ppb²) L2 + ceil(remaining / ppb) L3
///   for the triple tier
pub fn count_indirect_blocks(data_blocks: u32, block_size: u32) -> u64 {
    let ppb = (block_size / 4) as u64;
    if ppb == 0 {
        return 0;
    }
    let mut remaining = data_blocks as u64;
    let mut count: u64 = 0;

    // Tier 1 (direct): no indirect blocks.
    if remaining <= DIRECT_COUNT as u64 {
        return 0;
    }
    remaining -= DIRECT_COUNT as u64;

    // Tier 2 (single indirect): 1 indirect block holds up to ppb pointers.
    count += 1;
    if remaining <= ppb {
        return count;
    }
    remaining -= ppb;

    // Tier 3 (double indirect): 1 outer + ceil(remaining_in_tier / ppb) inners.
    count += 1; // outer
    let in_double = remaining.min(ppb * ppb);
    count += in_double.div_ceil(ppb);
    if remaining <= ppb * ppb {
        return count;
    }
    remaining -= ppb * ppb;

    // Tier 4 (triple indirect): 1 L1 + L2 layer + L3 layer.
    count += 1; // L1
    let in_triple = remaining.min(ppb * ppb * ppb);
    let l2_count = in_triple.div_ceil(ppb * ppb);
    let l3_count = in_triple.div_ceil(ppb);
    count += l2_count + l3_count;
    count
}

/// Plan an indirect-tree layout that maps logical blocks `0..data_block_count`
/// to physical blocks `first_data_phys..first_data_phys+data_block_count`.
///
/// `alloc_one` is invoked once per indirect-tree block needed:
/// - 0 calls for `count <= 12`
/// - 1 call for `count <= 12 + ppb`
/// - `1 + ceil((count - 12 - ppb) / ppb)` calls in the double-indirect tier
/// - additional calls in the triple-indirect tier
///
/// All pointers are 32-bit (no `INCOMPAT_64BIT` for ext2/3 in any production
/// deployment), so this errors if any input physical block exceeds `u32::MAX`
/// or if `data_block_count` exceeds the triple-indirect address span.
pub fn plan_contiguous<F>(
    data_block_count: u32,
    first_data_phys: u64,
    block_size: u32,
    mut alloc_one: F,
) -> Result<IndirectPlan>
where
    F: FnMut() -> Result<u64>,
{
    if !block_size.is_power_of_two() || block_size < 1024 {
        return Err(Error::InvalidArgument(
            "indirect_mut: block_size out of range",
        ));
    }
    let ppb = ppb(block_size);
    if ppb == 0 {
        return Err(Error::InvalidArgument(
            "indirect_mut: block_size too small for any pointers",
        ));
    }

    let mut plan = IndirectPlan {
        i_block: [0u8; 60],
        block_writes: Vec::new(),
        indirect_blocks_allocated: Vec::new(),
    };

    // Bounds: all data block addresses must fit in u32.
    let last_data_phys = first_data_phys
        .checked_add(data_block_count.saturating_sub(1) as u64)
        .ok_or(Error::InvalidArgument(
            "indirect_mut: physical address overflow",
        ))?;
    if last_data_phys > u32::MAX as u64 {
        return Err(Error::InvalidArgument(
            "indirect_mut: data physical block exceeds u32 (ext2/3 cap)",
        ));
    }

    let mut remaining = data_block_count;
    let mut logical_offset: u32 = 0;

    // Helper: write a contiguous run of data pointers into `buf` starting at
    // `idx` for `n` pointers. Returns the number of pointers written.
    let emit_data_ptrs = |buf: &mut [u8], idx: usize, n: u32, base: u32| {
        for i in 0..n {
            write_u32_le(buf, idx + i as usize, base + i);
        }
    };

    // ---------- Tier 1: direct (i_block[0..12]) ----------
    {
        let direct_count = remaining.min(DIRECT_COUNT);
        let base = (first_data_phys + logical_offset as u64) as u32;
        emit_data_ptrs(&mut plan.i_block, 0, direct_count, base);
        remaining -= direct_count;
        logical_offset += direct_count;
    }
    if remaining == 0 {
        return Ok(plan);
    }

    // ---------- Tier 2: single indirect (i_block[12]) ----------
    {
        let single_blk = alloc_one()?;
        check_u32(single_blk, "single-indirect block")?;
        plan.indirect_blocks_allocated.push(single_blk);
        write_u32_le(&mut plan.i_block, 12, single_blk as u32);

        let n = remaining.min(ppb);
        let mut buf = vec![0u8; block_size as usize];
        let base = (first_data_phys + logical_offset as u64) as u32;
        emit_data_ptrs(&mut buf, 0, n, base);
        plan.block_writes.push((single_blk, buf));

        remaining -= n;
        logical_offset += n;
    }
    if remaining == 0 {
        return Ok(plan);
    }

    // ---------- Tier 3: double indirect (i_block[13]) ----------
    {
        let outer_blk = alloc_one()?;
        check_u32(outer_blk, "double-indirect outer block")?;
        plan.indirect_blocks_allocated.push(outer_blk);
        write_u32_le(&mut plan.i_block, 13, outer_blk as u32);

        // Cap this tier's contribution at ppb*ppb data pointers.
        let tier_capacity = ppb as u64 * ppb as u64;
        let tier_count = (remaining as u64).min(tier_capacity) as u32;
        let inner_blocks_needed = tier_count.div_ceil(ppb);

        let mut outer_buf = vec![0u8; block_size as usize];
        for outer_idx in 0..inner_blocks_needed {
            let inner_blk = alloc_one()?;
            check_u32(inner_blk, "double-indirect inner block")?;
            plan.indirect_blocks_allocated.push(inner_blk);
            write_u32_le(&mut outer_buf, outer_idx as usize, inner_blk as u32);

            let inner_count = remaining.min(ppb);
            let mut inner_buf = vec![0u8; block_size as usize];
            let base = (first_data_phys + logical_offset as u64) as u32;
            emit_data_ptrs(&mut inner_buf, 0, inner_count, base);
            plan.block_writes.push((inner_blk, inner_buf));

            remaining -= inner_count;
            logical_offset += inner_count;
        }
        plan.block_writes.push((outer_blk, outer_buf));
    }
    if remaining == 0 {
        return Ok(plan);
    }

    // ---------- Tier 4: triple indirect (i_block[14]) ----------
    {
        let l1_blk = alloc_one()?;
        check_u32(l1_blk, "triple-indirect L1 block")?;
        plan.indirect_blocks_allocated.push(l1_blk);
        write_u32_le(&mut plan.i_block, 14, l1_blk as u32);

        let tier_capacity = ppb as u64 * ppb as u64 * ppb as u64;
        let tier_count = (remaining as u64).min(tier_capacity) as u32;
        let l2_blocks_needed = tier_count.div_ceil(ppb * ppb);

        let mut l1_buf = vec![0u8; block_size as usize];
        for l1_idx in 0..l2_blocks_needed {
            let l2_blk = alloc_one()?;
            check_u32(l2_blk, "triple-indirect L2 block")?;
            plan.indirect_blocks_allocated.push(l2_blk);
            write_u32_le(&mut l1_buf, l1_idx as usize, l2_blk as u32);

            // L2 block holds up to ppb pointers; each points at an L3 block
            // holding up to ppb data pointers.
            let l3_capacity_under_this_l2 = ppb as u64 * ppb as u64;
            let l3_count = (remaining as u64).min(l3_capacity_under_this_l2) as u32;
            let l3_blocks_needed = l3_count.div_ceil(ppb);

            let mut l2_buf = vec![0u8; block_size as usize];
            for l2_idx in 0..l3_blocks_needed {
                let l3_blk = alloc_one()?;
                check_u32(l3_blk, "triple-indirect L3 block")?;
                plan.indirect_blocks_allocated.push(l3_blk);
                write_u32_le(&mut l2_buf, l2_idx as usize, l3_blk as u32);

                let inner_count = remaining.min(ppb);
                let mut l3_buf = vec![0u8; block_size as usize];
                let base = (first_data_phys + logical_offset as u64) as u32;
                emit_data_ptrs(&mut l3_buf, 0, inner_count, base);
                plan.block_writes.push((l3_blk, l3_buf));

                remaining -= inner_count;
                logical_offset += inner_count;
            }
            plan.block_writes.push((l2_blk, l2_buf));
        }
        plan.block_writes.push((l1_blk, l1_buf));
    }

    if remaining > 0 {
        return Err(Error::InvalidArgument(
            "indirect_mut: data block count exceeds triple-indirect address space",
        ));
    }
    Ok(plan)
}

fn check_u32(v: u64, what: &'static str) -> Result<()> {
    if v > u32::MAX as u64 {
        // Static string only — Error::Corrupt takes &'static str. Use a
        // generic message; the `what` is for future logging once we have it.
        let _ = what;
        return Err(Error::Corrupt(
            "indirect_mut: indirect block address exceeds u32 (ext2/3 cap)",
        ));
    }
    Ok(())
}

/// Coalesced run of contiguous data blocks slated for freeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeRun {
    pub start: u64,
    pub len: u32,
}

/// Lists a truncate-to-zero produces:
/// - `data_runs`: data blocks, coalesced into contiguous runs (caller frees
///   via the block bitmap; `start..start+len` clears one bitmap range).
/// - `indirect_blocks`: every indirect-tree block reachable from the inode
///   (single block freed each — they're rarely contiguous with each other
///   or with the data, so leaving them as singletons is correct).
#[derive(Debug, Clone, Default)]
pub struct FreedBlocks {
    pub data_runs: Vec<FreeRun>,
    pub indirect_blocks: Vec<u64>,
}

/// Walk the indirect tree rooted in `i_block` and gather every physical
/// block reachable from it (data + indirect). Used by truncate-to-zero
/// before zeroing the inode's block-pointer region.
///
/// Sparse holes (zero pointers) are skipped — they reference no on-disk
/// blocks, so there is nothing to free.
///
/// `expected_data_blocks` lets the caller cap the walk at the file's
/// declared size (so trailing tier capacity beyond `inode.size` doesn't
/// dredge up garbage pointers from beyond-EOF). Pass `u32::MAX` to walk
/// the full address space.
pub fn collect_for_free(
    i_block: &[u8; 60],
    block_size: u32,
    expected_data_blocks: u32,
    dev: &dyn BlockDevice,
) -> Result<FreedBlocks> {
    if !block_size.is_power_of_two() || block_size < 1024 {
        return Err(Error::InvalidArgument(
            "indirect_mut: block_size out of range",
        ));
    }
    let ppb = ppb(block_size);

    let mut data_blocks: Vec<u64> = Vec::new();
    let mut indirect_blocks: Vec<u64> = Vec::new();
    let mut remaining = expected_data_blocks as u64;

    // Tier 1: direct. The first 12 logical blocks live inline.
    let direct_count = (remaining.min(DIRECT_COUNT as u64)) as usize;
    for i in 0..direct_count {
        let p = read_u32_le(i_block, i) as u64;
        if p != 0 {
            data_blocks.push(p);
        }
    }
    remaining = remaining.saturating_sub(direct_count as u64);

    // Tier 2: single indirect.
    let single_blk = read_u32_le(i_block, 12) as u64;
    if remaining > 0 && single_blk != 0 {
        indirect_blocks.push(single_blk);
        let buf = read_block(dev, single_blk, block_size)?;
        let take = remaining.min(ppb as u64) as usize;
        for i in 0..take {
            let p = read_u32_le(&buf, i) as u64;
            if p != 0 {
                data_blocks.push(p);
            }
        }
        remaining = remaining.saturating_sub(take as u64);
    } else {
        remaining = remaining.saturating_sub(ppb as u64);
    }

    // Tier 3: double indirect.
    let double_blk = read_u32_le(i_block, 13) as u64;
    if remaining > 0 && double_blk != 0 {
        indirect_blocks.push(double_blk);
        let outer = read_block(dev, double_blk, block_size)?;
        let outer_take = remaining.min(ppb as u64 * ppb as u64).div_ceil(ppb as u64) as usize;
        for outer_idx in 0..outer_take {
            let inner_blk = read_u32_le(&outer, outer_idx) as u64;
            if inner_blk == 0 {
                remaining = remaining.saturating_sub(ppb as u64);
                continue;
            }
            indirect_blocks.push(inner_blk);
            let inner = read_block(dev, inner_blk, block_size)?;
            let take = remaining.min(ppb as u64) as usize;
            for i in 0..take {
                let p = read_u32_le(&inner, i) as u64;
                if p != 0 {
                    data_blocks.push(p);
                }
            }
            remaining = remaining.saturating_sub(take as u64);
        }
    } else {
        remaining = remaining.saturating_sub(ppb as u64 * ppb as u64);
    }

    // Tier 4: triple indirect.
    let triple_blk = read_u32_le(i_block, 14) as u64;
    if remaining > 0 && triple_blk != 0 {
        indirect_blocks.push(triple_blk);
        let l1 = read_block(dev, triple_blk, block_size)?;
        let l2_count = remaining
            .min(ppb as u64 * ppb as u64 * ppb as u64)
            .div_ceil(ppb as u64 * ppb as u64) as usize;
        for l1_idx in 0..l2_count {
            let l2_blk = read_u32_le(&l1, l1_idx) as u64;
            if l2_blk == 0 {
                remaining = remaining.saturating_sub(ppb as u64 * ppb as u64);
                continue;
            }
            indirect_blocks.push(l2_blk);
            let l2 = read_block(dev, l2_blk, block_size)?;
            let l3_count = remaining.min(ppb as u64 * ppb as u64).div_ceil(ppb as u64) as usize;
            for l2_idx in 0..l3_count {
                let l3_blk = read_u32_le(&l2, l2_idx) as u64;
                if l3_blk == 0 {
                    remaining = remaining.saturating_sub(ppb as u64);
                    continue;
                }
                indirect_blocks.push(l3_blk);
                let l3 = read_block(dev, l3_blk, block_size)?;
                let take = remaining.min(ppb as u64) as usize;
                for i in 0..take {
                    let p = read_u32_le(&l3, i) as u64;
                    if p != 0 {
                        data_blocks.push(p);
                    }
                }
                remaining = remaining.saturating_sub(take as u64);
            }
        }
    }

    // Coalesce data blocks into runs. We sort + merge contiguous addresses.
    data_blocks.sort_unstable();
    data_blocks.dedup();
    let data_runs = coalesce_runs(&data_blocks);

    // Indirect blocks stay as singletons — they're scattered metadata.
    indirect_blocks.sort_unstable();
    indirect_blocks.dedup();

    Ok(FreedBlocks {
        data_runs,
        indirect_blocks,
    })
}

fn read_block(dev: &dyn BlockDevice, block_no: u64, block_size: u32) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; block_size as usize];
    let off = block_no
        .checked_mul(block_size as u64)
        .ok_or(Error::Corrupt("indirect_mut: block byte offset overflow"))?;
    dev.read_at(off, &mut buf)?;
    Ok(buf)
}

fn coalesce_runs(sorted: &[u64]) -> Vec<FreeRun> {
    let mut out: Vec<FreeRun> = Vec::new();
    for &b in sorted {
        if let Some(last) = out.last_mut() {
            if last.start + last.len as u64 == b {
                last.len += 1;
                continue;
            }
        }
        out.push(FreeRun { start: b, len: 1 });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_io::BlockDevice;
    use std::sync::Mutex;

    /// In-memory block device for tests. Mirrors the helper in `indirect.rs`
    /// — kept local rather than shared because both modules want to stay
    /// usable as standalone units.
    struct MemDev {
        data: Mutex<Vec<u8>>,
    }

    impl MemDev {
        fn new(size: usize) -> Self {
            Self {
                data: Mutex::new(vec![0u8; size]),
            }
        }
        fn write_block(&self, block_no: u64, block_size: u32, contents: &[u8]) {
            let mut d = self.data.lock().unwrap();
            let off = (block_no as usize) * (block_size as usize);
            d[off..off + contents.len()].copy_from_slice(contents);
        }
    }

    impl BlockDevice for MemDev {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let d = self.data.lock().unwrap();
            let start = offset as usize;
            buf.copy_from_slice(&d[start..start + buf.len()]);
            Ok(())
        }
        fn size_bytes(&self) -> u64 {
            self.data.lock().unwrap().len() as u64
        }
    }

    /// Bump-allocator: returns sequential block numbers starting at `next`.
    fn make_alloc(start: u64) -> impl FnMut() -> Result<u64> {
        let mut next = start;
        move || {
            let v = next;
            next += 1;
            Ok(v)
        }
    }

    #[test]
    fn plan_contiguous_direct_only() {
        let bs = 1024u32;
        let plan = plan_contiguous(5, 100, bs, make_alloc(1000)).unwrap();
        assert!(plan.indirect_blocks_allocated.is_empty());
        assert!(plan.block_writes.is_empty());
        for i in 0..5 {
            assert_eq!(read_u32_le(&plan.i_block, i), 100 + i as u32);
        }
        // i_block[5..15] all zero (no remaining direct/indirect/double/triple).
        for i in 5..15 {
            assert_eq!(read_u32_le(&plan.i_block, i), 0);
        }
    }

    #[test]
    fn plan_contiguous_fills_all_direct() {
        let bs = 1024u32;
        let plan = plan_contiguous(12, 200, bs, make_alloc(500)).unwrap();
        assert!(plan.indirect_blocks_allocated.is_empty());
        assert!(plan.block_writes.is_empty());
        for i in 0..12 {
            assert_eq!(read_u32_le(&plan.i_block, i), 200 + i as u32);
        }
        // i_block[12..15] zero — no indirect tier needed.
        for i in 12..15 {
            assert_eq!(read_u32_le(&plan.i_block, i), 0);
        }
    }

    #[test]
    fn plan_contiguous_into_single_indirect() {
        let bs = 1024u32; // ppb = 256
                          // 12 direct + 5 single-indirect = 17 blocks total.
        let plan = plan_contiguous(17, 300, bs, make_alloc(900)).unwrap();
        assert_eq!(plan.indirect_blocks_allocated, vec![900]);
        assert_eq!(plan.block_writes.len(), 1);
        // i_block[12] points at the indirect block.
        assert_eq!(read_u32_le(&plan.i_block, 12), 900);
        // Inner buffer holds 5 data pointers at indices 0..=4.
        let (blk_no, ref buf) = plan.block_writes[0];
        assert_eq!(blk_no, 900);
        for i in 0..5 {
            assert_eq!(read_u32_le(buf, i), 300 + 12 + i as u32);
        }
        // Index 5 onward is zero (no further data).
        assert_eq!(read_u32_le(buf, 5), 0);
    }

    #[test]
    fn plan_contiguous_fills_single_indirect_exactly() {
        let bs = 1024u32; // ppb = 256
                          // 12 direct + 256 single = 268 blocks.
        let plan = plan_contiguous(268, 1000, bs, make_alloc(50_000)).unwrap();
        assert_eq!(plan.indirect_blocks_allocated, vec![50_000]);
        assert_eq!(plan.block_writes.len(), 1);
        let (_, ref buf) = plan.block_writes[0];
        // All 256 single-indirect slots populated.
        for i in 0..256 {
            assert_eq!(read_u32_le(buf, i), 1000 + 12 + i as u32);
        }
        // i_block[13] zero — double tier not yet entered.
        assert_eq!(read_u32_le(&plan.i_block, 13), 0);
    }

    #[test]
    fn plan_contiguous_into_double_indirect() {
        let bs = 1024u32; // ppb = 256
                          // 12 direct + 256 single + 3 double = 271 blocks.
                          // Double tier needs 1 outer + ceil(3/256)=1 inner = 2 indirect blocks.
        let plan = plan_contiguous(271, 2000, bs, make_alloc(100_000)).unwrap();
        // Allocations in order: single(100000), outer(100001), inner(100002).
        assert_eq!(
            plan.indirect_blocks_allocated,
            vec![100_000, 100_001, 100_002]
        );
        assert_eq!(read_u32_le(&plan.i_block, 12), 100_000);
        assert_eq!(read_u32_le(&plan.i_block, 13), 100_001);
        assert_eq!(read_u32_le(&plan.i_block, 14), 0);

        // Find each block's buffer.
        let writes: std::collections::HashMap<u64, &Vec<u8>> =
            plan.block_writes.iter().map(|(b, v)| (*b, v)).collect();
        // Single-indirect block: 256 data pointers.
        let single_buf = writes[&100_000];
        for i in 0..256 {
            assert_eq!(read_u32_le(single_buf, i), 2000 + 12 + i as u32);
        }
        // Double outer: ptrs[0] = 100002 (the inner block).
        let outer_buf = writes[&100_001];
        assert_eq!(read_u32_le(outer_buf, 0), 100_002);
        assert_eq!(read_u32_le(outer_buf, 1), 0);
        // Double inner: 3 data pointers (logical 268, 269, 270).
        let inner_buf = writes[&100_002];
        for i in 0..3 {
            assert_eq!(read_u32_le(inner_buf, i), 2000 + 268 + i as u32);
        }
        assert_eq!(read_u32_le(inner_buf, 3), 0);
    }

    #[test]
    fn plan_contiguous_into_triple_indirect() {
        let bs = 1024u32; // ppb = 256
                          // Fill direct + all of single + all of double, then 1 block into triple.
                          // Single: 256, Double: 256*256 = 65536. Total before triple: 12 + 256 +
                          // 65536 = 65804. One past = 65805.
        let count = 65_805u32;
        let plan = plan_contiguous(count, 500_000, bs, make_alloc(1_000_000)).unwrap();
        // i_block[14] should be set; triple tier should have allocated:
        //   1 single (100000)
        //   1 double-outer (100001) + 256 double-inners (100002..100258)
        //   1 triple-l1 + 1 triple-l2 + 1 triple-l3 = 3 more blocks
        // Total: 1 + 1 + 256 + 3 = 261 indirect-tree blocks.
        assert_eq!(plan.indirect_blocks_allocated.len(), 1 + 1 + 256 + 3);
        assert_ne!(read_u32_le(&plan.i_block, 14), 0);
    }

    #[test]
    fn plan_contiguous_rejects_overflow_beyond_triple() {
        let bs = 1024u32; // ppb = 256 → triple cap = 12 + 256 + 65536 + 16777216 ≈ 16.8M
        let too_big = 12 + 256 + 65_536 + (256u32 * 256 * 256) + 1;
        // Trip the "exceeds triple-indirect" guard. We never get past the bounds
        // check at top because data_block_count > u32::MAX would saturate;
        // here we go just past triple capacity.
        let result = plan_contiguous(too_big, 1, bs, make_alloc(1));
        assert!(matches!(result, Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn count_indirect_blocks_matches_plan_contiguous() {
        // Property: for any data_block_count, count_indirect_blocks() must
        // equal plan_contiguous().indirect_blocks_allocated.len() — the two
        // counts drive the same physical reality (single bitmap allocation).
        let bs = 1024u32;
        for n in [
            1u32,
            11,
            12,
            13,
            12 + 256,
            12 + 257,
            12 + 256 + 1,
            271,
            1000,
            12 + 256 + 65_536,
            65_805,
        ] {
            let predicted = count_indirect_blocks(n, bs);
            let plan = plan_contiguous(n, 1, bs, make_alloc(1)).unwrap();
            assert_eq!(
                predicted as usize,
                plan.indirect_blocks_allocated.len(),
                "mismatch for n={n}: predicted={predicted}, actual={}",
                plan.indirect_blocks_allocated.len()
            );
        }
    }

    #[test]
    fn collect_for_free_walks_tree_and_coalesces_runs() {
        let bs = 1024u32; // ppb = 256
        let dev = MemDev::new(1024 * 4096);

        // Build an i_block with:
        // - direct[0..5] = blocks 100..105 (contiguous run)
        // - direct[7] = block 999 (isolated)
        // - single-indirect at block 50, holding [0]=200, [1]=201, [2]=202
        let mut indirect = vec![0u8; bs as usize];
        write_u32_le(&mut indirect, 0, 200);
        write_u32_le(&mut indirect, 1, 201);
        write_u32_le(&mut indirect, 2, 202);
        dev.write_block(50, bs, &indirect);

        let mut i_block = [0u8; 60];
        for i in 0..5 {
            write_u32_le(&mut i_block, i, 100 + i as u32);
        }
        write_u32_le(&mut i_block, 7, 999);
        write_u32_le(&mut i_block, 12, 50);

        // 12 direct + 3 single = 15 logical blocks of file content.
        let freed = collect_for_free(&i_block, bs, 15, &dev).unwrap();

        // Indirect tree: just block 50.
        assert_eq!(freed.indirect_blocks, vec![50]);

        // Data runs: {100..105 contiguous run} + {200..203 contiguous run}
        // + {999 singleton}. Sort order: 100, 200, 999 by start.
        assert_eq!(
            freed.data_runs,
            vec![
                FreeRun { start: 100, len: 5 },
                FreeRun { start: 200, len: 3 },
                FreeRun { start: 999, len: 1 },
            ]
        );
    }

    #[test]
    fn collect_for_free_skips_sparse_holes() {
        let bs = 1024u32;
        let dev = MemDev::new(1024 * 64);
        // i_block[0]=100, [1]=0 (hole), [2]=102, no indirect tiers used.
        let mut i_block = [0u8; 60];
        write_u32_le(&mut i_block, 0, 100);
        write_u32_le(&mut i_block, 2, 102);

        let freed = collect_for_free(&i_block, bs, 12, &dev).unwrap();
        assert!(freed.indirect_blocks.is_empty());
        // Two singletons (100 and 102 — not contiguous).
        assert_eq!(
            freed.data_runs,
            vec![
                FreeRun { start: 100, len: 1 },
                FreeRun { start: 102, len: 1 },
            ]
        );
    }

    #[test]
    fn collect_for_free_zero_size_yields_nothing() {
        let bs = 1024u32;
        let dev = MemDev::new(1024 * 64);
        let mut i_block = [0u8; 60];
        // Set some pointers; they should be ignored when expected_data_blocks=0.
        for i in 0..12 {
            write_u32_le(&mut i_block, i, 100 + i as u32);
        }
        let freed = collect_for_free(&i_block, bs, 0, &dev).unwrap();
        assert!(freed.indirect_blocks.is_empty());
        assert!(freed.data_runs.is_empty());
    }

    #[test]
    fn round_trip_plan_then_collect() {
        // Ensure plan_contiguous output, when persisted into a MemDev, is
        // walked correctly by collect_for_free — same set of physical blocks
        // come out (data + indirect).
        let bs = 1024u32; // ppb = 256
        let count = 271u32; // 12 direct + 256 single + 3 double
        let plan = plan_contiguous(count, 5_000, bs, make_alloc(99_000)).unwrap();

        let dev = MemDev::new(1024 * 200_000);
        for (blk, buf) in &plan.block_writes {
            dev.write_block(*blk, bs, buf);
        }

        let freed = collect_for_free(&plan.i_block, bs, count, &dev).unwrap();

        // Indirect blocks should match exactly (up to sort order).
        let mut got_indirect = freed.indirect_blocks.clone();
        let mut want_indirect = plan.indirect_blocks_allocated.clone();
        got_indirect.sort_unstable();
        want_indirect.sort_unstable();
        assert_eq!(got_indirect, want_indirect);

        // Data should coalesce into one big contiguous run of `count` blocks.
        assert_eq!(
            freed.data_runs,
            vec![FreeRun {
                start: 5_000,
                len: count
            }]
        );
    }
}
