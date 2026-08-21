//! File-write high-level planner (E10).
//!
//! Composes bitmap allocation (E5/E6), extent-tree mutation (E7), and
//! directory-entry mutation (E8) into file-level operations:
//!
//! - `split_into_block_writes` — turn a `(offset, data)` byte-range write into
//!   a list of `(logical_block, offset_in_block, payload_slice)` — the unit
//!   E11 journals.
//! - `plan_truncate_shrink` — free the tail extents that fall past a new,
//!   smaller size; delegates to `extent_mut::plan_free_extent`.
//! - `plan_truncate_grow` — growing a file without writing is a size-only
//!   update (creates a sparse hole); emits no extent mutations.
//! - `plan_append_logical_blocks` — given a file's current size and how many
//!   bytes the caller wants to append, returns the logical-block range the
//!   write touches and flags whether the last block is a partial write.
//!
//! Plan-only. E11 wraps plan application in a JBD2 transaction.

use crate::error::{Error, Result};
use crate::extent::{Extent, ExtentHeader};
use crate::extent_mut::{plan_free_extent, ExtentMutation};

/// One unit of a data-block write. `payload.len() <= block_size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWrite {
    /// Logical block number within the file (offset / block_size).
    pub logical_block: u64,
    /// Byte offset within the block where the payload starts (0..block_size).
    pub offset_in_block: u32,
    /// Bytes to write. For a full-block write, `payload.len() == block_size`
    /// and `offset_in_block == 0`.
    pub payload: Vec<u8>,
}

/// Split a byte-range write `(offset, data)` into per-block `BlockWrite` units.
///
/// Returned writes are in ascending logical order. Each non-final write either
/// starts at `offset_in_block == 0` AND covers the full block, OR is the
/// first write whose offset is not block-aligned. The last write may be
/// partial if `data.len()` does not end on a block boundary.
pub fn split_into_block_writes(offset: u64, data: &[u8], block_size: u32) -> Vec<BlockWrite> {
    if data.is_empty() {
        return Vec::new();
    }
    let bs = block_size as u64;
    let mut out = Vec::new();
    let mut cur = offset;
    let end = offset + data.len() as u64;
    let mut src = 0usize;

    while cur < end {
        let logical_block = cur / bs;
        let off_in_block = (cur % bs) as u32;
        let block_remaining = (bs - off_in_block as u64) as usize;
        let take = block_remaining.min(end.saturating_sub(cur) as usize);
        out.push(BlockWrite {
            logical_block,
            offset_in_block: off_in_block,
            payload: data[src..src + take].to_vec(),
        });
        src += take;
        cur += take as u64;
    }
    out
}

/// Describes the logical-block coverage of a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteBlockRange {
    /// First logical block touched.
    pub first: u64,
    /// Last logical block touched (inclusive).
    pub last: u64,
    /// True iff the write starts and ends on block boundaries (no RMW needed
    /// for the head or tail block).
    pub full_blocks: bool,
}

/// Compute the logical block range for a byte-range write.
pub fn compute_write_range(offset: u64, length: u64, block_size: u32) -> Option<WriteBlockRange> {
    if length == 0 {
        return None;
    }
    let bs = block_size as u64;
    let first = offset / bs;
    let last = (offset + length - 1) / bs;
    let full_blocks = offset.is_multiple_of(bs) && (offset + length).is_multiple_of(bs);
    Some(WriteBlockRange {
        first,
        last,
        full_blocks,
    })
}

/// Plan to grow `inode_size` to `new_size` without writing any data blocks.
/// Returns the size delta only — growing a file sparsely costs no blocks,
/// and the hole reads as zeros (via `extent::lookup` returning None).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeChange {
    pub old_size: u64,
    pub new_size: u64,
}

pub fn plan_truncate_grow(old_size: u64, new_size: u64) -> Result<SizeChange> {
    if new_size < old_size {
        return Err(Error::Corrupt("plan_truncate_grow: new_size < old_size"));
    }
    Ok(SizeChange { old_size, new_size })
}

/// Plan to shrink `inode_size` to `new_size`: drops whole leaf extents that
/// fall entirely past the new EOF, and — if the new EOF falls mid-extent —
/// splits that extent and frees the tail half.
///
/// Returns a vec of `ExtentMutation`s (the `WriteRoot` + `FreePhysicalRun`
/// pairs). Caller pairs these with block-bitmap frees (E5) when applying.
///
/// Does NOT issue any bitmap updates itself — callers of the plan apply the
/// `FreePhysicalRun` entries against the bitmap allocator.
///
/// Only handles inline-root (depth 0) trees for now. Multi-level trees
/// return [`Error::CorruptExtentTree`] with a clear message — E9/E11 will
/// wire in the deeper traversal when the write path goes through the
/// journal.
pub fn plan_truncate_shrink(
    old_size: u64,
    new_size: u64,
    root_bytes: &[u8],
    block_size: u32,
) -> Result<(SizeChange, Vec<ExtentMutation>)> {
    if new_size > old_size {
        return Err(Error::Corrupt("plan_truncate_shrink: new_size > old_size"));
    }
    let header = ExtentHeader::parse(root_bytes)?;
    if !header.is_leaf() {
        return Err(Error::CorruptExtentTree(
            "plan_truncate_shrink: multi-level tree not yet supported",
        ));
    }

    let bs = block_size as u64;
    let new_logical_end = new_size.div_ceil(bs); // exclusive upper bound

    // Read entries; identify which fully past end → drop, which straddle → split.
    let mut entries: Vec<Extent> = Vec::new();
    for i in 0..header.entries {
        let off = crate::extent::EXT4_EXT_NODE_SIZE * (1 + i as usize);
        entries.push(Extent::parse(
            &root_bytes[off..off + crate::extent::EXT4_EXT_NODE_SIZE],
        )?);
    }

    let mut muts: Vec<ExtentMutation> = Vec::new();
    // Walk from tail so indices into the live root stay valid for plan_free_extent.
    // Note: plan_free_extent re-parses the root each call, so we apply mutations
    // back onto a local copy and re-emit at the end. Simpler: compute final
    // entries ourselves + emit FreePhysicalRun for each discarded range, then
    // serialize once.
    let mut kept: Vec<Extent> = Vec::new();
    for e in entries.into_iter() {
        let e_start = e.logical_block as u64;
        let e_end = e_start + e.length as u64;
        if e_end <= new_logical_end {
            // Fully within the retained range — keep.
            kept.push(e);
        } else if e_start >= new_logical_end {
            // Entirely past EOF — free whole extent.
            muts.push(ExtentMutation::FreePhysicalRun {
                start: e.physical_block,
                len: e.length as u32,
            });
        } else {
            // Straddles EOF — keep the head, free the tail.
            let keep_len = (new_logical_end - e_start) as u16;
            let free_len = e.length - keep_len;
            let free_phys = e.physical_block + keep_len as u64;
            kept.push(Extent {
                logical_block: e.logical_block,
                length: keep_len,
                physical_block: e.physical_block,
                uninitialized: e.uninitialized,
            });
            muts.push(ExtentMutation::FreePhysicalRun {
                start: free_phys,
                len: free_len as u32,
            });
        }
    }

    // Emit the new root with the retained entries.
    let mut new_root = vec![0u8; root_bytes.len()];
    new_root[0..2].copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
    new_root[2..4].copy_from_slice(&(kept.len() as u16).to_le_bytes());
    new_root[4..6].copy_from_slice(&header.max.to_le_bytes());
    new_root[6..8].copy_from_slice(&header.depth.to_le_bytes());
    new_root[8..12].copy_from_slice(&header.generation.to_le_bytes());
    for (i, e) in kept.iter().enumerate() {
        let off = crate::extent::EXT4_EXT_NODE_SIZE * (1 + i);
        new_root[off..off + 4].copy_from_slice(&e.logical_block.to_le_bytes());
        let ee_len = if e.uninitialized {
            e.length + crate::extent::EXT_INIT_MAX_LEN
        } else {
            e.length
        };
        new_root[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
        let phys_hi = ((e.physical_block >> 32) & 0xFFFF) as u16;
        let phys_lo = (e.physical_block & 0xFFFF_FFFF) as u32;
        new_root[off + 6..off + 8].copy_from_slice(&phys_hi.to_le_bytes());
        new_root[off + 8..off + 12].copy_from_slice(&phys_lo.to_le_bytes());
    }
    muts.insert(0, ExtentMutation::WriteRoot { bytes: new_root });

    // Silence unused-variable warning for now; plan_free_extent is re-exported
    // for future per-entry flows (E11 may call it directly).
    let _ = plan_free_extent;

    Ok((SizeChange { old_size, new_size }, muts))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // split_into_block_writes
    // -----------------------------------------------------------------------

    #[test]
    fn split_aligned_single_block() {
        let data = vec![7u8; 4096];
        let out = split_into_block_writes(0, &data, 4096);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].logical_block, 0);
        assert_eq!(out[0].offset_in_block, 0);
        assert_eq!(out[0].payload.len(), 4096);
    }

    #[test]
    fn split_crosses_block_boundary() {
        let data = vec![1u8; 6000]; // starts at 3000, spans blocks 0, 1, 2
        let out = split_into_block_writes(3000, &data, 4096);
        assert_eq!(out.len(), 3);
        // block 0: offset 3000 to end, 1096 bytes
        assert_eq!(out[0].logical_block, 0);
        assert_eq!(out[0].offset_in_block, 3000);
        assert_eq!(out[0].payload.len(), 1096);
        // block 1: full 4096 bytes
        assert_eq!(out[1].logical_block, 1);
        assert_eq!(out[1].offset_in_block, 0);
        assert_eq!(out[1].payload.len(), 4096);
        // block 2: offset 0, 6000 - 1096 - 4096 = 808 bytes
        assert_eq!(out[2].logical_block, 2);
        assert_eq!(out[2].offset_in_block, 0);
        assert_eq!(out[2].payload.len(), 808);
    }

    #[test]
    fn split_empty_data_returns_empty() {
        assert!(split_into_block_writes(100, &[], 4096).is_empty());
    }

    #[test]
    fn split_sub_block_write() {
        let data = vec![2u8; 100];
        let out = split_into_block_writes(1000, &data, 4096);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset_in_block, 1000);
        assert_eq!(out[0].payload.len(), 100);
    }

    // -----------------------------------------------------------------------
    // compute_write_range
    // -----------------------------------------------------------------------

    #[test]
    fn write_range_full_blocks() {
        let r = compute_write_range(0, 8192, 4096).unwrap();
        assert_eq!(r.first, 0);
        assert_eq!(r.last, 1);
        assert!(r.full_blocks);
    }

    #[test]
    fn write_range_partial_head_and_tail() {
        let r = compute_write_range(100, 5000, 4096).unwrap();
        assert_eq!(r.first, 0);
        assert_eq!(r.last, 1);
        assert!(!r.full_blocks);
    }

    #[test]
    fn write_range_zero_length_returns_none() {
        assert!(compute_write_range(100, 0, 4096).is_none());
    }

    // -----------------------------------------------------------------------
    // plan_truncate_grow
    // -----------------------------------------------------------------------

    #[test]
    fn grow_returns_delta() {
        let s = plan_truncate_grow(1000, 5000).unwrap();
        assert_eq!(s.old_size, 1000);
        assert_eq!(s.new_size, 5000);
    }

    #[test]
    fn grow_rejects_shrink() {
        assert!(plan_truncate_grow(5000, 1000).is_err());
    }

    // -----------------------------------------------------------------------
    // plan_truncate_shrink
    // -----------------------------------------------------------------------

    /// Build an inline root with the given extents.
    fn mk_root(extents: &[Extent]) -> Vec<u8> {
        let mut buf = vec![0u8; 60];
        buf[0..2].copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        for (i, e) in extents.iter().enumerate() {
            let off = crate::extent::EXT4_EXT_NODE_SIZE * (1 + i);
            buf[off..off + 4].copy_from_slice(&e.logical_block.to_le_bytes());
            let ee_len = if e.uninitialized {
                e.length + crate::extent::EXT_INIT_MAX_LEN
            } else {
                e.length
            };
            buf[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
            let phys_hi = ((e.physical_block >> 32) & 0xFFFF) as u16;
            let phys_lo = (e.physical_block & 0xFFFF_FFFF) as u32;
            buf[off + 6..off + 8].copy_from_slice(&phys_hi.to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&phys_lo.to_le_bytes());
        }
        buf
    }

    fn ext(log: u32, len: u16, phys: u64) -> Extent {
        Extent {
            logical_block: log,
            length: len,
            physical_block: phys,
            uninitialized: false,
        }
    }

    #[test]
    fn shrink_drops_whole_tail_extent() {
        // File has extents [0..10]=1000 + [10..20]=2000.
        // Shrink to 10 blocks → drop second extent entirely.
        let root = mk_root(&[ext(0, 10, 1000), ext(10, 10, 2000)]);
        let (sc, muts) = plan_truncate_shrink(20 * 4096, 10 * 4096, &root, 4096).unwrap();
        assert_eq!(sc.new_size, 10 * 4096);
        // muts[0] = WriteRoot with only the first extent.
        // muts[1] = FreePhysicalRun { start: 2000, len: 10 }.
        assert_eq!(muts.len(), 2);
        match &muts[1] {
            ExtentMutation::FreePhysicalRun { start, len } => {
                assert_eq!(*start, 2000);
                assert_eq!(*len, 10);
            }
            _ => panic!("expected FreePhysicalRun"),
        }
    }

    #[test]
    fn shrink_splits_straddling_extent() {
        // One extent [0..10] → shrink to 4 blocks = keep 4, free 6.
        let root = mk_root(&[ext(0, 10, 1000)]);
        let (_, muts) = plan_truncate_shrink(10 * 4096, 4 * 4096, &root, 4096).unwrap();
        assert_eq!(muts.len(), 2);
        match &muts[1] {
            ExtentMutation::FreePhysicalRun { start, len } => {
                assert_eq!(*start, 1004);
                assert_eq!(*len, 6);
            }
            _ => panic!("expected FreePhysicalRun for tail"),
        }
    }

    #[test]
    fn shrink_to_zero_frees_all() {
        let root = mk_root(&[ext(0, 5, 500), ext(5, 5, 1000)]);
        let (_, muts) = plan_truncate_shrink(10 * 4096, 0, &root, 4096).unwrap();
        // 1 WriteRoot + 2 FreePhysicalRun.
        assert_eq!(muts.len(), 3);
        let freed: Vec<_> = muts
            .iter()
            .filter_map(|m| match m {
                ExtentMutation::FreePhysicalRun { start, len } => Some((*start, *len)),
                _ => None,
            })
            .collect();
        assert_eq!(freed, vec![(500, 5), (1000, 5)]);
    }

    #[test]
    fn shrink_rejects_grow_direction() {
        let root = mk_root(&[ext(0, 10, 1000)]);
        assert!(plan_truncate_shrink(4096, 8192, &root, 4096).is_err());
    }
}
