//! Legacy direct + indirect block-pointer scheme used by ext2 and ext3
//! file inodes (and by ext4 inodes whose `EXT4_EXTENTS_FL` is unset).
//!
//! Layout of the inode's 60-byte `i_block` region as 15 little-endian `u32`
//! block pointers:
//!
//! - `i_block[0..=11]`  — 12 direct pointers, mapping logical blocks 0..12
//! - `i_block[12]`      — single-indirect pointer; that block is a flat array
//!   of `block_size/4` direct pointers
//! - `i_block[13]`      — double-indirect pointer; points at a block of
//!   indirect-block pointers
//! - `i_block[14]`      — triple-indirect pointer; one more level of indirection
//!
//! A pointer of `0` means "sparse hole" — reads return zeros without ever
//! touching the disk. All pointers are 32 bits (no `INCOMPAT_64BIT` for
//! ext2/3 in any production deployment), so addressable space tops out at
//! `2^32` blocks regardless of indirection level.
//!
//! Spec source: kernel.org/doc/html/latest/filesystems/ext4/blockmap.html
//! (the same scheme ext4 inherited from ext2/ext3) and Carrier,
//! *File System Forensic Analysis*, ch. 14.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};

/// Number of direct block pointers in `i_block` (slots 0..=11).
pub const DIRECT_COUNT: u64 = 12;

/// Number of `u32` pointers that fit in one filesystem block.
#[inline]
fn ppb(block_size: u32) -> u64 {
    (block_size / 4) as u64
}

/// Read a `u32` block pointer from a slice of pointer bytes at index `i`.
#[inline]
fn ptr_at(buf: &[u8], i: usize) -> u64 {
    let off = i * 4;
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as u64
}

/// Single-entry cache for the most-recently-read indirect block. Sequential
/// reads through any single tier (single, double, or triple indirect) hit
/// this 100%. Cross-tier transitions cause one cache miss each, which is fine
/// — those happen at most twice per file (entering double, entering triple).
///
/// For higher-tier reads where two off-inode blocks must be touched (double
/// indirect needs the outer + inner block; triple needs three), only the
/// last-touched block stays cached. That trades read-coalescing within a
/// single inner block (good) for re-reading the outer block on every inner-
/// block transition (acceptable — `block_size/4` reads happen between such
/// transitions, so the cost is amortized).
pub struct IndirectCache {
    cached: Option<(u64, Vec<u8>)>,
}

impl Default for IndirectCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IndirectCache {
    pub fn new() -> Self {
        Self { cached: None }
    }

    /// Fetch a block from cache or read it through. The returned slice
    /// is borrowed from the cache and is valid until the next call.
    fn get(&mut self, dev: &dyn BlockDevice, block_no: u64, block_size: u32) -> Result<&[u8]> {
        let needs_read = !matches!(&self.cached, Some((b, _)) if *b == block_no);
        if needs_read {
            let mut buf = vec![0u8; block_size as usize];
            let byte_off = block_no
                .checked_mul(block_size as u64)
                .ok_or(Error::Corrupt("indirect: block byte offset overflow"))?;
            dev.read_at(byte_off, &mut buf)?;
            self.cached = Some((block_no, buf));
        }
        Ok(&self.cached.as_ref().unwrap().1)
    }
}

/// Flavor-aware logical→physical block lookup for any inode regardless of
/// block-mapping scheme. Dispatches on `EXT4_EXTENTS_FL` in `inode_flags`:
///
/// - flag set → traverses the extent tree via [`crate::extent::map_logical`]
/// - flag absent → walks the legacy direct/indirect tree via [`lookup`]
///
/// Use this from any code that walks a generic inode's block map (directory
/// scans, file reads outside the dedicated `file_io` paths, etc.). Without
/// it, an ext2/3 inode with raw block pointers in `i_block` will be
/// misparsed as a depth-0 extent header, returning
/// `CorruptExtentTree("bad extent header magic")`.
///
/// The indirect path constructs a fresh single-entry block cache per call.
/// Hot loops that need cross-call caching (sequential file reads) should
/// instead branch manually on the flag and pass a long-lived
/// [`IndirectCache`] into [`lookup`].
pub fn map_logical_any(
    i_block: &[u8; 60],
    inode_flags: u32,
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
) -> Result<Option<u64>> {
    if (inode_flags & crate::inode::InodeFlags::EXTENTS.bits()) != 0 {
        crate::extent::map_logical(i_block, dev, block_size, logical_block)
    } else {
        let mut cache = IndirectCache::new();
        lookup(i_block, dev, block_size, logical_block, &mut cache)
    }
}

/// Look up the physical block backing `logical_block` for an inode that uses
/// the legacy direct/indirect scheme.
///
/// Returns:
/// - `Ok(Some(physical))` if a non-zero pointer was found at every level.
/// - `Ok(None)` for sparse holes (any pointer in the chain is zero).
/// - `Err(Corrupt)` only on I/O failure or impossible logical-block values
///   (i.e. beyond the triple-indirect tier's address span).
///
/// Caller passes a long-lived `IndirectCache` to amortize indirect-block
/// reads across sequential `lookup` calls.
pub fn lookup(
    i_block: &[u8; 60],
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
    cache: &mut IndirectCache,
) -> Result<Option<u64>> {
    if block_size < 1024 || !block_size.is_power_of_two() {
        return Err(Error::Corrupt("indirect: block_size out of range"));
    }
    let ppb = ppb(block_size);

    // Tier 1 — direct pointers (logical 0..12).
    if logical_block < DIRECT_COUNT {
        let phys = ptr_at(i_block, logical_block as usize);
        return Ok(if phys == 0 { None } else { Some(phys) });
    }

    // Tier 2 — single indirect (logical [12, 12+ppb)).
    let single_base = DIRECT_COUNT;
    let single_end = single_base + ppb;
    if logical_block < single_end {
        let single_blk = ptr_at(i_block, 12);
        if single_blk == 0 {
            return Ok(None);
        }
        let idx = (logical_block - single_base) as usize;
        let buf = cache.get(dev, single_blk, block_size)?;
        let phys = ptr_at(buf, idx);
        return Ok(if phys == 0 { None } else { Some(phys) });
    }

    // Tier 3 — double indirect (logical [single_end, single_end + ppb*ppb)).
    let double_base = single_end;
    let double_end = double_base + ppb * ppb;
    if logical_block < double_end {
        let double_blk = ptr_at(i_block, 13);
        if double_blk == 0 {
            return Ok(None);
        }
        let off = logical_block - double_base;
        let outer_idx = (off / ppb) as usize;
        let inner_idx = (off % ppb) as usize;

        let outer_buf = cache.get(dev, double_blk, block_size)?;
        let inner_blk = ptr_at(outer_buf, outer_idx);
        if inner_blk == 0 {
            return Ok(None);
        }
        let inner_buf = cache.get(dev, inner_blk, block_size)?;
        let phys = ptr_at(inner_buf, inner_idx);
        return Ok(if phys == 0 { None } else { Some(phys) });
    }

    // Tier 4 — triple indirect (logical [double_end, double_end + ppb^3)).
    let triple_base = double_end;
    let triple_end = triple_base + ppb * ppb * ppb;
    if logical_block < triple_end {
        let triple_blk = ptr_at(i_block, 14);
        if triple_blk == 0 {
            return Ok(None);
        }
        let off = logical_block - triple_base;
        let l1_idx = (off / (ppb * ppb)) as usize;
        let rem = off % (ppb * ppb);
        let l2_idx = (rem / ppb) as usize;
        let l3_idx = (rem % ppb) as usize;

        let l1_buf = cache.get(dev, triple_blk, block_size)?;
        let l2_blk = ptr_at(l1_buf, l1_idx);
        if l2_blk == 0 {
            return Ok(None);
        }
        let l2_buf = cache.get(dev, l2_blk, block_size)?;
        let l3_blk = ptr_at(l2_buf, l2_idx);
        if l3_blk == 0 {
            return Ok(None);
        }
        let l3_buf = cache.get(dev, l3_blk, block_size)?;
        let phys = ptr_at(l3_buf, l3_idx);
        return Ok(if phys == 0 { None } else { Some(phys) });
    }

    // Beyond triple-indirect addressable range — corrupt or out-of-spec.
    Err(Error::Corrupt(
        "indirect: logical block exceeds triple-indirect address space",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_io::BlockDevice;
    use std::sync::Mutex;

    /// In-memory block device for unit tests.
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

    /// Build an `i_block` with the given 15 pointers.
    fn make_iblock(ptrs: [u32; 15]) -> [u8; 60] {
        let mut out = [0u8; 60];
        for (i, p) in ptrs.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&p.to_le_bytes());
        }
        out
    }

    /// Pack `ppb` pointers into a block buffer.
    fn pack_ptrs(ptrs: &[u32], block_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; block_size as usize];
        for (i, p) in ptrs.iter().enumerate() {
            buf[i * 4..i * 4 + 4].copy_from_slice(&p.to_le_bytes());
        }
        buf
    }

    #[test]
    fn direct_pointer_lookup() {
        let bs = 1024u32;
        let dev = MemDev::new(1024 * 64);
        let mut cache = IndirectCache::new();

        // Direct[0] = block 100, Direct[5] = block 105, rest sparse.
        let mut ptrs = [0u32; 15];
        ptrs[0] = 100;
        ptrs[5] = 105;
        let i_block = make_iblock(ptrs);

        assert_eq!(
            lookup(&i_block, &dev, bs, 0, &mut cache).unwrap(),
            Some(100)
        );
        assert_eq!(
            lookup(&i_block, &dev, bs, 5, &mut cache).unwrap(),
            Some(105)
        );
        // Direct[1] is zero → sparse hole.
        assert_eq!(lookup(&i_block, &dev, bs, 1, &mut cache).unwrap(), None);
        assert_eq!(lookup(&i_block, &dev, bs, 11, &mut cache).unwrap(), None);
    }

    #[test]
    fn single_indirect_lookup() {
        let bs = 1024u32; // ppb = 256
        let dev = MemDev::new(1024 * 1024);
        let mut cache = IndirectCache::new();

        // i_block[12] = single-indirect at block 50; that block holds 256
        // pointers, only [0]=200, [3]=203, [255]=455 set.
        let mut indirect_ptrs = vec![0u32; 256];
        indirect_ptrs[0] = 200;
        indirect_ptrs[3] = 203;
        indirect_ptrs[255] = 455;
        dev.write_block(50, bs, &pack_ptrs(&indirect_ptrs, bs));

        let mut ptrs = [0u32; 15];
        ptrs[12] = 50;
        let i_block = make_iblock(ptrs);

        // logical 12 = single[0] = 200
        assert_eq!(
            lookup(&i_block, &dev, bs, 12, &mut cache).unwrap(),
            Some(200)
        );
        // logical 15 = single[3] = 203
        assert_eq!(
            lookup(&i_block, &dev, bs, 15, &mut cache).unwrap(),
            Some(203)
        );
        // logical 13 = single[1] = 0 → hole
        assert_eq!(lookup(&i_block, &dev, bs, 13, &mut cache).unwrap(), None);
        // logical 12+255 = single[255] = 455
        assert_eq!(
            lookup(&i_block, &dev, bs, 12 + 255, &mut cache).unwrap(),
            Some(455)
        );
    }

    #[test]
    fn single_indirect_zero_pointer_is_hole() {
        let bs = 1024u32;
        let dev = MemDev::new(1024 * 64);
        let mut cache = IndirectCache::new();

        // i_block[12] = 0 → entire single-indirect tier is a hole.
        let i_block = make_iblock([0u32; 15]);
        assert_eq!(lookup(&i_block, &dev, bs, 12, &mut cache).unwrap(), None);
        assert_eq!(lookup(&i_block, &dev, bs, 200, &mut cache).unwrap(), None);
    }

    #[test]
    fn double_indirect_lookup() {
        let bs = 1024u32; // ppb = 256
        let dev = MemDev::new(1024 * 4096);
        let mut cache = IndirectCache::new();

        // i_block[13] = double-indirect at block 70.
        // Outer block 70: ptrs[0] = 71 (inner block), rest zero.
        // Inner block 71: ptrs[5] = 555.
        let mut outer = vec![0u32; 256];
        outer[0] = 71;
        outer[2] = 72;
        dev.write_block(70, bs, &pack_ptrs(&outer, bs));

        let mut inner1 = vec![0u32; 256];
        inner1[5] = 555;
        dev.write_block(71, bs, &pack_ptrs(&inner1, bs));

        let mut inner2 = vec![0u32; 256];
        inner2[10] = 1010;
        dev.write_block(72, bs, &pack_ptrs(&inner2, bs));

        let mut ptrs = [0u32; 15];
        ptrs[13] = 70;
        let i_block = make_iblock(ptrs);

        // double_base = 12 + 256 = 268.
        // outer[0], inner[5] → logical 268 + 0*256 + 5 = 273
        assert_eq!(
            lookup(&i_block, &dev, bs, 273, &mut cache).unwrap(),
            Some(555)
        );
        // outer[2], inner[10] → 268 + 2*256 + 10 = 790
        assert_eq!(
            lookup(&i_block, &dev, bs, 790, &mut cache).unwrap(),
            Some(1010)
        );
        // outer[1] is zero → entire inner range is a hole.
        assert_eq!(
            lookup(&i_block, &dev, bs, 268 + 256, &mut cache).unwrap(),
            None
        );
        // outer[0], inner[6] → present outer + zero inner → hole.
        assert_eq!(lookup(&i_block, &dev, bs, 274, &mut cache).unwrap(), None);
    }

    #[test]
    fn triple_indirect_lookup() {
        let bs = 1024u32; // ppb = 256
                          // ppb^3 * 1024 ≈ 16 GiB — too large for an in-mem device. Use 4096-byte
                          // device blocks of metadata only and synthesize a small triple-indirect
                          // chain at the very base of the tier.
        let dev = MemDev::new(1024 * 8192);
        let mut cache = IndirectCache::new();

        // outer L1 at block 80 → [0] = 81 (L2 block)
        // L2 at block 81      → [0] = 82 (L3 block)
        // L3 at block 82      → [7] = 7777
        let mut l1 = vec![0u32; 256];
        l1[0] = 81;
        dev.write_block(80, bs, &pack_ptrs(&l1, bs));

        let mut l2 = vec![0u32; 256];
        l2[0] = 82;
        dev.write_block(81, bs, &pack_ptrs(&l2, bs));

        let mut l3 = vec![0u32; 256];
        l3[7] = 7777;
        dev.write_block(82, bs, &pack_ptrs(&l3, bs));

        let mut ptrs = [0u32; 15];
        ptrs[14] = 80;
        let i_block = make_iblock(ptrs);

        // triple_base = 12 + 256 + 256*256 = 65804.
        // l1[0], l2[0], l3[7] → 65804 + 0 + 0 + 7 = 65811
        assert_eq!(
            lookup(&i_block, &dev, bs, 65811, &mut cache).unwrap(),
            Some(7777)
        );
        // l3[8] is zero → hole
        assert_eq!(lookup(&i_block, &dev, bs, 65812, &mut cache).unwrap(), None);
    }

    #[test]
    fn beyond_triple_indirect_is_corrupt() {
        let bs = 1024u32;
        let dev = MemDev::new(1024 * 64);
        let mut cache = IndirectCache::new();

        let i_block = make_iblock([0u32; 15]);
        // Beyond triple range: 12 + 256 + 256^2 + 256^3 = ~16M+. Pick something
        // safely past it.
        let result = lookup(&i_block, &dev, bs, 1u64 << 32, &mut cache);
        assert!(matches!(result, Err(Error::Corrupt(_))));
    }
}
