//! ext4 filesystem creation (mkfs).
//!
//! Writes a minimum-viable ext4 layout that mounts cleanly under both this
//! crate's read path and Linux. Targets a single block group for tiny test
//! volumes and scales to N groups for larger devices. v1 layout:
//!
//! - Block 0 (offset 0..1024)    : zero (boot sector)
//! - Block 0 (offset 1024..2048) : primary superblock
//! - Block 1                     : block group descriptor table
//! - Block 2                     : group 0 block bitmap
//! - Block 3                     : group 0 inode bitmap
//! - Blocks 4..N                 : group 0 inode table
//! - Block (4+itable_blocks)     : root directory data block
//!
//! Features enabled: FILETYPE, EXTENTS, 64BIT, METADATA_CSUM, SPARSE_SUPER.
//! Journal is intentionally OFF for v1, as the resulting FS mounts cleanly
//! without it.
//!
//! Inode 1 is reserved (unused), inode 2 is the root `/` directory.

use crate::block_io::BlockDevice;
use crate::checksum::{linux_crc32c, Checksummer};
use crate::dir::{self, DirEntryType};
use crate::error::{Error, Result};
use crate::features::{Compat, FsFlavor, Incompat, RoCompat};

const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_VALID_FS: u16 = 0x0001;
const EXT4_ROOT_INO: u32 = 2;
const EXT4_GOOD_OLD_INODE_SIZE: u16 = 128;
const I_EXTRA_ISIZE: u16 = 32; // covers checksum_hi, ctime/mtime/atime extra, crtime
const ROOT_MODE: u16 = 0o40755; // S_IFDIR | 0755
const EXTENT_MAGIC: u16 = 0xF30A;

/// Format `dev` as an ext4 filesystem (extents, 64-bit BGDs, metadata_csum,
/// no journal). Thin wrapper over [`format_filesystem_with_flavor`] for
/// callers that don't care about the dialect.
pub fn format_filesystem(
    dev: &dyn BlockDevice,
    label: Option<&str>,
    uuid: Option<[u8; 16]>,
    size_bytes: u64,
    block_size: u32,
) -> Result<()> {
    format_filesystem_with_flavor(dev, label, uuid, size_bytes, block_size, FsFlavor::Ext4)
}

/// Format `dev` as a filesystem of the requested dialect. The device must be
/// at least large enough to hold the metadata + one root directory block
/// (≈ 200 KiB at 4 KiB blocks with the default geometry).
///
/// `flavor` selects the on-disk feature set:
/// - [`FsFlavor::Ext4`] — extents, 64-bit BGDs, metadata_csum (current default).
/// - [`FsFlavor::Ext2`] — legacy direct/indirect block pointers, 32-byte BGDs,
///   128-byte inodes, no journal, no metadata_csum. Mounts under both this
///   crate and the kernel's single ext4 driver running in ext2-compat mode.
/// - [`FsFlavor::Ext3`] — ext2 layout plus a journal inode and JBD2 log area.
///   PARTIAL support: it formats and mounts read/write under this crate, but the
///   produced journal is not yet `e2fsck`-clean (the `mkfs_ext3_oracle` cases
///   stay `#[ignore]`d), so it is not yet a fully validated ext3 image.
///
/// Arguments:
/// - `label`     — volume name (truncated to 16 bytes; UTF-8 stored verbatim).
/// - `uuid`      — 128-bit volume UUID; if `None`, a random one is generated.
/// - `size_bytes`— total device size to format (must be ≤ device's reported size).
/// - `block_size`— filesystem block size in bytes; must be a power of two,
///   1024..=65536. Typical: 4096.
pub fn format_filesystem_with_flavor(
    dev: &dyn BlockDevice,
    label: Option<&str>,
    uuid: Option<[u8; 16]>,
    size_bytes: u64,
    block_size: u32,
    flavor: FsFlavor,
) -> Result<()> {
    // Per-flavor on-disk choices. ext3 sits between ext2 (no extents, no
    // metadata_csum, 32-byte BGDs) and ext4 (everything on) — same layout
    // as ext2 plus a journal inode + JBD2 log area at the head of the
    // data region.
    let (inode_size, desc_size, csum_enabled, dir_csum_tail) = flavor.geometry();
    // Journal sizing for ext3. JBD2's documented minimum is 1024 blocks;
    // we pick exactly that for fixture friendliness — at 1 KiB block_size
    // it's a 1 MiB journal that fits in our smallest-realistic test image.
    // A real-world ext3 mkfs would scale this up to ~32 MiB or more.
    let ext3_journal_blocks: u32 = if matches!(flavor, FsFlavor::Ext3) {
        1024
    } else {
        0
    };
    const EXT3_JOURNAL_INODE: u32 = 8;
    if !block_size.is_power_of_two() || !(1024..=65536).contains(&block_size) {
        return Err(Error::InvalidArgument("mkfs: block_size out of range"));
    }
    if size_bytes < block_size as u64 * 64 {
        return Err(Error::InvalidArgument("mkfs: device too small"));
    }
    if !dev.is_writable() {
        return Err(Error::ReadOnly);
    }

    let log_block_size = (block_size.trailing_zeros() as i32 - 10) as u32;

    // Geometry. blocks_per_group is the canonical 8 * block_size (so 32768
    // for 4 KiB blocks). Inodes-per-group is sized so the inode table stays
    // a small fraction of the group; for v1 simplicity we use 8192 — gives
    // 64 KiB / 256 B = 256 inodes per inode-table block, 32 inode-table
    // blocks per group at 4 KiB.
    let blocks_per_group: u32 = 8 * block_size; // 32768 at 4 KiB
    let blocks_count: u64 = size_bytes / block_size as u64;
    if blocks_count < 64 {
        return Err(Error::InvalidArgument("mkfs: too few blocks"));
    }

    if matches!(flavor, FsFlavor::Ext4) && block_size >= 2048 {
        return format_block_groups(dev, label, uuid, size_bytes, block_size);
    }
    if blocks_count > blocks_per_group as u64 {
        return Err(Error::InvalidArgument(
            "mkfs: multi-group volumes require ext4 with block_size >= 2048",
        ));
    }

    let inodes_per_group: u32 = 8192;
    let inode_table_blocks: u32 =
        (inodes_per_group as u64 * inode_size as u64).div_ceil(block_size as u64) as u32;

    // first_data_block is 1 for 1 KiB blocks, 0 otherwise — mirrors ext4 formatter.
    let first_data_block: u32 = if block_size == 1024 { 1 } else { 0 };

    // Layout within group 0:
    //   superblock           : block first_data_block (offset 1024 inside it for 4 KiB)
    //   bgd table            : block first_data_block + 1
    //   block bitmap         : block first_data_block + 2
    //   inode bitmap         : block first_data_block + 3
    //   inode table          : blocks first_data_block + 4 .. + 4 + itable_blocks
    //   root dir data block  : block first_data_block + 4 + itable_blocks
    let bgt_block: u64 = first_data_block as u64 + 1;
    let blk_bitmap: u64 = first_data_block as u64 + 2;
    let ino_bitmap: u64 = first_data_block as u64 + 3;
    let inode_table_start: u64 = first_data_block as u64 + 4;
    let root_dir_block: u64 = inode_table_start + inode_table_blocks as u64;
    // ext3 journal data lives immediately after the root dir block. Layout
    // gap-free so the journal inode's i_block tree maps to a single
    // contiguous physical run — the writer (`indirect_mut::plan_contiguous`)
    // is then a one-shot call.
    let journal_data_start: u64 = root_dir_block + 1;
    let journal_data_end: u64 = journal_data_start + ext3_journal_blocks as u64;
    // The ext3 journal inode maps its data run with legacy indirect blocks.
    // Those mapping blocks are allocated contiguously right after the data run
    // (see the journal-inode section below), so they must be counted as used —
    // both in the block bitmap and in the free-block totals. Counting them here
    // lets the main bitmap loop mark them and keeps free_blocks correct.
    let journal_indirect_blocks: u64 = if matches!(flavor, FsFlavor::Ext3) {
        crate::indirect_mut::count_indirect_blocks(ext3_journal_blocks, block_size)
    } else {
        0
    };
    let journal_end: u64 = journal_data_end + journal_indirect_blocks;

    // Sanity: every metadata block + journal (if any) must fit in the device.
    // `journal_end` is the exclusive end of the used run, so `== blocks_count`
    // is an exact fit (last used block is blocks_count-1, zero free) — valid;
    // only `> blocks_count` overflows the device.
    if journal_end > blocks_count {
        return Err(Error::InvalidArgument(
            "mkfs: device too small for layout (journal won't fit)",
        ));
    }

    // e2fsprogs convention: inodes 1..s_first_ino-1 are all "reserved-used"
    // in the bitmap regardless of whether the FS actually populates them.
    // build_superblock pins s_first_ino = 11, so inodes 1..=10 are all
    // marked used. ext3's journal at inode 8 falls inside that range, so
    // no flavor-specific bookkeeping is needed for free_inodes.
    const RESERVED_INODES: u32 = 10;
    let used_blocks: u64 = if matches!(flavor, FsFlavor::Ext3) {
        journal_end // journal data run + its indirect-tree blocks
    } else {
        root_dir_block + 1
    };
    let free_blocks: u64 = blocks_count - used_blocks;
    let free_inodes: u32 = inodes_per_group - RESERVED_INODES;

    let uuid = uuid.unwrap_or_else(generate_uuid);

    // ----- Superblock -------------------------------------------------------
    // Build the 1024-byte primary superblock then patch its checksum.
    let journal_inum_for_sb: u32 = if matches!(flavor, FsFlavor::Ext3) {
        EXT3_JOURNAL_INODE
    } else {
        0
    };
    let mut sb = build_superblock(
        inodes_per_group,
        blocks_count,
        free_blocks,
        free_inodes,
        first_data_block,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        &uuid,
        label.unwrap_or(""),
        flavor,
        inode_size,
        desc_size,
        journal_inum_for_sb,
    );
    // Superblock CRC32C: seed = ~0, covers bytes [0..0x3FC]. Only patched
    // when the volume advertises METADATA_CSUM — ext2/3 leave the slot zero.
    if csum_enabled {
        let sb_csum = linux_crc32c(!0, &sb[..0x3FC]);
        sb[0x3FC..0x400].copy_from_slice(&sb_csum.to_le_bytes());
    }

    // Mount-time checksummer, used for BGD + inode + dir-block CRCs.
    let csum_seed = linux_crc32c(!0, &uuid);
    let csum = Checksummer {
        seed: csum_seed,
        enabled: csum_enabled,
    };

    // ----- Block group descriptor (group 0 only) ---------------------------
    let mut bgd = vec![0u8; desc_size as usize];
    write_bgd_group(
        &mut bgd,
        blk_bitmap,
        ino_bitmap,
        inode_table_start,
        free_blocks,
        free_inodes,
        /* used_dirs */ 1, // root dir lives in group 0
        desc_size,
    );
    // (BGD CRC is patched LATER, once the bitmap csums have been written
    // into 0x18/0x1A/0x38/0x3A — otherwise fsck.ext4 -fnv reports
    // "Group 0 inode/block bitmap does not match checksum" because the
    // BGD it CRCs over carries stale bitmap-csum slots.)

    // ----- Block bitmap (group 0) ------------------------------------------
    // Block-bitmap bit `i` maps to absolute block (first_data_block + i), per
    // the ext4 convention. For 1 KiB blocks first_data_block is 1, so the whole
    // bitmap is shifted down one block relative to absolute numbering; indexing
    // it by absolute block over-marks the tail by one block and skips the
    // trailing pad bit (e2fsck flags both as "Free blocks count wrong" +
    // "Padding at end of block bitmap is not set"). Work in bit space.
    let fdb = first_data_block as u64;
    let mut block_bitmap = vec![0u8; block_size as usize];
    // Metadata occupies absolute blocks [first_data_block, used_blocks) (for
    // ext3 this includes the journal data run; for ext2/ext4 it stops at
    // root_dir_block), i.e. bits [0, used_blocks - first_data_block).
    set_bitmap_range(&mut block_bitmap, 0, used_blocks - fdb);
    // Tail-pad: bits whose block (first_data_block + bit) is >= blocks_count
    // are out of range and must read "used" so the allocator never tries them
    // and the bitmap checksum matches what e2fsck recomputes. blocks_per_group
    // bits cover the bitmap's logical span.
    set_bitmap_range(
        &mut block_bitmap,
        blocks_count - fdb,
        blocks_per_group as u64,
    );

    // ----- Inode bitmap (group 0) ------------------------------------------
    // ext4 inode numbers are 1-based; bit i = inode (i+1). e2fsprogs marks
    // every reserved inode (1..s_first_ino) as used so fsck.ext4 -fnv
    // doesn't report "Inode bitmap differences: +(3--10)" — fix that
    // by setting bits 0..RESERVED_INODES (inodes 1..=10). Then tail-pad
    // bits past inodes_per_group up to the bitmap block boundary so the
    // bitmap checksum matches what e2fsck recomputes (which assumes all
    // out-of-range bits are 1 — "Padding at end of inode bitmap is not set").
    let mut inode_bitmap = vec![0u8; block_size as usize];
    set_bitmap_range(&mut inode_bitmap, 0, RESERVED_INODES as u64);
    set_bitmap_range(
        &mut inode_bitmap,
        inodes_per_group as u64,
        block_size as u64 * 8,
    );

    // ----- Inode table (group 0) — only inode 2 has content ----------------
    let mut inode_table = vec![0u8; inode_table_blocks as usize * block_size as usize];
    // Inode 2 lives at byte offset (2-1) * inode_size.
    let root_inode_off = (EXT4_ROOT_INO as usize - 1) * inode_size as usize;
    write_root_inode(
        &mut inode_table[root_inode_off..root_inode_off + inode_size as usize],
        root_dir_block,
        block_size,
        flavor,
        inode_size,
        &csum,
    );

    // ----- Journal inode (ext3 only): inode 8 -------------------------------
    // Built from the same `indirect_mut::plan_contiguous` primitive every
    // ext2/3 file write uses. The journal lives at a contiguous physical
    // run of `ext3_journal_blocks` starting at `journal_data_start`, so
    // the planner produces a single (`i_block`, indirect_block_writes)
    // pair we splice in directly.
    let mut journal_indirect_writes: Vec<(u64, Vec<u8>)> = Vec::new();
    if matches!(flavor, FsFlavor::Ext3) {
        let jino_off = (EXT3_JOURNAL_INODE as usize - 1) * inode_size as usize;
        // Allocate any indirect-tree blocks immediately AFTER the journal
        // data run so they don't collide with metadata/data the bitmap
        // already reserved. For 1024-block journals at 1 KiB blocks the
        // tree only needs 1 single-indirect block (12 direct + 256 in single
        // tier covers 268; for 1024 we'll spill into double — count the
        // exact need via `count_indirect_blocks`).
        let n_indirect = journal_indirect_blocks;
        let mut next_indirect = journal_data_end;

        // Track the indirect-tree blocks so we can mark them allocated in
        // the bitmap a few lines below.
        let plan = crate::indirect_mut::plan_contiguous(
            ext3_journal_blocks,
            journal_data_start,
            block_size,
            || {
                let v = next_indirect;
                next_indirect += 1;
                Ok(v)
            },
        )?;
        write_journal_inode(
            &mut inode_table[jino_off..jino_off + inode_size as usize],
            ext3_journal_blocks as u64 * block_size as u64,
            (ext3_journal_blocks as u64 + n_indirect) * block_size as u64 / 512,
            &plan.i_block,
        );
        journal_indirect_writes = plan.block_writes;
        // The indirect-tree blocks sit contiguously right after the journal
        // data run, so the main block-bitmap loop already marked them used
        // (used_blocks includes journal_indirect_blocks) — no separate marking
        // needed, which also keeps the bitmap bit math first_data_block-correct.
    }

    let root_dir = build_root_dir(block_size, dir_csum_tail, &csum)?;

    // ----- BGD bitmap-csums + final BGD csum -------------------------------
    // Per Linux `fs/ext4/bitmap.c::ext4_{block,inode}_bitmap_csum_set`:
    //   bb_csum = crc32c(seed, bitmap[0..blocks_per_group / 8])
    //   ib_csum = crc32c(seed, bitmap[0..inodes_per_group / 8])
    // Stored split into 16-bit lo (BGD 0x18 / 0x1A) + 16-bit hi
    // (BGD 0x38 / 0x3A; 64-byte-desc only). e2fsck recomputes both and
    // refuses the volume if the slots don't match. Skipped when csums
    // are off (ext2) so the slots stay zero, matching e2fsprogs.
    if csum_enabled {
        let bb_sz = (blocks_per_group as usize) / 8;
        let ib_sz = (inodes_per_group as usize) / 8;
        let bb_csum = csum.crc(&block_bitmap[..bb_sz.min(block_bitmap.len())]);
        let ib_csum = csum.crc(&inode_bitmap[..ib_sz.min(inode_bitmap.len())]);
        finalize_bgd_checksum(&mut bgd, 0, bb_csum, ib_csum, desc_size, &csum);
    }

    // ----- Write everything out --------------------------------------------
    // Header zone: zero out block 0 (boot sector) and the SB block. For
    // block_size >= 2048 the SB shares block 0; for 1 KiB blocks the SB
    // occupies its own block 1 — the `.max(2048)` ensures we wipe both
    // bootloader region and SB block in either case so we don't carry over
    // stale image bytes (which sabotaged early mount experiments).
    let header_zero_len = (block_size as usize).max(2048);
    let zeros = vec![0u8; header_zero_len];
    dev.write_at(0, &zeros)?;
    // Primary superblock always lives at byte offset 1024 regardless of
    // block_size — for 4 KiB blocks that's mid-block-0; for 1 KiB blocks
    // it's the entirety of block 1.
    dev.write_at(crate::superblock::SUPERBLOCK_OFFSET, &sb)?;
    dev.flush()?;

    // BGT block (zeroed, then group 0's descriptor copied in at offset 0).
    let mut bgt_block_buf = vec![0u8; block_size as usize];
    bgt_block_buf[..desc_size as usize].copy_from_slice(&bgd);
    dev.write_at(bgt_block * block_size as u64, &bgt_block_buf)?;

    dev.write_at(blk_bitmap * block_size as u64, &block_bitmap)?;
    dev.write_at(ino_bitmap * block_size as u64, &inode_bitmap)?;
    dev.write_at(inode_table_start * block_size as u64, &inode_table)?;
    dev.write_at(root_dir_block * block_size as u64, &root_dir)?;

    // ext3 journal: write the JBD2 superblock at the head of the journal
    // data run, leave the rest as zeros (clean state — `s_start = 0` in
    // the JSB matches "no pending transactions"), then persist the
    // indirect-tree blocks the journal inode points at.
    if matches!(flavor, FsFlavor::Ext3) {
        let jsb_block = build_jbd2_superblock(block_size, ext3_journal_blocks, &uuid);
        dev.write_at(journal_data_start * block_size as u64, &jsb_block)?;
        for (blk, buf) in &journal_indirect_writes {
            dev.write_at(blk * block_size as u64, buf)?;
        }
    }

    dev.flush()?;
    Ok(())
}

/// Set bits `[start, end)` in a little-endian on-disk bitmap, clamped to the
/// buffer length.
fn set_bitmap_range(bitmap: &mut [u8], start: u64, end: u64) {
    for bit in start..end {
        let byte = (bit / 8) as usize;
        if byte >= bitmap.len() {
            break;
        }
        bitmap[byte] |= 1 << (bit % 8);
    }
}

/// Build the root directory's data block i.e., a `.`/`..` pair filling the
/// block, plus the `ext4_dir_entry_tail` checksum slot on metadata_csum
/// volumes.
fn build_root_dir(block_size: u32, dir_csum_tail: usize, csum: &Checksummer) -> Result<Vec<u8>> {
    let mut root_dir = vec![0u8; block_size as usize];
    let usable = block_size as usize - dir_csum_tail;
    // Bootstrap: one big tombstone entry that fills the usable region. The
    // dir helper splits this on each add.
    root_dir[0..4].copy_from_slice(&0u32.to_le_bytes()); // inode = 0 (tombstone)
    root_dir[4..6].copy_from_slice(&(usable as u16).to_le_bytes());

    dir::add_entry_to_block(
        &mut root_dir,
        EXT4_ROOT_INO,
        b".",
        DirEntryType::Directory,
        true,
        dir_csum_tail,
    )?;
    dir::add_entry_to_block(
        &mut root_dir,
        EXT4_ROOT_INO,
        b"..",
        DirEntryType::Directory,
        true,
        dir_csum_tail,
    )?;

    if csum.enabled {
        let end = root_dir.len();
        root_dir[end - 12..end - 8].copy_from_slice(&0u32.to_le_bytes()); // inode
        root_dir[end - 8..end - 6].copy_from_slice(&12u16.to_le_bytes()); // rec_len
        root_dir[end - 6] = 0; // name_len
        root_dir[end - 5] = 0xDE; // file_type marker
        root_dir[end - 4..end].copy_from_slice(&0u32.to_le_bytes()); // csum slot

        let mut c = linux_crc32c(csum.seed, &EXT4_ROOT_INO.to_le_bytes());
        c = linux_crc32c(c, &0u32.to_le_bytes()); // generation = 0
        c = linux_crc32c(c, &root_dir[..root_dir.len() - 12]);
        root_dir[end - 4..end].copy_from_slice(&c.to_le_bytes());
    }
    Ok(root_dir)
}

/// Write the block/inode bitmap checksums and the descriptor's own CRC into a
/// block-group descriptor `bgd`.
fn finalize_bgd_checksum(
    bgd: &mut [u8],
    group: u32,
    bb_csum: u32,
    ib_csum: u32,
    desc_size: u16,
    csum: &Checksummer,
) {
    bgd[0x18..0x1A].copy_from_slice(&((bb_csum & 0xFFFF) as u16).to_le_bytes());
    bgd[0x1A..0x1C].copy_from_slice(&((ib_csum & 0xFFFF) as u16).to_le_bytes());
    if desc_size >= 64 {
        bgd[0x38..0x3A].copy_from_slice(&((bb_csum >> 16) as u16).to_le_bytes());
        bgd[0x3A..0x3C].copy_from_slice(&((ib_csum >> 16) as u16).to_le_bytes());
    }
    let mut tmp = bgd.to_vec();
    tmp[0x1E] = 0;
    tmp[0x1F] = 0;
    let bgd_csum = (csum.crc_with_prefix(group, &tmp) & 0xFFFF) as u16;
    bgd[0x1E..0x20].copy_from_slice(&bgd_csum.to_le_bytes());
}

/// Format an ext4 volume as one or more block groups. Superblock + GDT
/// backups follow the classic RO_COMPAT_SPARSE_SUPER rule (groups 0, 1, and
/// powers of 3/5/7); every group gets its own block and inode bitmaps plus an
/// inode table. Classic non-flex_bg layout, and no journal for the time being.
#[allow(clippy::too_many_lines)]
fn format_block_groups(
    dev: &dyn BlockDevice,
    label: Option<&str>,
    uuid: Option<[u8; 16]>,
    size_bytes: u64,
    block_size: u32,
) -> Result<()> {
    const RESERVED_INODES: u32 = 10;

    let (inode_size, desc_size, _, dir_csum_tail) = FsFlavor::Ext4.geometry();

    let bs = block_size as u64;
    let log_block_size = (block_size.trailing_zeros() as i32 - 10) as u32;
    let blocks_per_group: u32 = 8 * block_size;
    let bpg = blocks_per_group as u64;
    let inodes_per_group: u32 = 8192;
    let inode_table_blocks: u32 = (inodes_per_group as u64 * inode_size as u64).div_ceil(bs) as u32;

    let blocks_count: u64 = size_bytes / bs;
    let group_count: u64 = blocks_count.div_ceil(bpg);
    let gdt_blocks: u32 = (group_count * desc_size as u64).div_ceil(bs) as u32;

    if bpg <= 4 + gdt_blocks as u64 + inode_table_blocks as u64 {
        return Err(Error::InvalidArgument(
            "mkfs: group descriptor table does not fit in a single block group",
        ));
    }

    let inodes_count: u64 = group_count * inodes_per_group as u64;
    if inodes_count > u32::MAX as u64 {
        return Err(Error::InvalidArgument("mkfs: too many inodes for layout"));
    }
    let total_free_inodes: u64 = inodes_count - RESERVED_INODES as u64;

    let uuid = uuid.unwrap_or_else(generate_uuid);
    let csum = Checksummer {
        seed: linux_crc32c(!0, &uuid),
        enabled: true,
    };

    let mut gdt = vec![0u8; gdt_blocks as usize * block_size as usize];
    let mut total_free_blocks: u64 = 0;
    let mut root_dir_block: u64 = 0;

    for g in 0..group_count {
        let gstart = g * bpg;
        let glen = bpg.min(blocks_count - gstart);

        let group_meta = if group_has_super(g) {
            1 + gdt_blocks as u64
        } else {
            0
        };
        let bb_block = gstart + group_meta;
        let ib_block = bb_block + 1;
        let it_block = ib_block + 1;
        let data_start = it_block + inode_table_blocks as u64;
        let used = (data_start - gstart) + u64::from(g == 0);
        if g == 0 {
            root_dir_block = data_start;
        }
        let free = glen.checked_sub(used).ok_or(Error::InvalidArgument(
            "mkfs: group overhead exceeds group size",
        ))?;
        total_free_blocks += free;

        let mut block_bitmap = vec![0u8; block_size as usize];
        set_bitmap_range(&mut block_bitmap, 0, used);
        // Pad blocks past a short final group:
        set_bitmap_range(&mut block_bitmap, glen, bpg);
        let bb_csum = csum.crc(&block_bitmap[..blocks_per_group as usize / 8]);

        let mut inode_bitmap = vec![0u8; block_size as usize];
        if g == 0 {
            set_bitmap_range(&mut inode_bitmap, 0, RESERVED_INODES as u64);
        }
        set_bitmap_range(&mut inode_bitmap, inodes_per_group as u64, bs * 8);
        let ib_csum = csum.crc(&inode_bitmap[..inodes_per_group as usize / 8]);

        let mut inode_table = vec![0u8; inode_table_blocks as usize * block_size as usize];
        if g == 0 {
            let off = (EXT4_ROOT_INO as usize - 1) * inode_size as usize;
            write_root_inode(
                &mut inode_table[off..off + inode_size as usize],
                root_dir_block,
                block_size,
                FsFlavor::Ext4,
                inode_size,
                &csum,
            );
        }

        let free_inodes_g = if g == 0 {
            inodes_per_group - RESERVED_INODES
        } else {
            inodes_per_group
        };
        let used_dirs_g = u32::from(g == 0);
        let bgd = &mut gdt[g as usize * desc_size as usize..(g as usize + 1) * desc_size as usize];
        write_bgd_group(
            bgd,
            bb_block,
            ib_block,
            it_block,
            free,
            free_inodes_g,
            used_dirs_g,
            desc_size,
        );
        finalize_bgd_checksum(bgd, g as u32, bb_csum, ib_csum, desc_size, &csum);

        dev.write_at(bb_block * bs, &block_bitmap)?;
        dev.write_at(ib_block * bs, &inode_bitmap)?;
        dev.write_at(it_block * bs, &inode_table)?;
    }

    let mut sb = build_superblock(
        inodes_count as u32,
        blocks_count,
        total_free_blocks,
        total_free_inodes as u32,
        0,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        &uuid,
        label.unwrap_or(""),
        FsFlavor::Ext4,
        inode_size,
        desc_size,
        0,
    );
    let c = linux_crc32c(!0, &sb[..0x3FC]);
    sb[0x3FC..0x400].copy_from_slice(&c.to_le_bytes());

    let root_dir = build_root_dir(block_size, dir_csum_tail, &csum)?;

    dev.write_at(0, &vec![0u8; block_size as usize])?;
    dev.write_at(crate::superblock::SUPERBLOCK_OFFSET, &sb)?;
    dev.write_at(bs, &gdt)?;
    dev.write_at(root_dir_block * bs, &root_dir)?;

    // Superblock/GDT backups go into sparse-super groups 0, 1, and further
    // following powers of 3/5/7.
    //
    // Each backup is a verbatim GDT combined with a copy of the primary
    // superblock differing only in `s_block_group_nr` (and thus its checksum);
    // `e2fsck` reads them to recover a damaged primary block. The backup
    // superbock sits at offset 0 of the group's first block, with the GDT copy
    // in the blocks immediately after.
    for g in 1..group_count {
        if !group_has_super(g) {
            continue;
        }
        let gstart = g * bpg;
        let mut sb_blk = vec![0u8; block_size as usize];
        sb_blk[..sb.len()].copy_from_slice(&sb);
        sb_blk[0x5A..0x5C].copy_from_slice(&(g as u16).to_le_bytes());
        let c = linux_crc32c(!0, &sb_blk[..0x3FC]);
        sb_blk[0x3FC..0x400].copy_from_slice(&c.to_le_bytes());
        dev.write_at(gstart * bs, &sb_blk)?;
        dev.write_at((gstart + 1) * bs, &gdt)?;
    }

    dev.flush()?;
    Ok(())
}

/// True if block group `g` carries a superblock + GDT backup under the classic
/// RO_COMPAT_SPARSE_SUPER rule: group 0, group 1, and every power of 3, 5, or
/// 7. Mirrors the kernel's / e2fsprogs' `ext4_bg_has_super`.
fn group_has_super(g: u64) -> bool {
    fn is_power_of(mut g: u64, base: u64) -> bool {
        while g.is_multiple_of(base) {
            g /= base;
        }
        g == 1
    }
    g <= 1 || is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7)
}

/// Build a clean JBD2 v2 superblock for a fresh ext3 journal. Layout per
/// `jbd2.rs` module docs (big-endian throughout, magic 0xc03b3998 + V2
/// block_type = 4). All fields zero except the spec-required ones:
/// `block_size`, `max_len`, `first = 1` (block 0 is the JSB itself),
/// `sequence = 1` (replay starts here on first mount), `start = 0`
/// (journal is clean — nothing to replay), per-volume `uuid`.
fn build_jbd2_superblock(block_size: u32, max_len: u32, uuid: &[u8; 16]) -> Vec<u8> {
    let mut buf = vec![0u8; block_size as usize];
    // Header: magic + block_type + h_sequence (big-endian).
    buf[0x00..0x04].copy_from_slice(&crate::jbd2::JBD2_MAGIC_NUMBER.to_be_bytes());
    buf[0x04..0x08].copy_from_slice(&crate::jbd2::JBD2_SUPERBLOCK_V2.to_be_bytes());
    buf[0x08..0x0C].copy_from_slice(&1u32.to_be_bytes()); // h_sequence
                                                          // s_blocksize, s_maxlen, s_first, s_sequence, s_start, s_errno.
    buf[0x0C..0x10].copy_from_slice(&block_size.to_be_bytes());
    buf[0x10..0x14].copy_from_slice(&max_len.to_be_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes()); // s_first = 1
    buf[0x18..0x1C].copy_from_slice(&1u32.to_be_bytes()); // s_sequence = 1
    buf[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes()); // s_start = 0 (clean)
                                                          // s_errno = 0 (already zero from vec init)
                                                          // V2 fields — leave feature bits all-zero (no compression / 64bit /
                                                          // csum-v2 etc.). UUID at 0x30 + s_nr_users = 1 at 0x40.
    buf[0x30..0x40].copy_from_slice(uuid);
    buf[0x40..0x44].copy_from_slice(&1u32.to_be_bytes()); // s_nr_users = 1
    buf
}

/// Write the journal-inode image (typically inode 8) for ext3. The
/// journal inode is mode-less (`i_mode = 0`), `i_links_count = 1`, and
/// `i_block` is filled by the caller from `indirect_mut::plan_contiguous`
/// — the journal data lives at a contiguous physical run, so the same
/// indirect-tree primitive every regular ext2/3 file uses works here.
///
/// `i_size` covers ONLY the journal data blocks (not the indirect-tree
/// metadata blocks, which add to `i_blocks` but not `i_size`).
fn write_journal_inode(slot: &mut [u8], size_bytes: u64, blocks_512: u64, i_block: &[u8; 60]) {
    // i_mode = 0 — journal has no POSIX type. The kernel checks ino number,
    // not mode, when locating it. Linux mkfs writes 0 here.
    slot[0x00..0x02].copy_from_slice(&0u16.to_le_bytes());
    // i_size_lo
    slot[0x04..0x08].copy_from_slice(&((size_bytes & 0xFFFF_FFFF) as u32).to_le_bytes());
    // i_links_count = 1 (the journal-inode-table reference itself).
    slot[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
    // i_blocks_lo: 512-byte sectors = data + indirect-tree blocks.
    slot[0x1C..0x20].copy_from_slice(&((blocks_512 & 0xFFFF_FFFF) as u32).to_le_bytes());
    // i_flags = 0 (no EXTENTS_FL — ext3 journal is always indirect).
    slot[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
    // i_block: the indirect-tree root we built externally.
    slot[0x28..0x28 + 60].copy_from_slice(i_block);
    // i_size_hi at 0x6C — only meaningful past the 4 GiB cap; our 1024-block
    // journal at any block_size stays well under it.
}

/// 16 random bytes from `/dev/urandom`, falling back to a time-seeded LCG if
/// the device is unavailable. Sets the v4 UUID layout bits.
fn generate_uuid() -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if f.read_exact(&mut out).is_ok() {
            // RFC 4122 v4: top nibble of byte 6 = 0x4, top two bits of byte 8 = 0b10.
            out[6] = (out[6] & 0x0F) | 0x40;
            out[8] = (out[8] & 0x3F) | 0x80;
            return out;
        }
    }
    // Fallback: deterministic mix of nanos + pid. Not cryptographic — but
    // /dev/urandom is universally available on Darwin and Linux so this
    // path effectively only fires inside aggressively sandboxed tests.
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEF)
        ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    for b in out.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 56) as u8;
    }
    out[6] = (out[6] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
    out
}

#[allow(clippy::too_many_arguments)]
fn build_superblock(
    inodes_count: u32,
    blocks_count: u64,
    free_blocks: u64,
    free_inodes: u32,
    first_data_block: u32,
    log_block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    uuid: &[u8; 16],
    label: &str,
    flavor: FsFlavor,
    inode_size: u16,
    desc_size: u16,
    journal_inum: u32,
) -> Vec<u8> {
    let mut sb = vec![0u8; 1024];

    let blocks_lo = (blocks_count & 0xFFFF_FFFF) as u32;
    let blocks_hi = (blocks_count >> 32) as u32;
    let free_lo = (free_blocks & 0xFFFF_FFFF) as u32;
    let free_hi = (free_blocks >> 32) as u32;

    sb[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
    sb[0x04..0x08].copy_from_slice(&blocks_lo.to_le_bytes());
    // 0x08..0x0C s_r_blocks_count_lo (reserved blocks) — 0 is fine.
    sb[0x0C..0x10].copy_from_slice(&free_lo.to_le_bytes());
    sb[0x10..0x14].copy_from_slice(&free_inodes.to_le_bytes());
    sb[0x14..0x18].copy_from_slice(&first_data_block.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&log_block_size.to_le_bytes());
    // 0x1C..0x20 s_log_cluster_size — must mirror s_log_block_size when bigalloc off.
    sb[0x1C..0x20].copy_from_slice(&log_block_size.to_le_bytes());
    sb[0x20..0x24].copy_from_slice(&blocks_per_group.to_le_bytes());
    // 0x24..0x28 s_clusters_per_group (mirrors blocks_per_group, no bigalloc).
    sb[0x24..0x28].copy_from_slice(&blocks_per_group.to_le_bytes());
    sb[0x28..0x2C].copy_from_slice(&inodes_per_group.to_le_bytes());

    // s_mtime, s_wtime stay 0 — ext4 spec allows; no Y2038 trap here.
    // s_mnt_count = 0, s_max_mnt_count = 0xFFFF (no fsck nag).
    sb[0x34..0x36].copy_from_slice(&0u16.to_le_bytes()); // mnt_count
    sb[0x36..0x38].copy_from_slice(&0xFFFFu16.to_le_bytes()); // max_mnt_count

    sb[0x38..0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
    sb[0x3A..0x3C].copy_from_slice(&EXT4_VALID_FS.to_le_bytes()); // state
    sb[0x3C..0x3E].copy_from_slice(&1u16.to_le_bytes()); // errors = continue
    sb[0x3E..0x40].copy_from_slice(&0u16.to_le_bytes()); // minor_rev_level

    // 0x40..0x44 s_lastcheck = 0
    // 0x44..0x48 s_checkinterval = 0
    sb[0x48..0x4C].copy_from_slice(&0u32.to_le_bytes()); // creator_os = 0 (Linux)

    sb[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes()); // rev_level = DYNAMIC
    sb[0x50..0x52].copy_from_slice(&0u16.to_le_bytes()); // def_resuid
    sb[0x52..0x54].copy_from_slice(&0u16.to_le_bytes()); // def_resgid

    // Dynamic-rev fields.
    sb[0x54..0x58].copy_from_slice(&11u32.to_le_bytes()); // first_ino (>= 11 reserved-end)
    sb[0x58..0x5A].copy_from_slice(&inode_size.to_le_bytes());
    sb[0x5A..0x5C].copy_from_slice(&0u16.to_le_bytes()); // block_group_nr (this SB's group = 0)

    // Per-flavor feature bits. Ext2 advertises FILETYPE only (so directory
    // entries carry a file_type byte); ext4 layers on EXTENTS + 64BIT for
    // wide block addressing and METADATA_CSUM for the on-disk CRCs the
    // checksum_type=crc32c byte selects below.
    let (feat_compat, feat_incompat, feat_ro_compat): (u32, u32, u32) = match flavor {
        FsFlavor::Ext2 => (0u32, Incompat::FILETYPE.bits(), 0u32),
        FsFlavor::Ext3 => (
            // HAS_JOURNAL signals that `s_journal_inum` (set below) names a
            // valid journal inode. Mounters that don't grok HAS_JOURNAL will
            // (correctly) refuse the volume — historically that's how ext2-
            // only drivers stayed safe in the face of a dirty ext3 journal.
            Compat::HAS_JOURNAL.bits(),
            Incompat::FILETYPE.bits(),
            0u32,
        ),
        FsFlavor::Ext4 => (
            0u32,
            Incompat::FILETYPE.bits() | Incompat::EXTENTS.bits() | Incompat::BIT64.bits(),
            // SPARSE_SUPER: backups in groups 0, 1, and powers of 3/5/7.
            RoCompat::METADATA_CSUM.bits() | RoCompat::SPARSE_SUPER.bits(),
        ),
    };
    sb[0x5C..0x60].copy_from_slice(&feat_compat.to_le_bytes());
    sb[0x60..0x64].copy_from_slice(&feat_incompat.to_le_bytes());
    sb[0x64..0x68].copy_from_slice(&feat_ro_compat.to_le_bytes());

    sb[0x68..0x78].copy_from_slice(uuid);

    // Volume label — 16 bytes, NUL-padded.
    let lbl = label.as_bytes();
    let n = lbl.len().min(16);
    sb[0x78..0x78 + n].copy_from_slice(&lbl[..n]);

    // s_last_mounted (64 bytes at 0x88) stays zero.
    // Algorithm bits / prealloc / reserved (0xC8..0xD8) zero.

    // s_journal_inum at 0xE0..0xE4 — set to inode 8 for ext3 (HAS_JOURNAL),
    // zero for everything else. (The 0xD8 region holds algorithm bits +
    // prealloc counters, NOT the journal inode pointer.)
    sb[0xE0..0xE4].copy_from_slice(&journal_inum.to_le_bytes());
    // 0xDC..0xE0 s_journal_dev  — 0.
    // 0xE0..0xE4 s_last_orphan  — 0.
    // 0xE4..0xF4 s_hash_seed[4] — pick a stable nonzero seed. (Only matters
    // if HTree is in play; we don't set DIR_INDEX, but ext4 formatter still seeds
    // these so tools don't whine.)
    sb[0xE4..0xE8].copy_from_slice(&0xC1A2B3C4u32.to_le_bytes());
    sb[0xE8..0xEC].copy_from_slice(&0xD5E6F7A8u32.to_le_bytes());
    sb[0xEC..0xF0].copy_from_slice(&0xB9CADBECu32.to_le_bytes());
    sb[0xF0..0xF4].copy_from_slice(&0xFD0E1F2Au32.to_le_bytes());

    sb[0xFC] = 1; // s_def_hash_version = HALF_MD4
                  // 0xFD reserved_char_pad
                  // 0xFE..0x100 s_desc_size
                  // s_desc_size: only meaningful when INCOMPAT_64BIT is set (i.e. ext4).
                  // Spec says leave 0 for legacy 32-byte BGDs; the reader treats 0 as 32.
    let on_disk_desc_size: u16 = if matches!(flavor, FsFlavor::Ext4) {
        desc_size
    } else {
        0
    };
    sb[0xFE..0x100].copy_from_slice(&on_disk_desc_size.to_le_bytes());

    // 0x100..0x104 s_default_mount_opts = 0
    // 0x104..0x108 s_first_meta_bg     = 0 (no META_BG)
    // 0x108..0x10C s_mkfs_time         = 0
    // 0x10C..0x14C s_jnl_blocks[17]    = 0

    // s_blocks_count_hi at 0x150 (64BIT).
    sb[0x150..0x154].copy_from_slice(&blocks_hi.to_le_bytes());
    // s_r_blocks_count_hi 0x154 = 0.
    sb[0x158..0x15C].copy_from_slice(&free_hi.to_le_bytes()); // free_blocks_count_hi

    // s_min_extra_isize / s_want_extra_isize (0x15C / 0x15E): only meaningful
    // when on-disk inodes carry the post-128 extra section (ext4 with
    // 256-byte inodes). Ext2's 128-byte inodes leave both fields zero.
    if inode_size >= 160 {
        sb[0x15C..0x15E].copy_from_slice(&I_EXTRA_ISIZE.to_le_bytes());
        sb[0x15E..0x160].copy_from_slice(&I_EXTRA_ISIZE.to_le_bytes());
    }

    // s_flags 0x160..0x164: bit 0 = signed dirhash (matches ext4 formatter default).
    sb[0x160..0x164].copy_from_slice(&0x1u32.to_le_bytes());

    // 0x164..0x166 s_raid_stride / 0x166..0x168 mmp_update_interval / etc — zero.

    // s_kbytes_written at 0x148..0x150 = 0 (no writes yet).

    // s_inode_size at 0x58 already set; s_min_extra_isize done above.

    // s_log_groups_per_flex (0x174) — 0 means flex_bg disabled.

    // s_checksum_type at 0x175 = 1 (crc32c) when METADATA_CSUM is on. Ext2
    // leaves it 0 (no algorithm) since no on-disk checksums are written.
    if matches!(flavor, FsFlavor::Ext4) {
        sb[0x175] = 1;
    }

    // s_encryption_level (0x176) reserved-pad (0x177) zero.

    // s_kbytes_written (0x148): 0.

    // s_snapshot_inum / list / id_xattr — zero.

    // s_creator_os already 0.

    // Leave s_checksum (0x3FC..0x400) as zero — caller patches it.
    sb
}

#[allow(clippy::too_many_arguments)]
fn write_bgd_group(
    out: &mut [u8],
    block_bitmap_block: u64,
    inode_bitmap_block: u64,
    inode_table_block: u64,
    free_blocks: u64,
    free_inodes: u32,
    used_dirs: u32,
    desc_size: u16,
) {
    // Lo halves: present in both 32-byte and 64-byte BGD layouts.
    out[0x00..0x04].copy_from_slice(&(block_bitmap_block as u32).to_le_bytes());
    out[0x04..0x08].copy_from_slice(&(inode_bitmap_block as u32).to_le_bytes());
    out[0x08..0x0C].copy_from_slice(&(inode_table_block as u32).to_le_bytes());
    out[0x0C..0x0E].copy_from_slice(&(free_blocks as u16).to_le_bytes());
    out[0x0E..0x10].copy_from_slice(&(free_inodes as u16).to_le_bytes());
    out[0x10..0x12].copy_from_slice(&(used_dirs as u16).to_le_bytes());
    out[0x12..0x14].copy_from_slice(&0u16.to_le_bytes()); // bg_flags = 0 (initialised)
                                                          // 0x14..0x18 exclude_bitmap reserved.
                                                          // 0x18..0x1A block_bitmap_csum_lo, 0x1A..0x1C inode_bitmap_csum_lo — leave 0;
                                                          // only validated on metadata_csum volumes.
    out[0x1C..0x1E].copy_from_slice(&0u16.to_le_bytes()); // itable_unused_lo
                                                          // 0x1E..0x20 checksum — patched after struct is complete.

    // 64-bit hi halves only present in the 64-byte BGD layout.
    if desc_size >= 64 {
        out[0x20..0x24].copy_from_slice(&((block_bitmap_block >> 32) as u32).to_le_bytes());
        out[0x24..0x28].copy_from_slice(&((inode_bitmap_block >> 32) as u32).to_le_bytes());
        out[0x28..0x2C].copy_from_slice(&((inode_table_block >> 32) as u32).to_le_bytes());
        out[0x2C..0x2E].copy_from_slice(&((free_blocks >> 16) as u16).to_le_bytes()); // free_blocks_hi
        out[0x2E..0x30].copy_from_slice(&0u16.to_le_bytes()); // free_inodes_hi
        out[0x30..0x32].copy_from_slice(&0u16.to_le_bytes()); // used_dirs_hi
        out[0x32..0x34].copy_from_slice(&0u16.to_le_bytes()); // itable_unused_hi
                                                              // 0x34..0x38 reserved
        out[0x38..0x3A].copy_from_slice(&0u16.to_le_bytes()); // bb_csum_hi
        out[0x3A..0x3C].copy_from_slice(&0u16.to_le_bytes()); // ib_csum_hi
                                                              // 0x3C..0x40 reserved
    }
}

/// Write the root directory inode (ino 2). Layout depends on `flavor`:
/// ext4 uses an extent header pointing at `root_dir_block`; ext2/3 use the
/// legacy direct/indirect scheme with `i_block[0] = root_dir_block`.
/// Caller patches the CRC slots afterwards on metadata_csum volumes.
fn write_root_inode(
    slot: &mut [u8],
    root_dir_block: u64,
    block_size: u32,
    flavor: FsFlavor,
    inode_size: u16,
    csum: &Checksummer,
) {
    // i_mode
    slot[0x00..0x02].copy_from_slice(&ROOT_MODE.to_le_bytes());
    // i_uid_lo, i_size_lo. Size = one directory data block.
    slot[0x04..0x08].copy_from_slice(&(block_size).to_le_bytes());
    // i_atime, i_ctime, i_mtime — left zero; mkfs convention but not required.
    // i_links_count = 2 (`.` and `..`)
    slot[0x1A..0x1C].copy_from_slice(&2u16.to_le_bytes());
    // i_blocks_lo: 512-byte units. One 4 KiB block = 8 sectors.
    let i_blocks = block_size / 512;
    slot[0x1C..0x20].copy_from_slice(&i_blocks.to_le_bytes());

    if flavor.uses_extents() {
        // i_flags: EXT4_EXTENTS_FL
        slot[0x20..0x24].copy_from_slice(&crate::inode::InodeFlags::EXTENTS.bits().to_le_bytes());

        // i_block[60]: extent header + one extent.
        // Header: magic, entries=1, max=4, depth=0, generation=0
        slot[0x28..0x2A].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        slot[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes()); // entries
        slot[0x2C..0x2E].copy_from_slice(&4u16.to_le_bytes()); // max
        slot[0x2E..0x30].copy_from_slice(&0u16.to_le_bytes()); // depth
        slot[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // generation
                                                               // First extent at 0x34..0x40:
                                                               //   ee_block (logical=0), ee_len=1, ee_start_hi, ee_start_lo
        slot[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // ee_block
        slot[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // ee_len
        slot[0x3A..0x3C].copy_from_slice(&((root_dir_block >> 32) as u16).to_le_bytes()); // ee_start_hi
        slot[0x3C..0x40].copy_from_slice(&(root_dir_block as u32).to_le_bytes());
    // ee_start_lo
    // Remaining 0x40..0x64 in i_block region stays zero (padding).
    } else {
        // ext2/3: i_flags clear, i_block[0] = direct pointer to the root dir
        // data block. ext2/3 cap addresses at 32 bits, so the high half of
        // `root_dir_block` is asserted zero by the geometry the caller picked
        // (single-group fixtures fit comfortably in u32).
        debug_assert!(
            root_dir_block <= u32::MAX as u64,
            "ext2 i_block pointer overflow"
        );
        slot[0x20..0x24].copy_from_slice(&0u32.to_le_bytes()); // i_flags = 0
        slot[0x28..0x2C].copy_from_slice(&(root_dir_block as u32).to_le_bytes());
        // i_block[1..15] stays zero — no further direct/indirect pointers
        // since the directory fits in one block.
    }

    slot[0x64..0x68].copy_from_slice(&0u32.to_le_bytes()); // i_generation
                                                           // i_file_acl_lo (0x68), i_size_hi (0x6C), obso_faddr (0x70) — zero.
                                                           // i_blocks_hi (0x74), i_file_acl_hi (0x76), i_uid_hi (0x78), i_gid_hi (0x7A)
                                                           // — zero. i_checksum_lo at 0x7C — caller patches when csum is on.

    // Extra section (only present when on-disk inode size >= 160 bytes).
    // Ext2's 128-byte inodes skip this entirely.
    if inode_size >= 160 && slot.len() > 0x80 {
        slot[0x80..0x82].copy_from_slice(&I_EXTRA_ISIZE.to_le_bytes());
        // i_checksum_hi (0x82..0x84) patched by caller on csum volumes.
        // 0x84..0x98 *_extra timestamps + crtime — zero.
    }

    if csum.enabled {
        if let Some((lo, hi)) = csum.compute_inode_checksum(EXT4_ROOT_INO, 0, slot) {
            slot[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
            slot[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
        }
    }
}
