//! In-process **empty, writable, growable** ext4 formatter — the `mkfs` sibling
//! of the read-only [`build_image`](crate::ext4::build_image) packer.
//!
//! `build_image` assembles a whole content-sized image in RAM and marks every
//! block used (a read-only rootfs sealed by dm-verity). A persistent host cache
//! — the Stage 0 Nix store — needs the opposite: a filesystem sized to the full
//! backing device (tens of GiB), mounted read-write, that a guest keeps adding
//! files to across boots. So this path writes only the (small) metadata blocks
//! directly to a pre-sized, sparse device at their byte offsets, marks the vast
//! data region **free**, and never materializes the device in memory.
//!
//! Same minimal feature set as the reader path — extents + filetype, no journal,
//! no metadata_csum — which the Linux kernel mounts read-write. The device/file
//! must already exist at `size_bytes` (mirrors the `mkfs.ext4` convention); a
//! sparse file is fine, only touched blocks consume space.

use std::io::{self, Seek, SeekFrom, Write};

use crate::ext4::{
    BLOCK_SIZE, BLOCKS_PER_GROUP, EXT4_MAGIC, EXTENT_MAGIC, EXTENTS_FL, FIRST_INO, FT_DIR,
    INCOMPAT_FILETYPE_EXTENTS, INODE_SIZE, MAX_GROUPS, MIN_INODES_PER_GROUP, ROOT_INO, S_IFDIR,
    ceil_div_u32, round_up_8,
};

/// Failure formatting an empty ext4. All variants are recoverable (no panics on
/// caller-influenced input); I/O errors carry the underlying [`io::Error`].
#[derive(Debug)]
pub enum MkfsError {
    /// `size_bytes` is too small to hold even one block group's metadata plus a
    /// root directory block.
    TooSmall { size_bytes: u64, min_bytes: u64 },
    /// The device needs more block groups than the sanity ceiling allows.
    TooLarge { blocks: u64 },
    /// Writing the metadata to the device failed.
    Io(io::Error),
}

impl std::fmt::Display for MkfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MkfsError::TooSmall {
                size_bytes,
                min_bytes,
            } => write!(
                f,
                "device is {size_bytes} bytes, below the {min_bytes}-byte minimum for an ext4 layout"
            ),
            MkfsError::TooLarge { blocks } => write!(
                f,
                "device needs {blocks} blocks, exceeding the {MAX_GROUPS}-group ceiling"
            ),
            MkfsError::Io(e) => write!(f, "writing ext4 metadata: {e}"),
        }
    }
}

impl std::error::Error for MkfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MkfsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MkfsError {
    fn from(e: io::Error) -> Self {
        MkfsError::Io(e)
    }
}

/// What [`format_empty_ext4`] laid down — handy for logging and for tests to
/// assert the free-space accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSummary {
    /// Total 4 KiB blocks the filesystem spans (may be < device size when a tiny
    /// trailing partial group is dropped).
    pub total_blocks: u32,
    /// Blocks free for data immediately after format (device minus metadata and
    /// the root directory block). Non-zero — this is the point of the path.
    pub free_blocks: u32,
    /// Inode slots the filesystem provides.
    pub inode_slots: u32,
    /// Inode slots free after format (all but the reserved 1..=10).
    pub free_inodes: u32,
    /// Block groups.
    pub groups: u32,
}

/// Resolved geometry for a device of `size_bytes`. Uniform per group (no
/// sparse_super: a superblock + GDT backup sits at the start of every group),
/// so `prefix` — the metadata block count reserved at the head of each group —
/// is the same everywhere.
struct Geometry {
    total_blocks: u32,
    groups: u32,
    inodes_per_group: u32,
    gdt_blocks: u32,
    prefix: u32,
}

/// The reserved inodes (1..=10) are all marked used; root is inode 2 among
/// them. We create no `lost+found` — the kernel mounts and writes without it.
const RESERVED_INODES: u32 = 10;

impl Geometry {
    fn plan(size_bytes: u64) -> Result<Self, MkfsError> {
        let bs = BLOCK_SIZE as u64;
        let device_blocks = size_bytes / bs;
        if device_blocks > u32::MAX as u64 {
            return Err(MkfsError::TooLarge {
                blocks: device_blocks,
            });
        }
        // One inode per ~16 KiB, ext4's default density: BLOCKS_PER_GROUP / 4
        // inodes per group (rounded to a multiple of 8 for the bitmap).
        let inodes_per_group = round_up_8((BLOCKS_PER_GROUP / 4).max(MIN_INODES_PER_GROUP));
        let itb = ceil_div_u32(
            inodes_per_group.saturating_mul(INODE_SIZE as u32),
            BLOCK_SIZE,
        );

        // Converge on a group count: the last group must hold the full metadata
        // prefix plus at least the root block, else drop it into unused tail
        // (a sub-prefix sliver, < 2 MiB, is not worth a runt group). `gdt_blocks`
        // depends on `groups`, so recompute the prefix each round.
        let mut total_blocks = device_blocks as u32;
        let mut groups = total_blocks.div_ceil(BLOCKS_PER_GROUP);
        loop {
            if groups == 0 {
                let min_blocks = 3 + 1 + itb + 1; // sb + 1 gdt + bitmaps..itb + root
                return Err(MkfsError::TooSmall {
                    size_bytes,
                    min_bytes: min_blocks as u64 * bs,
                });
            }
            if groups > MAX_GROUPS {
                return Err(MkfsError::TooLarge {
                    blocks: device_blocks,
                });
            }
            let gdt_blocks = ceil_div_u32(groups.saturating_mul(32), BLOCK_SIZE);
            let prefix = 3 + gdt_blocks + itb;
            let last_group_blocks = total_blocks - (groups - 1) * BLOCKS_PER_GROUP;
            // `> prefix` == room for the metadata prefix plus at least the root block.
            if last_group_blocks > prefix {
                return Ok(Self {
                    total_blocks,
                    groups,
                    inodes_per_group,
                    gdt_blocks,
                    prefix,
                });
            }
            // Trailing group can't carry its own metadata: drop it, keeping only
            // the full groups below it.
            groups -= 1;
            total_blocks = groups * BLOCKS_PER_GROUP;
        }
    }

    fn group_start(&self, g: u32) -> u32 {
        g * BLOCKS_PER_GROUP
    }
    fn block_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 1 + self.gdt_blocks
    }
    fn inode_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 2 + self.gdt_blocks
    }
    fn inode_table(&self, g: u32) -> u32 {
        self.group_start(g) + 3 + self.gdt_blocks
    }
    /// First data block of group `g` (also root's data block in group 0).
    fn data_start(&self, g: u32) -> u32 {
        self.group_start(g) + self.prefix
    }
    /// Real blocks in group `g` (the final group may be partial).
    fn group_blocks(&self, g: u32) -> u32 {
        ((g + 1) * BLOCKS_PER_GROUP).min(self.total_blocks) - self.group_start(g)
    }
    fn inode_slots(&self) -> u32 {
        self.inodes_per_group * self.groups
    }
    /// Data blocks free in group `g`: its real blocks minus the metadata prefix,
    /// minus the root directory block that lives in group 0.
    fn group_free_blocks(&self, g: u32) -> u32 {
        self.group_blocks(g) - self.prefix - if g == 0 { 1 } else { 0 }
    }
    fn free_blocks(&self) -> u32 {
        // Σ group_blocks == total_blocks; Σ prefix == groups*prefix; one root block.
        self.total_blocks - self.groups * self.prefix - 1
    }
}

/// Format `dev` as an empty, writable ext4 filesystem spanning `size_bytes`.
///
/// The device/file must already be at least `size_bytes` long (a sparse file is
/// fine). Only metadata blocks are written; the data region is left untouched,
/// so a sparse backing file stays sparse. Returns the resolved layout.
pub fn format_empty_ext4<W: Write + Seek>(
    dev: &mut W,
    size_bytes: u64,
) -> Result<FormatSummary, MkfsError> {
    let geom = Geometry::plan(size_bytes)?;

    let superblock = build_superblock(&geom);
    let gdt = build_gdt(&geom);

    // Primary superblock: at byte offset 1024, inside block 0 (which also holds
    // the 1024-byte boot area). Primary GDT: blocks 1..1+gdt_blocks.
    write_at(dev, 1024, &superblock)?;
    write_block(dev, 1, &gdt)?;

    for g in 0..geom.groups {
        // No sparse_super, so every group past 0 carries a superblock + GDT
        // backup at its head. Offline tools trust these; the kernel uses the
        // primary. The backup superblock sits at the very start of the group.
        if g != 0 {
            let mut backup_sb = superblock.clone();
            put_u16(&mut backup_sb, 0x5A, g as u16); // s_block_group_nr
            write_block_at_offset(dev, geom.group_start(g), 0, &backup_sb)?;
            write_block(dev, geom.group_start(g) + 1, &gdt)?;
        }
        write_block(dev, geom.block_bitmap(g), &build_block_bitmap(&geom, g))?;
        write_block(dev, geom.inode_bitmap(g), &build_inode_bitmap(&geom, g))?;
    }

    // Group 0's first inode-table block carries the reserved inodes and root.
    write_block(
        dev,
        geom.inode_table(0),
        &build_root_inode_table_block(&geom),
    )?;
    // Root directory data block: "." and ".." both point at root.
    write_block(dev, geom.data_start(0), &build_root_dir_block())?;

    dev.flush()?;

    Ok(FormatSummary {
        total_blocks: geom.total_blocks,
        free_blocks: geom.free_blocks(),
        inode_slots: geom.inode_slots(),
        free_inodes: geom.inode_slots() - RESERVED_INODES,
        groups: geom.groups,
    })
}

// ── byte / block writers ────────────────────────────────────────────────────

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn set_bit(buf: &mut [u8], bit: usize) {
    buf[bit / 8] |= 1u8 << (bit % 8);
}

fn write_at<W: Write + Seek>(dev: &mut W, offset: u64, bytes: &[u8]) -> io::Result<()> {
    dev.seek(SeekFrom::Start(offset))?;
    dev.write_all(bytes)
}
fn write_block<W: Write + Seek>(dev: &mut W, block: u32, bytes: &[u8]) -> io::Result<()> {
    write_at(dev, block as u64 * BLOCK_SIZE as u64, bytes)
}
fn write_block_at_offset<W: Write + Seek>(
    dev: &mut W,
    block: u32,
    within: u64,
    bytes: &[u8],
) -> io::Result<()> {
    write_at(dev, block as u64 * BLOCK_SIZE as u64 + within, bytes)
}

// ── metadata builders ───────────────────────────────────────────────────────

/// The 1024-byte superblock. Mirrors the field set the read-only writer emits
/// (which the kernel mounts), differing only in a real `s_free_blocks_count`.
fn build_superblock(geom: &Geometry) -> Vec<u8> {
    let mut sb = vec![0u8; 1024];
    let free_inodes = geom.inode_slots() - RESERVED_INODES;
    put_u32(&mut sb, 0x00, geom.inode_slots()); // s_inodes_count
    put_u32(&mut sb, 0x04, geom.total_blocks); // s_blocks_count_lo
    put_u32(&mut sb, 0x0C, geom.free_blocks()); // s_free_blocks_count_lo
    put_u32(&mut sb, 0x10, free_inodes); // s_free_inodes_count
    put_u32(&mut sb, 0x14, 0); // s_first_data_block (0 for 4 KiB)
    put_u32(&mut sb, 0x18, 2); // s_log_block_size: 1024<<2 = 4096
    put_u32(&mut sb, 0x1C, 2); // s_log_cluster_size
    put_u32(&mut sb, 0x20, BLOCKS_PER_GROUP); // s_blocks_per_group
    put_u32(&mut sb, 0x24, BLOCKS_PER_GROUP); // s_clusters_per_group
    put_u32(&mut sb, 0x28, geom.inodes_per_group); // s_inodes_per_group
    put_u16(&mut sb, 0x36, 0xFFFF); // s_max_mnt_count = -1
    put_u16(&mut sb, 0x38, EXT4_MAGIC); // s_magic
    put_u16(&mut sb, 0x3A, 1); // s_state: cleanly unmounted
    put_u16(&mut sb, 0x3C, 1); // s_errors: continue
    put_u32(&mut sb, 0x4C, 1); // s_rev_level: dynamic
    put_u32(&mut sb, 0x54, FIRST_INO); // s_first_ino
    put_u16(&mut sb, 0x58, INODE_SIZE); // s_inode_size
    put_u16(&mut sb, 0x5A, 0); // s_block_group_nr (primary)
    put_u32(&mut sb, 0x60, INCOMPAT_FILETYPE_EXTENTS); // s_feature_incompat
    // s_feature_ro_compat / compat left 0; UUID + volume name left zero, as in
    // the read-only writer. s_desc_size left 0 → 32-byte group descriptors.
    sb
}

/// The group-descriptor table: one 32-byte descriptor per group, packed into
/// `gdt_blocks` blocks (the tail is zero padding).
fn build_gdt(geom: &Geometry) -> Vec<u8> {
    let mut gdt = vec![0u8; geom.gdt_blocks as usize * BLOCK_SIZE as usize];
    for g in 0..geom.groups {
        let d = g as usize * 32;
        put_u32(&mut gdt, d, geom.block_bitmap(g)); // bg_block_bitmap_lo
        put_u32(&mut gdt, d + 0x04, geom.inode_bitmap(g)); // bg_inode_bitmap_lo
        put_u32(&mut gdt, d + 0x08, geom.inode_table(g)); // bg_inode_table_lo
        put_u16(&mut gdt, d + 0x0C, geom.group_free_blocks(g) as u16); // bg_free_blocks_count_lo
        let free_inodes = if g == 0 {
            geom.inodes_per_group - RESERVED_INODES
        } else {
            geom.inodes_per_group
        };
        put_u16(&mut gdt, d + 0x0E, free_inodes as u16); // bg_free_inodes_count_lo
        put_u16(&mut gdt, d + 0x10, if g == 0 { 1 } else { 0 }); // bg_used_dirs_count_lo (root)
    }
    gdt
}

/// A group's block bitmap (one block, `BLOCKS_PER_GROUP` bits). Metadata prefix
/// used; root block used in group 0; blocks past a partial group's real extent
/// marked used so the allocator never hands out non-existent blocks; rest free.
fn build_block_bitmap(geom: &Geometry, g: u32) -> Vec<u8> {
    let mut bm = vec![0u8; BLOCK_SIZE as usize];
    for b in 0..geom.prefix {
        set_bit(&mut bm, b as usize);
    }
    if g == 0 {
        set_bit(&mut bm, geom.prefix as usize); // root directory data block
    }
    for b in geom.group_blocks(g)..BLOCKS_PER_GROUP {
        set_bit(&mut bm, b as usize); // padding past a partial final group
    }
    bm
}

/// A group's inode bitmap. Group 0's reserved inodes (1..=10) are used; bits
/// past `inodes_per_group` are padding (not real inodes) and marked used.
fn build_inode_bitmap(geom: &Geometry, g: u32) -> Vec<u8> {
    let mut bm = vec![0u8; BLOCK_SIZE as usize];
    if g == 0 {
        for local in 0..RESERVED_INODES {
            set_bit(&mut bm, local as usize);
        }
    }
    for pad in geom.inodes_per_group..(BLOCK_SIZE * 8) {
        set_bit(&mut bm, pad as usize);
    }
    bm
}

/// Group 0's first inode-table block: reserved inodes 1..=10 left zero except
/// root (inode 2), a directory whose single extent maps its data block.
fn build_root_inode_table_block(geom: &Geometry) -> Vec<u8> {
    let mut blk = vec![0u8; BLOCK_SIZE as usize];
    // Inode i occupies slot (i-1); root is inode 2 → slot 1.
    let off = (ROOT_INO as usize - 1) * INODE_SIZE as usize;
    put_u16(&mut blk, off, S_IFDIR | 0o755); // i_mode
    put_u32(&mut blk, off + 0x04, BLOCK_SIZE); // i_size_lo (one dir block)
    put_u16(&mut blk, off + 0x1A, 2); // i_links_count ("." + "..")
    put_u32(&mut blk, off + 0x1C, BLOCK_SIZE / 512); // i_blocks_lo (sectors)
    put_u32(&mut blk, off + 0x20, EXTENTS_FL); // i_flags
    put_u16(&mut blk, off + 0x80, 32); // i_extra_isize
    // i_block (offset 0x28): extent header (depth 0, one entry) + one extent
    // mapping logical block 0 → the root directory data block.
    let eh = off + 0x28;
    put_u16(&mut blk, eh, EXTENT_MAGIC); // eh_magic
    put_u16(&mut blk, eh + 0x02, 1); // eh_entries
    put_u16(&mut blk, eh + 0x04, 4); // eh_max
    put_u16(&mut blk, eh + 0x06, 0); // eh_depth
    put_u32(&mut blk, eh + 12, 0); // ee_block (logical 0)
    put_u16(&mut blk, eh + 12 + 0x04, 1); // ee_len
    put_u16(&mut blk, eh + 12 + 0x06, 0); // ee_start_hi
    put_u32(&mut blk, eh + 12 + 0x08, geom.data_start(0)); // ee_start_lo
    blk
}

/// The root directory data block: "." and ".." dirents, both pointing at root.
fn build_root_dir_block() -> Vec<u8> {
    let mut blk = vec![0u8; BLOCK_SIZE as usize];
    // "." → root, fixed 12-byte record.
    put_u32(&mut blk, 0, ROOT_INO);
    put_u16(&mut blk, 0x04, 12); // rec_len
    blk[0x06] = 1; // name_len
    blk[0x07] = FT_DIR;
    blk[0x08] = b'.';
    // ".." → root, rec_len spans to the end of the block (last entry).
    let off = 12;
    put_u32(&mut blk, off, ROOT_INO);
    put_u16(&mut blk, off + 0x04, (BLOCK_SIZE as usize - off) as u16); // rec_len
    blk[off + 0x06] = 2; // name_len
    blk[off + 0x07] = FT_DIR;
    blk[off + 0x08] = b'.';
    blk[off + 0x09] = b'.';
    blk
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Format into an in-memory buffer of `size_bytes` and return it.
    fn format_buf(size_bytes: u64) -> (Vec<u8>, FormatSummary) {
        let mut cur = Cursor::new(vec![0u8; size_bytes as usize]);
        let summary = format_empty_ext4(&mut cur, size_bytes).expect("format");
        (cur.into_inner(), summary)
    }

    #[test]
    fn single_group_has_valid_superblock_and_free_space() {
        // 64 MiB → one partial group.
        let (img, s) = format_buf(64 * 1024 * 1024);
        assert_eq!(s.groups, 1);
        // Magic at superblock offset 1024 + 0x38.
        assert_eq!(
            u16::from_le_bytes([img[1024 + 0x38], img[1024 + 0x39]]),
            0xEF53
        );
        // Free blocks are non-zero and reported consistently in the superblock.
        assert!(s.free_blocks > 0);
        let sb_free = u32::from_le_bytes([
            img[1024 + 0x0C],
            img[1024 + 0x0D],
            img[1024 + 0x0E],
            img[1024 + 0x0F],
        ]);
        assert_eq!(sb_free, s.free_blocks);
        // All but the reserved inodes are free.
        assert_eq!(s.free_inodes, s.inode_slots - 10);
    }

    #[test]
    fn multi_group_layout_writes_backup_superblocks() {
        // 160 MiB → 2 groups (one full 128 MiB group + a partial one).
        let (img, s) = format_buf(160 * 1024 * 1024);
        assert_eq!(s.groups, 2);
        // Backup superblock at the start of group 1 (block BLOCKS_PER_GROUP),
        // magic at offset 0x38, and s_block_group_nr == 1.
        let g1 = BLOCKS_PER_GROUP as usize * BLOCK_SIZE as usize;
        assert_eq!(u16::from_le_bytes([img[g1 + 0x38], img[g1 + 0x39]]), 0xEF53);
        assert_eq!(u16::from_le_bytes([img[g1 + 0x5A], img[g1 + 0x5B]]), 1);
    }

    #[test]
    fn free_block_accounting_matches_per_group_sum() {
        let (_img, s) = format_buf(160 * 1024 * 1024);
        let geom = Geometry::plan(160 * 1024 * 1024).unwrap();
        let per_group: u32 = (0..geom.groups).map(|g| geom.group_free_blocks(g)).sum();
        assert_eq!(per_group, s.free_blocks);
    }

    #[test]
    fn too_small_is_rejected() {
        let mut cur = Cursor::new(vec![0u8; 1024 * 1024]);
        assert!(matches!(
            format_empty_ext4(&mut cur, 1024 * 1024),
            Err(MkfsError::TooSmall { .. })
        ));
    }
}
