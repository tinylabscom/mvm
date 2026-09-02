//! Block group descriptor (BGD) parsing.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/group_descr.html
//!
//! BGDs live in the block(s) immediately following the primary superblock.
//! Each BGD is `superblock.desc_size` bytes (32 legacy, 64 with INCOMPAT_64BIT).

use crate::block_io::BlockDevice;
use crate::checksum::Checksummer;
use crate::error::{Error, Result};
use crate::superblock::Superblock;

/// Block group descriptor (post-parse, all 64-bit fields combined lo+hi).
#[derive(Debug, Clone, Copy)]
pub struct BlockGroupDescriptor {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub flags: u16,
    pub itable_unused: u32,
    pub block_bitmap_csum: u32,
    pub inode_bitmap_csum: u32,
    pub checksum: u16,
}

bitflags::bitflags! {
    /// BGD flags (`bg_flags`).
    #[derive(Debug, Clone, Copy)]
    pub struct BgdFlags: u16 {
        /// Inode table not initialized — skip reading (treat as all-free).
        const INODE_UNINIT = 0x0001;
        /// Block bitmap not initialized — treat as all blocks free.
        const BLOCK_UNINIT = 0x0002;
        /// Inode table is fully zeroed on disk.
        const ITABLE_ZEROED = 0x0004;
    }
}

impl BlockGroupDescriptor {
    /// Parse one descriptor from a buffer of at least `desc_size` bytes.
    pub fn parse(buf: &[u8], desc_size: u16) -> Result<Self> {
        if buf.len() < desc_size as usize {
            return Err(Error::Corrupt("bgd buffer too small"));
        }

        let block_bitmap_lo = u32::from_le_bytes(buf[0x00..0x04].try_into().unwrap());
        let inode_bitmap_lo = u32::from_le_bytes(buf[0x04..0x08].try_into().unwrap());
        let inode_table_lo = u32::from_le_bytes(buf[0x08..0x0C].try_into().unwrap());
        let free_blocks_lo = u16::from_le_bytes(buf[0x0C..0x0E].try_into().unwrap());
        let free_inodes_lo = u16::from_le_bytes(buf[0x0E..0x10].try_into().unwrap());
        let used_dirs_lo = u16::from_le_bytes(buf[0x10..0x12].try_into().unwrap());
        let flags = u16::from_le_bytes(buf[0x12..0x14].try_into().unwrap());
        let block_bitmap_csum_lo = u16::from_le_bytes(buf[0x18..0x1A].try_into().unwrap());
        let inode_bitmap_csum_lo = u16::from_le_bytes(buf[0x1A..0x1C].try_into().unwrap());
        let itable_unused_lo = u16::from_le_bytes(buf[0x1C..0x1E].try_into().unwrap());
        let checksum = u16::from_le_bytes(buf[0x1E..0x20].try_into().unwrap());

        let (
            block_bitmap_hi,
            inode_bitmap_hi,
            inode_table_hi,
            free_blocks_hi,
            free_inodes_hi,
            used_dirs_hi,
            itable_unused_hi,
            block_bitmap_csum_hi,
            inode_bitmap_csum_hi,
        ) = if desc_size >= 64 {
            (
                u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap()),
                u32::from_le_bytes(buf[0x24..0x28].try_into().unwrap()),
                u32::from_le_bytes(buf[0x28..0x2C].try_into().unwrap()),
                u16::from_le_bytes(buf[0x2C..0x2E].try_into().unwrap()),
                u16::from_le_bytes(buf[0x2E..0x30].try_into().unwrap()),
                u16::from_le_bytes(buf[0x30..0x32].try_into().unwrap()),
                u16::from_le_bytes(buf[0x32..0x34].try_into().unwrap()),
                u16::from_le_bytes(buf[0x38..0x3A].try_into().unwrap()),
                u16::from_le_bytes(buf[0x3A..0x3C].try_into().unwrap()),
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0, 0)
        };

        Ok(Self {
            block_bitmap: ((block_bitmap_hi as u64) << 32) | block_bitmap_lo as u64,
            inode_bitmap: ((inode_bitmap_hi as u64) << 32) | inode_bitmap_lo as u64,
            inode_table: ((inode_table_hi as u64) << 32) | inode_table_lo as u64,
            free_blocks_count: ((free_blocks_hi as u32) << 16) | free_blocks_lo as u32,
            free_inodes_count: ((free_inodes_hi as u32) << 16) | free_inodes_lo as u32,
            used_dirs_count: ((used_dirs_hi as u32) << 16) | used_dirs_lo as u32,
            flags,
            itable_unused: ((itable_unused_hi as u32) << 16) | itable_unused_lo as u32,
            block_bitmap_csum: ((block_bitmap_csum_hi as u32) << 16) | block_bitmap_csum_lo as u32,
            inode_bitmap_csum: ((inode_bitmap_csum_hi as u32) << 16) | inode_bitmap_csum_lo as u32,
            checksum,
        })
    }

    pub fn flags(&self) -> BgdFlags {
        BgdFlags::from_bits_truncate(self.flags)
    }
}

/// Read all block group descriptors for the filesystem.
///
/// When `csum.enabled`, each descriptor's CRC32C is verified; a mismatch
/// returns `Error::BadChecksum { what: "block group descriptor" }`.
pub fn read_all<D: BlockDevice + ?Sized>(
    dev: &D,
    sb: &Superblock,
    csum: &Checksummer,
) -> Result<Vec<BlockGroupDescriptor>> {
    let block_size = sb.block_size() as u64;
    // BGT starts at block (first_data_block + 1).
    let bgt_block = sb.first_data_block as u64 + 1;
    let bgt_offset = bgt_block * block_size;

    let group_count = sb.block_group_count();
    let total_bytes = (group_count as usize) * (sb.desc_size as usize);

    let mut buf = vec![0u8; total_bytes];
    dev.read_at(bgt_offset, &mut buf)?;

    let mut groups = Vec::with_capacity(group_count as usize);
    for i in 0..(group_count as usize) {
        let off = i * sb.desc_size as usize;
        let raw = &buf[off..off + sb.desc_size as usize];
        if csum.enabled && !csum.verify_bgd(i as u32, raw, sb.desc_size) {
            return Err(Error::BadChecksum {
                what: "block group descriptor",
            });
        }
        let bgd = BlockGroupDescriptor::parse(raw, sb.desc_size)?;
        groups.push(bgd);
    }
    Ok(groups)
}

/// Locate the inode table block + offset for a given inode number.
/// Returns (physical block containing the inode, byte offset within block).
pub fn locate_inode(
    sb: &Superblock,
    groups: &[BlockGroupDescriptor],
    ino: u32,
) -> Result<(u64, u32)> {
    if ino == 0 || ino > sb.inodes_count {
        return Err(Error::InvalidInode(ino));
    }
    if sb.inodes_per_group == 0 || sb.inode_size == 0 {
        return Err(Error::Corrupt(
            "superblock: zero inodes_per_group or inode_size",
        ));
    }
    let group_idx = ((ino - 1) / sb.inodes_per_group) as usize;
    let local_idx = ((ino - 1) % sb.inodes_per_group) as u64;

    let bgd = groups.get(group_idx).ok_or(Error::InvalidInode(ino))?;
    let block_size = sb.block_size() as u64;
    let inode_size = sb.inode_size as u64;
    if inode_size > block_size {
        return Err(Error::Corrupt(
            "superblock: inode_size larger than block_size",
        ));
    }
    let inodes_per_block = block_size / inode_size;
    if inodes_per_block == 0 {
        return Err(Error::Corrupt("superblock: inode_size exceeds block_size"));
    }

    let block = bgd
        .inode_table
        .checked_add(local_idx / inodes_per_block)
        .ok_or(Error::Corrupt("inode table block number overflow"))?;
    let off_bytes = (local_idx % inodes_per_block) * inode_size;
    let offset_in_block: u32 = off_bytes
        .try_into()
        .map_err(|_| Error::Corrupt("inode offset exceeds u32"))?;

    Ok((block, offset_in_block))
}
