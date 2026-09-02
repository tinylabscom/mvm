//! ext4 superblock parsing.
//!
//! Spec: docs/ext4-spec/superblock.md
//! Located at byte offset 1024, 1024 bytes long. Magic 0xEF53 at offset 56.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};

pub const SUPERBLOCK_OFFSET: u64 = 1024;
pub const SUPERBLOCK_SIZE: usize = 1024;
pub const EXT4_MAGIC: u16 = 0xEF53;

/// `s_state` bits (byte offset 0x3A). The kernel sets `VALID_FS` when a
/// clean unmount completes and clears it on mount; a dirty value on a
/// not-currently-mounted image therefore indicates an unclean shutdown
/// and signals the caller that journal replay (or `fsck`) is required
/// before writes are safe.
pub const EXT4_VALID_FS: u16 = 0x0001;
pub const EXT4_ERROR_FS: u16 = 0x0002;

/// Parsed in-memory representation of the ext4 superblock.
/// Field names mirror the kernel's `struct ext4_super_block` (s_ prefix dropped).
#[derive(Debug, Clone)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64, // combined lo + hi
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    /// `s_r_blocks_count` (lo at 0x08, hi at 0x154 — 64-bit on
    /// INCOMPAT_64BIT volumes). Blocks reserved for the superuser
    /// — explains the gap between `free_blocks` and what `df`
    /// reports as available to a normal user.
    pub r_blocks_count: u64,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    /// `s_state` (0x3A). `EXT4_VALID_FS` = cleanly unmounted. Any other
    /// value means the FS was mounted and not cleanly unmounted (dirty)
    /// or that the kernel marked the FS as having errors.
    pub state: u16,
    /// `s_errors` (0x3C). Kernel error policy: 1=continue, 2=remount-ro,
    /// 3=panic. Informational from a Swift host's POV but useful in
    /// diagnostics output.
    pub errors_behavior: u16,
    /// `s_minor_rev_level` (0x3E). Bumped by filesystem admin tools for minor format
    /// tweaks within a major rev_level.
    pub minor_rev_level: u16,
    pub rev_level: u32,
    pub inode_size: u16,
    /// `s_first_ino` (0x54, dynamic-rev only). First non-reserved
    /// inode number; defaults to 11 on rev_level=1+ filesystems.
    pub first_inode: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: String,
    /// `s_last_mounted` (0x88, 64 bytes). Last directory the FS was
    /// mounted at — handy for diagnostics ("when was this disk last
    /// in another machine?").
    pub last_mounted: String,
    pub desc_size: u16, // BGD size: 32 or 64
    pub hash_seed: [u32; 4],
    pub default_hash_version: u8,
    pub checksum_seed: u32, // s_checksum_seed (used when INCOMPAT_CSUM_SEED)
    pub journal_inode: u32,
    /// `s_last_orphan` (0xE8). Head of the orphan-inode list — inodes
    /// whose link count reached zero while still open. The kernel
    /// inserts unlink-while-open targets here so that, on the next
    /// mount, recovery can reclaim them. Each inode's `i_dtime` field
    /// is overloaded to point at the next orphan in the chain; the
    /// chain terminates with a zero `dtime`.
    pub last_orphan: u32,
    /// `s_mtime` (0x2C). Timestamp the FS was last mounted.
    pub mtime: u32,
    /// `s_wtime` (0x30). Timestamp the FS was last written to.
    pub wtime: u32,
    /// `s_mnt_count` (0x34). Mounts since last fsck.
    pub mnt_count: u16,
    /// `s_max_mnt_count` (0x36). Forced fsck after this many mounts;
    /// 0 disables.
    pub max_mnt_count: u16,
    /// `s_lastcheck` (0x40). Timestamp of the last fsck pass.
    pub lastcheck: u32,
    /// `s_checkinterval` (0x44). Seconds between forced fscks; 0
    /// disables time-based forced fsck.
    pub checkinterval: u32,
    /// `s_creator_os` (0x48). 0=Linux, 1=Hurd, 2=Masix, 3=FreeBSD,
    /// 4=Lites.
    pub creator_os: u32,
    /// `s_def_resuid` (0x50). UID with access to reserved blocks.
    pub def_resuid: u16,
    /// `s_def_resgid` (0x52). GID with access to reserved blocks.
    pub def_resgid: u16,
    pub raw: Vec<u8>, // keep raw bytes for re-checksum on writes (future)
}

impl Superblock {
    /// Read and parse the superblock from a block device.
    pub fn read<D: BlockDevice + ?Sized>(dev: &D) -> Result<Self> {
        let mut buf = vec![0u8; SUPERBLOCK_SIZE];
        dev.read_at(SUPERBLOCK_OFFSET, &mut buf)?;
        Self::parse(buf)
    }

    pub fn parse(raw: Vec<u8>) -> Result<Self> {
        if raw.len() < SUPERBLOCK_SIZE {
            return Err(Error::Corrupt("superblock buffer too small"));
        }

        let magic = u16::from_le_bytes([raw[0x38], raw[0x39]]);
        if magic != EXT4_MAGIC {
            return Err(Error::BadMagic {
                found: magic,
                expected: EXT4_MAGIC,
            });
        }

        let inodes_count = u32::from_le_bytes(raw[0x00..0x04].try_into().unwrap());
        let blocks_count_lo = u32::from_le_bytes(raw[0x04..0x08].try_into().unwrap());
        let r_blocks_count_lo = u32::from_le_bytes(raw[0x08..0x0C].try_into().unwrap());
        let free_blocks_count_lo = u32::from_le_bytes(raw[0x0C..0x10].try_into().unwrap());
        let free_inodes_count = u32::from_le_bytes(raw[0x10..0x14].try_into().unwrap());
        let first_data_block = u32::from_le_bytes(raw[0x14..0x18].try_into().unwrap());
        let log_block_size = u32::from_le_bytes(raw[0x18..0x1C].try_into().unwrap());
        let blocks_per_group = u32::from_le_bytes(raw[0x20..0x24].try_into().unwrap());
        let inodes_per_group = u32::from_le_bytes(raw[0x28..0x2C].try_into().unwrap());
        let mtime = u32::from_le_bytes(raw[0x2C..0x30].try_into().unwrap());
        let wtime = u32::from_le_bytes(raw[0x30..0x34].try_into().unwrap());
        let mnt_count = u16::from_le_bytes(raw[0x34..0x36].try_into().unwrap());
        let max_mnt_count = u16::from_le_bytes(raw[0x36..0x38].try_into().unwrap());
        let state = u16::from_le_bytes(raw[0x3A..0x3C].try_into().unwrap());
        let errors_behavior = u16::from_le_bytes(raw[0x3C..0x3E].try_into().unwrap());
        let minor_rev_level = u16::from_le_bytes(raw[0x3E..0x40].try_into().unwrap());
        let lastcheck = u32::from_le_bytes(raw[0x40..0x44].try_into().unwrap());
        let checkinterval = u32::from_le_bytes(raw[0x44..0x48].try_into().unwrap());
        let creator_os = u32::from_le_bytes(raw[0x48..0x4C].try_into().unwrap());
        let rev_level = u32::from_le_bytes(raw[0x4C..0x50].try_into().unwrap());
        let def_resuid = u16::from_le_bytes(raw[0x50..0x52].try_into().unwrap());
        let def_resgid = u16::from_le_bytes(raw[0x52..0x54].try_into().unwrap());

        // Dynamic-rev fields (rev_level >= 1). Pre-rev1 filesystems
        // pin sensible defaults — `inode_size = 128` (the historical
        // ext2 size), `first_inode = 11` (the spec-defined start of
        // user-visible inodes; lower numbers are reserved).
        let first_inode = if rev_level >= 1 {
            u32::from_le_bytes(raw[0x54..0x58].try_into().unwrap())
        } else {
            11
        };
        let inode_size = if rev_level >= 1 {
            u16::from_le_bytes(raw[0x58..0x5A].try_into().unwrap())
        } else {
            128
        };
        let feature_compat = if rev_level >= 1 {
            u32::from_le_bytes(raw[0x5C..0x60].try_into().unwrap())
        } else {
            0
        };
        let feature_incompat = if rev_level >= 1 {
            u32::from_le_bytes(raw[0x60..0x64].try_into().unwrap())
        } else {
            0
        };
        let feature_ro_compat = if rev_level >= 1 {
            u32::from_le_bytes(raw[0x64..0x68].try_into().unwrap())
        } else {
            0
        };

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw[0x68..0x78]);

        let volume_name_bytes = &raw[0x78..0x88];
        let nul = volume_name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let volume_name = String::from_utf8_lossy(&volume_name_bytes[..nul]).into_owned();

        // s_last_mounted at 0x88, 64 bytes. The kernel writes the path
        // here on every successful mount; a freshly mkfs'd filesystem
        // leaves it zero-padded.
        let last_mounted_bytes = &raw[0x88..0xC8];
        let nul = last_mounted_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(64);
        let last_mounted = String::from_utf8_lossy(&last_mounted_bytes[..nul]).into_owned();

        let desc_size = u16::from_le_bytes(raw[0xFE..0x100].try_into().unwrap());
        // If desc_size is 0, default to 32 (legacy); spec says 32 or 64
        let desc_size = if desc_size == 0 { 32 } else { desc_size };

        let mut hash_seed = [0u32; 4];
        for (i, slot) in hash_seed.iter_mut().enumerate() {
            let off = 0xEC + i * 4;
            *slot = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        }
        let default_hash_version = raw[0xFC];

        // 64-bit fields (only valid when INCOMPAT_64BIT). Pre-64bit
        // filesystems leave the high halves zero so combining is safe
        // unconditionally.
        let blocks_count_hi = u32::from_le_bytes(raw[0x150..0x154].try_into().unwrap());
        let r_blocks_count_hi = u32::from_le_bytes(raw[0x154..0x158].try_into().unwrap());
        let free_blocks_count_hi = u32::from_le_bytes(raw[0x158..0x15C].try_into().unwrap());

        let blocks_count = ((blocks_count_hi as u64) << 32) | (blocks_count_lo as u64);
        let r_blocks_count = ((r_blocks_count_hi as u64) << 32) | (r_blocks_count_lo as u64);
        let free_blocks_count =
            ((free_blocks_count_hi as u64) << 32) | (free_blocks_count_lo as u64);

        let checksum_seed = u32::from_le_bytes(raw[0x270..0x274].try_into().unwrap());
        let journal_inode = u32::from_le_bytes(raw[0xE0..0xE4].try_into().unwrap());
        let last_orphan = u32::from_le_bytes(raw[0xE8..0xEC].try_into().unwrap());

        // Reject impossible geometry early so downstream arithmetic never
        // divides by zero. All three are required for the filesystem to
        // name even a single block or inode.
        if blocks_per_group == 0 {
            return Err(Error::Corrupt("superblock: blocks_per_group == 0"));
        }
        if inodes_per_group == 0 {
            return Err(Error::Corrupt("superblock: inodes_per_group == 0"));
        }
        if inode_size == 0 {
            return Err(Error::Corrupt("superblock: inode_size == 0"));
        }
        // log_block_size above 20 would produce a 1 GiB block — spec allows up
        // to 64 KiB, anything larger is certainly a corrupt field. Guard here
        // so `1024 << log_block_size` does not overflow u32 later.
        if log_block_size > 20 {
            return Err(Error::Corrupt(
                "superblock: log_block_size exceeds sane maximum",
            ));
        }
        if blocks_count == 0 {
            return Err(Error::Corrupt("superblock: blocks_count == 0"));
        }

        Ok(Self {
            inodes_count,
            blocks_count,
            free_blocks_count,
            free_inodes_count,
            r_blocks_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            magic,
            state,
            errors_behavior,
            minor_rev_level,
            rev_level,
            inode_size,
            first_inode,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            uuid,
            volume_name,
            last_mounted,
            desc_size,
            hash_seed,
            default_hash_version,
            checksum_seed,
            journal_inode,
            last_orphan,
            mtime,
            wtime,
            mnt_count,
            max_mnt_count,
            lastcheck,
            checkinterval,
            creator_os,
            def_resuid,
            def_resgid,
            raw,
        })
    }

    /// Whether the filesystem was cleanly unmounted. `false` here means
    /// the FS was not cleanly unmounted and a journal replay (or fsck)
    /// is required before writes are safe. Read-only consumers can
    /// still mount a dirty FS; callers that intend to write should
    /// surface this to the user and either run fsck or refuse to
    /// mount read-write.
    pub fn is_clean(&self) -> bool {
        self.state & EXT4_VALID_FS != 0
    }

    /// Block size in bytes: 1024 << log_block_size.
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Number of block groups.
    pub fn block_group_count(&self) -> u64 {
        self.blocks_count.div_ceil(self.blocks_per_group as u64)
    }

    /// Whether the 64BIT incompat feature is enabled.
    pub fn is_64bit(&self) -> bool {
        self.feature_incompat & crate::features::Incompat::BIT64.bits() != 0
    }
}
