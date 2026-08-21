//! JBD2 journal superblock parser.
//!
//! Spec: `fs/jbd2/journal.c` + `include/linux/jbd2.h` in the Linux kernel.
//!
//! JBD2 writes journal metadata in **big-endian**, unlike the ext4 filesystem
//! body which is little-endian. Every block in the journal begins with a
//! 12-byte `journal_header_t` whose magic is `0xc03b3998`. Block-type 3 or 4
//! identifies the superblock (v1 / v2). The superblock is at journal block 0.
//!
//! Locating the journal: `sb.journal_inode` (usually 8) names an inode whose
//! extent tree maps the journal file. Journal block N = logical block N of
//! that inode; convert to a physical fs block via the extent tree.
//!
//! Phase 1: parse only. Transaction replay (E4) lives in a separate module.
//!
//! Layout summary:
//! ```text
//!   0x0000 journal_header_t (12 bytes)
//!            __be32 h_magic       = 0xc03b3998
//!            __be32 h_blocktype   = 3 (V1) or 4 (V2)
//!            __be32 h_sequence
//!   0x000C __be32 s_blocksize   (journal block size)
//!   0x0010 __be32 s_maxlen      (total blocks in journal)
//!   0x0014 __be32 s_first       (first block of log information)
//!   0x0018 __be32 s_sequence    (first commit ID expected on next replay)
//!   0x001C __be32 s_start       (block number of the log start; 0 = clean)
//!   0x0020 __be32 s_errno
//!   --- V2 fields begin (0x0024+) ---
//!   0x0024 __be32 s_feature_compat
//!   0x0028 __be32 s_feature_incompat
//!   0x002C __be32 s_feature_ro_compat
//!   0x0030 u8[16] s_uuid
//!   0x0040 __be32 s_nr_users
//!   0x0044 __be32 s_dynsuper
//!   0x0048 __be32 s_max_transaction
//!   0x004C __be32 s_max_trans_data
//!   0x0050 u8     s_checksum_type
//!   0x0051 u8[3]  padding
//!   0x0054 __be32 s_num_fc_blks
//!   0x0058 __be32 s_head
//!   0x005C u8[160] padding
//!   0x00FC __be32 s_checksum
//!   0x0100 u8[16*48] s_users
//!   0x0400 end
//! ```

use crate::error::{Error, Result};
use crate::fs::Filesystem;
use crate::inode::Inode;

/// JBD2 header magic — big-endian `0xc0 0x3b 0x39 0x98` on disk.
pub const JBD2_MAGIC_NUMBER: u32 = 0xc03b_3998;

/// Header block-type values.
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub const JBD2_COMMIT_BLOCK: u32 = 2;
pub const JBD2_SUPERBLOCK_V1: u32 = 3;
pub const JBD2_SUPERBLOCK_V2: u32 = 4;
pub const JBD2_REVOKE_BLOCK: u32 = 5;

bitflags::bitflags! {
    /// `s_feature_incompat` — kernel must refuse to replay if any unknown bit set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct JbdIncompat: u32 {
        const REVOKE        = 0x0000_0001;
        const BIT64         = 0x0000_0002;
        const ASYNC_COMMIT  = 0x0000_0004;
        const CSUM_V2       = 0x0000_0008;
        const CSUM_V3       = 0x0000_0010;
        const FAST_COMMIT   = 0x0000_0020;
    }
}

/// Parsed JBD2 superblock (read-only view).
#[derive(Debug, Clone)]
pub struct JournalSuperblock {
    /// Header block-type (`JBD2_SUPERBLOCK_V1` or `_V2`).
    pub block_type: u32,
    /// Next expected sequence number from the header (not s_sequence).
    pub header_sequence: u32,
    /// Journal block size in bytes.
    pub block_size: u32,
    /// Total blocks in the journal.
    pub max_len: u32,
    /// First block of log information (typically 1 — block 0 is the sb).
    pub first: u32,
    /// First commit ID expected when replay starts.
    pub sequence: u32,
    /// Start block of the log. **0 means clean unmount** (nothing to replay).
    pub start: u32,
    /// Error code set by `jbd2_journal_abort`, 0 if healthy.
    pub errno: u32,
    /// V2-only feature flags (zero on V1 superblocks).
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    /// UUID identifying this journal (V2 only).
    pub uuid: [u8; 16],
    /// Number of filesystems sharing this journal (V2 only; always 1 for
    /// internal ext4 journals).
    pub nr_users: u32,
    /// Checksum algorithm id (V2 only; 1 = crc32, 4 = crc32c).
    pub checksum_type: u8,
    /// Total fast-commit blocks (V2, INCOMPAT_FAST_COMMIT only).
    pub num_fc_blocks: u32,
    /// Superblock checksum as stored on disk (V2 only).
    pub checksum: u32,
}

impl JournalSuperblock {
    /// True when the log has no outstanding transactions and replay is a no-op.
    pub fn is_clean(&self) -> bool {
        self.start == 0
    }

    /// Returns true if the journal uses v2 or v3 checksum tags.
    pub fn uses_csum_v2_or_v3(&self) -> bool {
        self.feature_incompat & (JbdIncompat::CSUM_V2.bits() | JbdIncompat::CSUM_V3.bits()) != 0
    }

    /// Returns true if the journal uses 64-bit block numbers (tag.t_blocknr_high).
    pub fn uses_64bit(&self) -> bool {
        self.feature_incompat & JbdIncompat::BIT64.bits() != 0
    }

    /// Returns true if revoke blocks are used.
    pub fn has_revoke(&self) -> bool {
        self.feature_incompat & JbdIncompat::REVOKE.bits() != 0
    }

    /// Parse a journal superblock from its 1024-byte on-disk representation.
    /// `raw` should be at least 1024 bytes (block-size bytes in practice); we
    /// only read up to offset 0x100.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 0x100 {
            return Err(Error::Corrupt("jbd2 superblock buffer too small"));
        }

        let h_magic = u32::from_be_bytes(raw[0x00..0x04].try_into().unwrap());
        if h_magic != JBD2_MAGIC_NUMBER {
            return Err(Error::Corrupt("jbd2 superblock magic mismatch"));
        }
        let block_type = u32::from_be_bytes(raw[0x04..0x08].try_into().unwrap());
        if block_type != JBD2_SUPERBLOCK_V1 && block_type != JBD2_SUPERBLOCK_V2 {
            return Err(Error::Corrupt("jbd2 header is not a superblock block type"));
        }
        let header_sequence = u32::from_be_bytes(raw[0x08..0x0C].try_into().unwrap());

        let block_size = u32::from_be_bytes(raw[0x0C..0x10].try_into().unwrap());
        let max_len = u32::from_be_bytes(raw[0x10..0x14].try_into().unwrap());
        let first = u32::from_be_bytes(raw[0x14..0x18].try_into().unwrap());
        let sequence = u32::from_be_bytes(raw[0x18..0x1C].try_into().unwrap());
        let start = u32::from_be_bytes(raw[0x1C..0x20].try_into().unwrap());
        let errno = u32::from_be_bytes(raw[0x20..0x24].try_into().unwrap());

        let mut out = Self {
            block_type,
            header_sequence,
            block_size,
            max_len,
            first,
            sequence,
            start,
            errno,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
            uuid: [0; 16],
            nr_users: 0,
            checksum_type: 0,
            num_fc_blocks: 0,
            checksum: 0,
        };

        // V2 extends with the dynamic-journal-features section.
        if block_type == JBD2_SUPERBLOCK_V2 {
            out.feature_compat = u32::from_be_bytes(raw[0x24..0x28].try_into().unwrap());
            out.feature_incompat = u32::from_be_bytes(raw[0x28..0x2C].try_into().unwrap());
            out.feature_ro_compat = u32::from_be_bytes(raw[0x2C..0x30].try_into().unwrap());
            out.uuid.copy_from_slice(&raw[0x30..0x40]);
            out.nr_users = u32::from_be_bytes(raw[0x40..0x44].try_into().unwrap());
            // 0x44 s_dynsuper ignored (never used by upstream)
            // 0x48 s_max_transaction / 0x4C s_max_trans_data ignored (hints only)
            out.checksum_type = raw[0x50];
            // 0x51..0x54 padding
            out.num_fc_blocks = u32::from_be_bytes(raw[0x54..0x58].try_into().unwrap());
            // 0x58 s_head / padding
            out.checksum = u32::from_be_bytes(raw[0xFC..0x100].try_into().unwrap());
        }

        Ok(out)
    }
}

/// Map a journal-relative block number to its physical fs block. Journal
/// block 0 contains the superblock.
///
/// Flavor-aware via [`crate::indirect::map_logical_any`]: ext4 journals
/// (whose journal inode carries `EXT4_EXTENTS_FL`) traverse the extent
/// tree; ext3 journals (legacy direct/indirect block pointers) walk the
/// indirect tree. Both schemes return `Ok(Some(physical))` for mapped
/// blocks, `Ok(None)` for sparse holes (which a healthy journal should
/// never have, but we don't enforce that here).
pub fn journal_block_to_physical(
    fs: &Filesystem,
    journal_inode: &Inode,
    journal_block: u64,
) -> Result<Option<u64>> {
    crate::indirect::map_logical_any(
        &journal_inode.block,
        journal_inode.flags,
        fs.dev.as_ref(),
        fs.sb.block_size(),
        journal_block,
    )
}

/// Read and parse the JBD2 superblock at block 0 of the journal.
///
/// Flow:
///   1. Look up `sb.journal_inode` (typically ino 8).
///   2. Map journal logical block 0 → physical fs block via its extent tree.
///   3. Read the block (one fs block; the JBD2 sb fits within it).
///   4. Parse the first 256 bytes as a `JournalSuperblock`.
///
/// Returns `Ok(None)` if `sb.journal_inode == 0` (filesystem lacks a journal).
pub fn read_superblock(fs: &Filesystem) -> Result<Option<JournalSuperblock>> {
    let jino_num = fs.sb.journal_inode;
    if jino_num == 0 {
        return Ok(None);
    }

    let raw = fs.read_inode_raw(jino_num)?;
    let jinode = Inode::parse(&raw)?;

    let phys = journal_block_to_physical(fs, &jinode, 0)?
        .ok_or(Error::Corrupt("journal block 0 unmapped (sparse journal?)"))?;

    let block_size = fs.sb.block_size() as u64;
    let mut buf = vec![0u8; block_size as usize];
    fs.dev.read_at(phys * block_size, &mut buf)?;
    Ok(Some(JournalSuperblock::parse(&buf)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic V2 superblock buffer for parser unit-testing.
    fn make_v2_sb() -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        buf[0x00..0x04].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
        buf[0x04..0x08].copy_from_slice(&JBD2_SUPERBLOCK_V2.to_be_bytes());
        buf[0x08..0x0C].copy_from_slice(&1u32.to_be_bytes()); // header seq
        buf[0x0C..0x10].copy_from_slice(&4096u32.to_be_bytes()); // block_size
        buf[0x10..0x14].copy_from_slice(&8192u32.to_be_bytes()); // max_len
        buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes()); // first
        buf[0x18..0x1C].copy_from_slice(&42u32.to_be_bytes()); // sequence
        buf[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes()); // start = 0 (clean)
        buf[0x20..0x24].copy_from_slice(&0u32.to_be_bytes()); // errno
        buf[0x24..0x28].copy_from_slice(&0u32.to_be_bytes()); // feat_compat
        buf[0x28..0x2C].copy_from_slice(
            &(JbdIncompat::REVOKE.bits() | JbdIncompat::CSUM_V3.bits()).to_be_bytes(),
        );
        buf[0x2C..0x30].copy_from_slice(&0u32.to_be_bytes()); // feat_ro
        buf[0x30..0x40].copy_from_slice(&[0xAA; 16]);
        buf[0x40..0x44].copy_from_slice(&1u32.to_be_bytes()); // nr_users
        buf[0x50] = 4; // crc32c
        buf[0xFC..0x100].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        buf
    }

    #[test]
    fn parses_v2_superblock() {
        let buf = make_v2_sb();
        let sb = JournalSuperblock::parse(&buf).unwrap();
        assert_eq!(sb.block_type, JBD2_SUPERBLOCK_V2);
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.max_len, 8192);
        assert_eq!(sb.first, 1);
        assert_eq!(sb.sequence, 42);
        assert!(sb.is_clean());
        assert!(sb.has_revoke());
        assert!(sb.uses_csum_v2_or_v3());
        assert!(!sb.uses_64bit());
        assert_eq!(sb.checksum_type, 4);
        assert_eq!(sb.checksum, 0xDEADBEEF);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = make_v2_sb();
        buf[0] = 0;
        assert!(JournalSuperblock::parse(&buf).is_err());
    }

    #[test]
    fn rejects_non_superblock_block_type() {
        let mut buf = make_v2_sb();
        buf[0x04..0x08].copy_from_slice(&JBD2_DESCRIPTOR_BLOCK.to_be_bytes());
        assert!(JournalSuperblock::parse(&buf).is_err());
    }

    #[test]
    fn v1_leaves_feature_fields_zero() {
        let mut buf = make_v2_sb();
        buf[0x04..0x08].copy_from_slice(&JBD2_SUPERBLOCK_V1.to_be_bytes());
        // Even though we wrote feature bytes, parse skips them on V1.
        let sb = JournalSuperblock::parse(&buf).unwrap();
        assert_eq!(sb.feature_incompat, 0);
        assert_eq!(sb.uuid, [0; 16]);
        assert_eq!(sb.checksum, 0);
    }

    #[test]
    fn dirty_sb_is_not_clean() {
        let mut buf = make_v2_sb();
        buf[0x1C..0x20].copy_from_slice(&100u32.to_be_bytes()); // start != 0
        let sb = JournalSuperblock::parse(&buf).unwrap();
        assert!(!sb.is_clean());
        assert_eq!(sb.start, 100);
    }
}
