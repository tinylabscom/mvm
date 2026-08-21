//! Metadata checksum verification (RO_COMPAT_METADATA_CSUM).
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/checksums.html
//!
//! When `RO_COMPAT_METADATA_CSUM` is set, ext4 stores a CRC32C of every
//! metadata structure to detect on-disk corruption. The checksum is salted
//! by the **filesystem UUID** (or by `s_checksum_seed` when
//! `INCOMPAT_CSUM_SEED` is also set) so the same byte pattern in two
//! different filesystems hashes differently.
//!
//! The spec uses a chained CRC pattern:
//!
//! 1. Start with the seed (UUID or s_checksum_seed).
//! 2. For per-group/per-inode structures, fold in the group number / inode
//!    number / generation as a "context" prefix.
//! 3. Then CRC the actual structure with the checksum field zeroed.
//!
//! This module exposes two helpers:
//!   - [`Checksummer::seed`] — derived once at mount time
//!   - [`Checksummer::superblock`], [`Checksummer::inode`], etc.
//!
//! Phase 1: read-only verification. We do NOT recompute checksums on writes
//! (no writes yet). Verification is currently INFORMATIONAL — corrupt
//! metadata would still parse; this module just lets callers decide whether
//! to trust the result.

use crate::features::{Incompat, RoCompat};
use crate::superblock::Superblock;

/// Linux-semantics CRC32C: no final XOR at either end. The `crc32c` crate's
/// `crc32c_append(s, d)` is `~iterate(~s, d)`; the kernel's `__crc32c_le(c, d, l)`
/// is `iterate(c, d)`. Wrap to get the kernel's semantics out of the crate.
///
/// Public so write-path callers that rewrite a metadata block (dir, BGD, SB)
/// can recompute the tail checksum inline without rebuilding a `Checksummer`.
#[inline]
pub fn linux_crc32c(seed: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!seed, data)
}

/// Per-mount checksum context: the seed and "is it enabled" flag.
#[derive(Debug, Clone, Copy)]
pub struct Checksummer {
    pub seed: u32,
    pub enabled: bool,
}

impl Checksummer {
    /// Derive the checksum context from a parsed superblock.
    ///
    /// Per spec: if `INCOMPAT_CSUM_SEED` is set, use the explicit
    /// `s_checksum_seed` field. Otherwise, the seed is the kernel's
    /// `__crc32c_le(~0, UUID, 16)` — i.e. our `linux_crc32c(!0, UUID)`.
    pub fn from_superblock(sb: &Superblock) -> Self {
        let enabled = (sb.feature_ro_compat & RoCompat::METADATA_CSUM.bits()) != 0;
        let seed = if (sb.feature_incompat & Incompat::CSUM_SEED.bits()) != 0 {
            sb.checksum_seed
        } else {
            linux_crc32c(!0, &sb.uuid)
        };
        Self { seed, enabled }
    }

    /// Linux-semantics CRC32C of a buffer using the mount-wide seed.
    pub fn crc(&self, data: &[u8]) -> u32 {
        linux_crc32c(self.seed, data)
    }

    /// Linux-semantics CRC32C with a 32-bit context prefix folded in first.
    pub fn crc_with_prefix(&self, prefix: u32, data: &[u8]) -> u32 {
        let mid = linux_crc32c(self.seed, &prefix.to_le_bytes());
        linux_crc32c(mid, data)
    }

    /// Verify the superblock checksum. Stored at byte offset 0x3FC; CRC
    /// covers the first 0x3FC bytes. Initial seed is `~0` (NOT the per-FS
    /// seed — superblock checksum is special since the seed lives inside it).
    pub fn verify_superblock(&self, sb_raw: &[u8]) -> bool {
        if !self.enabled {
            return true;
        }
        if sb_raw.len() < 1024 {
            return false;
        }
        let stored = u32::from_le_bytes(sb_raw[0x3FC..0x400].try_into().unwrap());
        let computed = linux_crc32c(!0, &sb_raw[..0x3FC]);
        stored == computed
    }

    /// Verify a block group descriptor's checksum.
    ///
    /// Per spec (`ext4/group_descr.html`), when `RO_COMPAT_METADATA_CSUM` is
    /// set the GDT checksum is computed as:
    ///
    /// ```text
    ///   crc32c(seed, group_no_le_u32 || bgd_with_csum_zeroed) & 0xFFFF
    /// ```
    ///
    /// `desc_size` is the on-disk descriptor size (32 or 64).
    /// `bgd_raw` must be at least `desc_size` bytes; the stored checksum at
    /// offset 0x1E is treated as zero for the computation.
    pub fn verify_bgd(&self, group_no: u32, bgd_raw: &[u8], desc_size: u16) -> bool {
        if !self.enabled {
            return true;
        }
        let n = desc_size as usize;
        if bgd_raw.len() < n || n < 0x20 {
            return false;
        }
        let stored = u16::from_le_bytes(bgd_raw[0x1E..0x20].try_into().unwrap());

        let mut tmp = bgd_raw[..n].to_vec();
        tmp[0x1E] = 0;
        tmp[0x1F] = 0;

        let computed16 = self.crc_with_prefix(group_no, &tmp) as u16;
        computed16 == stored
    }

    /// Verify a directory block's trailing `ext4_dir_entry_tail` checksum.
    ///
    /// Linear directory blocks with `metadata_csum` enabled end in a 12-byte
    /// `struct ext4_dir_entry_tail { u32 det_reserved_zero1; u16 det_rec_len;
    /// u8 det_reserved_zero2; u8 det_reserved_ft; u32 det_checksum; }`.
    ///
    /// Per Linux `fs/ext4/dir.c::ext4_dirent_csum_set` the CRC covers
    /// **`block[0..block_size - 12]`** — i.e. everything BEFORE the tail.
    /// The tail's own bytes (including `det_checksum`) are excluded:
    ///
    /// ```text
    ///   crc32c(seed, ino_le) → crc32c(., gen_le) → crc32c(., block[..len-12])
    /// ```
    ///
    /// `block` is the whole directory block including the trailing tail.
    pub fn verify_dir_entry_tail(&self, ino: u32, generation: u32, block: &[u8]) -> bool {
        if !self.enabled {
            return true;
        }
        if block.len() < 12 {
            return false;
        }
        let end = block.len();
        let stored = u32::from_le_bytes(block[end - 4..end].try_into().unwrap());

        let mut c = linux_crc32c(self.seed, &ino.to_le_bytes());
        c = linux_crc32c(c, &generation.to_le_bytes());
        c = linux_crc32c(c, &block[..end - 12]);
        c == stored
    }

    /// Verify an extent-block tail checksum.
    ///
    /// Extent index/leaf blocks (those read off-inode when the tree has
    /// internal nodes) end in a 4-byte `struct ext4_extent_tail
    /// { u32 et_checksum; }`. Per Linux
    /// `fs/ext4/extents.c::ext4_extent_block_csum_set` the CRC covers
    /// **`block[0..len-4]`** — only the trailing `et_checksum` field is
    /// excluded:
    ///
    /// ```text
    ///   crc32c(seed, ino_le) → crc32c(., gen_le) → crc32c(., block[..len-4])
    /// ```
    ///
    /// Different from `verify_dir_entry_tail`, which excludes the full
    /// 12-byte tail entry.
    pub fn verify_extent_tail(&self, ino: u32, generation: u32, block: &[u8]) -> bool {
        if !self.enabled {
            return true;
        }
        if block.len() < 4 {
            return false;
        }
        let end = block.len();
        let stored = u32::from_le_bytes(block[end - 4..end].try_into().unwrap());

        let mut c = linux_crc32c(self.seed, &ino.to_le_bytes());
        c = linux_crc32c(c, &generation.to_le_bytes());
        c = linux_crc32c(c, &block[..end - 4]);
        c == stored
    }

    /// Verify a parsed inode's checksum.
    /// Chained: seed → ino_le → gen_le → inode_bytes (with checksum slots zeroed).
    pub fn verify_inode(&self, ino: u32, generation: u32, inode_raw: &[u8]) -> bool {
        if !self.enabled || inode_raw.len() < 128 {
            return true;
        }
        let stored_lo = u16::from_le_bytes(inode_raw[0x7C..0x7E].try_into().unwrap()) as u32;
        let stored_hi = if inode_raw.len() >= 0x84 {
            u16::from_le_bytes(inode_raw[0x82..0x84].try_into().unwrap()) as u32
        } else {
            0
        };
        let stored = (stored_hi << 16) | stored_lo;
        match self.compute_inode_checksum(ino, generation, inode_raw) {
            Some((lo, hi)) => ((hi as u32) << 16 | lo as u32) == stored,
            None => true, // disabled / too short — accept
        }
    }

    /// Write the `ext4_extent_tail.et_checksum` u32 at the end of a freshly-
    /// built extent index/leaf block. Mirrors `verify_extent_tail`: the CRC
    /// covers `block[..len-4]`, chained seed → ino → generation → body.
    /// No-op when checksums are disabled; returns true when it patched.
    pub fn patch_extent_tail(&self, ino: u32, generation: u32, block: &mut [u8]) -> bool {
        if !self.enabled || block.len() < 4 {
            return false;
        }
        let end = block.len();
        let mut c = linux_crc32c(self.seed, &ino.to_le_bytes());
        c = linux_crc32c(c, &generation.to_le_bytes());
        c = linux_crc32c(c, &block[..end - 4]);
        block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        true
    }

    /// Verify an external xattr block's checksum.
    ///
    /// Per Linux `fs/ext4/xattr.c::ext4_xattr_block_csum`, the recipe is:
    ///
    /// ```text
    ///   crc32c(seed, block_nr_le_u64)
    ///   → crc32c(., block[0x00..0x10])      // magic, refcount, blocks, hash
    ///   → crc32c(., [0u32])                  // h_checksum slot zeroed (4 bytes)
    ///   → crc32c(., block[0x14..end])        // rest of block
    /// ```
    ///
    /// The stored u32 lives at offset 0x10 of the block.
    pub fn verify_xattr_block(&self, block_nr: u64, block: &[u8]) -> bool {
        if !self.enabled {
            return true;
        }
        if block.len() < 0x20 {
            return false;
        }
        let stored = u32::from_le_bytes(block[0x10..0x14].try_into().unwrap());
        let computed = self.compute_xattr_block_csum(block_nr, block);
        stored == computed
    }

    /// Patch the `h_checksum` field of an external xattr block in place.
    /// Mirrors [`verify_xattr_block`]. No-op when checksums are disabled.
    /// Returns `true` when the block was patched.
    pub fn patch_xattr_block(&self, block_nr: u64, block: &mut [u8]) -> bool {
        if !self.enabled || block.len() < 0x20 {
            return false;
        }
        let csum = self.compute_xattr_block_csum(block_nr, block);
        block[0x10..0x14].copy_from_slice(&csum.to_le_bytes());
        true
    }

    fn compute_xattr_block_csum(&self, block_nr: u64, block: &[u8]) -> u32 {
        let mut c = linux_crc32c(self.seed, &block_nr.to_le_bytes());
        c = linux_crc32c(c, &block[0x00..0x10]);
        c = linux_crc32c(c, &0u32.to_le_bytes());
        c = linux_crc32c(c, &block[0x14..]);
        c
    }

    /// Compute the inode checksum as two u16 halves (lo=checksum_lo at 0x7C,
    /// hi=checksum_hi at 0x82). Returns `None` when checksums are disabled
    /// or the buffer is too short to patch. Callers use this after mutating
    /// an inode image to restore the checksum before writing back.
    pub fn compute_inode_checksum(
        &self,
        ino: u32,
        generation: u32,
        inode_raw: &[u8],
    ) -> Option<(u16, u16)> {
        if !self.enabled || inode_raw.len() < 128 {
            return None;
        }
        // i_checksum_hi (0x82) is part of the checksum only when i_extra_isize
        // (0x80) is large enough to cover it — the kernel's EXT4_FITS_IN_INODE
        // test, which here means i_extra_isize >= 4. On a zeroed freed inode
        // (i_extra_isize = 0) the kernel uses ONLY the 16-bit lo checksum and
        // treats 0x82 as ordinary (zero) data; zeroing hi and storing a full
        // 32-bit value there mismatches ("checksum does not match inode").
        let fits_hi = inode_raw.len() >= 0x84
            && u16::from_le_bytes(inode_raw[0x80..0x82].try_into().unwrap()) >= 4;
        let mut tmp = inode_raw.to_vec();
        tmp[0x7C] = 0;
        tmp[0x7D] = 0;
        if fits_hi {
            tmp[0x82] = 0;
            tmp[0x83] = 0;
        }
        let mut c = linux_crc32c(self.seed, &ino.to_le_bytes());
        c = linux_crc32c(c, &generation.to_le_bytes());
        c = linux_crc32c(c, &tmp);
        let lo = (c & 0xFFFF) as u16;
        let hi = if fits_hi {
            ((c >> 16) & 0xFFFF) as u16
        } else {
            0
        };
        Some((lo, hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_feature_off() {
        // crc32c of an empty seed always yields 0; not interesting.
        let c = Checksummer {
            seed: 0,
            enabled: false,
        };
        assert!(c.verify_superblock(&[]));
        assert!(c.verify_inode(2, 0, &[]));
        assert!(c.verify_dir_entry_tail(2, 0, &[0u8; 12]));
        assert!(c.verify_extent_tail(2, 0, &[0u8; 64]));
    }

    #[test]
    fn dir_tail_roundtrip_and_tamper() {
        let c = Checksummer {
            seed: 0xCAFEBABE,
            enabled: true,
        };
        let ino = 42u32;
        let gen = 0xDEADBEEFu32;
        let mut block = vec![0u8; 4096];
        // Plant a fake `ext4_dir_entry_tail` at the last 12 bytes — the spec
        // reserves these and the CRC excludes them entirely.
        let end = block.len();
        block[end - 12..end - 8].copy_from_slice(&0u32.to_le_bytes()); // det_reserved_zero1
        block[end - 8..end - 6].copy_from_slice(&12u16.to_le_bytes()); // det_rec_len
        block[end - 6] = 0; // det_reserved_zero2
        block[end - 5] = 0xDE; // det_reserved_ft
                               // Some plausible directory content bytes (BEFORE the tail).
        block[0..8].copy_from_slice(&[2, 0, 0, 0, 12, 0, 1, 2]);
        block[100] = 0x5A;
        // CRC covers block[..len-12]; tail's last 4 bytes hold the result.
        let mut expected = linux_crc32c(c.seed, &ino.to_le_bytes());
        expected = linux_crc32c(expected, &gen.to_le_bytes());
        expected = linux_crc32c(expected, &block[..end - 12]);
        block[end - 4..end].copy_from_slice(&expected.to_le_bytes());
        assert!(c.verify_dir_entry_tail(ino, gen, &block));

        // Tamper one byte inside the covered region, expect failure.
        block[100] ^= 0xFF;
        assert!(!c.verify_dir_entry_tail(ino, gen, &block));
    }

    #[test]
    fn extent_tail_excludes_only_last_4_bytes() {
        // The extent tail recipe excludes only the final u32 et_checksum,
        // unlike dir_entry_tail which excludes the full 12-byte tail.
        let c = Checksummer {
            seed: 0x12345678,
            enabled: true,
        };
        let mut block = vec![0u8; 1024];
        block[0..12].copy_from_slice(&[0x0A, 0xF3, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        block[500] = 0xAB;
        let end = block.len();
        let mut expected = linux_crc32c(c.seed, &7u32.to_le_bytes());
        expected = linux_crc32c(expected, &9u32.to_le_bytes());
        expected = linux_crc32c(expected, &block[..end - 4]);
        block[end - 4..end].copy_from_slice(&expected.to_le_bytes());
        assert!(c.verify_extent_tail(7, 9, &block));
    }

    #[test]
    fn patch_extent_tail_is_verify_inverse() {
        let c = Checksummer {
            seed: 0xFEEDFACE,
            enabled: true,
        };
        let mut block = vec![0u8; 4096];
        // Synthetic leaf header + one entry so the body is interesting.
        block[0..12].copy_from_slice(&[0x0A, 0xF3, 1, 0, 0x54, 0x01, 0, 0, 1, 2, 3, 4]);
        block[12..24].copy_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0xE8, 0x03]);
        let patched = c.patch_extent_tail(42, 0xABCDEF01, &mut block);
        assert!(patched);
        assert!(c.verify_extent_tail(42, 0xABCDEF01, &block));
        // Tampering with body invalidates.
        block[200] ^= 0xFF;
        assert!(!c.verify_extent_tail(42, 0xABCDEF01, &block));
    }

    #[test]
    fn patch_extent_tail_disabled_is_noop() {
        let c = Checksummer {
            seed: 0,
            enabled: false,
        };
        let mut block = vec![0u8; 64];
        assert!(!c.patch_extent_tail(1, 1, &mut block));
        assert_eq!(&block[..], &[0u8; 64]);
    }

    #[test]
    fn dir_tail_rejects_too_short_block_when_enabled() {
        let c = Checksummer {
            seed: 0,
            enabled: true,
        };
        // Less than 12 bytes cannot even hold the tail struct.
        assert!(!c.verify_dir_entry_tail(2, 0, &[0u8; 8]));
    }

    #[test]
    fn crc_helpers_are_deterministic() {
        let c = Checksummer {
            seed: 0xDEAD_BEEF,
            enabled: true,
        };
        let a = c.crc(b"hello");
        let b = c.crc(b"hello");
        assert_eq!(a, b);
        let p1 = c.crc_with_prefix(1, b"hello");
        let p2 = c.crc_with_prefix(2, b"hello");
        assert_ne!(p1, p2, "prefix changes hash");
    }

    /// Verify our superblock-checksum routine against a real ext4-basic.img
    /// (which has metadata_csum enabled).
    #[test]
    fn verifies_real_superblock() {
        use crate::block_io::FileDevice;

        let path = "test-disks/ext4-basic.img";
        let dev = match FileDevice::open(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let sb = Superblock::read(&dev).expect("parse sb");
        let csum = Checksummer::from_superblock(&sb);
        if !csum.enabled {
            eprintln!("skip: metadata_csum not enabled in ext4-basic.img");
            return;
        }
        assert!(
            csum.verify_superblock(&sb.raw),
            "superblock checksum mismatch on {path}"
        );
    }

    /// Verify our BGD checksum against a real image — every group must pass.
    #[test]
    fn verifies_real_bgd() {
        use crate::block_io::{BlockDevice, FileDevice};

        let path = "test-disks/ext4-basic.img";
        let dev = match FileDevice::open(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let sb = Superblock::read(&dev).expect("parse sb");
        let csum = Checksummer::from_superblock(&sb);
        if !csum.enabled {
            eprintln!("skip: metadata_csum not enabled");
            return;
        }
        // Read raw BGT and verify each descriptor.
        let block_size = sb.block_size() as u64;
        let bgt_off = (sb.first_data_block as u64 + 1) * block_size;
        let group_count = sb.block_group_count();
        let total = group_count as usize * sb.desc_size as usize;
        let mut buf = vec![0u8; total];
        dev.read_at(bgt_off, &mut buf).expect("read bgt");
        for i in 0..group_count as usize {
            let off = i * sb.desc_size as usize;
            let raw = &buf[off..off + sb.desc_size as usize];
            assert!(
                csum.verify_bgd(i as u32, raw, sb.desc_size),
                "BGD {i} checksum mismatch on {path}"
            );
        }
    }

    /// Verify our inode checksum against a real image — root inode (2) must pass.
    #[test]
    fn verifies_real_inode() {
        use crate::block_io::FileDevice;
        use crate::fs::Filesystem;
        use std::sync::Arc;

        let path = "test-disks/ext4-basic.img";
        let dev = match FileDevice::open(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let dev_dyn: Arc<dyn crate::block_io::BlockDevice> = Arc::new(dev);
        let fs = Filesystem::mount(dev_dyn).expect("mount");
        if !fs.csum.enabled {
            eprintln!("skip: metadata_csum not enabled");
            return;
        }
        // Inode 2 = root dir.
        let (inode, raw) = fs.read_inode_verified(2).expect("read root inode");
        assert!(inode.is_dir());
        assert!(fs.csum.verify_inode(2, inode.generation, &raw));
    }

    /// Verify dir-block tail csum against a real image. Root dir on
    /// ext4-basic.img is a single-block linear directory with a tail.
    #[test]
    fn verifies_real_dir_tail() {
        use crate::block_io::{BlockDevice, FileDevice};
        use crate::dir;
        use crate::extent;
        use crate::fs::Filesystem;
        use std::sync::Arc;

        let path = "test-disks/ext4-basic.img";
        let dev = match FileDevice::open(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let dev_dyn: Arc<dyn BlockDevice> = Arc::new(dev);
        let fs = Filesystem::mount(dev_dyn.clone()).expect("mount");
        if !fs.csum.enabled {
            eprintln!("skip: metadata_csum not enabled");
            return;
        }
        let (root_inode, _raw) = fs.read_inode_verified(2).expect("root inode");
        let bs = fs.sb.block_size();
        let phys = extent::map_logical(&root_inode.block, dev_dyn.as_ref(), bs, 0)
            .expect("map_logical")
            .expect("dir block 0 mapped");
        let mut block = vec![0u8; bs as usize];
        dev_dyn.read_at(phys * bs as u64, &mut block).unwrap();
        assert!(
            dir::has_csum_tail(&block),
            "expected tail on root dir block"
        );
        assert!(
            fs.csum
                .verify_dir_entry_tail(2, root_inode.generation, &block),
            "dir tail csum mismatch on {path} root dir"
        );
    }

    /// Verify extent-block tail csum against ext4-deep-extents.img: any file
    /// with depth > 0 has off-inode extent index/leaf blocks. We pick the
    /// largest regular file and traverse one internal-node block.
    #[test]
    fn verifies_real_extent_tail() {
        use crate::block_io::{BlockDevice, FileDevice};
        use crate::extent::{self, ExtentHeader, ExtentIdx, EXT4_EXT_NODE_SIZE};
        use crate::fs::Filesystem;
        use std::sync::Arc;

        let path = "test-disks/ext4-deep-extents.img";
        let dev = match FileDevice::open(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let dev_dyn: Arc<dyn BlockDevice> = Arc::new(dev);
        let fs = Filesystem::mount(dev_dyn.clone()).expect("mount");
        if !fs.csum.enabled {
            eprintln!("skip: metadata_csum not enabled");
            return;
        }
        // Walk first ~50 inodes looking for one with depth>0.
        let bs = fs.sb.block_size();
        let mut found = None;
        for ino in 11..200u32 {
            let (inode, _raw) = match fs.read_inode_verified(ino) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if !inode.is_file() || !inode.has_extents() {
                continue;
            }
            let header = match ExtentHeader::parse(&inode.block) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if header.depth > 0 && header.entries >= 1 {
                let idx =
                    ExtentIdx::parse(&inode.block[EXT4_EXT_NODE_SIZE..2 * EXT4_EXT_NODE_SIZE])
                        .expect("parse first idx");
                found = Some((ino, inode.generation, idx.leaf_block));
                break;
            }
        }
        let (ino, gen, child_block) = match found {
            Some(x) => x,
            None => {
                eprintln!("skip: no depth>0 inode in first 200 of {path}");
                return;
            }
        };
        let mut buf = vec![0u8; bs as usize];
        dev_dyn.read_at(child_block * bs as u64, &mut buf).unwrap();
        assert!(
            fs.csum.verify_extent_tail(ino, gen, &buf),
            "extent block csum mismatch (ino={ino} child_block={child_block} on {path})"
        );

        // Also exercise the verified traversal API end-to-end.
        let (inode, _) = fs.read_inode_verified(ino).unwrap();
        let ctx = extent::ExtentVerifyCtx {
            ino,
            generation: gen,
            csum: &fs.csum,
        };
        let _ = extent::lookup_verified(&inode.block, dev_dyn.as_ref(), bs, 0, Some(&ctx))
            .expect("lookup_verified must accept valid extent blocks");
    }
}
