//! Extent tree traversal.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/blockmap.html#extent-tree
//!
//! When `EXT4_EXTENTS_FL` is set on an inode, the 60-byte `i_block` field holds
//! an `ext4_extent_header` followed by entries. Entries are one of:
//!
//! - **Leaf** (`eh_depth == 0`): `ext4_extent` records mapping logical blocks
//!   to physical blocks.
//! - **Internal** (`eh_depth > 0`): `ext4_extent_idx` records pointing at child
//!   blocks containing further `ext4_extent_header` + entries.
//!
//! Each on-disk node is 12 bytes:
//! ```text
//!  ext4_extent_header (12 bytes):
//!    0x00 u16 eh_magic      (0xF30A)
//!    0x02 u16 eh_entries    (number of valid entries)
//!    0x04 u16 eh_max        (max entries this node can hold)
//!    0x06 u16 eh_depth      (0 = leaf, else internal)
//!    0x08 u32 eh_generation
//!
//!  ext4_extent (leaf, 12 bytes):
//!    0x00 u32 ee_block      (first logical block)
//!    0x04 u16 ee_len        (number of blocks; >32768 means uninitialized)
//!    0x06 u16 ee_start_hi   (upper 16 bits of physical block)
//!    0x08 u32 ee_start_lo   (lower 32 bits of physical block)
//!
//!  ext4_extent_idx (internal, 12 bytes):
//!    0x00 u32 ei_block      (first logical block in subtree)
//!    0x04 u32 ei_leaf_lo    (lower 32 bits of child physical block)
//!    0x08 u16 ei_leaf_hi    (upper 16 bits of child physical block)
//!    0x0A u16 ei_unused
//! ```
//!
//! Uninitialized extents: when `ee_len > 32768`, the extent is a pre-allocated
//! hole — reads return zeros. The actual length is `ee_len - 32768`. Writes
//! convert it to initialised by clearing the high bit.
//!
//! Checksums: when `METADATA_CSUM` or `GDT_CSUM` is enabled, each extent block
//! (i.e. internal-node data, not the inline i_block) has a trailing
//! `ext4_extent_tail` (4-byte CRC32c). We parse but don't verify in Phase 1.

use crate::block_io::BlockDevice;
use crate::checksum::Checksummer;
use crate::error::{Error, Result};

/// Context for verifying extent-block tail checksums during a tree walk.
///
/// Pass `Some(&ctx)` to `lookup_verified` / `map_logical_verified` /
/// `collect_all_verified` when reading a real on-disk extent tree under
/// a `metadata_csum` filesystem. Each off-inode block's
/// `ext4_extent_tail.et_checksum` is verified against
/// `crc32c(seed, ino_le, gen_le, block[..len-4])`.
///
/// Pass `None` to skip verification (tests, callers without a `Filesystem`).
#[derive(Clone, Copy)]
pub struct ExtentVerifyCtx<'a> {
    /// Inode number that owns this extent tree.
    pub ino: u32,
    /// Inode `generation` field (salts the per-inode CRC).
    pub generation: u32,
    /// Mount-wide checksummer (skipped when `csum.enabled == false`).
    pub csum: &'a Checksummer,
}

impl<'a> ExtentVerifyCtx<'a> {
    /// True if every off-inode node read should be CRC-verified.
    fn active(&self) -> bool {
        self.csum.enabled
    }
}

/// Magic number at the start of every extent header.
pub const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// High bit flag on `ee_len` marking an uninitialised (pre-allocated) extent.
/// Actual length = `ee_len & 0x7FFF` if `ee_len > EXT_INIT_MAX_LEN`.
pub const EXT_INIT_MAX_LEN: u16 = 32768;

/// Bytes per on-disk extent node (header or entry).
pub const EXT4_EXT_NODE_SIZE: usize = 12;

/// Maximum extent tree depth we will descend. ext4 spec puts the hard
/// limit at 5; anything above that is a pathological / malformed image
/// and we bail out rather than chase pointers forever.
pub const EXT4_EXT_MAX_DEPTH: u16 = 5;

/// Header at the start of every extent tree node.
#[derive(Debug, Clone, Copy)]
pub struct ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max: u16,
    pub depth: u16,
    pub generation: u32,
}

impl ExtentHeader {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < EXT4_EXT_NODE_SIZE {
            return Err(Error::CorruptExtentTree("header buffer too small"));
        }
        let magic = u16::from_le_bytes(raw[0x00..0x02].try_into().unwrap());
        let entries = u16::from_le_bytes(raw[0x02..0x04].try_into().unwrap());
        let max = u16::from_le_bytes(raw[0x04..0x06].try_into().unwrap());
        let depth = u16::from_le_bytes(raw[0x06..0x08].try_into().unwrap());
        let generation = u32::from_le_bytes(raw[0x08..0x0C].try_into().unwrap());

        if magic != EXT4_EXT_MAGIC {
            return Err(Error::CorruptExtentTree("bad extent header magic"));
        }
        if entries > max {
            return Err(Error::CorruptExtentTree("entries > max"));
        }
        Ok(Self {
            magic,
            entries,
            max,
            depth,
            generation,
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }
}

/// Leaf extent: maps `[ee_block, ee_block+ee_len)` logical to physical.
#[derive(Debug, Clone, Copy)]
pub struct Extent {
    /// First logical block number covered by this extent.
    pub logical_block: u32,
    /// Number of contiguous blocks (after masking the uninit flag).
    pub length: u16,
    /// Physical block where the data lives (assembled from hi/lo).
    pub physical_block: u64,
    /// True if this extent is a pre-allocated hole (reads return zeros).
    pub uninitialized: bool,
}

impl Extent {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < EXT4_EXT_NODE_SIZE {
            return Err(Error::CorruptExtentTree("leaf extent buffer too small"));
        }
        let logical_block = u32::from_le_bytes(raw[0x00..0x04].try_into().unwrap());
        let ee_len = u16::from_le_bytes(raw[0x04..0x06].try_into().unwrap());
        let start_hi = u16::from_le_bytes(raw[0x06..0x08].try_into().unwrap());
        let start_lo = u32::from_le_bytes(raw[0x08..0x0C].try_into().unwrap());

        let (length, uninitialized) = if ee_len > EXT_INIT_MAX_LEN {
            (ee_len - EXT_INIT_MAX_LEN, true)
        } else {
            (ee_len, false)
        };
        let physical_block = ((start_hi as u64) << 32) | start_lo as u64;

        Ok(Self {
            logical_block,
            length,
            physical_block,
            uninitialized,
        })
    }

    /// Does this extent cover the given logical block?
    pub fn contains(&self, logical: u64) -> bool {
        let start = self.logical_block as u64;
        let end = start + self.length as u64;
        logical >= start && logical < end
    }

    /// Physical block corresponding to `logical` (caller must check contains()).
    pub fn map(&self, logical: u64) -> u64 {
        debug_assert!(self.contains(logical));
        self.physical_block + (logical - self.logical_block as u64)
    }
}

/// Internal (index) node pointing at a child extent block.
#[derive(Debug, Clone, Copy)]
pub struct ExtentIdx {
    /// First logical block in the subtree rooted at this index.
    pub logical_block: u32,
    /// Physical block holding the child header + entries.
    pub leaf_block: u64,
}

impl ExtentIdx {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < EXT4_EXT_NODE_SIZE {
            return Err(Error::CorruptExtentTree("index entry buffer too small"));
        }
        let logical_block = u32::from_le_bytes(raw[0x00..0x04].try_into().unwrap());
        let leaf_lo = u32::from_le_bytes(raw[0x04..0x08].try_into().unwrap());
        let leaf_hi = u16::from_le_bytes(raw[0x08..0x0A].try_into().unwrap());
        // 0x0A..0x0C reserved.
        let leaf_block = ((leaf_hi as u64) << 32) | leaf_lo as u64;
        Ok(Self {
            logical_block,
            leaf_block,
        })
    }
}

/// Traverse the extent tree rooted in `inode.block` and find the extent covering
/// the given logical block. Reads internal-node blocks via `dev` as needed.
///
/// Returns `Ok(None)` if the logical block falls in a sparse hole (no extent
/// covers it). Returns `Ok(Some(extent))` if a mapping was found.
pub fn lookup(
    root: &[u8],
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
) -> Result<Option<Extent>> {
    lookup_verified(root, dev, block_size, logical_block, None)
}

/// Same as `lookup`, but verifies each off-inode internal-node block's
/// `ext4_extent_tail.et_checksum` when `ctx` is `Some` and enabled.
///
/// A mismatch returns `Error::BadChecksum { what: "extent block" }`.
pub fn lookup_verified(
    root: &[u8],
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
    ctx: Option<&ExtentVerifyCtx>,
) -> Result<Option<Extent>> {
    // Parse root header from inode.block (the 60-byte i_block area).
    let mut header = ExtentHeader::parse(root)?;
    if header.depth > EXT4_EXT_MAX_DEPTH {
        return Err(Error::CorruptExtentTree(
            "extent tree depth exceeds spec maximum",
        ));
    }
    // Holds data for non-root nodes once we descend into internal indices.
    // `cursor` borrows from `root` initially, then from `node` after the first
    // descent — we keep `node` alive for the duration of the lookup.
    let mut node: Vec<u8>;
    let mut cursor: &[u8] = root;
    // Guard against malformed images where an internal node's child
    // references cycle back (self or each other). We never need to
    // recurse more than the root's claimed depth.
    let mut descents_remaining = header.depth as usize;

    loop {
        if header.is_leaf() {
            // Binary-search-ish linear walk (entries are sorted by logical_block).
            // ext4 extent counts per node are small (≤340 for 4 KiB blocks, and
            // ≤4 for the inline root) so linear scan is fine.
            let mut found: Option<Extent> = None;
            for i in 0..header.entries {
                let off = EXT4_EXT_NODE_SIZE * (1 + i as usize);
                if off + EXT4_EXT_NODE_SIZE > cursor.len() {
                    return Err(Error::CorruptExtentTree("leaf entry out of range"));
                }
                let ext = Extent::parse(&cursor[off..off + EXT4_EXT_NODE_SIZE])?;
                if ext.contains(logical_block) {
                    found = Some(ext);
                    break;
                }
                // Past our target — no mapping (sparse hole).
                if (ext.logical_block as u64) > logical_block {
                    break;
                }
            }
            return Ok(found);
        }

        // Internal: find the largest index entry whose ei_block <= logical_block.
        let mut chosen_idx: Option<ExtentIdx> = None;
        for i in 0..header.entries {
            let off = EXT4_EXT_NODE_SIZE * (1 + i as usize);
            if off + EXT4_EXT_NODE_SIZE > cursor.len() {
                return Err(Error::CorruptExtentTree("index entry out of range"));
            }
            let idx = ExtentIdx::parse(&cursor[off..off + EXT4_EXT_NODE_SIZE])?;
            if (idx.logical_block as u64) <= logical_block {
                chosen_idx = Some(idx);
            } else {
                break;
            }
        }
        let idx = chosen_idx.ok_or(Error::CorruptExtentTree(
            "no index entry covers logical block",
        ))?;

        // Read the child block, parse its header, continue loop.
        let mut buf = vec![0u8; block_size as usize];
        let child_offset =
            idx.leaf_block
                .checked_mul(block_size as u64)
                .ok_or(Error::CorruptExtentTree(
                    "extent index: child block offset overflow",
                ))?;
        dev.read_at(child_offset, &mut buf)?;
        if let Some(c) = ctx {
            if c.active() && !c.csum.verify_extent_tail(c.ino, c.generation, &buf) {
                return Err(Error::BadChecksum {
                    what: "extent block",
                });
            }
        }
        node = buf;
        cursor = &node[..];
        header = ExtentHeader::parse(cursor)?;
        if descents_remaining == 0 {
            return Err(Error::CorruptExtentTree(
                "extent tree descended past claimed depth",
            ));
        }
        descents_remaining -= 1;
    }
}

/// Walk the entire extent tree and collect every leaf extent. Useful for
/// building a file-block list or for testing.
pub fn collect_all(root: &[u8], dev: &dyn BlockDevice, block_size: u32) -> Result<Vec<Extent>> {
    let header = ExtentHeader::parse(root)?;
    if header.depth > EXT4_EXT_MAX_DEPTH {
        return Err(Error::CorruptExtentTree(
            "extent tree depth exceeds spec maximum",
        ));
    }
    let mut out = Vec::new();
    walk(root, &header, dev, block_size, &mut out, header.depth)?;
    Ok(out)
}

fn walk(
    node: &[u8],
    header: &ExtentHeader,
    dev: &dyn BlockDevice,
    block_size: u32,
    out: &mut Vec<Extent>,
    descents_remaining: u16,
) -> Result<()> {
    if header.is_leaf() {
        for i in 0..header.entries {
            let off = EXT4_EXT_NODE_SIZE * (1 + i as usize);
            if off + EXT4_EXT_NODE_SIZE > node.len() {
                return Err(Error::CorruptExtentTree("leaf entry out of range"));
            }
            out.push(Extent::parse(&node[off..off + EXT4_EXT_NODE_SIZE])?);
        }
        return Ok(());
    }

    if descents_remaining == 0 {
        return Err(Error::CorruptExtentTree(
            "extent tree descended past claimed depth",
        ));
    }

    for i in 0..header.entries {
        let off = EXT4_EXT_NODE_SIZE * (1 + i as usize);
        if off + EXT4_EXT_NODE_SIZE > node.len() {
            return Err(Error::CorruptExtentTree("index entry out of range"));
        }
        let idx = ExtentIdx::parse(&node[off..off + EXT4_EXT_NODE_SIZE])?;
        let mut buf = vec![0u8; block_size as usize];
        let child_offset =
            idx.leaf_block
                .checked_mul(block_size as u64)
                .ok_or(Error::CorruptExtentTree(
                    "extent walk: child block offset overflow",
                ))?;
        dev.read_at(child_offset, &mut buf)?;
        let child_header = ExtentHeader::parse(&buf)?;
        walk(
            &buf,
            &child_header,
            dev,
            block_size,
            out,
            descents_remaining - 1,
        )?;
    }
    Ok(())
}

/// Map a logical block to its physical block. Returns `None` for sparse holes
/// and for uninitialised extents (callers wanting to read zeros should handle
/// that case explicitly — see `map_for_read`).
pub fn map_logical(
    root: &[u8],
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
) -> Result<Option<u64>> {
    map_logical_verified(root, dev, block_size, logical_block, None)
}

/// Same as `map_logical`, with optional extent-tail CRC verification on
/// every off-inode node read.
pub fn map_logical_verified(
    root: &[u8],
    dev: &dyn BlockDevice,
    block_size: u32,
    logical_block: u64,
    ctx: Option<&ExtentVerifyCtx>,
) -> Result<Option<u64>> {
    match lookup_verified(root, dev, block_size, logical_block, ctx)? {
        Some(ext) if !ext.uninitialized => Ok(Some(ext.map(logical_block))),
        Some(_) => Ok(None), // uninitialised → read as zeros
        None => Ok(None),    // sparse hole → read as zeros
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_io::FileDevice;
    use crate::fs::Filesystem;
    use crate::inode::Inode;
    use std::sync::Arc;

    /// Build a minimal root header + leaf extent buffer inline (fits in 60 bytes).
    fn make_root(ext_count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 60];
        // header
        buf[0..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&ext_count.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // max
        buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth = 0 (leaf)
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    fn set_leaf(buf: &mut [u8], i: usize, log: u32, len: u16, phys: u64) {
        let off = 12 * (1 + i);
        buf[off..off + 4].copy_from_slice(&log.to_le_bytes());
        buf[off + 4..off + 6].copy_from_slice(&len.to_le_bytes());
        buf[off + 6..off + 8].copy_from_slice(&((phys >> 32) as u16).to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&((phys & 0xFFFF_FFFF) as u32).to_le_bytes());
    }

    #[test]
    fn leaf_lookup_finds_mapping() {
        let mut buf = make_root(2);
        set_leaf(&mut buf, 0, 0, 4, 100); // logical 0..4 -> physical 100..104
        set_leaf(&mut buf, 1, 4, 2, 200); // logical 4..6 -> physical 200..202

        // Stub dev; never read.
        struct Dummy;
        impl BlockDevice for Dummy {
            fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<()> {
                unreachable!()
            }
            fn size_bytes(&self) -> u64 {
                0
            }
        }

        let r = lookup(&buf, &Dummy, 4096, 0).unwrap().unwrap();
        assert_eq!(r.map(0), 100);

        let r = lookup(&buf, &Dummy, 4096, 3).unwrap().unwrap();
        assert_eq!(r.map(3), 103);

        let r = lookup(&buf, &Dummy, 4096, 5).unwrap().unwrap();
        assert_eq!(r.map(5), 201);

        // Beyond all extents = hole.
        assert!(lookup(&buf, &Dummy, 4096, 10).unwrap().is_none());
    }

    #[test]
    fn uninitialized_extent_maps_to_none() {
        let mut buf = make_root(1);
        // length stored as EXT_INIT_MAX_LEN + 4 means "4 blocks uninitialised"
        set_leaf(&mut buf, 0, 0, EXT_INIT_MAX_LEN + 4, 500);

        struct Dummy;
        impl BlockDevice for Dummy {
            fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<()> {
                unreachable!()
            }
            fn size_bytes(&self) -> u64 {
                0
            }
        }

        // The lookup succeeds but map_logical returns None (read as zeros).
        assert!(map_logical(&buf, &Dummy, 4096, 2).unwrap().is_none());

        let ext = lookup(&buf, &Dummy, 4096, 2).unwrap().unwrap();
        assert!(ext.uninitialized);
        assert_eq!(ext.length, 4);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = make_root(0);
        buf[0] = 0x00;
        buf[1] = 0x00;
        let err = ExtentHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptExtentTree(_)));
    }

    #[test]
    fn rejects_entries_gt_max() {
        let mut buf = make_root(10); // entries=10, max=4
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        let err = ExtentHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, Error::CorruptExtentTree(_)));
    }

    #[test]
    fn rejects_impossible_depth() {
        // depth=99 is well past the spec-allowed max of 5.
        let mut buf = make_root(0);
        buf[6..8].copy_from_slice(&99u16.to_le_bytes());

        struct Dummy;
        impl BlockDevice for Dummy {
            fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<()> {
                unreachable!()
            }
            fn size_bytes(&self) -> u64 {
                0
            }
        }

        // lookup/collect_all must refuse rather than try to descend 99 levels.
        assert!(matches!(
            lookup(&buf, &Dummy, 4096, 0),
            Err(Error::CorruptExtentTree(_))
        ));
        assert!(matches!(
            collect_all(&buf, &Dummy, 4096),
            Err(Error::CorruptExtentTree(_))
        ));
    }

    /// Real ext4-basic.img test: the root directory's inode has exactly one
    /// leaf extent pointing at a single directory block. We verify the extent
    /// layout and that reading the mapped physical block returns data that
    /// parses as directory entries.
    #[test]
    fn ext4_basic_root_inode_has_extent() {
        let path = "test-disks/ext4-basic.img";
        let file = match FileDevice::open(path) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("skip: {path} not present");
                return;
            }
        };
        let dev: Arc<dyn BlockDevice> = Arc::new(file);
        let fs = Filesystem::mount(dev.clone()).expect("mount");
        let raw = fs.read_inode_raw(2).expect("root inode"); // inode 2 = root dir
        let inode = Inode::parse(&raw).expect("parse inode");

        assert!(inode.is_dir(), "root inode is not a directory");
        assert!(inode.has_extents(), "root inode does not use extents");

        let header = ExtentHeader::parse(&inode.block).expect("parse extent header");
        assert_eq!(header.magic, EXT4_EXT_MAGIC);
        assert_eq!(header.depth, 0, "expected a leaf root for tiny test image");
        assert!(header.entries >= 1);

        let all =
            collect_all(&inode.block, dev.as_ref(), fs.sb.block_size()).expect("collect extents");
        assert!(!all.is_empty());
        // First extent should start at logical block 0 for a small dir.
        assert_eq!(all[0].logical_block, 0);
        assert!(!all[0].uninitialized);

        // Read the first physical block and verify it looks like a dir block
        // (should have '.' as the first entry).
        let first_phys = all[0].map(0);
        let mut blk = vec![0u8; fs.sb.block_size() as usize];
        dev.read_at(first_phys * fs.sb.block_size() as u64, &mut blk)
            .unwrap();

        let entries = crate::dir::parse_block(&blk, true).expect("parse dir block");
        assert!(!entries.is_empty());
        assert_eq!(entries[0].name, b".");
    }

    fn make_extent(logical_block: u32, length: u16, physical_block: u64) -> Extent {
        Extent {
            logical_block,
            length,
            physical_block,
            uninitialized: false,
        }
    }

    #[test]
    fn extent_contains_within_range() {
        let e = make_extent(10, 5, 100); // covers logical 10..15
        assert!(e.contains(10));
        assert!(e.contains(12));
        assert!(e.contains(14));
    }

    #[test]
    fn extent_contains_rejects_before_start() {
        let e = make_extent(10, 5, 100);
        assert!(!e.contains(9));
        assert!(!e.contains(0));
    }

    #[test]
    fn extent_contains_rejects_at_end() {
        let e = make_extent(10, 5, 100); // end = 15, exclusive
        assert!(!e.contains(15));
        assert!(!e.contains(100));
    }

    #[test]
    fn extent_contains_single_block_extent() {
        let e = make_extent(7, 1, 50);
        assert!(e.contains(7));
        assert!(!e.contains(6));
        assert!(!e.contains(8));
    }

    #[test]
    fn extent_map_start_of_extent() {
        let e = make_extent(10, 5, 100);
        assert_eq!(e.map(10), 100);
    }

    #[test]
    fn extent_map_interior_block() {
        let e = make_extent(10, 5, 100);
        assert_eq!(e.map(13), 103);
    }

    #[test]
    fn extent_map_last_block() {
        let e = make_extent(10, 5, 100);
        assert_eq!(e.map(14), 104);
    }

    #[test]
    fn extent_parse_rejects_short_buffer() {
        let short = vec![0u8; 4];
        assert!(Extent::parse(&short).is_err());
    }

    #[test]
    fn extent_parse_uninitialized_flag() {
        let mut raw = vec![0u8; 12];
        // ee_len > EXT_INIT_MAX_LEN (32768) marks as uninitialized
        let uninit_len: u16 = EXT_INIT_MAX_LEN + 1;
        raw[4..6].copy_from_slice(&uninit_len.to_le_bytes());
        let e = Extent::parse(&raw).unwrap();
        assert!(e.uninitialized);
        assert_eq!(e.length, 1);
    }

    #[test]
    fn extent_parse_initialized() {
        let mut raw = vec![0u8; 12];
        raw[0..4].copy_from_slice(&5u32.to_le_bytes()); // logical_block
        raw[4..6].copy_from_slice(&3u16.to_le_bytes()); // ee_len (init)
        raw[8..12].copy_from_slice(&200u32.to_le_bytes()); // phys lo
        let e = Extent::parse(&raw).unwrap();
        assert_eq!(e.logical_block, 5);
        assert_eq!(e.length, 3);
        assert_eq!(e.physical_block, 200);
        assert!(!e.uninitialized);
    }
}
