//! Extent tree mutation — planning layer (E7).
//!
//! Produces typed [`ExtentMutation`] values describing how the extent tree
//! should change. Does NOT write to disk; E10 composes these into file write
//! operations and E11 journals them.
//!
//! Scope for Phase 4 initial landing:
//! - Operations on the inline root (leaf, depth 0). The inline root carries up
//!   to 4 entries on a standard 60-byte i_block area, which covers the common
//!   case of small files (≤ 4 contiguous extents).
//! - `insert_extent`: place a new leaf extent in sorted position; returns an
//!   error tagged `LEAF_FULL_NEEDS_PROMOTION` when the root is saturated and
//!   the caller must promote to depth > 0 (future task).
//! - `split_extent`: split one extent at a logical-block boundary (used when
//!   partially overwriting, freeing a middle run, or converting uninit→init on
//!   a sub-range).
//! - `merge_adjacent`: fuse two neighbours whose `[log+len, phys+len)` line up.
//! - `free_extent`: drop an entry and report the physical block range to
//!   hand to the block bitmap freer (E5).
//!
//! Multi-level tree mutation (leaf-block split, internal-node rebalance) is
//! deferred. Hitting it returns [`Error::Corrupt`] with a clear message so
//! callers can fall back to copy-on-write or error out cleanly.

use crate::error::{Error, Result};
use crate::extent::{
    Extent, ExtentHeader, ExtentIdx, EXT4_EXT_MAGIC, EXT4_EXT_MAX_DEPTH, EXT4_EXT_NODE_SIZE,
    EXT_INIT_MAX_LEN,
};

// Byte offsets within a 12-byte extent tree node header.
const EXT4_EXT_HDR_MAGIC_OFF: usize = 0;
const EXT4_EXT_HDR_ENTRIES_OFF: usize = 2;
const EXT4_EXT_HDR_MAX_OFF: usize = 4;
const EXT4_EXT_HDR_DEPTH_OFF: usize = 6;
const EXT4_EXT_HDR_GEN_OFF: usize = 8;

/// Byte offset of extent entry `i` within a node body (entries follow the
/// 12-byte header, so entry 0 is at offset `EXT4_EXT_NODE_SIZE`).
#[inline]
fn extent_entry_offset(i: usize) -> usize {
    EXT4_EXT_NODE_SIZE * (1 + i)
}

/// Split a 64-bit physical block address into the hi u16 and lo u32 fields
/// used by ext4 extent and index entries.
#[inline]
pub(crate) fn split_phys_block(block: u64) -> (u16, u32) {
    let hi = ((block >> 32) & 0xFFFF) as u16;
    let lo = (block & 0xFFFF_FFFF) as u32;
    (hi, lo)
}

/// A primitive change the extent-write path wants to make to the tree. The
/// caller (E10 or a test) converts this into real I/O under a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtentMutation {
    /// Overwrite the inline root (60 bytes of `i_block`) with these bytes.
    WriteRoot { bytes: Vec<u8> },
    /// Allocate a fresh leaf block and write these bytes to it. Returned for
    /// future multi-level operations; not produced by the current plan fns.
    AllocLeafBlock { bytes: Vec<u8> },
    /// Free a previously-used leaf/index block back to the bitmap.
    FreeLeafBlock { block: u64 },
    /// Free a contiguous physical-block run back to the bitmap (from a
    /// dropped leaf extent). `start` is the first physical block, `len` is
    /// the count.
    FreePhysicalRun { start: u64, len: u32 },
}

/// Build a leaf extent entry's 12 bytes.
fn encode_extent(e: &Extent) -> [u8; EXT4_EXT_NODE_SIZE] {
    let mut buf = [0u8; EXT4_EXT_NODE_SIZE];
    buf[0..4].copy_from_slice(&e.logical_block.to_le_bytes());
    let ee_len: u16 = if e.uninitialized {
        e.length + EXT_INIT_MAX_LEN
    } else {
        e.length
    };
    buf[4..6].copy_from_slice(&ee_len.to_le_bytes());
    let (phys_hi, phys_lo) = split_phys_block(e.physical_block);
    buf[6..8].copy_from_slice(&phys_hi.to_le_bytes());
    buf[8..12].copy_from_slice(&phys_lo.to_le_bytes());
    buf
}

/// Re-emit the inline root from a header + sorted extent list. `root_len` is
/// the size of the i_block area (always 60 for inline root, larger for a
/// full-block leaf).
fn build_root(header: &ExtentHeader, extents: &[Extent], root_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; root_len];
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&(extents.len() as u16).to_le_bytes());
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&header.max.to_le_bytes());
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2]
        .copy_from_slice(&header.depth.to_le_bytes());
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4]
        .copy_from_slice(&header.generation.to_le_bytes());
    for (i, e) in extents.iter().enumerate() {
        let off = extent_entry_offset(i);
        out[off..off + EXT4_EXT_NODE_SIZE].copy_from_slice(&encode_extent(e));
    }
    out
}

/// Read the leaf entries from an inline root. Errors on non-leaf (the root
/// has descended into index entries — caller must handle the multi-level
/// case separately).
fn read_leaf_entries(root: &[u8]) -> Result<(ExtentHeader, Vec<Extent>)> {
    let header = ExtentHeader::parse(root)?;
    if !header.is_leaf() {
        return Err(Error::CorruptExtentTree(
            "extent_mut: multi-level tree mutation not yet supported",
        ));
    }
    let mut out = Vec::with_capacity(header.entries as usize);
    for i in 0..header.entries {
        let off = extent_entry_offset(i as usize);
        if off + EXT4_EXT_NODE_SIZE > root.len() {
            return Err(Error::CorruptExtentTree("leaf entry out of range"));
        }
        out.push(Extent::parse(&root[off..off + EXT4_EXT_NODE_SIZE])?);
    }
    Ok((header, out))
}

/// Returns true iff two adjacent leaf extents are physically contiguous and
/// in the same uninit state — candidate for a merge.
fn are_contiguous(a: &Extent, b: &Extent) -> bool {
    if a.uninitialized != b.uninitialized {
        return false;
    }
    let a_log_end = a.logical_block as u64 + a.length as u64;
    let a_phys_end = a.physical_block + a.length as u64;
    a_log_end == b.logical_block as u64 && a_phys_end == b.physical_block
}

/// Plan insertion of `new` into the inline-root leaf. Preserves sort order on
/// `logical_block`, rejects overlaps, and auto-merges with the prev / next
/// entry when contiguous.
///
/// Errors:
/// - `LEAF_FULL_NEEDS_PROMOTION` if there is no room AND no merge was
///   possible. Caller must promote to an internal-root tree (future task).
/// - `extent overlaps existing` if `new`'s logical range overlaps an existing
///   entry.
pub fn plan_insert_extent(root: &[u8], new: Extent) -> Result<Vec<ExtentMutation>> {
    let (header, mut entries) = read_leaf_entries(root)?;

    // Reject overlaps. Assumes entries sorted by logical_block.
    for e in &entries {
        let e_end = e.logical_block as u64 + e.length as u64;
        let n_end = new.logical_block as u64 + new.length as u64;
        if !(n_end <= e.logical_block as u64 || new.logical_block as u64 >= e_end) {
            return Err(Error::CorruptExtentTree("extent overlaps existing"));
        }
    }

    // Find insert position (stable — first index whose logical_block > new).
    let pos = entries
        .iter()
        .position(|e| e.logical_block as u64 > new.logical_block as u64)
        .unwrap_or(entries.len());
    entries.insert(pos, new);

    // Auto-merge with left neighbour if contiguous.
    if pos > 0 && are_contiguous(&entries[pos - 1], &entries[pos]) {
        let right = entries.remove(pos);
        entries[pos - 1].length += right.length;
    }
    // Auto-merge with right neighbour (pos may have shifted — recompute).
    let pos = entries
        .iter()
        .position(|e| {
            e.logical_block == new.logical_block
                || (e.logical_block as u64) < new.logical_block as u64
                    && (e.logical_block as u64 + e.length as u64) > new.logical_block as u64
        })
        .unwrap_or(entries.len().saturating_sub(1));
    if pos + 1 < entries.len() && are_contiguous(&entries[pos], &entries[pos + 1]) {
        let right = entries.remove(pos + 1);
        entries[pos].length += right.length;
    }

    if entries.len() as u16 > header.max {
        return Err(Error::CorruptExtentTree(
            "LEAF_FULL_NEEDS_PROMOTION: root has no slot for new extent",
        ));
    }

    let new_root = build_root(&header, &entries, root.len());
    Ok(vec![ExtentMutation::WriteRoot { bytes: new_root }])
}

/// Layout for a promote-leaf-to-depth-1 operation: the new leaf block that
/// holds the five entries (four old + the new one), and the rewritten inline
/// root that indexes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionPlan {
    /// Full-block bytes for the freshly-allocated leaf node. Header at the
    /// start, sorted leaf entries, zeros to end. If `reserved_tail_csum` was
    /// true the last 4 bytes are reserved for the caller to patch with
    /// `checksum.patch_extent_tail`.
    pub leaf_bytes: Vec<u8>,
    /// 60 bytes of the new inline root: depth=1, entries=1, single index
    /// entry whose logical_block = 0 and leaf_block = the physical block the
    /// caller allocated for `leaf_bytes`.
    pub new_root_bytes: Vec<u8>,
}

/// Build a depth-0 leaf block (full `block_size` bytes). Reserves 4 tail
/// bytes for the ext4_extent_tail CRC when `reserved_tail_csum` is true.
fn build_leaf_block(
    generation: u32,
    extents: &[Extent],
    block_size: usize,
    reserved_tail_csum: bool,
) -> Vec<u8> {
    let mut out = vec![0u8; block_size];
    let header_body_len = block_size.saturating_sub(if reserved_tail_csum { 4 } else { 0 });
    let max_entries = ((header_body_len - EXT4_EXT_NODE_SIZE) / EXT4_EXT_NODE_SIZE) as u16;
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&(extents.len() as u16).to_le_bytes());
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&max_entries.to_le_bytes());
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2].copy_from_slice(&0u16.to_le_bytes());
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4].copy_from_slice(&generation.to_le_bytes());
    for (i, e) in extents.iter().enumerate() {
        let off = extent_entry_offset(i);
        out[off..off + EXT4_EXT_NODE_SIZE].copy_from_slice(&encode_extent(e));
    }
    out
}

/// Build a 60-byte depth-1 inline root containing a single index entry
/// pointing at `leaf_phys` (logical 0).
fn build_depth1_index_root(generation: u32, leaf_phys: u64) -> Vec<u8> {
    let mut out = vec![0u8; 60];
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&1u16.to_le_bytes()); // entries=1
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&4u16.to_le_bytes()); // max=4 (inline root)
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2].copy_from_slice(&1u16.to_le_bytes()); // depth=1
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4].copy_from_slice(&generation.to_le_bytes());
    let ei_block: u32 = 0;
    let (ei_leaf_hi, ei_leaf_lo) = split_phys_block(leaf_phys);
    out[12..16].copy_from_slice(&ei_block.to_le_bytes());
    out[16..20].copy_from_slice(&ei_leaf_lo.to_le_bytes());
    out[20..22].copy_from_slice(&ei_leaf_hi.to_le_bytes());
    out
}

/// Plan a depth-0 → depth-1 promotion. The caller must have already seen
/// `LEAF_FULL_NEEDS_PROMOTION` from `plan_insert_extent` and allocated one
/// fresh filesystem block to hold the new leaf.
///
/// Produces:
///   - `leaf_bytes`: the entire new leaf block (`block_size` bytes) containing
///     all existing extents + `new`, sorted and merge-compatible with the
///     existing layout. Last 4 bytes are reserved for the caller to patch
///     with `checksum.patch_extent_tail` when metadata_csum is on.
///   - `new_root_bytes`: 60 bytes, depth=1, one index entry → `new_leaf_phys`.
///
/// Errors if `root` is not a leaf (depth != 0) — the multi-level split case
/// is a further task. Also rejects overlaps with existing entries.
pub fn plan_promote_leaf(
    root: &[u8],
    new: Extent,
    block_size: usize,
    new_leaf_phys: u64,
    reserved_tail_csum: bool,
) -> Result<PromotionPlan> {
    let (header, mut entries) = read_leaf_entries(root)?;

    for e in &entries {
        let e_end = e.logical_block as u64 + e.length as u64;
        let n_end = new.logical_block as u64 + new.length as u64;
        if !(n_end <= e.logical_block as u64 || new.logical_block as u64 >= e_end) {
            return Err(Error::CorruptExtentTree("extent overlaps existing"));
        }
    }

    let pos = entries
        .iter()
        .position(|e| e.logical_block as u64 > new.logical_block as u64)
        .unwrap_or(entries.len());
    entries.insert(pos, new);

    if pos > 0 && are_contiguous(&entries[pos - 1], &entries[pos]) {
        let right = entries.remove(pos);
        entries[pos - 1].length += right.length;
    }
    let merged_pos = entries
        .iter()
        .position(|e| {
            e.logical_block == new.logical_block
                || ((e.logical_block as u64) < new.logical_block as u64
                    && (e.logical_block as u64 + e.length as u64) > new.logical_block as u64)
        })
        .unwrap_or(entries.len().saturating_sub(1));
    if merged_pos + 1 < entries.len()
        && are_contiguous(&entries[merged_pos], &entries[merged_pos + 1])
    {
        let right = entries.remove(merged_pos + 1);
        entries[merged_pos].length += right.length;
    }

    let leaf_capacity_bytes = block_size.saturating_sub(if reserved_tail_csum { 4 } else { 0 });
    let leaf_max = ((leaf_capacity_bytes - EXT4_EXT_NODE_SIZE) / EXT4_EXT_NODE_SIZE) as u16;
    if entries.len() as u16 > leaf_max {
        return Err(Error::CorruptExtentTree(
            "plan_promote_leaf: entry count exceeds leaf capacity",
        ));
    }

    let leaf_bytes = build_leaf_block(header.generation, &entries, block_size, reserved_tail_csum);
    let new_root_bytes = build_depth1_index_root(header.generation, new_leaf_phys);
    Ok(PromotionPlan {
        leaf_bytes,
        new_root_bytes,
    })
}

// ----------------------------------------------------------------------------
// Depth ≥ 2 mutation: descend, insert at leaf, propagate splits, promote root.
// ----------------------------------------------------------------------------

/// Read interface used by [`plan_insert_extent_deep`] to fetch any internal
/// or leaf block referenced by an index entry on the way down. Callers wire
/// this through a `BlockDevice` (or a buffered cache when running under a
/// transaction).
pub trait DeepReader {
    /// Read exactly `out.len()` bytes of the block numbered `block`. The
    /// caller picks the buffer size (always `block_size`).
    fn read_block(&self, block: u64, out: &mut [u8]) -> Result<()>;
}

/// Result of a deep insert. The caller stages each component into its
/// transaction (inode-i_block patch + per-block writes + bitmap/BGD updates
/// for the freshly-allocated blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepInsertPlan {
    /// New 60 bytes of `i_block`. Depth may have changed (root promotion).
    pub new_root: Vec<u8>,
    /// Block writes, one per modified-or-new block. Each entry is
    /// `(block_num, full block_size bytes)`. Non-root blocks have their last
    /// 4 bytes zeroed and reserved — the caller patches `et_checksum` via
    /// [`crate::checksum::Checksummer::patch_extent_tail`].
    pub block_writes: Vec<(u64, Vec<u8>)>,
    /// Block numbers freshly pulled from the allocator closure, in the order
    /// they were drawn. The caller marks each used in the bitmap and bumps
    /// BGD/SB counters in the same transaction.
    pub allocated_blocks: Vec<u64>,
}

/// One frame on the descent path: the block we read, its raw bytes, and the
/// index entry inside its parent that pointed at it. The root frame uses
/// `block = 0` and `idx_in_parent = 0` purely as placeholders — root is
/// recognized by its position (the first frame) rather than by these fields.
struct PathFrame {
    /// Block number of this node. `0` if this is the inline root.
    block: u64,
    /// Raw bytes (60 for root, `block_size` for everything below).
    bytes: Vec<u8>,
    /// Position of the index entry inside the parent that selected this
    /// child. `0` for the root frame (no parent).
    idx_in_parent: usize,
}

/// Encode a 12-byte index entry pointing at `child_phys` for the subtree
/// whose smallest logical block is `logical_block`.
fn encode_index(logical_block: u32, child_phys: u64) -> [u8; EXT4_EXT_NODE_SIZE] {
    let mut buf = [0u8; EXT4_EXT_NODE_SIZE];
    let (leaf_hi, leaf_lo) = split_phys_block(child_phys);
    buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
    buf[4..8].copy_from_slice(&leaf_lo.to_le_bytes());
    buf[8..10].copy_from_slice(&leaf_hi.to_le_bytes());
    // 0x0A..0x0C is ei_unused — already zero.
    buf
}

/// Read every leaf entry from a node body, regardless of whether it's inline
/// or a full block. Caller has already verified the header is a leaf.
fn parse_leaf_entries(node: &[u8], header: &ExtentHeader) -> Result<Vec<Extent>> {
    let mut out = Vec::with_capacity(header.entries as usize);
    for i in 0..header.entries {
        let off = extent_entry_offset(i as usize);
        if off + EXT4_EXT_NODE_SIZE > node.len() {
            return Err(Error::CorruptExtentTree("leaf entry out of range"));
        }
        out.push(Extent::parse(&node[off..off + EXT4_EXT_NODE_SIZE])?);
    }
    Ok(out)
}

/// Read every index entry from an internal node body. Caller has already
/// verified the header is non-leaf.
fn parse_index_entries(node: &[u8], header: &ExtentHeader) -> Result<Vec<ExtentIdx>> {
    let mut out = Vec::with_capacity(header.entries as usize);
    for i in 0..header.entries {
        let off = extent_entry_offset(i as usize);
        if off + EXT4_EXT_NODE_SIZE > node.len() {
            return Err(Error::CorruptExtentTree("index entry out of range"));
        }
        out.push(ExtentIdx::parse(&node[off..off + EXT4_EXT_NODE_SIZE])?);
    }
    Ok(out)
}

/// Capacity (in entries) of a non-root leaf or index block. The trailing
/// 4-byte tail is always reserved — every consumer that uses this code path
/// is on a metadata_csum volume in practice, and reserving the slot when it
/// isn't strictly needed costs nothing on layout.
fn node_max_entries(block_size: usize) -> u16 {
    ((block_size - EXT4_EXT_NODE_SIZE - 4) / EXT4_EXT_NODE_SIZE) as u16
}

/// Build a leaf block (full `block_size` bytes) from the given entries. Last
/// 4 bytes are zeroed and reserved for the caller to patch with the
/// extent_tail CRC.
fn build_full_leaf_block(generation: u32, extents: &[Extent], block_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; block_size];
    let max = node_max_entries(block_size);
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&(extents.len() as u16).to_le_bytes());
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&max.to_le_bytes());
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2].copy_from_slice(&0u16.to_le_bytes());
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4].copy_from_slice(&generation.to_le_bytes());
    for (i, e) in extents.iter().enumerate() {
        let off = extent_entry_offset(i);
        out[off..off + EXT4_EXT_NODE_SIZE].copy_from_slice(&encode_extent(e));
    }
    out
}

/// Build a non-root index block (full `block_size` bytes) at the given
/// depth. Last 4 bytes are zeroed and reserved for the extent_tail CRC.
fn build_full_index_block(
    generation: u32,
    depth: u16,
    indices: &[(u32, u64)],
    block_size: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; block_size];
    let max = node_max_entries(block_size);
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&(indices.len() as u16).to_le_bytes());
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&max.to_le_bytes());
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2].copy_from_slice(&depth.to_le_bytes());
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4].copy_from_slice(&generation.to_le_bytes());
    for (i, (logical, child)) in indices.iter().enumerate() {
        let off = extent_entry_offset(i);
        out[off..off + EXT4_EXT_NODE_SIZE].copy_from_slice(&encode_index(*logical, *child));
    }
    out
}

/// Build the 60-byte inline root for an index node at the given depth.
fn build_inline_index_root(generation: u32, depth: u16, indices: &[(u32, u64)]) -> Vec<u8> {
    let mut out = vec![0u8; 60];
    out[EXT4_EXT_HDR_MAGIC_OFF..EXT4_EXT_HDR_MAGIC_OFF + 2]
        .copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    out[EXT4_EXT_HDR_ENTRIES_OFF..EXT4_EXT_HDR_ENTRIES_OFF + 2]
        .copy_from_slice(&(indices.len() as u16).to_le_bytes());
    out[EXT4_EXT_HDR_MAX_OFF..EXT4_EXT_HDR_MAX_OFF + 2].copy_from_slice(&4u16.to_le_bytes()); // max=4 (inline root)
    out[EXT4_EXT_HDR_DEPTH_OFF..EXT4_EXT_HDR_DEPTH_OFF + 2].copy_from_slice(&depth.to_le_bytes());
    out[EXT4_EXT_HDR_GEN_OFF..EXT4_EXT_HDR_GEN_OFF + 4].copy_from_slice(&generation.to_le_bytes());
    for (i, (logical, child)) in indices.iter().enumerate() {
        let off = extent_entry_offset(i);
        out[off..off + EXT4_EXT_NODE_SIZE].copy_from_slice(&encode_index(*logical, *child));
    }
    out
}

/// Build the 60-byte inline root for a leaf node (depth 0).
fn build_inline_leaf_root(generation: u32, extents: &[Extent]) -> Vec<u8> {
    let header = ExtentHeader {
        magic: EXT4_EXT_MAGIC,
        entries: extents.len() as u16,
        max: 4,
        depth: 0,
        generation,
    };
    build_root(&header, extents, 60)
}

/// Reject any insert whose logical range overlaps an existing leaf entry.
fn check_no_overlap(entries: &[Extent], new: &Extent) -> Result<()> {
    let n_start = new.logical_block as u64;
    let n_end = n_start + new.length as u64;
    for e in entries {
        let e_start = e.logical_block as u64;
        let e_end = e_start + e.length as u64;
        if !(n_end <= e_start || n_start >= e_end) {
            return Err(Error::CorruptExtentTree("extent overlaps existing"));
        }
    }
    Ok(())
}

/// Insert `new` into `entries` (sorted by `logical_block`) and auto-merge
/// with neighbours when contiguous. Mirrors `plan_insert_extent`'s logic but
/// works on a generic vector rather than the inline root.
fn insert_into_leaf_sorted(entries: &mut Vec<Extent>, new: Extent) {
    let pos = entries
        .iter()
        .position(|e| e.logical_block as u64 > new.logical_block as u64)
        .unwrap_or(entries.len());
    entries.insert(pos, new);
    if pos > 0 && are_contiguous(&entries[pos - 1], &entries[pos]) {
        let right = entries.remove(pos);
        entries[pos - 1].length += right.length;
    }
    // Recompute the merged-into position to consider a right merge.
    let merged_pos = entries
        .iter()
        .position(|e| {
            e.logical_block == new.logical_block
                || ((e.logical_block as u64) < new.logical_block as u64
                    && (e.logical_block as u64 + e.length as u64) > new.logical_block as u64)
        })
        .unwrap_or(entries.len().saturating_sub(1));
    if merged_pos + 1 < entries.len()
        && are_contiguous(&entries[merged_pos], &entries[merged_pos + 1])
    {
        let right = entries.remove(merged_pos + 1);
        entries[merged_pos].length += right.length;
    }
}

/// Insert a new index entry in sorted-by-logical_block order.
fn insert_into_index_sorted(entries: &mut Vec<(u32, u64)>, new_logical: u32, new_child: u64) {
    let pos = entries
        .iter()
        .position(|(l, _)| *l > new_logical)
        .unwrap_or(entries.len());
    entries.insert(pos, (new_logical, new_child));
}

/// State carried up the tree during split propagation. When `Some`, the
/// parent must absorb a new index entry pointing at the freshly-split-off
/// sibling.
struct PropagatedSplit {
    /// First logical block in the new sibling subtree.
    new_logical: u32,
    /// Block number of the new sibling node.
    new_child: u64,
}

/// Walk the tree from the root to the leaf that should hold `target_logical`.
/// Returns the descent path with one frame per level (root first, leaf last).
fn descend_to_leaf(
    root_bytes: &[u8],
    target_logical: u32,
    block_size: u32,
    reader: &dyn DeepReader,
) -> Result<Vec<PathFrame>> {
    let root_header = ExtentHeader::parse(root_bytes)?;
    if root_header.depth > EXT4_EXT_MAX_DEPTH {
        return Err(Error::CorruptExtentTree(
            "extent tree depth exceeds spec maximum",
        ));
    }
    let mut path = Vec::with_capacity(root_header.depth as usize + 1);
    path.push(PathFrame {
        block: 0,
        bytes: root_bytes.to_vec(),
        idx_in_parent: 0,
    });

    loop {
        let frame = path.last().unwrap();
        let header = ExtentHeader::parse(&frame.bytes)?;
        if header.is_leaf() {
            return Ok(path);
        }
        if header.entries == 0 {
            return Err(Error::CorruptExtentTree(
                "internal node with zero index entries",
            ));
        }
        // Find largest index entry whose ei_block <= target_logical (mirrors
        // the read-side descent in extent::lookup_verified).
        let mut chosen_pos: usize = 0;
        let mut chosen_idx: Option<ExtentIdx> = None;
        for i in 0..header.entries {
            let off = extent_entry_offset(i as usize);
            let idx = ExtentIdx::parse(&frame.bytes[off..off + EXT4_EXT_NODE_SIZE])?;
            if idx.logical_block <= target_logical {
                chosen_pos = i as usize;
                chosen_idx = Some(idx);
            } else {
                break;
            }
        }
        // If target is below the smallest index entry, descend into the
        // first child (the new extent will sort into the leftmost subtree).
        let idx = match chosen_idx {
            Some(i) => i,
            None => {
                let off = extent_entry_offset(0);
                ExtentIdx::parse(&frame.bytes[off..off + EXT4_EXT_NODE_SIZE])?
            }
        };
        let mut child_buf = vec![0u8; block_size as usize];
        reader.read_block(idx.leaf_block, &mut child_buf)?;
        path.push(PathFrame {
            block: idx.leaf_block,
            bytes: child_buf,
            idx_in_parent: chosen_pos,
        });
    }
}

/// Insert `new` into the extent tree rooted at `root_bytes` (60 bytes from
/// the inode's `i_block`), descending through internal nodes as needed,
/// splitting full nodes, and promoting the root if the inline area can no
/// longer hold the post-split index entries.
///
/// `block_size` must match the volume's filesystem block size.
///
/// `reader` provides the bytes of any internal/leaf block we walk through on
/// the way down. `alloc` is called once per freshly-needed block; the caller
/// is responsible for marking each result used in the bitmap (and bumping
/// BGD/SB counters) inside the same transaction as the inode write.
///
/// Caps the post-insert tree depth at [`EXT4_EXT_MAX_DEPTH`]. Beyond that
/// returns [`Error::CorruptExtentTree`].
pub fn plan_insert_extent_deep(
    root_bytes: &[u8],
    new: Extent,
    block_size: u32,
    reader: &dyn DeepReader,
    alloc: &mut dyn FnMut() -> Result<u64>,
) -> Result<DeepInsertPlan> {
    if root_bytes.len() < 12 {
        return Err(Error::CorruptExtentTree("root buffer too small"));
    }
    let bs = block_size as usize;
    let root_header = ExtentHeader::parse(root_bytes)?;
    let generation = root_header.generation;

    // Descend to the leaf that should hold `new`.
    let mut path = descend_to_leaf(root_bytes, new.logical_block, block_size, reader)?;

    let mut block_writes: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut allocated_blocks: Vec<u64> = Vec::new();

    // ---- Leaf level ----
    let leaf_frame = path.pop().unwrap();
    let leaf_header = ExtentHeader::parse(&leaf_frame.bytes)?;
    debug_assert!(leaf_header.is_leaf());
    let mut leaf_entries = parse_leaf_entries(&leaf_frame.bytes, &leaf_header)?;
    check_no_overlap(&leaf_entries, &new)?;
    insert_into_leaf_sorted(&mut leaf_entries, new);

    // Capacity for this leaf depends on whether it's the inline root or a
    // full block. The inline root holds up to 4 entries (no tail); a full
    // block holds up to `node_max_entries(bs)` entries (with tail reserved).
    let is_root_leaf = path.is_empty();
    let leaf_cap = if is_root_leaf {
        4
    } else {
        node_max_entries(bs)
    };

    // `propagated` carries the (logical, block) tuple of the split-off
    // sibling that the next-higher level must absorb as a new index entry.
    // Initially set by the leaf-split branch below; replaced by the in-loop
    // split branch each time a non-root index node also overflows.
    let mut propagated: Option<PropagatedSplit>;

    if (leaf_entries.len() as u16) <= leaf_cap {
        // Leaf fits — emit it.
        if is_root_leaf {
            // Root + leaf: rewrite the inline root and we're done.
            let new_root = build_inline_leaf_root(generation, &leaf_entries);
            return Ok(DeepInsertPlan {
                new_root,
                block_writes,
                allocated_blocks,
            });
        }
        // Non-root leaf absorbed cleanly — every level above is unchanged,
        // so the inline root bytes go back verbatim.
        let new_leaf = build_full_leaf_block(generation, &leaf_entries, bs);
        block_writes.push((leaf_frame.block, new_leaf));
        return Ok(DeepInsertPlan {
            new_root: root_bytes.to_vec(),
            block_writes,
            allocated_blocks,
        });
    } else {
        // Leaf overflowed — split it 50/50.
        if is_root_leaf {
            // Special case: inline root is a leaf and overflowed. Promote to
            // depth 1 by allocating a single block and dumping all entries
            // there, then rewriting the root with a single index entry.
            // (This mirrors `plan_promote_leaf`, inlined so we control the
            // alloc + write emission.)
            let new_leaf_block = alloc()?;
            allocated_blocks.push(new_leaf_block);
            let new_leaf_bytes = build_full_leaf_block(generation, &leaf_entries, bs);
            block_writes.push((new_leaf_block, new_leaf_bytes));
            let new_root = build_inline_index_root(
                generation,
                1,
                &[(leaf_entries[0].logical_block, new_leaf_block)],
            );
            return Ok(DeepInsertPlan {
                new_root,
                block_writes,
                allocated_blocks,
            });
        }
        // Non-root leaf split.
        let mid = leaf_entries.len() / 2;
        let right_entries: Vec<Extent> = leaf_entries.split_off(mid);
        let left_entries = leaf_entries;
        let right_first_logical = right_entries[0].logical_block;
        let new_right_block = alloc()?;
        allocated_blocks.push(new_right_block);

        let left_bytes = build_full_leaf_block(generation, &left_entries, bs);
        let right_bytes = build_full_leaf_block(generation, &right_entries, bs);
        block_writes.push((leaf_frame.block, left_bytes));
        block_writes.push((new_right_block, right_bytes));

        propagated = Some(PropagatedSplit {
            new_logical: right_first_logical,
            new_child: new_right_block,
        });
    }

    // ---- Walk up internal levels, absorbing the propagated split. ----
    // Invariant: at the top of every loop iteration, `propagated` is Some —
    // a level absorbs without overflow (sets propagated=None) only on a
    // path that returns immediately, since every higher level is unchanged.
    while let Some(frame) = path.pop() {
        let split = propagated
            .take()
            .expect("deep insert invariant: propagated must be Some at every loop iter");

        let header = ExtentHeader::parse(&frame.bytes)?;
        debug_assert!(!header.is_leaf());
        let mut indices: Vec<(u32, u64)> = parse_index_entries(&frame.bytes, &header)?
            .into_iter()
            .map(|i| (i.logical_block, i.leaf_block))
            .collect();
        insert_into_index_sorted(&mut indices, split.new_logical, split.new_child);

        let is_root_here = path.is_empty();
        let cap = if is_root_here {
            4
        } else {
            node_max_entries(bs)
        };

        if (indices.len() as u16) <= cap {
            if is_root_here {
                let new_root = build_inline_index_root(generation, header.depth, &indices);
                return Ok(DeepInsertPlan {
                    new_root,
                    block_writes,
                    allocated_blocks,
                });
            }
            let bytes = build_full_index_block(generation, header.depth, &indices, bs);
            block_writes.push((frame.block, bytes));
            // No more propagation — every level above this is unchanged, so
            // the inline root bytes can be returned verbatim.
            return Ok(DeepInsertPlan {
                new_root: root_bytes.to_vec(),
                block_writes,
                allocated_blocks,
            });
        } else {
            // Index overflow.
            if is_root_here {
                // Root promotion: allocate two new index blocks, split the
                // index entries 50/50 between them, rewrite the inline root
                // as depth+1 with two index entries.
                let new_depth = header.depth + 1;
                if new_depth > EXT4_EXT_MAX_DEPTH {
                    return Err(Error::CorruptExtentTree(
                        "extent tree depth would exceed spec maximum",
                    ));
                }
                let mid = indices.len() / 2;
                let right_indices: Vec<(u32, u64)> = indices.split_off(mid);
                let left_indices = indices;
                let left_first = left_indices[0].0;
                let right_first = right_indices[0].0;
                let left_block = alloc()?;
                allocated_blocks.push(left_block);
                let right_block = alloc()?;
                allocated_blocks.push(right_block);
                let left_bytes =
                    build_full_index_block(generation, header.depth, &left_indices, bs);
                let right_bytes =
                    build_full_index_block(generation, header.depth, &right_indices, bs);
                block_writes.push((left_block, left_bytes));
                block_writes.push((right_block, right_bytes));
                let new_root = build_inline_index_root(
                    generation,
                    new_depth,
                    &[(left_first, left_block), (right_first, right_block)],
                );
                return Ok(DeepInsertPlan {
                    new_root,
                    block_writes,
                    allocated_blocks,
                });
            }
            // Non-root index split.
            let mid = indices.len() / 2;
            let right_indices: Vec<(u32, u64)> = indices.split_off(mid);
            let left_indices = indices;
            let right_first = right_indices[0].0;
            let new_right_block = alloc()?;
            allocated_blocks.push(new_right_block);
            let left_bytes = build_full_index_block(generation, header.depth, &left_indices, bs);
            let right_bytes = build_full_index_block(generation, header.depth, &right_indices, bs);
            block_writes.push((frame.block, left_bytes));
            block_writes.push((new_right_block, right_bytes));
            propagated = Some(PropagatedSplit {
                new_logical: right_first,
                new_child: new_right_block,
            });
        }
    }

    // The loop only exits when every level absorbed without spilling to the
    // root, but in that case we already returned from inside the loop. If
    // execution reaches here the invariant above is broken — surface as a
    // logic bug rather than silently producing the wrong tree.
    Err(Error::CorruptExtentTree(
        "deep insert: unexpected path exhaustion",
    ))
}

/// Plan a split of `entries[idx]` at logical block `split_at` — the entry is
/// replaced by two halves [`start..split_at`, `split_at..end`]. The caller
/// uses this when partially overwriting, freeing a middle run, or converting
/// uninit→init on a sub-range.
///
/// Errors if `split_at` is not strictly inside the chosen extent.
pub fn plan_split_extent(root: &[u8], idx: usize, split_at: u32) -> Result<Vec<ExtentMutation>> {
    let (header, mut entries) = read_leaf_entries(root)?;
    let e = *entries
        .get(idx)
        .ok_or(Error::CorruptExtentTree("split idx out of range"))?;
    let start = e.logical_block;
    let end = start + e.length as u32;
    if split_at <= start || split_at >= end {
        return Err(Error::CorruptExtentTree("split point outside extent"));
    }
    let left = Extent {
        logical_block: start,
        length: (split_at - start) as u16,
        physical_block: e.physical_block,
        uninitialized: e.uninitialized,
    };
    let right = Extent {
        logical_block: split_at,
        length: (end - split_at) as u16,
        physical_block: e.physical_block + (split_at - start) as u64,
        uninitialized: e.uninitialized,
    };
    entries[idx] = left;
    entries.insert(idx + 1, right);

    if entries.len() as u16 > header.max {
        return Err(Error::CorruptExtentTree(
            "LEAF_FULL_NEEDS_PROMOTION: split exceeds root capacity",
        ));
    }

    let new_root = build_root(&header, &entries, root.len());
    Ok(vec![ExtentMutation::WriteRoot { bytes: new_root }])
}

/// Plan fusing entries[i] and entries[i+1] when they're physically adjacent
/// and in the same uninit state. No-op (returns empty mutation list) if the
/// pair isn't contiguous.
pub fn plan_merge_adjacent(root: &[u8], i: usize) -> Result<Vec<ExtentMutation>> {
    let (header, mut entries) = read_leaf_entries(root)?;
    if i + 1 >= entries.len() {
        return Err(Error::CorruptExtentTree("merge idx out of range"));
    }
    if !are_contiguous(&entries[i], &entries[i + 1]) {
        return Ok(Vec::new());
    }
    let right = entries.remove(i + 1);
    entries[i].length += right.length;
    let new_root = build_root(&header, &entries, root.len());
    Ok(vec![ExtentMutation::WriteRoot { bytes: new_root }])
}

/// Plan removal of `entries[idx]`: drops the entry from the root and emits a
/// [`ExtentMutation::FreePhysicalRun`] so the caller can free the backing
/// blocks via the bitmap allocator (E5).
pub fn plan_free_extent(root: &[u8], idx: usize) -> Result<Vec<ExtentMutation>> {
    let (header, mut entries) = read_leaf_entries(root)?;
    let removed = entries
        .get(idx)
        .copied()
        .ok_or(Error::CorruptExtentTree("free idx out of range"))?;
    entries.remove(idx);
    let new_root = build_root(&header, &entries, root.len());
    Ok(vec![
        ExtentMutation::WriteRoot { bytes: new_root },
        ExtentMutation::FreePhysicalRun {
            start: removed.physical_block,
            len: removed.length as u32,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an inline root (60 bytes) for a leaf with the given extents.
    fn mk_root(extents: &[Extent]) -> Vec<u8> {
        let header = ExtentHeader {
            magic: EXT4_EXT_MAGIC,
            entries: extents.len() as u16,
            max: 4,
            depth: 0,
            generation: 0,
        };
        build_root(&header, extents, 60)
    }

    fn ext(log: u32, len: u16, phys: u64, uninit: bool) -> Extent {
        Extent {
            logical_block: log,
            length: len,
            physical_block: phys,
            uninitialized: uninit,
        }
    }

    fn read_back(bytes: &[u8]) -> Vec<Extent> {
        read_leaf_entries(bytes).unwrap().1
    }

    #[test]
    fn insert_into_empty_root() {
        let root = mk_root(&[]);
        let muts = plan_insert_extent(&root, ext(0, 10, 1000, false)).unwrap();
        assert_eq!(muts.len(), 1);
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!("expected WriteRoot");
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].logical_block, 0);
        assert_eq!(back[0].length, 10);
    }

    #[test]
    fn insert_sorted_ordering() {
        let root = mk_root(&[ext(100, 5, 2000, false)]);
        let muts = plan_insert_extent(&root, ext(0, 10, 1000, false)).unwrap();
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back[0].logical_block, 0);
        assert_eq!(back[1].logical_block, 100);
    }

    #[test]
    fn insert_merges_left_contiguous() {
        let root = mk_root(&[ext(0, 10, 1000, false)]);
        // New extent at logical 10, phys 1010 — contiguous with the first.
        let muts = plan_insert_extent(&root, ext(10, 5, 1010, false)).unwrap();
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 1, "should merge into single extent");
        assert_eq!(back[0].length, 15);
    }

    #[test]
    fn insert_does_not_merge_across_uninit_boundary() {
        let root = mk_root(&[ext(0, 10, 1000, false)]);
        // Contiguous physically/logically but marked uninitialised — must NOT merge.
        let muts = plan_insert_extent(&root, ext(10, 5, 1010, true)).unwrap();
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 2);
        assert!(!back[0].uninitialized);
        assert!(back[1].uninitialized);
    }

    #[test]
    fn insert_rejects_overlap() {
        let root = mk_root(&[ext(0, 10, 1000, false)]);
        let err = plan_insert_extent(&root, ext(5, 5, 2000, false)).unwrap_err();
        match err {
            Error::CorruptExtentTree(msg) => assert!(msg.contains("overlaps")),
            _ => panic!("wrong error kind"),
        }
    }

    #[test]
    fn insert_fails_when_root_full_and_no_merge() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(100, 5, 2000, false),
            ext(200, 5, 3000, false),
            ext(300, 5, 4000, false),
        ]);
        let err = plan_insert_extent(&root, ext(500, 5, 5000, false)).unwrap_err();
        match err {
            Error::CorruptExtentTree(msg) => assert!(msg.contains("LEAF_FULL_NEEDS_PROMOTION")),
            _ => panic!("wrong error kind"),
        }
    }

    #[test]
    fn split_extent_at_midpoint() {
        let root = mk_root(&[ext(0, 10, 1000, false)]);
        let muts = plan_split_extent(&root, 0, 4).unwrap();
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].logical_block, 0);
        assert_eq!(back[0].length, 4);
        assert_eq!(back[0].physical_block, 1000);
        assert_eq!(back[1].logical_block, 4);
        assert_eq!(back[1].length, 6);
        assert_eq!(back[1].physical_block, 1004);
    }

    #[test]
    fn split_rejects_boundary_point() {
        let root = mk_root(&[ext(0, 10, 1000, false)]);
        assert!(plan_split_extent(&root, 0, 0).is_err()); // start
        assert!(plan_split_extent(&root, 0, 10).is_err()); // end
    }

    #[test]
    fn merge_adjacent_contiguous_pair() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(5, 5, 1005, false), // contiguous
        ]);
        let muts = plan_merge_adjacent(&root, 0).unwrap();
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].length, 10);
    }

    #[test]
    fn merge_noop_when_not_contiguous() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(5, 5, 5000, false), // physically apart
        ]);
        let muts = plan_merge_adjacent(&root, 0).unwrap();
        assert!(muts.is_empty(), "no-op when not contiguous");
    }

    #[test]
    fn free_extent_emits_physical_run() {
        let root = mk_root(&[ext(0, 5, 1000, false), ext(10, 3, 2000, false)]);
        let muts = plan_free_extent(&root, 0).unwrap();
        assert_eq!(muts.len(), 2);
        match &muts[1] {
            ExtentMutation::FreePhysicalRun { start, len } => {
                assert_eq!(*start, 1000);
                assert_eq!(*len, 5);
            }
            _ => panic!("expected FreePhysicalRun"),
        }
        let ExtentMutation::WriteRoot { bytes } = &muts[0] else {
            panic!()
        };
        let back = read_back(bytes);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].logical_block, 10);
    }

    #[test]
    fn promote_leaf_moves_entries_into_new_leaf_block() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(100, 5, 2000, false),
            ext(200, 5, 3000, false),
            ext(300, 5, 4000, false),
        ]);
        let plan = plan_promote_leaf(&root, ext(500, 5, 5000, false), 4096, 900_000, true).unwrap();

        assert_eq!(plan.new_root_bytes.len(), 60);
        let hdr = ExtentHeader::parse(&plan.new_root_bytes).unwrap();
        assert_eq!(hdr.depth, 1);
        assert_eq!(hdr.entries, 1);
        assert_eq!(hdr.max, 4);
        let idx = crate::extent::ExtentIdx::parse(
            &plan.new_root_bytes[EXT4_EXT_NODE_SIZE..2 * EXT4_EXT_NODE_SIZE],
        )
        .unwrap();
        assert_eq!(idx.logical_block, 0);
        assert_eq!(idx.leaf_block, 900_000);

        assert_eq!(plan.leaf_bytes.len(), 4096);
        let leaf_hdr = ExtentHeader::parse(&plan.leaf_bytes).unwrap();
        assert_eq!(leaf_hdr.depth, 0);
        assert_eq!(leaf_hdr.entries, 5);
        let expected_max = ((4096 - 12 - 4) / 12) as u16;
        assert_eq!(leaf_hdr.max, expected_max);
        let parsed = read_back(&plan.leaf_bytes[..12 + 5 * 12]);
        assert_eq!(parsed.len(), 5);
        let logs: Vec<u32> = parsed.iter().map(|e| e.logical_block).collect();
        assert_eq!(logs, vec![0, 100, 200, 300, 500]);
    }

    #[test]
    fn promote_leaf_rejects_overlap() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(100, 5, 2000, false),
            ext(200, 5, 3000, false),
            ext(300, 5, 4000, false),
        ]);
        let err = plan_promote_leaf(&root, ext(2, 5, 9000, false), 4096, 500, true).unwrap_err();
        match err {
            Error::CorruptExtentTree(m) => assert!(m.contains("overlaps")),
            _ => panic!("wrong error kind"),
        }
    }

    #[test]
    fn promote_leaf_preserves_generation() {
        let extents = [
            ext(0, 5, 1000, false),
            ext(100, 5, 2000, false),
            ext(200, 5, 3000, false),
            ext(300, 5, 4000, false),
        ];
        let header = ExtentHeader {
            magic: EXT4_EXT_MAGIC,
            entries: 4,
            max: 4,
            depth: 0,
            generation: 0xDEAD_BEEF,
        };
        let root = build_root(&header, &extents, 60);
        let plan = plan_promote_leaf(&root, ext(500, 5, 5000, false), 4096, 777, false).unwrap();
        assert_eq!(
            ExtentHeader::parse(&plan.new_root_bytes)
                .unwrap()
                .generation,
            0xDEAD_BEEF
        );
        assert_eq!(
            ExtentHeader::parse(&plan.leaf_bytes).unwrap().generation,
            0xDEAD_BEEF
        );
    }

    #[test]
    fn promote_leaf_merges_when_contiguous_with_new() {
        let root = mk_root(&[
            ext(0, 5, 1000, false),
            ext(100, 5, 2000, false),
            ext(200, 5, 3000, false),
            ext(300, 5, 4000, false),
        ]);
        let plan = plan_promote_leaf(&root, ext(305, 5, 4005, false), 4096, 123, false).unwrap();
        let leaf_hdr = ExtentHeader::parse(&plan.leaf_bytes).unwrap();
        assert_eq!(leaf_hdr.entries, 4);
        let parsed = read_back(&plan.leaf_bytes[..12 + 4 * 12]);
        assert_eq!(parsed[3].logical_block, 300);
        assert_eq!(parsed[3].length, 10);
    }

    #[test]
    fn multi_level_tree_refused_cleanly() {
        // Synthetic internal-node root (depth=1).
        let mut buf = vec![0u8; 60];
        buf[0..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&0u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // depth=1 → not leaf
        let err = plan_insert_extent(&buf, ext(0, 1, 1000, false)).unwrap_err();
        match err {
            Error::CorruptExtentTree(msg) => assert!(msg.contains("multi-level")),
            _ => panic!("wrong error kind"),
        }
    }
}
