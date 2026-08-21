//! HTree (hash tree) directory lookup.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/directory.html#hash-tree-directories
//!
//! Indexed directories (those with the `EXT4_INDEX_FL` inode flag) store the
//! root of a B+ tree in the first directory block. Each interior node is
//! itself a directory block with two leading "fake" entries (`.` and `..`)
//! followed by an `dx_root_info` then an array of `dx_entry` records sorted
//! by hash. The tree depth is at most 2 (root → optional intermediate → leaf).
//!
//! The leaf blocks contain regular `ext4_dir_entry_2` records that we parse
//! with [`crate::dir::parse_block`].
//!
//! Lookup algorithm:
//!   1. Compute h = name_hash(name, root_info.hash_version, sb.hash_seed)
//!   2. At depth 0, binary-search dx_entry[] for largest entry with hash <= h
//!   3. If indir_levels > 0, descend: read child block, scan its dx_entry[]
//!   4. The final dx_entry.block is the logical block index (within the dir)
//!      of the leaf containing entries with this hash range.
//!   5. Caller does linear scan in that leaf block for the actual name match.

use crate::error::{Error, Result};
use crate::hash::{name_hash, HashVersion, NameHash};

/// Magic check value for dx_root header reserved field (always 0).
const DX_ROOT_RESERVED_ZERO: u32 = 0;

/// Parsed dx_root_info (8 bytes immediately after the two fake "." and ".." entries).
#[derive(Debug, Clone, Copy)]
pub struct DxRootInfo {
    pub reserved_zero: u32,
    pub hash_version: HashVersion,
    /// Length of the info structure in bytes (always 8).
    pub info_length: u8,
    /// 0 = entries[] are leaf pointers; 1 = entries[] point at intermediate nodes.
    pub indirect_levels: u8,
    pub unused_flags: u8,
}

/// Header of any dx node (root or intermediate). 8 bytes.
#[derive(Debug, Clone, Copy)]
pub struct DxCountLimit {
    /// Maximum number of dx_entry records this block can hold.
    pub limit: u16,
    /// Current number of valid dx_entry records (including the leading "fake" one).
    pub count: u16,
}

impl DxCountLimit {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(Error::Corrupt("dx count_limit buffer too small"));
        }
        Ok(Self {
            limit: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            count: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
        })
    }
}

/// One entry in a dx_node array — maps a hash bound to a child block.
#[derive(Debug, Clone, Copy)]
pub struct DxEntry {
    /// Lower-bound hash for entries pointed to by `block` (0 for the first slot).
    pub hash: u32,
    /// Logical block index *within the directory* (i.e. relative to the
    /// directory file, not absolute physical block).
    pub block: u32,
}

impl DxEntry {
    pub const SIZE: usize = 8;

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::Corrupt("dx entry buffer too small"));
        }
        Ok(Self {
            hash: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            block: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

/// Parse `DxRootInfo` from a directory's first block. Layout:
///
/// ```text
///   0..12   "."  fake dir entry  (inode, rec_len=12, name_len=1, type, '.')
///  12..24   ".." fake dir entry  (inode, rec_len=block_size-12, ...)
///  24..32   dx_root_info  (reserved_zero, hash_version, info_length,
///                          indirect_levels, unused_flags)
///  32..     dx_count_limit (4 bytes) followed by dx_entry[] (8 bytes each)
/// ```
pub fn parse_root_info(block: &[u8]) -> Result<DxRootInfo> {
    if block.len() < 32 {
        return Err(Error::Corrupt("dx root block too small"));
    }
    let reserved = u32::from_le_bytes(block[24..28].try_into().unwrap());
    if reserved != DX_ROOT_RESERVED_ZERO {
        return Err(Error::Corrupt("dx root reserved must be 0"));
    }
    let hash_version_byte = block[28];
    let hash_version = HashVersion::from_u8(hash_version_byte)
        .ok_or(Error::Corrupt("unknown htree hash version"))?;
    Ok(DxRootInfo {
        reserved_zero: reserved,
        hash_version,
        info_length: block[29],
        indirect_levels: block[30],
        unused_flags: block[31],
    })
}

/// Parse the count_limit + dx_entry array from a dx_root block.
///
/// Kernel layout trick: `entries[0]` sits at offset `24 + info_length`. Its
/// 4-byte *hash* slot is **overloaded** with `(limit u16, count u16)` — but
/// its 4-byte *block* slot is a real leaf/node pointer covering the low-hash
/// range. Earlier versions of this module skipped past the limit/count and
/// treated `entries[1..]` as `entries[0..]`, losing the first pointer and
/// breaking lookups whenever a name hashed below the real `entries[1].hash`
/// boundary. We now parse starting at `cl_offset` and force
/// `entries[0].hash = 0` to match the kernel semantics.
pub fn parse_root_entries(block: &[u8]) -> Result<(DxCountLimit, Vec<DxEntry>)> {
    let info = parse_root_info(block)?;
    let cl_offset = 24 + info.info_length as usize;
    if cl_offset + 4 > block.len() {
        return Err(Error::Corrupt("dx root count_limit out of range"));
    }
    let cl = DxCountLimit::parse(&block[cl_offset..cl_offset + 4])?;
    let (cl, mut entries) = parse_entries_from(block, cl_offset, cl)?;
    if let Some(first) = entries.first_mut() {
        // The 4 bytes we just parsed as `hash` are really (limit, count); the
        // kernel reads entry[0] with hash == 0 (slot-0 sentinel).
        first.hash = 0;
    }
    Ok((cl, entries))
}

/// Parse the count_limit + dx_entry array from an *intermediate* dx_node block.
/// Layout is simpler than the root: a single 8-byte "fake" entry as a header
/// (inode=0, rec_len=block_size, name_len=0, type=0), then `entries[0]` whose
/// hash slot is overloaded with `(limit, count)` — same trick as the root.
pub fn parse_node_entries(block: &[u8]) -> Result<(DxCountLimit, Vec<DxEntry>)> {
    if block.len() < 8 + 4 {
        return Err(Error::Corrupt("dx node block too small"));
    }
    let cl = DxCountLimit::parse(&block[8..12])?;
    let (cl, mut entries) = parse_entries_from(block, 8, cl)?;
    if let Some(first) = entries.first_mut() {
        first.hash = 0;
    }
    Ok((cl, entries))
}

fn parse_entries_from(
    block: &[u8],
    start: usize,
    cl: DxCountLimit,
) -> Result<(DxCountLimit, Vec<DxEntry>)> {
    if cl.count == 0 {
        return Err(Error::Corrupt("dx node has zero entries"));
    }
    if cl.count > cl.limit {
        return Err(Error::Corrupt("dx count > limit"));
    }
    let need_bytes = cl.count as usize * DxEntry::SIZE;
    if start + need_bytes > block.len() {
        return Err(Error::Corrupt("dx entries overflow block"));
    }
    let mut out = Vec::with_capacity(cl.count as usize);
    for i in 0..cl.count as usize {
        let off = start + i * DxEntry::SIZE;
        out.push(DxEntry::parse(&block[off..off + DxEntry::SIZE])?);
    }
    Ok((cl, out))
}

/// Find the dx_entry whose hash range covers `target`. Returns the largest
/// entry with `entry.hash <= target`. The first entry's hash field is the
/// "limit" sentinel (always 0 in slot 0) — slot 0 covers `[0, slot1.hash)`.
pub fn find_entry_for_hash(entries: &[DxEntry], target: u32) -> &DxEntry {
    debug_assert!(!entries.is_empty(), "dx node must have ≥1 entry");
    // Linear scan is fine: typical dx blocks hold ≤500 entries and we only
    // descend at most twice. Binary search is a future optimisation.
    let mut chosen = &entries[0];
    for e in &entries[1..] {
        if e.hash <= target {
            chosen = e;
        } else {
            break;
        }
    }
    chosen
}

/// One step of the descent. Caller supplies the current node block and gets
/// back the next logical block to read (within the directory file).
///
/// Returns:
/// - `Ok(NextStep::Leaf(block))` if the descent has reached a leaf and the
///   caller should now linearly scan that block for the name.
/// - `Ok(NextStep::Inner(block))` if there's another intermediate level.
pub enum NextStep {
    /// `block` is the logical block index of a leaf containing dir entries.
    Leaf(u32),
    /// `block` is the logical block index of another intermediate dx_node.
    Inner(u32),
}

/// Compute the lookup target hash for a name, then walk the root + 0/1
/// intermediate nodes to produce the leaf block index.
///
/// `block_size` is needed only to make the algorithm self-describing; the
/// caller is responsible for actually reading dir blocks via [`crate::file_io`]
/// because reading inside the directory file (logical → physical) requires
/// the inode + extent tree.
pub fn target_hash(name: &[u8], root_block: &[u8], hash_seed: &[u32; 4]) -> Result<NameHash> {
    let info = parse_root_info(root_block)?;
    Ok(name_hash(name, info.hash_version, hash_seed))
}

/// Resolve the leaf block (logical block index within the directory) that
/// MIGHT contain `name`. Returns `Some(leaf_block)` on success or `None`
/// only when the dx tree is empty (defensive — should not happen in a real
/// indexed directory).
///
/// `read_dx_block` is a closure the caller provides to read a logical block
/// of the directory file (since this module has no view of the inode/extent
/// tree). Signature: `fn(logical_block: u32) -> Result<Vec<u8>>`.
pub fn lookup_leaf<R>(
    name: &[u8],
    root_block: &[u8],
    hash_seed: &[u32; 4],
    mut read_dx_block: R,
) -> Result<Option<u32>>
where
    R: FnMut(u32) -> Result<Vec<u8>>,
{
    let info = parse_root_info(root_block)?;
    let hash = name_hash(name, info.hash_version, hash_seed);

    // Root: parse + pick the entry whose range covers this hash.
    let (_cl, entries) = parse_root_entries(root_block)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let mut target = find_entry_for_hash(&entries, hash.major).block;

    // Descend through `indirect_levels` intermediate nodes, if any.
    for _level in 0..info.indirect_levels {
        let block = read_dx_block(target)?;
        let (_cl, entries) = parse_node_entries(&block)?;
        if entries.is_empty() {
            return Ok(None);
        }
        target = find_entry_for_hash(&entries, hash.major).block;
    }

    Ok(Some(target))
}

// ---------------------------------------------------------------------------
// Tests — synthetic data only (real htree images need a special mkfs config)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal dx_root block: "." entry, ".." entry, root_info
    /// declaring TEA hash with 0 indirect levels, count_limit (count=2,
    /// limit=200), then two dx_entry slots.
    fn synth_root_block() -> Vec<u8> {
        let block_size = 4096;
        let mut buf = vec![0u8; block_size];

        // "." dir entry (12 bytes): inode=2, rec_len=12, name_len=1, type=2, "."
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2;
        buf[8] = b'.';

        // ".." dir entry (12 bytes): inode=2, rec_len=block_size-12, name_len=2, type=2, ".."
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        buf[16..18].copy_from_slice(&((block_size - 12) as u16).to_le_bytes());
        buf[18] = 2;
        buf[19] = 2;
        buf[20] = b'.';
        buf[21] = b'.';

        // dx_root_info (8 bytes at offset 24):
        //   reserved=0, hash_version=2 (TEA), info_length=8, indirect=0, flags=0
        buf[24..28].copy_from_slice(&0u32.to_le_bytes());
        buf[28] = 2; // TEA
        buf[29] = 8; // info_length
        buf[30] = 0; // indirect_levels
        buf[31] = 0; // unused_flags

        // entries[0] at offset 32..40: hash slot overloaded with (limit, count),
        // block = 1 (sentinel slot — covers the low-hash range [0, entries[1].hash)).
        buf[32..34].copy_from_slice(&200u16.to_le_bytes()); // limit
        buf[34..36].copy_from_slice(&2u16.to_le_bytes()); // count
        buf[36..40].copy_from_slice(&1u32.to_le_bytes()); // entries[0].block

        // entries[1] at offset 40..48: hash=0x80000000, block=2 (covers high hashes).
        buf[40..44].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        buf[44..48].copy_from_slice(&2u32.to_le_bytes());

        buf
    }

    #[test]
    fn parses_root_info_correctly() {
        let buf = synth_root_block();
        let info = parse_root_info(&buf).expect("parse");
        assert_eq!(info.hash_version, HashVersion::Tea);
        assert_eq!(info.info_length, 8);
        assert_eq!(info.indirect_levels, 0);
    }

    #[test]
    fn parses_root_entries_count_2() {
        let buf = synth_root_block();
        let (cl, entries) = parse_root_entries(&buf).expect("parse entries");
        assert_eq!(cl.count, 2);
        assert_eq!(cl.limit, 200);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].block, 1);
        assert_eq!(entries[1].block, 2);
        assert_eq!(entries[1].hash, 0x8000_0000);
    }

    #[test]
    fn find_entry_for_hash_picks_correct_slot() {
        let buf = synth_root_block();
        let (_cl, entries) = parse_root_entries(&buf).unwrap();
        // Low hash → slot 0 (block 1)
        let e = find_entry_for_hash(&entries, 0x1000);
        assert_eq!(e.block, 1);
        // High hash → slot 1 (block 2)
        let e = find_entry_for_hash(&entries, 0x9000_0000);
        assert_eq!(e.block, 2);
        // Exact boundary → slot 1
        let e = find_entry_for_hash(&entries, 0x8000_0000);
        assert_eq!(e.block, 2);
    }

    #[test]
    fn lookup_leaf_zero_indirect_picks_correct_block() {
        let buf = synth_root_block();
        let seed = [0u32; 4];
        // The closure won't be called when indirect_levels == 0.
        let result = lookup_leaf(b"any-name", &buf, &seed, |_| {
            unreachable!("should not descend with 0 indirect levels")
        })
        .expect("lookup");
        assert!(result.is_some());
        // We can't predict which block deterministically because the hash
        // depends on the name + seed, but it must be 1 or 2.
        let block = result.unwrap();
        assert!(block == 1 || block == 2, "expected 1 or 2, got {block}");
    }

    #[test]
    fn rejects_bad_hash_version() {
        let mut buf = synth_root_block();
        buf[28] = 99; // unknown version
        let result = parse_root_info(&buf);
        assert!(matches!(result, Err(Error::Corrupt(_))));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut buf = synth_root_block();
        buf[24] = 1; // corrupt reserved field
        let result = parse_root_info(&buf);
        assert!(matches!(result, Err(Error::Corrupt(_))));
    }
}
