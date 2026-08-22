//! Htree rebalance — planning layer (E9).
//!
//! Produces typed [`HtreeMutation`] values describing how to rebalance an
//! indexed directory after `dir::add_entry_to_block` fails with `OutOfBounds`
//! on a full leaf block. Does NOT write to disk; E10 composes into file-level
//! writes, E11 journals.
//!
//! Scope of the initial landing:
//! - **Leaf split** — the common case. A leaf block that can't fit one more
//!   entry is split in two at the median hash. Caller allocates a new logical
//!   block (via E5) and calls `plan_leaf_split` to get the two leaves' bytes
//!   + the hash→block pair that must be inserted in the parent.
//! - **DX entry insert into root** — once the caller has the new leaf's
//!   hash bound + block number, `plan_insert_dx_entry_root` (or `_node`)
//!   emits the updated parent-block bytes. If the parent overflows, we
//!   return `NEEDS_PARENT_SPLIT` so the caller can split the parent too
//!   (or, for depth-1 root → depth-2 promotion, fail clearly).
//!
//! Deferred to future iterations:
//! - Intermediate-node split (parent full while root still has room).
//! - Depth-0 → depth-1 promotion (inline root out of room; no intermediate
//!   level exists yet).
//! - Depth-1 → depth-2 promotion (large-dir feature).
//! - Leaf merge on delete.

use crate::error::{Error, Result};
use crate::hash::{name_hash, HashVersion, NameHash};
use crate::htree::{DxCountLimit, DxEntry};

/// Primitive change to the directory tree. The caller (E10 or a test) turns
/// these into real I/O under a JBD2 transaction (E11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtreeMutation {
    /// Overwrite an existing directory leaf/root/intermediate block.
    /// `logical_block` is the dir-file-relative block index.
    WriteDirBlock { logical_block: u32, bytes: Vec<u8> },
    /// Allocate a NEW logical block at the tail of the dir file and write
    /// these bytes there. The caller also needs to extend the inode size +
    /// extent tree via E7 to make the new logical block mapped.
    AppendNewDirBlock { bytes: Vec<u8> },
}

/// Result of a leaf-split planning call. The caller still needs to:
///   1. Allocate a new logical block for `new_leaf` (extent + inode size).
///   2. Apply both `WriteDirBlock` mutations.
///   3. Call `plan_insert_dx_entry_root` / `_node` on the parent with
///      `split_out_hash` and the new leaf's logical block number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafSplit {
    /// Updated bytes of the original (left) leaf block. Contains entries with
    /// hash < `split_out_hash`.
    pub left_bytes: Vec<u8>,
    /// Bytes of the new (right) leaf block. Contains entries with hash >=
    /// `split_out_hash`. Caller writes to the freshly-allocated block.
    pub right_bytes: Vec<u8>,
    /// Hash bound for the new right-leaf — this is the dx_entry.hash the
    /// caller must install in the parent when routing the new leaf into the
    /// tree.
    pub split_out_hash: u32,
}

/// Read the packed entries from a linear dir leaf into a vector of
/// (hash, raw entry bytes including trailing pad). `reserved_tail` is the
/// number of bytes at the end that are reserved for the metadata-csum tail
/// entry (typically 12) — those bytes are preserved verbatim in the output
/// blocks. `has_file_type` follows the ext4 FILETYPE feature (almost always
/// true in modern fs).
fn read_leaf_entries(
    leaf: &[u8],
    has_file_type: bool,
    hash_version: HashVersion,
    hash_seed: &[u32; 4],
    reserved_tail: usize,
) -> Result<Vec<(NameHash, Vec<u8>)>> {
    let usable = leaf
        .len()
        .checked_sub(reserved_tail)
        .ok_or(Error::OutOfBounds)?;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= usable {
        let cur_inode = u32::from_le_bytes(leaf[off..off + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(leaf[off + 4..off + 6].try_into().unwrap()) as usize;
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > usable {
            return Err(Error::CorruptDirEntry(
                "bad rec_len during htree leaf split",
            ));
        }

        if cur_inode != 0 {
            let name_len_lo = leaf[off + 6];
            let type_or_hi = leaf[off + 7];
            let name_len = if has_file_type {
                name_len_lo as usize
            } else {
                ((type_or_hi as usize) << 8) | name_len_lo as usize
            };
            if 8 + name_len > rec_len {
                return Err(Error::CorruptDirEntry(
                    "name overflows rec_len in htree split",
                ));
            }
            let name = &leaf[off + 8..off + 8 + name_len];
            let h = name_hash(name, hash_version, hash_seed);
            // Copy just the minimum needed: 8-byte header + name + pad to 4.
            let padded = 8 + ((name_len + 3) & !3);
            let mut entry_bytes = vec![0u8; padded];
            entry_bytes[..8].copy_from_slice(&leaf[off..off + 8]);
            entry_bytes[8..8 + name_len].copy_from_slice(name);
            // The rec_len inside entry_bytes is still the old one — the caller
            // fixes it up when emitting into the new block.
            out.push((h, entry_bytes));
        }
        off += rec_len;
    }
    Ok(out)
}

/// Write a packed list of entries into a fresh leaf block, setting correct
/// `rec_len`s (last entry absorbs the remaining space up to the tail).
fn write_packed_leaf(
    entries: &[&[u8]],
    block_size: usize,
    reserved_tail: usize,
) -> Result<Vec<u8>> {
    let usable = block_size
        .checked_sub(reserved_tail)
        .ok_or(Error::OutOfBounds)?;
    let mut out = vec![0u8; block_size];
    let mut off = 0usize;
    for (i, raw) in entries.iter().enumerate() {
        let is_last = i + 1 == entries.len();
        let padded = raw.len();
        if off + padded > usable {
            return Err(Error::OutOfBounds);
        }
        // rec_len: either exact padded size, or (for the last entry) all the
        // remaining space up to the tail. Matches kernel layout.
        let rec_len = if is_last { usable - off } else { padded };
        out[off..off + raw.len()].copy_from_slice(raw);
        // Patch rec_len in the copied header.
        out[off + 4..off + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
        off += rec_len;
    }
    // Tail region preserved as zeros — caller re-applies metadata-csum tail
    // separately after JBD2 commit.
    Ok(out)
}

/// Plan a leaf split. Reads `leaf_bytes`, rehashes names, sorts by hash,
/// cuts at the median, emits two balanced leaves + the hash bound for the
/// parent dx_entry.
///
/// Caller contract: this only rebuilds the two leaf BLOCKS. Updating the
/// parent's dx_entry array is a separate call (`plan_insert_dx_entry_*`).
pub fn plan_leaf_split(
    leaf_bytes: &[u8],
    hash_version: HashVersion,
    hash_seed: &[u32; 4],
    has_file_type: bool,
    block_size: usize,
    reserved_tail: usize,
) -> Result<LeafSplit> {
    let mut entries = read_leaf_entries(
        leaf_bytes,
        has_file_type,
        hash_version,
        hash_seed,
        reserved_tail,
    )?;
    if entries.len() < 2 {
        return Err(Error::Corrupt(
            "htree leaf split needs >=2 entries; caller's overflow may be spurious",
        ));
    }
    // Sort stably by major hash.
    entries.sort_by_key(|(h, _)| h.major);

    // Split at midpoint; promote the right-half's lowest hash as the bound.
    let mid = entries.len() / 2;
    let split_out_hash = entries[mid].0.major;
    let (left, right) = entries.split_at(mid);
    let left_bytes = write_packed_leaf(
        &left.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>(),
        block_size,
        reserved_tail,
    )?;
    let right_bytes = write_packed_leaf(
        &right.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>(),
        block_size,
        reserved_tail,
    )?;
    Ok(LeafSplit {
        left_bytes,
        right_bytes,
        split_out_hash,
    })
}

/// Insert a new `(hash, block)` routing entry into a dx_root's entry array.
/// Returns the updated root block bytes. Errors with `NEEDS_PARENT_SPLIT`
/// when the root is saturated (count == limit).
///
/// `cl_offset` is the offset at which the `DxCountLimit` lives in the root
/// (24 + info_length; info_length is always 8 in practice, so 32).
pub fn plan_insert_dx_entry_root(
    root_bytes: &[u8],
    cl_offset: usize,
    new_hash: u32,
    new_block: u32,
) -> Result<Vec<u8>> {
    plan_insert_dx_entry_generic(root_bytes, cl_offset, new_hash, new_block)
}

/// Insert a new `(hash, block)` routing entry into an intermediate dx_node.
/// Intermediate nodes have the `DxCountLimit` at offset 8 (after the single
/// fake dir entry header).
pub fn plan_insert_dx_entry_node(
    node_bytes: &[u8],
    new_hash: u32,
    new_block: u32,
) -> Result<Vec<u8>> {
    plan_insert_dx_entry_generic(node_bytes, 8, new_hash, new_block)
}

fn plan_insert_dx_entry_generic(
    block: &[u8],
    cl_offset: usize,
    new_hash: u32,
    new_block: u32,
) -> Result<Vec<u8>> {
    if cl_offset + 4 > block.len() {
        return Err(Error::Corrupt("dx cl_offset out of range"));
    }
    let cl = DxCountLimit::parse(&block[cl_offset..cl_offset + 4])?;
    if cl.count >= cl.limit {
        return Err(Error::CorruptExtentTree("NEEDS_PARENT_SPLIT: dx node full"));
    }

    let entries_start = cl_offset + 4;
    let existing = {
        let mut out = Vec::with_capacity(cl.count as usize);
        for i in 0..cl.count as usize {
            let off = entries_start + i * DxEntry::SIZE;
            if off + DxEntry::SIZE > block.len() {
                return Err(Error::Corrupt("dx entries overrun block"));
            }
            out.push(DxEntry::parse(&block[off..off + DxEntry::SIZE])?);
        }
        out
    };

    // Reject duplicate hash (kernel allows it by convention but here we want
    // strict uniqueness for tests — real callers get unique hashes from a
    // fresh leaf split).
    for e in &existing {
        if e.hash == new_hash {
            return Err(Error::CorruptExtentTree("duplicate dx hash insert"));
        }
    }

    // Insert at sorted position. The first entry's hash is a lower-bound
    // sentinel (always 0) and is preserved at index 0.
    let pos = existing
        .iter()
        .skip(1)
        .position(|e| e.hash > new_hash)
        .map(|p| p + 1)
        .unwrap_or(existing.len());
    let mut merged = existing.clone();
    merged.insert(
        pos,
        DxEntry {
            hash: new_hash,
            block: new_block,
        },
    );

    // Emit updated block: preserve everything before cl_offset, bump count,
    // serialize the new entry array.
    let mut out = block.to_vec();
    let new_count = cl.count + 1;
    out[cl_offset + 2..cl_offset + 4].copy_from_slice(&new_count.to_le_bytes());
    for (i, e) in merged.iter().enumerate() {
        let off = entries_start + i * DxEntry::SIZE;
        if off + DxEntry::SIZE > out.len() {
            return Err(Error::Corrupt("dx serialized entries exceed block"));
        }
        out[off..off + 4].copy_from_slice(&e.hash.to_le_bytes());
        out[off + 4..off + 8].copy_from_slice(&e.block.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir::{add_entry_to_block, DirEntryType};

    /// Compose a fresh leaf populated with `count` small entries named
    /// "file_<i>" with inode `100 + i`.
    fn make_populated_leaf(count: usize, block_size: usize, reserved_tail: usize) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        // Seed the block with one oversized initial entry so add_entry_to_block
        // has something to split against.
        let usable = block_size - reserved_tail;
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..6].copy_from_slice(&(usable as u16).to_le_bytes());
        buf[6] = 1;
        buf[7] = DirEntryType::RegFile as u8;
        buf[8] = b'a';
        for i in 0..count {
            let name = format!("file_{}", i);
            add_entry_to_block(
                &mut buf,
                100 + i as u32,
                name.as_bytes(),
                DirEntryType::RegFile,
                true,
                reserved_tail,
            )
            .unwrap();
        }
        buf
    }

    #[test]
    fn leaf_split_balances_entries() {
        let leaf = make_populated_leaf(40, 4096, 0);
        let split = plan_leaf_split(&leaf, HashVersion::HalfMd4, &[0; 4], true, 4096, 0).unwrap();
        // Both halves should be valid leaf blocks of the full size.
        assert_eq!(split.left_bytes.len(), 4096);
        assert_eq!(split.right_bytes.len(), 4096);
        // The split_out_hash sits at the boundary — every right-side entry
        // should rehash >= it, every left-side entry < it.
        let left_entries =
            read_leaf_entries(&split.left_bytes, true, HashVersion::HalfMd4, &[0; 4], 0).unwrap();
        let right_entries =
            read_leaf_entries(&split.right_bytes, true, HashVersion::HalfMd4, &[0; 4], 0).unwrap();
        for (h, _) in &left_entries {
            assert!(
                h.major < split.split_out_hash,
                "left entry hash {} >= split_out {}",
                h.major,
                split.split_out_hash
            );
        }
        for (h, _) in &right_entries {
            assert!(
                h.major >= split.split_out_hash,
                "right entry hash {} < split_out {}",
                h.major,
                split.split_out_hash
            );
        }
        // Both halves populated (not all-in-one).
        assert!(!left_entries.is_empty());
        assert!(!right_entries.is_empty());
    }

    #[test]
    fn leaf_split_rejects_trivial() {
        // Only one entry — split has no meaning.
        let leaf = make_populated_leaf(0, 4096, 0); // just the initial "a" seed
        let err = plan_leaf_split(&leaf, HashVersion::HalfMd4, &[0; 4], true, 4096, 0).unwrap_err();
        match err {
            Error::Corrupt(msg) => assert!(msg.contains(">=2 entries")),
            _ => panic!("wrong error kind"),
        }
    }

    /// Build a synthetic dx root with `count` entries.
    fn make_dx_root(count: u16, limit: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        // Fake "." at 0..12
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = DirEntryType::Directory as u8;
        buf[8] = b'.';
        // Fake ".." at 12..24
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());
        buf[16..18].copy_from_slice(&(4096u16 - 12).to_le_bytes());
        buf[18] = 2;
        buf[19] = DirEntryType::Directory as u8;
        buf[20] = b'.';
        buf[21] = b'.';
        // dx_root_info at 24..32: reserved(4)=0, hash_version=1, info_length=8, levels=0, flags=0
        buf[28] = HashVersion::HalfMd4 as u8;
        buf[29] = 8;
        // dx_count_limit at 32..36
        buf[32..34].copy_from_slice(&limit.to_le_bytes());
        buf[34..36].copy_from_slice(&count.to_le_bytes());
        // dx_entry[0] at 36..44: hash=0 (sentinel), block=1
        buf[36..40].copy_from_slice(&0u32.to_le_bytes());
        buf[40..44].copy_from_slice(&1u32.to_le_bytes());
        // dx_entry[1..count]: fill with synthetic hashes
        for i in 1..count as usize {
            let off = 36 + i * DxEntry::SIZE;
            let hash: u32 = (i as u32) * 1000;
            buf[off..off + 4].copy_from_slice(&hash.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&((i as u32) + 1).to_le_bytes());
        }
        buf
    }

    #[test]
    fn dx_entry_insert_root_preserves_sort() {
        // count=3 entries: hash=0, 1000, 2000 → insert 1500 → should land at slot 2.
        let root = make_dx_root(3, 500);
        let updated = plan_insert_dx_entry_root(&root, 32, 1500, 42).unwrap();
        let count = u16::from_le_bytes(updated[34..36].try_into().unwrap());
        assert_eq!(count, 4);
        let hash_at_2 = u32::from_le_bytes(updated[36 + 2 * 8..40 + 2 * 8].try_into().unwrap());
        let block_at_2 = u32::from_le_bytes(updated[40 + 2 * 8..44 + 2 * 8].try_into().unwrap());
        assert_eq!(hash_at_2, 1500);
        assert_eq!(block_at_2, 42);
    }

    #[test]
    fn dx_entry_insert_at_end() {
        let root = make_dx_root(3, 500);
        let updated = plan_insert_dx_entry_root(&root, 32, 9999, 77).unwrap();
        let count = u16::from_le_bytes(updated[34..36].try_into().unwrap());
        assert_eq!(count, 4);
        // New last entry at index 3 (0-based).
        let hash_at_3 = u32::from_le_bytes(updated[36 + 3 * 8..40 + 3 * 8].try_into().unwrap());
        assert_eq!(hash_at_3, 9999);
    }

    #[test]
    fn dx_entry_insert_rejects_full_node() {
        let root = make_dx_root(5, 5); // count==limit
        let err = plan_insert_dx_entry_root(&root, 32, 1234, 10).unwrap_err();
        match err {
            Error::CorruptExtentTree(msg) => assert!(msg.contains("NEEDS_PARENT_SPLIT")),
            _ => panic!("wrong error kind"),
        }
    }

    #[test]
    fn dx_entry_insert_rejects_duplicate_hash() {
        let root = make_dx_root(3, 500);
        let err = plan_insert_dx_entry_root(&root, 32, 1000, 42).unwrap_err();
        match err {
            Error::CorruptExtentTree(msg) => assert!(msg.contains("duplicate")),
            _ => panic!("wrong error kind"),
        }
    }
}
