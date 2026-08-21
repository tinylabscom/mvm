//! Extended attribute (xattr) reading.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#extended-attributes
//!
//! ext4 stores xattrs in two places:
//!
//! 1. **In-inode** — between the end of the base 128-byte inode + extra_isize
//!    region and the end of the on-disk inode (when inode_size > 128).
//!    Starts with a 4-byte header containing the magic 0xEA020000.
//!
//! 2. **External xattr block** — when more space is needed, `i_file_acl`
//!    (combined hi+lo, 48-bit physical block number) points at a single
//!    block whose layout is: 32-byte header (magic 0xEA020000 + refcount
//!    + ...) followed by `ext4_xattr_entry` records growing forward, with
//!    values stored from the END of the block growing backward.
//!
//! Entry layout (variable size, padded to 4 bytes):
//!   0x00 u8  e_name_len           (length of name in bytes, no NUL)
//!   0x01 u8  e_name_index         (namespace prefix code; see NAME_PREFIX)
//!   0x02 u16 e_value_offs         (offset within the block where value lives)
//!   0x04 u32 e_value_inum         (if EA_INODE feature: inode holding the value)
//!   0x08 u32 e_value_size         (length of value in bytes)
//!   0x0C u32 e_hash               (hash of name + value)
//!   0x10 ..  e_name (e_name_len bytes, no NUL, padded to 4)
//!
//! Phase 1: read-only, in-inode + external block. Hash verification + EA_INODE
//! large-value support deferred.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};
use crate::inode::Inode;

/// Magic number at the start of an xattr region (in-inode or external block).
pub const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;

/// Standard namespace prefixes (`e_name_index` value → string).
pub const NAME_PREFIXES: &[(u8, &str)] = &[
    (1, "user."),
    (2, "system.posix_acl_access"),
    (3, "system.posix_acl_default"),
    (4, "trusted."),
    (5, "lustre."),
    (6, "security."),
    (7, "system."),
    (8, "system.richacl"),
];

/// Look up the human-readable prefix for a numeric name_index.
pub fn prefix_for_index(idx: u8) -> Option<&'static str> {
    NAME_PREFIXES
        .iter()
        .find(|(i, _)| *i == idx)
        .map(|(_, s)| *s)
}

/// One parsed xattr entry: fully-qualified name + raw value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrEntry {
    /// Fully-qualified name, e.g. "user.com.apple.FinderInfo".
    pub name: String,
    /// Raw value bytes (Finder uses binary data, ACLs are binary, etc.).
    pub value: Vec<u8>,
}

/// Read all extended attributes attached to an inode.
///
/// `inode` is the parsed metadata (we need `file_acl` for the external xattr
/// block). `inode_raw` is the on-disk inode bytes (we need bytes past offset
/// 128 + i_extra_isize for the in-inode xattr region).
///
/// Returns entries from in-inode area first, then external xattr block (if any).
/// An inode with no xattrs returns `Ok(vec![])`.
pub fn read_all(
    dev: &dyn BlockDevice,
    inode: &Inode,
    inode_raw: &[u8],
    inode_size: u16,
    block_size: u32,
) -> Result<Vec<XattrEntry>> {
    let mut out = Vec::new();

    // 1. In-inode xattrs: data between end of i_extra_isize area and end of inode.
    if inode_raw.len() >= 128 + 4 {
        let extra_isize = u16::from_le_bytes(inode_raw[128..130].try_into().unwrap()) as usize;
        let xattr_region_start = 128 + extra_isize;
        if xattr_region_start + 4 <= inode_size as usize
            && xattr_region_start + 4 <= inode_raw.len()
        {
            let region = &inode_raw[xattr_region_start..(inode_size as usize).min(inode_raw.len())];
            let magic = u32::from_le_bytes(region[..4].try_into().unwrap());
            if magic == EXT4_XATTR_MAGIC {
                // Entries follow the 4-byte magic; values are at e_value_offs from
                // the start of the entry table (== start of region + 4).
                parse_entries(&region[4..], region.len() - 4, &mut out)?;
            }
        }
    }

    // 2. External xattr block: i_file_acl (combined hi+lo) → block number.
    if inode.file_acl != 0 {
        let mut buf = vec![0u8; block_size as usize];
        dev.read_at(inode.file_acl * block_size as u64, &mut buf)?;
        let magic = u32::from_le_bytes(buf[..4].try_into().unwrap());
        if magic != EXT4_XATTR_MAGIC {
            return Err(Error::Corrupt("xattr block magic mismatch"));
        }
        // External block layout: 32-byte header, then entries; values offset
        // is from the start of the block (NOT from end-of-header).
        parse_entries_block(&buf, &mut out)?;
    }

    Ok(out)
}

/// Parse entries from the in-inode xattr area.
///
/// `entries_buf` starts immediately AFTER the 4-byte magic header.
/// In the in-inode format, `e_value_offs` is measured from the start of the
/// entries area (i.e. directly indexes into `entries_buf`). Values are packed
/// backward from the end of the entries area while entries grow forward.
fn parse_entries(entries_buf: &[u8], _region_len: usize, out: &mut Vec<XattrEntry>) -> Result<()> {
    let mut pos = 0;
    while pos + 16 <= entries_buf.len() {
        // Kernel's IS_LAST_ENTRY: the terminator has the full first 4-byte
        // header word all zero. We cannot short-circuit on name_len == 0
        // alone, because ACL xattrs (name_index 2 / 3 for
        // system.posix_acl_{access,default}) legitimately store name_len=0
        // — their full name is implied by the index.
        let header = u32::from_le_bytes(entries_buf[pos..pos + 4].try_into().unwrap());
        if header == 0 {
            break;
        }
        let name_len = entries_buf[pos] as usize;
        let name_index = entries_buf[pos + 1];
        let value_offs =
            u16::from_le_bytes(entries_buf[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let _value_inum = u32::from_le_bytes(entries_buf[pos + 4..pos + 8].try_into().unwrap());
        let value_size =
            u32::from_le_bytes(entries_buf[pos + 8..pos + 12].try_into().unwrap()) as usize;
        // pos+12..pos+16 = e_hash (ignored)

        let entry_size = 16 + name_len;
        let entry_padded = (entry_size + 3) & !3;
        if pos + 16 + name_len > entries_buf.len() {
            return Err(Error::Corrupt("xattr entry name overruns region"));
        }

        let name_bytes = &entries_buf[pos + 16..pos + 16 + name_len];
        let prefix = prefix_for_index(name_index).unwrap_or("");
        let suffix =
            std::str::from_utf8(name_bytes).map_err(|_| Error::Corrupt("xattr name not utf-8"))?;
        let full_name = format!("{prefix}{suffix}");

        let value = if value_size > 0 {
            if value_offs + value_size > entries_buf.len() {
                return Err(Error::Corrupt("xattr value out of range"));
            }
            entries_buf[value_offs..value_offs + value_size].to_vec()
        } else {
            Vec::new()
        };

        out.push(XattrEntry {
            name: full_name,
            value,
        });

        pos += entry_padded;
    }
    Ok(())
}

/// Parse entries from a full external xattr block.
/// Block layout: 32-byte header at offset 0, then entries starting at 32.
/// `e_value_offs` here is from the START of the block, not the entry table.
fn parse_entries_block(block: &[u8], out: &mut Vec<XattrEntry>) -> Result<()> {
    if block.len() < 32 {
        return Err(Error::Corrupt("xattr block too small"));
    }

    let mut pos = 32; // skip the 32-byte header
    while pos + 16 <= block.len() {
        // See parse_entries: terminator = first 4-byte header word all zero,
        // NOT name_len == 0 (which is legal for ACL entries).
        let header = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
        if header == 0 {
            break;
        }
        let name_len = block[pos] as usize;
        let name_index = block[pos + 1];
        let value_offs = u16::from_le_bytes(block[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let _value_inum = u32::from_le_bytes(block[pos + 4..pos + 8].try_into().unwrap());
        let value_size = u32::from_le_bytes(block[pos + 8..pos + 12].try_into().unwrap()) as usize;

        let entry_size = 16 + name_len;
        let entry_padded = (entry_size + 3) & !3;
        if pos + 16 + name_len > block.len() {
            return Err(Error::Corrupt("xattr entry name overruns block"));
        }

        let name_bytes = &block[pos + 16..pos + 16 + name_len];
        let prefix = prefix_for_index(name_index).unwrap_or("");
        let suffix =
            std::str::from_utf8(name_bytes).map_err(|_| Error::Corrupt("xattr name not utf-8"))?;
        let full_name = format!("{prefix}{suffix}");

        let value = if value_size > 0 {
            if value_offs + value_size > block.len() {
                return Err(Error::Corrupt("xattr block value out of range"));
            }
            block[value_offs..value_offs + value_size].to_vec()
        } else {
            Vec::new()
        };

        out.push(XattrEntry {
            name: full_name,
            value,
        });

        pos += entry_padded;
    }
    Ok(())
}

/// Split a fully-qualified xattr name (e.g. `"user.com.apple.FinderInfo"`)
/// into (name_index, suffix). Returns `None` if no known prefix matches.
pub fn split_qualified_name(name: &str) -> Option<(u8, &str)> {
    for (idx, prefix) in NAME_PREFIXES {
        if let Some(rest) = name.strip_prefix(*prefix) {
            return Some((*idx, rest));
        }
    }
    None
}

/// Result of [`plan_remove_in_inode_region`]: the entry was either removed
/// (bytes in place updated) or wasn't present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// Region rewritten; caller must patch the inode checksum + write back.
    Removed,
    /// The name wasn't in this region.
    NotFound,
}

/// Remove an xattr by fully-qualified name from the in-inode region.
/// The `region` slice must span from the 4-byte magic (inclusive) to the
/// end of the inode (exclusive of any later metadata). Returns `Removed`
/// if the name was present and the bytes have been rewritten, `NotFound`
/// otherwise. `Error::InvalidArgument` if the name lacks a known
/// namespace prefix.
pub fn plan_remove_in_inode_region(region: &mut [u8], name: &str) -> Result<RemoveOutcome> {
    let Some((name_index, suffix)) = split_qualified_name(name) else {
        return Err(Error::InvalidArgument(
            "xattr name missing known namespace prefix",
        ));
    };
    if region.len() < 4 {
        return Ok(RemoveOutcome::NotFound);
    }
    let magic = u32::from_le_bytes(region[..4].try_into().unwrap());
    if magic != EXT4_XATTR_MAGIC {
        return Ok(RemoveOutcome::NotFound);
    }

    // Decode every entry (header + name + value bytes).
    let entries = decode_in_inode_entries(&region[4..])?;
    let before = entries.len();
    let kept: Vec<DecodedEntry> = entries
        .into_iter()
        .filter(|e| !(e.name_index == name_index && e.name_bytes == suffix.as_bytes()))
        .collect();
    if kept.len() == before {
        return Ok(RemoveOutcome::NotFound);
    }

    encode_in_inode_entries(region, &kept);
    Ok(RemoveOutcome::Removed)
}

/// Result of [`plan_set_in_inode_region`]: the entry was either
/// inserted (no previous entry with this name) or replaced (new value
/// overwrote an existing entry's value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOutcome {
    Inserted,
    Replaced,
}

/// Set (create-or-replace) an xattr entry in the in-inode region.
/// `region` spans from the 4-byte magic to the end of the inode image.
/// On success the bytes have been rewritten to include the new entry.
///
/// Errors:
/// - `Error::InvalidArgument` when `name` lacks a known namespace prefix
///   or the suffix is empty (except for ACL namespaces 2 + 3).
/// - `Error::NameTooLong` when the suffix is longer than 255 bytes.
/// - `Error::NoSpaceLeftOnDevice` when the rewritten region wouldn't fit
///   (entries + values + 4-byte terminator > region capacity).
pub fn plan_set_in_inode_region(region: &mut [u8], name: &str, value: &[u8]) -> Result<SetOutcome> {
    let Some((name_index, suffix)) = split_qualified_name(name) else {
        return Err(Error::InvalidArgument(
            "xattr name missing known namespace prefix",
        ));
    };
    if suffix.is_empty() && !matches!(name_index, 2 | 3) {
        return Err(Error::InvalidArgument("xattr name suffix is empty"));
    }
    if suffix.len() > 255 {
        return Err(Error::NameTooLong);
    }
    if region.len() < 8 {
        return Err(Error::NoSpaceLeftOnDevice);
    }

    let magic_present = {
        let m = u32::from_le_bytes(region[..4].try_into().unwrap());
        m == EXT4_XATTR_MAGIC
    };
    let mut entries = if magic_present {
        decode_in_inode_entries(&region[4..])?
    } else {
        Vec::new()
    };

    let mut outcome = SetOutcome::Inserted;
    let suffix_bytes = suffix.as_bytes();
    for e in entries.iter_mut() {
        if e.name_index == name_index && e.name_bytes == suffix_bytes {
            e.value = value.to_vec();
            outcome = SetOutcome::Replaced;
            break;
        }
    }
    if matches!(outcome, SetOutcome::Inserted) {
        entries.push(DecodedEntry {
            name_index,
            name_bytes: suffix_bytes.to_vec(),
            value: value.to_vec(),
        });
    }

    let area_len = region.len() - 4;
    let needed_entries: usize = entries
        .iter()
        .map(|e| (16 + e.name_bytes.len() + 3) & !3)
        .sum();
    let needed_values: usize = entries
        .iter()
        .filter(|e| !e.value.is_empty())
        .map(|e| (e.value.len() + 3) & !3)
        .sum();
    if needed_entries + 4 + needed_values > area_len {
        return Err(Error::NoSpaceLeftOnDevice);
    }

    encode_in_inode_entries(region, &entries);
    Ok(outcome)
}

/// One fully-owned xattr entry decoded from an in-inode region.
#[derive(Debug, Clone)]
struct DecodedEntry {
    name_index: u8,
    name_bytes: Vec<u8>,
    value: Vec<u8>,
}

/// Parse every entry out of the in-inode region's entries-area slice
/// (starts immediately AFTER the 4-byte magic).
fn decode_in_inode_entries(entries_buf: &[u8]) -> Result<Vec<DecodedEntry>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 16 <= entries_buf.len() {
        let header = u32::from_le_bytes(entries_buf[pos..pos + 4].try_into().unwrap());
        if header == 0 {
            break;
        }
        let name_len = entries_buf[pos] as usize;
        let name_index = entries_buf[pos + 1];
        let value_offs =
            u16::from_le_bytes(entries_buf[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let value_size =
            u32::from_le_bytes(entries_buf[pos + 8..pos + 12].try_into().unwrap()) as usize;
        if pos + 16 + name_len > entries_buf.len() {
            return Err(Error::Corrupt("xattr entry name overruns region"));
        }
        let name_bytes = entries_buf[pos + 16..pos + 16 + name_len].to_vec();
        let value = if value_size == 0 {
            Vec::new()
        } else {
            if value_offs + value_size > entries_buf.len() {
                return Err(Error::Corrupt("xattr value out of range"));
            }
            entries_buf[value_offs..value_offs + value_size].to_vec()
        };
        out.push(DecodedEntry {
            name_index,
            name_bytes,
            value,
        });
        pos += (16 + name_len + 3) & !3;
    }
    Ok(out)
}

/// Re-emit the in-inode region from a list of entries. Zeros the entire
/// region, stamps magic at [0..4], packs entries forward from offset 4,
/// and packs their values backward from the end. Leaves a u32 zero
/// terminator after the last entry (implicit via the initial zero sweep).
///
/// Caller must size `region` large enough; this function is only called
/// after `decode_in_inode_entries` produced the list so the byte budget
/// is always ≤ the original region.
fn encode_in_inode_entries(region: &mut [u8], entries: &[DecodedEntry]) {
    for b in region.iter_mut() {
        *b = 0;
    }
    region[..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let entries_area = &mut region[4..];
    let area_len = entries_area.len();

    // Stable sort: kernel stores entries ordered by (name_index, name).
    let mut sorted: Vec<&DecodedEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        a.name_index
            .cmp(&b.name_index)
            .then_with(|| a.name_bytes.cmp(&b.name_bytes))
    });

    let mut entry_cursor: usize = 0;
    let mut value_cursor: usize = area_len;

    for e in &sorted {
        let name_len = e.name_bytes.len();
        let entry_padded = (16 + name_len + 3) & !3;

        let value_offs = if e.value.is_empty() {
            0
        } else {
            let value_padded = (e.value.len() + 3) & !3;
            value_cursor -= value_padded;
            entries_area[value_cursor..value_cursor + e.value.len()].copy_from_slice(&e.value);
            value_cursor
        };

        entries_area[entry_cursor] = name_len as u8;
        entries_area[entry_cursor + 1] = e.name_index;
        entries_area[entry_cursor + 2..entry_cursor + 4]
            .copy_from_slice(&(value_offs as u16).to_le_bytes());
        // e_value_inum at +4..+8 = 0 (no EA_INODE)
        entries_area[entry_cursor + 8..entry_cursor + 12]
            .copy_from_slice(&(e.value.len() as u32).to_le_bytes());
        // e_hash at +12..+16 = 0 (in-inode hash is dedup-only)
        entries_area[entry_cursor + 16..entry_cursor + 16 + name_len]
            .copy_from_slice(&e.name_bytes);
        entry_cursor += entry_padded;
    }
    // Terminator u32 at entry_cursor is already zero from the sweep.
}

// ---------------------------------------------------------------------------
// External xattr block: write-side
// ---------------------------------------------------------------------------

/// Outcome of [`plan_remove_from_external_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRemoveOutcome {
    /// Entry removed; the block still has at least one entry remaining.
    Removed,
    /// Entry removed AND the block is now empty — caller should free the
    /// block and zero `i_file_acl`.
    RemovedNowEmpty,
    /// The named entry wasn't in this block.
    NotFound,
}

/// Decode every entry from an external xattr block (the 32-byte header is
/// expected at offset 0). Skips the terminator. Used by both the read path
/// and the write path.
fn decode_external_block_entries(block: &[u8]) -> Result<Vec<DecodedEntry>> {
    if block.len() < 32 {
        return Err(Error::Corrupt("xattr block too small"));
    }
    let mut out = Vec::new();
    let mut pos = 32usize;
    while pos + 16 <= block.len() {
        let header = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
        if header == 0 {
            break;
        }
        let name_len = block[pos] as usize;
        let name_index = block[pos + 1];
        let value_offs = u16::from_le_bytes(block[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let value_size = u32::from_le_bytes(block[pos + 8..pos + 12].try_into().unwrap()) as usize;
        if pos + 16 + name_len > block.len() {
            return Err(Error::Corrupt("xattr entry name overruns block"));
        }
        let name_bytes = block[pos + 16..pos + 16 + name_len].to_vec();
        let value = if value_size == 0 {
            Vec::new()
        } else {
            if value_offs + value_size > block.len() {
                return Err(Error::Corrupt("xattr block value out of range"));
            }
            block[value_offs..value_offs + value_size].to_vec()
        };
        out.push(DecodedEntry {
            name_index,
            name_bytes,
            value,
        });
        pos += (16 + name_len + 3) & !3;
    }
    Ok(out)
}

/// Re-emit a full external xattr block from a list of entries.
///
/// Lays out:
/// - `[0x00..0x04]` magic = `EXT4_XATTR_MAGIC`
/// - `[0x04..0x08]` `h_refcount` (caller-provided; default 1)
/// - `[0x08..0x0C]` `h_blocks` = 1 (always single-block)
/// - `[0x0C..0x10]` `h_hash` = 0 (kernel recomputes lazily; readers tolerate 0)
/// - `[0x10..0x14]` `h_checksum` slot — left as 0 here; caller patches via
///   `Checksummer::patch_xattr_block` after layout.
/// - `[0x14..0x20]` reserved zeros
/// - `[0x20..]`     entries growing forward, values growing backward from
///   end of block. `e_value_offs` is BLOCK-relative
///   (different from in-inode where it's region-relative).
fn encode_external_block(block: &mut [u8], entries: &[DecodedEntry], refcount: u32) {
    for b in block.iter_mut() {
        *b = 0;
    }
    block[0x00..0x04].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    block[0x04..0x08].copy_from_slice(&refcount.to_le_bytes());
    block[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
    // h_hash + h_checksum + reserved: stay zero until checksum patch.

    // Stable sort: kernel orders by (name_index, name).
    let mut sorted: Vec<&DecodedEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        a.name_index
            .cmp(&b.name_index)
            .then_with(|| a.name_bytes.cmp(&b.name_bytes))
    });

    let block_len = block.len();
    let mut entry_cursor: usize = 0x20;
    let mut value_cursor: usize = block_len;
    // Fold each entry's e_hash into the block hash (h_hash). Mirrors the
    // kernel's ext4_xattr_rehash: any zero entry hash forces h_hash = 0.
    let mut block_hash: u32 = 0;
    let mut any_zero_hash = false;

    for e in &sorted {
        let name_len = e.name_bytes.len();
        let entry_padded = (16 + name_len + 3) & !3;

        let value_offs = if e.value.is_empty() {
            0
        } else {
            let value_padded = (e.value.len() + 3) & !3;
            value_cursor -= value_padded;
            block[value_cursor..value_cursor + e.value.len()].copy_from_slice(&e.value);
            value_cursor
        };

        // External-block entries carry a real e_hash (over name + value); the
        // kernel and e2fsck reject a zero hash ("has a hash (0) which is invalid").
        let e_hash = xattr_entry_hash(&e.name_bytes, &e.value);

        block[entry_cursor] = name_len as u8;
        block[entry_cursor + 1] = e.name_index;
        block[entry_cursor + 2..entry_cursor + 4]
            .copy_from_slice(&(value_offs as u16).to_le_bytes());
        // e_value_inum at +4..+8 = 0 (no EA_INODE)
        block[entry_cursor + 8..entry_cursor + 12]
            .copy_from_slice(&(e.value.len() as u32).to_le_bytes());
        block[entry_cursor + 12..entry_cursor + 16].copy_from_slice(&e_hash.to_le_bytes());
        block[entry_cursor + 16..entry_cursor + 16 + name_len].copy_from_slice(&e.name_bytes);
        entry_cursor += entry_padded;

        if e_hash == 0 {
            any_zero_hash = true;
        } else if !any_zero_hash {
            block_hash = (block_hash << 16) ^ (block_hash >> 16) ^ e_hash;
        }
    }
    // h_hash (0x0C): zero if any entry hash was zero, else the folded value.
    let h_hash = if any_zero_hash { 0 } else { block_hash };
    block[0x0C..0x10].copy_from_slice(&h_hash.to_le_bytes());
    // Terminator already zero from the wipe.
}

/// ext4 xattr entry hash (`ext4_xattr_hash_entry`): a rolling hash over the
/// name bytes (shift 5), then the value as little-endian 32-bit words (shift
/// 16) with the final partial word zero-padded. External-block entries store
/// this in `e_hash`; in-inode entries leave it zero.
fn xattr_entry_hash(name: &[u8], value: &[u8]) -> u32 {
    const NAME_SHIFT: u32 = 5;
    const VALUE_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &b in name {
        hash = (hash << NAME_SHIFT) ^ (hash >> (32 - NAME_SHIFT)) ^ (b as u32);
    }
    for chunk in value.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        let v = u32::from_le_bytes(word);
        hash = (hash << VALUE_SHIFT) ^ (hash >> (32 - VALUE_SHIFT)) ^ v;
    }
    hash
}

/// Set (create-or-replace) an xattr in an external block buffer.
///
/// `block` is the full xattr block (caller has already read it from disk
/// or freshly zeroed it for a brand-new allocation). `refcount` is what to
/// stamp into `h_refcount` — pass 1 for a non-shared block. On success the
/// bytes have been rewritten; the caller must (a) patch `h_checksum` via
/// `Checksummer::patch_xattr_block` and (b) write the block back.
///
/// Errors:
/// - `Error::InvalidArgument` if the name lacks a known prefix or has an
///   empty suffix (except ACL namespaces 2 + 3).
/// - `Error::NameTooLong` if the suffix > 255 bytes.
/// - `Error::NoSpaceLeftOnDevice` if the new layout would not fit in the
///   block (entries + values + terminator > block size).
pub fn plan_set_in_external_block(
    block: &mut [u8],
    name: &str,
    value: &[u8],
    refcount: u32,
) -> Result<SetOutcome> {
    let Some((name_index, suffix)) = split_qualified_name(name) else {
        return Err(Error::InvalidArgument(
            "xattr name missing known namespace prefix",
        ));
    };
    if suffix.is_empty() && !matches!(name_index, 2 | 3) {
        return Err(Error::InvalidArgument("xattr name suffix is empty"));
    }
    if suffix.len() > 255 {
        return Err(Error::NameTooLong);
    }
    if block.len() < 0x40 {
        return Err(Error::NoSpaceLeftOnDevice);
    }

    let magic_present = u32::from_le_bytes(block[..4].try_into().unwrap()) == EXT4_XATTR_MAGIC;
    let mut entries = if magic_present {
        decode_external_block_entries(block)?
    } else {
        Vec::new()
    };

    let mut outcome = SetOutcome::Inserted;
    let suffix_bytes = suffix.as_bytes();
    for e in entries.iter_mut() {
        if e.name_index == name_index && e.name_bytes == suffix_bytes {
            e.value = value.to_vec();
            outcome = SetOutcome::Replaced;
            break;
        }
    }
    if matches!(outcome, SetOutcome::Inserted) {
        entries.push(DecodedEntry {
            name_index,
            name_bytes: suffix_bytes.to_vec(),
            value: value.to_vec(),
        });
    }

    let entries_capacity = block.len() - 0x20;
    let needed_entries: usize = entries
        .iter()
        .map(|e| (16 + e.name_bytes.len() + 3) & !3)
        .sum();
    let needed_values: usize = entries
        .iter()
        .filter(|e| !e.value.is_empty())
        .map(|e| (e.value.len() + 3) & !3)
        .sum();
    if needed_entries + 4 + needed_values > entries_capacity {
        return Err(Error::NoSpaceLeftOnDevice);
    }

    encode_external_block(block, &entries, refcount);
    Ok(outcome)
}

/// Remove an xattr from an external block buffer.
///
/// Returns [`BlockRemoveOutcome::RemovedNowEmpty`] when the last entry is
/// gone — the caller should free the underlying block + zero `i_file_acl`
/// rather than leaving an empty xattr block on disk. Otherwise rewrites
/// the block in place; caller must re-checksum + write back.
pub fn plan_remove_from_external_block(
    block: &mut [u8],
    name: &str,
    refcount: u32,
) -> Result<BlockRemoveOutcome> {
    let Some((name_index, suffix)) = split_qualified_name(name) else {
        return Err(Error::InvalidArgument(
            "xattr name missing known namespace prefix",
        ));
    };
    if block.len() < 0x20 {
        return Ok(BlockRemoveOutcome::NotFound);
    }
    let magic = u32::from_le_bytes(block[..4].try_into().unwrap());
    if magic != EXT4_XATTR_MAGIC {
        return Ok(BlockRemoveOutcome::NotFound);
    }

    let entries = decode_external_block_entries(block)?;
    let before = entries.len();
    let kept: Vec<DecodedEntry> = entries
        .into_iter()
        .filter(|e| !(e.name_index == name_index && e.name_bytes == suffix.as_bytes()))
        .collect();
    if kept.len() == before {
        return Ok(BlockRemoveOutcome::NotFound);
    }
    if kept.is_empty() {
        return Ok(BlockRemoveOutcome::RemovedNowEmpty);
    }
    encode_external_block(block, &kept, refcount);
    Ok(BlockRemoveOutcome::Removed)
}

/// Convenience: get a single xattr value by name. Returns `None` if not present.
pub fn get(
    dev: &dyn BlockDevice,
    inode: &Inode,
    inode_raw: &[u8],
    inode_size: u16,
    block_size: u32,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let all = read_all(dev, inode, inode_raw, inode_size, block_size)?;
    Ok(all.into_iter().find(|e| e.name == name).map(|e| e.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_known() {
        assert_eq!(prefix_for_index(1), Some("user."));
        assert_eq!(prefix_for_index(7), Some("system."));
        assert_eq!(prefix_for_index(99), None);
    }

    #[test]
    fn split_qualified_name_roundtrip() {
        assert_eq!(split_qualified_name("user.color"), Some((1, "color")));
        assert_eq!(
            split_qualified_name("user.com.apple.FinderInfo"),
            Some((1, "com.apple.FinderInfo"))
        );
        assert_eq!(
            split_qualified_name("security.selinux"),
            Some((6, "selinux"))
        );
        assert_eq!(split_qualified_name("unknown.foo"), None);
    }

    /// Build a minimal in-inode region with two `user.*` entries, then remove
    /// one by name. Verify the other survives and a readback decodes cleanly.
    #[test]
    fn remove_in_inode_roundtrips_one_of_two() {
        // 96-byte region is plenty for two short entries (each ~24 bytes
        // header+name + a handful of value bytes).
        let mut region = vec![0u8; 96];
        let entries = vec![
            DecodedEntry {
                name_index: 1,
                name_bytes: b"color".to_vec(),
                value: b"red".to_vec(),
            },
            DecodedEntry {
                name_index: 1,
                name_bytes: b"mood".to_vec(),
                value: b"happy".to_vec(),
            },
        ];
        encode_in_inode_entries(&mut region, &entries);

        // Sanity: before-remove decode returns both entries.
        let decoded = decode_in_inode_entries(&region[4..]).unwrap();
        assert_eq!(decoded.len(), 2);

        let outcome = plan_remove_in_inode_region(&mut region, "user.color").unwrap();
        assert_eq!(outcome, RemoveOutcome::Removed);

        let after = decode_in_inode_entries(&region[4..]).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].name_bytes, b"mood");
        assert_eq!(after[0].value, b"happy");
    }

    #[test]
    fn remove_in_inode_returns_not_found_for_missing() {
        let mut region = vec![0u8; 64];
        let entries = vec![DecodedEntry {
            name_index: 1,
            name_bytes: b"color".to_vec(),
            value: b"red".to_vec(),
        }];
        encode_in_inode_entries(&mut region, &entries);
        let outcome = plan_remove_in_inode_region(&mut region, "user.mood").unwrap();
        assert_eq!(outcome, RemoveOutcome::NotFound);
    }

    #[test]
    fn remove_in_inode_unknown_prefix_is_einval() {
        let mut region = vec![0u8; 64];
        let err = plan_remove_in_inode_region(&mut region, "nope.name").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn remove_in_inode_missing_magic_is_not_found() {
        let mut region = vec![0u8; 64];
        // all zeros → no magic
        let outcome = plan_remove_in_inode_region(&mut region, "user.x").unwrap();
        assert_eq!(outcome, RemoveOutcome::NotFound);
    }

    #[test]
    fn set_in_inode_inserts_new_into_empty_region() {
        let mut region = vec![0u8; 64];
        let outcome = plan_set_in_inode_region(&mut region, "user.color", b"red").unwrap();
        assert_eq!(outcome, SetOutcome::Inserted);
        let decoded = decode_in_inode_entries(&region[4..]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name_bytes, b"color");
        assert_eq!(decoded[0].value, b"red");
    }

    #[test]
    fn set_in_inode_replaces_existing_value() {
        let mut region = vec![0u8; 96];
        plan_set_in_inode_region(&mut region, "user.color", b"red").unwrap();
        let outcome = plan_set_in_inode_region(&mut region, "user.color", b"emerald").unwrap();
        assert_eq!(outcome, SetOutcome::Replaced);
        let decoded = decode_in_inode_entries(&region[4..]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value, b"emerald");
    }

    #[test]
    fn set_in_inode_preserves_other_entries() {
        let mut region = vec![0u8; 128];
        plan_set_in_inode_region(&mut region, "user.color", b"red").unwrap();
        plan_set_in_inode_region(&mut region, "user.mood", b"happy").unwrap();
        plan_set_in_inode_region(&mut region, "user.color", b"blue").unwrap();
        let decoded = decode_in_inode_entries(&region[4..]).unwrap();
        let by_name: std::collections::BTreeMap<_, _> = decoded
            .into_iter()
            .map(|e| (e.name_bytes.clone(), e.value))
            .collect();
        assert_eq!(by_name.get(b"color".as_slice()).unwrap(), b"blue");
        assert_eq!(by_name.get(b"mood".as_slice()).unwrap(), b"happy");
    }

    #[test]
    fn set_in_inode_enospc_on_overflow() {
        let mut region = vec![0u8; 32];
        let err =
            plan_set_in_inode_region(&mut region, "user.x", b"this_is_20_bytes_xx!").unwrap_err();
        assert!(matches!(err, Error::NoSpaceLeftOnDevice));
    }

    #[test]
    fn set_in_inode_unknown_prefix_is_einval() {
        let mut region = vec![0u8; 64];
        let err = plan_set_in_inode_region(&mut region, "weird.key", b"v").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }
}
