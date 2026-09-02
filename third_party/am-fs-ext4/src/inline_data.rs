//! Inline data reading.
//!
//! Spec: kernel.org/doc/html/latest/filesystems/ext4/inlinedata.html
//!
//! When the `INCOMPAT_INLINE_DATA` feature is enabled and an inode has the
//! `EXT4_INLINE_DATA_FL` flag, the file's contents live inside the inode
//! itself instead of being stored in extent-allocated data blocks.
//!
//! Layout:
//!   - First **60 bytes** of the file are stored in the `i_block[60]` array
//!     (the same field that normally holds the extent header / direct block
//!     pointers).
//!   - If the file is larger than 60 bytes, the remainder is stored as the
//!     value of a special xattr named `system.data`. Concatenate the two to
//!     get the full file content.
//!   - Maximum inline file size = 60 + (in-inode-xattr-region-size minus
//!     headers and other entries). Typically 60–~150 bytes for inode_size=256.

use crate::block_io::BlockDevice;
use crate::error::Result;
use crate::inode::Inode;
use crate::xattr;

/// Read the contents of an inline-data file in full.
///
/// Returns the concatenation of:
/// 1. `inode.block` (60 bytes), truncated to the file's `size`
/// 2. The `system.data` xattr value (if file size > 60)
///
/// Caller must verify the inode actually has `INLINE_DATA_FL` set before
/// calling — otherwise the returned bytes are garbage (extent header etc.).
pub fn read_all(
    dev: &dyn BlockDevice,
    inode: &Inode,
    inode_raw: &[u8],
    inode_size: u16,
    block_size: u32,
) -> Result<Vec<u8>> {
    let total = inode.size as usize;

    // Up to 60 bytes from i_block.
    let inline_max = 60;
    let from_block = total.min(inline_max);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&inode.block[..from_block]);

    if total <= inline_max {
        return Ok(out);
    }

    // Overflow lives in the system.data xattr.
    if let Some(extra) = xattr::get(dev, inode, inode_raw, inode_size, block_size, "system.data")? {
        let need = total - inline_max;
        let take = extra.len().min(need);
        out.extend_from_slice(&extra[..take]);
    }

    Ok(out)
}

/// Read a range from an inline-data file.
/// Returns the bytes copied into `dst`, or `Ok(0)` if `offset >= size`.
pub fn read_range(
    dev: &dyn BlockDevice,
    inode: &Inode,
    inode_raw: &[u8],
    inode_size: u16,
    block_size: u32,
    offset: u64,
    dst: &mut [u8],
) -> Result<usize> {
    let total = inode.size;
    if offset >= total {
        return Ok(0);
    }
    let full = read_all(dev, inode, inode_raw, inode_size, block_size)?;
    let want = ((total - offset) as usize).min(dst.len());
    let avail = full.len().saturating_sub(offset as usize);
    let n = want.min(avail);
    dst[..n].copy_from_slice(&full[offset as usize..offset as usize + n]);
    Ok(n)
}
