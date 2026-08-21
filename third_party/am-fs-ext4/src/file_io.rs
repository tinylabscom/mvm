//! Read file (or directory) contents using extent traversal.
//!
//! Composes `inode::Inode` + `extent::lookup` + `block_io::BlockDevice` into
//! a Read/Seek-style API. Phase 1 read-only.

use crate::error::{Error, Result};
use crate::extent;
use crate::fs::Filesystem;
use crate::indirect;
use crate::inline_data;
use crate::inode::{Inode, InodeFlags};

/// Read up to `length` bytes from `inode` starting at byte `offset`.
/// Returns the actual number of bytes read (may be less than requested
/// if EOF is reached).
///
/// Sparse holes and uninitialised extents are returned as zero bytes.
///
/// Files with `EXT4_INLINE_DATA_FL` cannot go through this function — their
/// content lives in the inode's xattr region which the parsed `Inode` doesn't
/// carry. Callers must use [`read_with_raw`] or [`read_inline`] instead;
/// this function returns `Err(Corrupt)` on inline inodes.
pub fn read(
    fs: &Filesystem,
    inode: &Inode,
    offset: u64,
    length: u64,
    out: &mut [u8],
) -> Result<u64> {
    if length == 0 || out.is_empty() {
        return Ok(0);
    }

    // Inline data: file lives in i_block (60 bytes) + system.data xattr overflow.
    // Caller must use [`read_inline`] for inline files since we need the raw
    // inode bytes (xattr region) which the parsed Inode no longer carries.
    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
        return Err(Error::Corrupt(
            "inline-data file: caller must use file_io::read_inline with raw inode bytes",
        ));
    }

    // Clamp length to file size.
    if offset >= inode.size {
        return Ok(0);
    }
    let max_read = (inode.size - offset).min(length).min(out.len() as u64);
    if max_read == 0 {
        return Ok(0);
    }

    let block_size = fs.sb.block_size() as u64;
    let bs32 = fs.sb.block_size();
    let mut written: u64 = 0;
    let mut cur_offset = offset;
    let end_offset = offset + max_read;

    // Two block-mapping schemes share the same byte-walking loop:
    //   * `EXT4_EXTENTS_FL` set → extent tree (modern ext4 default).
    //   * Flag absent          → legacy direct/indirect block-pointer scheme
    //     used by ext2, ext3, and ext4 inodes that opted out of extents.
    // Both lookups are amortized: the extent path caches the last extent;
    // the indirect path caches the last indirect block read.
    let uses_extents = (inode.flags & InodeFlags::EXTENTS.bits()) != 0;
    let mut cached_extent: Option<extent::Extent> = None;
    let mut indirect_cache = indirect::IndirectCache::new();

    // Walk byte-by-block until we've satisfied the request.
    while cur_offset < end_offset {
        let logical_block = cur_offset / block_size;
        let off_in_block = (cur_offset % block_size) as usize;
        let bytes_available_in_block = block_size as usize - off_in_block;
        let bytes_remaining = (end_offset - cur_offset) as usize;
        let copy_len = bytes_available_in_block.min(bytes_remaining);

        let dst = &mut out[written as usize..written as usize + copy_len];

        if uses_extents {
            let ext_opt = match cached_extent {
                Some(e) if e.contains(logical_block) => Some(e),
                _ => {
                    let fresh = extent::lookup(&inode.block, fs.dev.as_ref(), bs32, logical_block)?;
                    cached_extent = fresh;
                    fresh
                }
            };

            match ext_opt {
                None => dst.fill(0),
                Some(ext) if ext.uninitialized => dst.fill(0),
                Some(ext) => {
                    let physical_block = ext.map(logical_block);
                    let phys_byte_offset = physical_block
                        .checked_mul(block_size)
                        .and_then(|b| b.checked_add(off_in_block as u64))
                        .ok_or(Error::CorruptExtentTree("physical block offset overflow"))?;
                    fs.dev.read_at(phys_byte_offset, dst)?;
                }
            }
        } else {
            let phys_opt = indirect::lookup(
                &inode.block,
                fs.dev.as_ref(),
                bs32,
                logical_block,
                &mut indirect_cache,
            )?;
            match phys_opt {
                None => dst.fill(0),
                Some(physical_block) => {
                    let phys_byte_offset = physical_block
                        .checked_mul(block_size)
                        .and_then(|b| b.checked_add(off_in_block as u64))
                        .ok_or(Error::Corrupt("indirect: physical block offset overflow"))?;
                    fs.dev.read_at(phys_byte_offset, dst)?;
                }
            }
        }

        written += copy_len as u64;
        cur_offset += copy_len as u64;
    }

    Ok(written)
}

/// Convenience: read an entire file into a freshly-allocated Vec.
/// Caps at `inode.size` — files larger than `usize::MAX` will panic.
///
/// For inline-data files, callers should use [`read_all_with_raw`] to provide
/// the raw inode bytes (needed to read the in-inode xattr region holding
/// data overflow).
pub fn read_all(fs: &Filesystem, inode: &Inode) -> Result<Vec<u8>> {
    let size = inode.size as usize;
    let mut buf = vec![0u8; size];
    let n = read(fs, inode, 0, size as u64, &mut buf)?;
    buf.truncate(n as usize);
    Ok(buf)
}

/// Read an inline-data file. Equivalent to `read_all` but for files with
/// `EXT4_INLINE_DATA_FL` set — needs the raw on-disk inode bytes since the
/// data overflow lives in the in-inode xattr region.
pub fn read_inline(fs: &Filesystem, inode: &Inode, inode_raw: &[u8]) -> Result<Vec<u8>> {
    inline_data::read_all(
        fs.dev.as_ref(),
        inode,
        inode_raw,
        fs.sb.inode_size,
        fs.sb.block_size(),
    )
}

/// Read a range from any file (inline or extent-backed). Use this when you
/// already have the raw inode bytes (and don't want to special-case inline
/// at the call site).
pub fn read_with_raw(
    fs: &Filesystem,
    inode: &Inode,
    inode_raw: &[u8],
    offset: u64,
    length: u64,
    out: &mut [u8],
) -> Result<u64> {
    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
        let n = inline_data::read_range(
            fs.dev.as_ref(),
            inode,
            inode_raw,
            fs.sb.inode_size,
            fs.sb.block_size(),
            offset,
            out,
        )?;
        return Ok(n as u64);
    }
    read(fs, inode, offset, length, out)
}

/// Read a range from an extent-backed file with extent-tail CRC verification.
///
/// Identical to [`read`] but each off-inode extent index/leaf block traversed
/// during the lookup is CRC-verified using `(ino, inode.generation, fs.csum)`.
/// A mismatch aborts the read with `Error::BadChecksum`.
///
/// Inline-data files must use [`read_with_raw_verified`] (or the unverified
/// `read_inline`) — extent verification is meaningless without an extent tree.
pub fn read_verified(
    fs: &Filesystem,
    inode: &Inode,
    ino: u32,
    offset: u64,
    length: u64,
    out: &mut [u8],
) -> Result<u64> {
    if length == 0 || out.is_empty() {
        return Ok(0);
    }
    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
        return Err(Error::Corrupt(
            "inline-data file: caller must use file_io::read_inline with raw inode bytes",
        ));
    }
    if offset >= inode.size {
        return Ok(0);
    }
    let max_read = (inode.size - offset).min(length).min(out.len() as u64);
    if max_read == 0 {
        return Ok(0);
    }

    let block_size = fs.sb.block_size() as u64;
    let bs32 = fs.sb.block_size();
    let ctx = extent::ExtentVerifyCtx {
        ino,
        generation: inode.generation,
        csum: &fs.csum,
    };
    let uses_extents = (inode.flags & InodeFlags::EXTENTS.bits()) != 0;
    let mut written: u64 = 0;
    let mut cur_offset = offset;
    let end_offset = offset + max_read;
    let mut cached_extent: Option<extent::Extent> = None;
    let mut indirect_cache = indirect::IndirectCache::new();

    while cur_offset < end_offset {
        let logical_block = cur_offset / block_size;
        let off_in_block = (cur_offset % block_size) as usize;
        let bytes_available_in_block = block_size as usize - off_in_block;
        let bytes_remaining = (end_offset - cur_offset) as usize;
        let copy_len = bytes_available_in_block.min(bytes_remaining);
        let dst = &mut out[written as usize..written as usize + copy_len];

        if uses_extents {
            let ext_opt = match cached_extent {
                Some(e) if e.contains(logical_block) => Some(e),
                _ => {
                    let fresh = extent::lookup_verified(
                        &inode.block,
                        fs.dev.as_ref(),
                        bs32,
                        logical_block,
                        Some(&ctx),
                    )?;
                    cached_extent = fresh;
                    fresh
                }
            };

            match ext_opt {
                None => dst.fill(0),
                Some(ext) if ext.uninitialized => dst.fill(0),
                Some(ext) => {
                    let physical_block = ext.map(logical_block);
                    let phys_byte_offset = physical_block
                        .checked_mul(block_size)
                        .and_then(|b| b.checked_add(off_in_block as u64))
                        .ok_or(Error::CorruptExtentTree("physical block offset overflow"))?;
                    fs.dev.read_at(phys_byte_offset, dst)?;
                }
            }
        } else {
            // ext2/ext3 (or ext4 inode without EXTENTS_FL): no extent-block
            // CRCs to verify — there are no off-inode metadata blocks unique
            // to the indirect scheme that carry checksums. Fall back to the
            // unverified indirect lookup; the inode itself was already
            // checksum-verified by the caller.
            let phys_opt = indirect::lookup(
                &inode.block,
                fs.dev.as_ref(),
                bs32,
                logical_block,
                &mut indirect_cache,
            )?;
            match phys_opt {
                None => dst.fill(0),
                Some(physical_block) => {
                    let phys_byte_offset = physical_block
                        .checked_mul(block_size)
                        .and_then(|b| b.checked_add(off_in_block as u64))
                        .ok_or(Error::Corrupt("indirect: physical block offset overflow"))?;
                    fs.dev.read_at(phys_byte_offset, dst)?;
                }
            }
        }
        written += copy_len as u64;
        cur_offset += copy_len as u64;
    }
    Ok(written)
}

/// Read range from any file with verification of extent blocks (when the
/// file is extent-backed and `fs.csum.enabled`). Inline-data files dispatch
/// straight to `inline_data::read_range` — there's nothing to verify in that
/// path beyond the inode itself, which the caller should already have read
/// via `Filesystem::read_inode_verified`.
pub fn read_with_raw_verified(
    fs: &Filesystem,
    inode: &Inode,
    inode_raw: &[u8],
    ino: u32,
    offset: u64,
    length: u64,
    out: &mut [u8],
) -> Result<u64> {
    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
        let n = inline_data::read_range(
            fs.dev.as_ref(),
            inode,
            inode_raw,
            fs.sb.inode_size,
            fs.sb.block_size(),
            offset,
            out,
        )?;
        return Ok(n as u64);
    }
    read_verified(fs, inode, ino, offset, length, out)
}
