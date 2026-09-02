//! Path-to-inode resolution.
//!
//! Walk a slash-separated UTF-8 path from the root directory (inode 2) down to
//! a target inode number. Used by every public-facing C API function that
//! accepts a path (stat, dir_open, read_file, readlink).
//!
//! Algorithm: start at `EXT4_ROOT_INODE`, read its inode, for each non-empty
//! path component look up the entry by name in the current directory's data
//! blocks, then descend into the matching child inode.
//!
//! Phase 1 supports **linear directory scans only**. HTree-indexed directories
//! work transparently because the linear block representation is still valid —
//! htree is an acceleration on top, not a replacement. Phase 2 adds htree
//! fast-path lookups using `hash::ext4_htree_hash` once `dir::htree_lookup`
//! lands.

use crate::block_io::BlockDevice;
use crate::dir::{self, DirEntry};
use crate::error::{Error, Result};
use crate::htree;
use crate::indirect;
use crate::inode::{Inode, InodeFlags};
use crate::superblock::Superblock;

/// Root directory inode number (always 2 on every ext[234] filesystem).
pub const EXT4_ROOT_INODE: u32 = 2;

/// Resolve a slash-separated path to an inode number.
///
/// `path` is expected in the form `/a/b/c` (leading slash accepted, trailing
/// slash accepted, empty path returns the root). Non-UTF-8 bytes in directory
/// entries are compared literally.
///
/// Returns:
/// - `Ok(inode)` — inode number for the resolved path
/// - `Err(Error::NotFound)` — any component did not exist
/// - `Err(Error::NotADirectory)` — a non-dir component appeared mid-path
/// - `Err(Error::Io(..))` / other corruption errors — disk I/O or malformed data
pub fn lookup<F>(
    dev: &dyn BlockDevice,
    sb: &Superblock,
    read_inode: &mut F,
    path: &str,
) -> Result<u32>
where
    F: FnMut(u32) -> Result<Inode>,
{
    // Backwards-compatible shim — defers to `lookup_with_csum` with a
    // disabled `Checksummer` so callers that don't have one keep working
    // (verification is silently skipped).
    let csum = crate::checksum::Checksummer {
        seed: 0,
        enabled: false,
    };
    lookup_with_csum(dev, sb, read_inode, path, &csum)
}

/// Path → inode lookup with directory-block checksum verification.
///
/// Identical to `lookup`, but passes the supplied `Checksummer` down to
/// `find_entry` so each directory block's CRC32C tail is verified
/// (when present and `csum.enabled`). Callers with a mounted `Filesystem`
/// should pass `&fs.csum`.
pub fn lookup_with_csum<F>(
    dev: &dyn BlockDevice,
    sb: &Superblock,
    read_inode: &mut F,
    path: &str,
    csum: &crate::checksum::Checksummer,
) -> Result<u32>
where
    F: FnMut(u32) -> Result<Inode>,
{
    let components = split_path(path);
    let mut current_ino: u32 = EXT4_ROOT_INODE;

    for name in components {
        let inode = read_inode(current_ino)?;
        if !inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        current_ino = find_entry(dev, sb, current_ino, &inode, name.as_bytes(), csum)?;
    }

    Ok(current_ino)
}

/// Read one directory's entries and return the inode number matching `name`.
///
/// Routes through the htree fast path when the directory has the
/// `EXT4_INDEX_FL` flag, falling back to a full linear scan otherwise.
fn find_entry(
    dev: &dyn BlockDevice,
    sb: &Superblock,
    dir_ino: u32,
    dir_inode: &Inode,
    name: &[u8],
    csum: &crate::checksum::Checksummer,
) -> Result<u32> {
    // Both extent-backed and legacy direct/indirect-backed directories are
    // supported here — `find_entry_linear` and `find_entry_htree` use
    // `indirect::map_logical_any` for flavor-aware logical→physical mapping.
    if dir_inode.has_inline_data() {
        return find_inline(dir_inode, name);
    }

    let has_filetype = sb.feature_incompat & crate::features::Incompat::FILETYPE.bits() != 0;
    let block_size = sb.block_size();

    // HTree fast path: indexed directories (EXT4_INDEX_FL = 0x1000).
    if (dir_inode.flags & InodeFlags::INDEX.bits()) != 0 {
        if let Some(found) =
            find_entry_htree(dev, sb, dir_ino, dir_inode, name, has_filetype, csum)?
        {
            return Ok(found);
        }
        // htree said "not in expected leaf" — fall through to a full linear
        // scan as a safety net (covers edge cases / corruption).
    }

    find_entry_linear(
        dev,
        sb,
        dir_ino,
        dir_inode,
        name,
        has_filetype,
        block_size,
        csum,
    )
}

/// Linear scan of every directory data block.
#[allow(clippy::too_many_arguments)]
fn find_entry_linear(
    dev: &dyn BlockDevice,
    _sb: &Superblock,
    dir_ino: u32,
    dir_inode: &Inode,
    name: &[u8],
    has_filetype: bool,
    block_size: u32,
    csum: &crate::checksum::Checksummer,
) -> Result<u32> {
    let dir_size = dir_inode.size;
    let total_blocks = dir_size.div_ceil(block_size as u64);
    let gen = dir_inode.generation;

    let mut block = vec![0u8; block_size as usize];
    for logical in 0..total_blocks {
        let phys = match indirect::map_logical_any(
            &dir_inode.block,
            dir_inode.flags,
            dev,
            block_size,
            logical,
        )? {
            Some(p) => p,
            None => continue,
        };
        dev.read_at(phys * block_size as u64, &mut block)?;

        // The first block of an indexed dir is the dx_root and *cannot* be
        // parsed as linear entries (its contents after "." and ".." are
        // dx_entry records, not dir entries). Skip parse errors there.
        match dir::parse_block_verified(&block, has_filetype, dir_ino, gen, csum) {
            Ok(entries) => {
                for entry in entries {
                    if entry.name == name {
                        return Ok(entry.inode);
                    }
                }
            }
            Err(_) if logical == 0 && (dir_inode.flags & InodeFlags::INDEX.bits()) != 0 => {
                // dx_root in an indexed dir — only "." and ".." matter here,
                // and find_entry_htree already handled the indexed path.
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(Error::NotFound)
}

/// HTree-indexed lookup. Returns:
///   Ok(Some(ino)) — found
///   Ok(None)      — htree said not in any leaf (caller may fall back)
///   Err(..)       — corruption or I/O error
fn find_entry_htree(
    dev: &dyn BlockDevice,
    sb: &Superblock,
    dir_ino: u32,
    dir_inode: &Inode,
    name: &[u8],
    has_filetype: bool,
    csum: &crate::checksum::Checksummer,
) -> Result<Option<u32>> {
    let block_size = sb.block_size();

    // Read logical block 0 of the directory: the dx_root. Flavor-aware
    // dispatch — htree directories on ext2/3 (rare but legal) use the
    // legacy block-map scheme, not extents.
    let phys0 =
        match indirect::map_logical_any(&dir_inode.block, dir_inode.flags, dev, block_size, 0)? {
            Some(p) => p,
            None => return Ok(None),
        };
    let mut root_block = vec![0u8; block_size as usize];
    dev.read_at(phys0 * block_size as u64, &mut root_block)?;

    // Walk the htree. lookup_leaf needs a closure for reading further dx
    // blocks (intermediate nodes); we map logical→physical via whichever
    // block-map scheme the dir's inode uses.
    let read_dx_block = |logical: u32| -> Result<Vec<u8>> {
        let phys = indirect::map_logical_any(
            &dir_inode.block,
            dir_inode.flags,
            dev,
            block_size,
            logical as u64,
        )?
        .ok_or(Error::CorruptDirEntry("htree pointed at sparse block"))?;
        let mut buf = vec![0u8; block_size as usize];
        dev.read_at(phys * block_size as u64, &mut buf)?;
        Ok(buf)
    };

    let leaf_logical = match htree::lookup_leaf(name, &root_block, &sb.hash_seed, read_dx_block)? {
        Some(b) => b,
        None => return Ok(None),
    };

    // Read the leaf block and linear-scan it for the name.
    let phys = indirect::map_logical_any(
        &dir_inode.block,
        dir_inode.flags,
        dev,
        block_size,
        leaf_logical as u64,
    )?
    .ok_or(Error::CorruptDirEntry("htree leaf at sparse block"))?;
    let mut leaf = vec![0u8; block_size as usize];
    dev.read_at(phys * block_size as u64, &mut leaf)?;

    // Verify the leaf block's csum tail (if present) before scanning.
    if csum.enabled
        && dir::has_csum_tail(&leaf)
        && !csum.verify_dir_entry_tail(dir_ino, dir_inode.generation, &leaf)
    {
        return Err(Error::BadChecksum {
            what: "directory block",
        });
    }

    for entry in dir::DirBlockIter::new(&leaf, has_filetype) {
        let entry: DirEntry = entry?;
        if entry.name == name {
            return Ok(Some(entry.inode));
        }
    }

    // Name not in the htree-selected leaf. Could be hash collision spilling
    // to neighbouring leaf — caller will fall back to linear scan.
    Ok(None)
}

/// Handle directories whose entries live inline in i_block + inline xattrs.
/// For tiny directories ext4 stores the entries directly inside the inode
/// (INLINE_DATA feature). We only handle the i_block portion for now; the
/// xattr-side continuation is rare and will be added with xattr support.
fn find_inline(dir_inode: &Inode, name: &[u8]) -> Result<u32> {
    // Inline-data dirs reuse the 60-byte i_block area. Entries start
    // at offset 0 with the same on-disk format as normal dir blocks,
    // but with a smaller buffer.
    for entry in dir::DirBlockIter::new(&dir_inode.block, /* has_filetype */ true) {
        let entry = entry?;
        if entry.name == name {
            return Ok(entry.inode);
        }
    }
    Err(Error::NotFound)
}

/// Split "/foo/bar/baz" into ["foo", "bar", "baz"]. Empty components (from
/// doubled slashes or leading/trailing slashes) are dropped.
fn split_path(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgd;
    use crate::block_io::FileDevice;
    use crate::extent;
    use crate::fs::Filesystem;
    use std::sync::Arc;

    #[test]
    fn split_path_basic() {
        assert_eq!(split_path(""), Vec::<&str>::new());
        assert_eq!(split_path("/"), Vec::<&str>::new());
        assert_eq!(split_path("/foo"), vec!["foo"]);
        assert_eq!(split_path("/foo/bar"), vec!["foo", "bar"]);
        assert_eq!(split_path("foo/bar"), vec!["foo", "bar"]);
        assert_eq!(split_path("/foo//bar/"), vec!["foo", "bar"]);
        assert_eq!(split_path("///"), Vec::<&str>::new());
    }

    /// Build a read_inode closure that reads raw bytes via Filesystem and
    /// parses them through Inode::parse.
    fn read_inode_fn(fs: &Filesystem) -> impl FnMut(u32) -> Result<Inode> + '_ {
        move |ino: u32| {
            let (block, offset) = bgd::locate_inode(&fs.sb, &fs.groups, ino)?;
            let block_data = fs.read_block(block)?;
            let inode_size = fs.sb.inode_size as usize;
            let off = offset as usize;
            Inode::parse(&block_data[off..off + inode_size])
        }
    }

    #[test]
    fn root_resolves_to_inode_2() {
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
        let mut reader = read_inode_fn(&fs);

        for root_path in ["/", "", "///"] {
            let ino = lookup(dev.as_ref(), &fs.sb, &mut reader, root_path)
                .unwrap_or_else(|e| panic!("lookup({root_path:?}) failed: {e}"));
            assert_eq!(ino, EXT4_ROOT_INODE, "path {root_path:?}");
        }
    }

    #[test]
    fn missing_path_returns_not_found() {
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
        let mut reader = read_inode_fn(&fs);

        let result = lookup(
            dev.as_ref(),
            &fs.sb,
            &mut reader,
            "/this-does-not-exist-xyz",
        );
        assert!(matches!(result, Err(Error::NotFound)), "got {result:?}");
    }

    #[test]
    fn non_dir_component_returns_not_a_directory() {
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
        let mut reader = read_inode_fn(&fs);

        // Find any regular file in root so we can stack a component after it.
        let root = reader(EXT4_ROOT_INODE).expect("root inode");
        let block_size = fs.sb.block_size();
        let total_blocks = root.size.div_ceil(block_size as u64);
        let has_filetype = fs.sb.feature_incompat & crate::features::Incompat::FILETYPE.bits() != 0;

        let mut reg_file_name: Option<Vec<u8>> = None;
        'outer: for logical in 0..total_blocks {
            if let Some(phys) = extent::map_logical(&root.block, dev.as_ref(), block_size, logical)
                .expect("map logical")
            {
                let mut blk = vec![0u8; block_size as usize];
                dev.read_at(phys * block_size as u64, &mut blk).unwrap();
                for entry in dir::DirBlockIter::new(&blk, has_filetype) {
                    let e = entry.expect("entry");
                    if e.file_type == dir::DirEntryType::RegFile {
                        reg_file_name = Some(e.name);
                        break 'outer;
                    }
                }
            }
        }

        let Some(name) = reg_file_name else {
            eprintln!("skip: no regular file in root of ext4-basic.img");
            return;
        };
        let name_str = std::str::from_utf8(&name).expect("name utf8");
        let bad_path = format!("/{name_str}/child");

        let result = lookup(dev.as_ref(), &fs.sb, &mut reader, &bad_path);
        assert!(
            matches!(result, Err(Error::NotADirectory)),
            "got {result:?} for path {bad_path}"
        );
    }
}
