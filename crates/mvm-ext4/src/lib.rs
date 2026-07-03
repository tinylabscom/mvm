//! Minimal, memory-safe, deterministic **ext4 image writer** for read-only
//! microVM rootfs materialization — no `mkfs`, no builder VM, no subprocess.
//!
//! # Why this exists
//!
//! Materializing an OCI rootfs used to boot a builder VM and shell
//! `mkfs.ext4 + cp` inside it. This crate builds the ext4 image in-process, in
//! pure safe Rust, so the run path never shells out. Its output feeds dm-verity
//! (integrity, claim 3), so it is **deterministic by construction** (fixed inode
//! order, zeroed timestamps, sequential allocation) and **memory-safe by
//! construction** (`#![forbid(unsafe_code)]` — a bug is at worst a returned
//! error or a caught panic, never host memory corruption).
//!
//! # Scope (deliberately minimal)
//!
//! Read-only rootfs only: **extents + filetype**, **no journal**, **no
//! metadata_csum**, **no htree**, **fast symlinks**. That is a valid ext4 that
//! real readers (and the Linux kernel) mount; integrity comes from verity, not
//! from in-filesystem checksums. The unused ~80% of a full ext4 (journaling,
//! casefold, ACL, fsck) is intentionally absent — it would only be attack
//! surface. Single block group for now (≤128 MiB at 4 KiB blocks); multi-group
//! is a mechanical follow-up.
//!
//! Correctness is validated by reading the output back through an independent
//! ext4 reader (`am-fs-ext4`, a dev-only test oracle) and, in CI, by mounting it
//! on Linux.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub const BLOCK_SIZE: u32 = 4096;
const INODE_SIZE: u16 = 256;
const EXT4_MAGIC: u16 = 0xEF53;
const ROOT_INO: u32 = 2;
const FIRST_INO: u32 = 11;
const EXTENT_MAGIC: u16 = 0xF30A;
const EXTENTS_FL: u32 = 0x0008_0000;
const INCOMPAT_FILETYPE_EXTENTS: u32 = 0x2 | 0x40;
const MAX_BLOCKS_PER_GROUP: u32 = BLOCK_SIZE * 8; // 32768 at 4 KiB

// File-type byte in a directory entry (ext4 filetype feature).
const FT_FILE: u8 = 1;
const FT_DIR: u8 = 2;
const FT_SYMLINK: u8 = 7;

// Mode type bits.
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

/// Error building an image. All variants are recoverable (no panics on
/// caller-influenced input).
#[derive(Debug)]
pub enum Ext4Error {
    /// The tree does not fit in a single block group (≤128 MiB at 4 KiB).
    TooLarge { blocks: u64 },
    /// A node's parent directory was not present in the input.
    MissingParent(String),
    /// A path was empty or not rooted at `/`.
    BadPath(String),
    /// A directory's entries did not fit the single-block assumption.
    DirTooLarge(String),
}

impl std::fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ext4Error::TooLarge { blocks } => {
                write!(
                    f,
                    "image needs {blocks} blocks; single block group holds at most {MAX_BLOCKS_PER_GROUP}"
                )
            }
            Ext4Error::MissingParent(p) => {
                write!(f, "node {p} has no parent directory in the input")
            }
            Ext4Error::BadPath(p) => write!(f, "bad path {p:?} (must be absolute)"),
            Ext4Error::DirTooLarge(p) => {
                write!(f, "directory {p} has too many entries for one block")
            }
        }
    }
}

impl std::error::Error for Ext4Error {}

/// A filesystem node to place in the image. Paths are absolute (`/`-rooted);
/// `/` (the root) is implicit and always present.
#[derive(Debug, Clone)]
pub enum Node {
    Dir {
        path: String,
        mode: u16,
    },
    File {
        path: String,
        mode: u16,
        data: Vec<u8>,
    },
    Symlink {
        path: String,
        target: String,
    },
}

impl Node {
    fn path(&self) -> &str {
        match self {
            Node::Dir { path, .. } | Node::File { path, .. } | Node::Symlink { path, .. } => path,
        }
    }
}

/// A little-endian byte writer over a fixed image buffer. Bounds-checked by
/// `Vec`/slice indexing (a bug returns/panics, never corrupts memory).
struct Image {
    bytes: Vec<u8>,
}

impl Image {
    fn new(blocks: u32) -> Self {
        Self {
            bytes: vec![0u8; blocks as usize * BLOCK_SIZE as usize],
        }
    }
    fn put_u16(&mut self, off: usize, v: u16) {
        self.bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, off: usize, v: u32) {
        self.bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_bytes(&mut self, off: usize, v: &[u8]) {
        self.bytes[off..off + v.len()].copy_from_slice(v);
    }
    fn block_off(&self, block: u32) -> usize {
        block as usize * BLOCK_SIZE as usize
    }
}

// A planned inode: its number, kind, and the data blocks assigned to it.
struct Planned {
    ino: u32,
    kind: Kind,
    mode: u16,
    parent: u32,
    // Data blocks (contiguous) assigned; empty for fast symlinks.
    first_block: u32,
    block_count: u32,
    size: u64,
    // File contents / symlink target for the emit pass.
    data: Vec<u8>,
    symlink_target: Option<String>,
    // Directory children: (name, child_ino, child_ft). Filled after planning.
    children: Vec<(String, u32, u8)>,
    links: u16,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Dir,
    File,
    Symlink,
}

/// Build a deterministic read-only ext4 image containing `nodes` (plus the
/// implicit root directory). Returns the raw image bytes.
pub fn build_image(nodes: &[Node]) -> Result<Vec<u8>, Ext4Error> {
    // 1. Deterministic order: sort by path so inode numbers + block layout are
    //    a pure function of the input set.
    let mut sorted: Vec<&Node> = nodes.iter().collect();
    sorted.sort_by(|a, b| a.path().cmp(b.path()));

    // 2. Assign inode numbers: root=2, then FIRST_INO.. in sorted order.
    let mut ino_of: BTreeMap<String, u32> = BTreeMap::new();
    ino_of.insert("/".to_string(), ROOT_INO);
    let mut next = FIRST_INO;
    for n in &sorted {
        let p = normalize(n.path())?;
        ino_of.insert(p, next);
        next += 1;
    }
    let inode_count = next; // inodes 0..next-1 exist conceptually; we size for `next`.

    // 3. Build planned inodes (root first).
    let mut planned: Vec<Planned> = Vec::new();
    planned.push(Planned {
        ino: ROOT_INO,
        kind: Kind::Dir,
        mode: S_IFDIR | 0o755,
        parent: ROOT_INO,
        first_block: 0,
        block_count: 0,
        size: 0,
        data: Vec::new(),
        symlink_target: None,
        children: Vec::new(),
        links: 2,
    });
    for n in &sorted {
        let p = normalize(n.path())?;
        let ino = ino_of[&p];
        let parent_path = parent_of(&p);
        let parent_ino = *ino_of
            .get(&parent_path)
            .ok_or_else(|| Ext4Error::MissingParent(p.clone()))?;
        let (kind, mode, data, symlink_target, size) = match n {
            Node::Dir { mode, .. } => {
                (Kind::Dir, S_IFDIR | (mode & 0o7777), Vec::new(), None, 0u64)
            }
            Node::File { mode, data, .. } => (
                Kind::File,
                S_IFREG | (mode & 0o7777),
                data.clone(),
                None,
                data.len() as u64,
            ),
            Node::Symlink { target, .. } => (
                Kind::Symlink,
                S_IFLNK | 0o777,
                Vec::new(),
                Some(target.clone()),
                target.len() as u64,
            ),
        };
        planned.push(Planned {
            ino,
            kind,
            mode,
            parent: parent_ino,
            first_block: 0,
            block_count: 0,
            size,
            data,
            symlink_target,
            children: Vec::new(),
            links: if kind == Kind::Dir { 2 } else { 1 },
        });
    }

    // 4. Wire directory children + link counts. A dir's link count is
    //    2 (self "." + its entry in the parent) + one per child directory
    //    (each child's ".."). Order children by name for determinism.
    let index: BTreeMap<u32, usize> = planned
        .iter()
        .enumerate()
        .map(|(i, p)| (p.ino, i))
        .collect();
    // Collect (parent_ino, name, child_ino, ft) first to avoid borrow conflicts.
    let mut child_edges: Vec<(u32, String, u32, u8)> = Vec::new();
    for n in &sorted {
        let p = normalize(n.path())?;
        let ino = ino_of[&p];
        let parent_ino = *ino_of.get(&parent_of(&p)).unwrap();
        let name = leaf_name(&p);
        let ft = match n {
            Node::Dir { .. } => FT_DIR,
            Node::File { .. } => FT_FILE,
            Node::Symlink { .. } => FT_SYMLINK,
        };
        child_edges.push((parent_ino, name, ino, ft));
    }
    for (parent_ino, name, child_ino, ft) in child_edges {
        let pi = index[&parent_ino];
        planned[pi].children.push((name, child_ino, ft));
        if ft == FT_DIR {
            planned[pi].links += 1;
        }
    }
    for p in planned.iter_mut() {
        p.children.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // 5. Compute data blocks per node.
    let mut data_blocks_total: u64 = 0;
    for p in planned.iter_mut() {
        let nblocks = match p.kind {
            Kind::Dir => {
                // "." + ".." + children must fit one block (single-block dirs).
                let need = dir_bytes(&p.children);
                if need > BLOCK_SIZE as usize {
                    return Err(Ext4Error::DirTooLarge(format!("ino {}", p.ino)));
                }
                p.size = BLOCK_SIZE as u64;
                1
            }
            Kind::File => p.size.div_ceil(BLOCK_SIZE as u64) as u32,
            Kind::Symlink => {
                // Fast symlink: target ≤ 60 bytes lives in i_block, no data block.
                if p.size <= 60 {
                    0
                } else {
                    p.size.div_ceil(BLOCK_SIZE as u64) as u32
                }
            }
        };
        p.block_count = nblocks;
        data_blocks_total += nblocks as u64;
    }

    // 6. Fixed metadata layout (single group, 4 KiB blocks):
    //    block 0: superblock, 1: GDT, 2: block bitmap, 3: inode bitmap,
    //    4..4+itb: inode table, then data blocks.
    let inode_table_blocks =
        (inode_count as u64 * INODE_SIZE as u64).div_ceil(BLOCK_SIZE as u64) as u32;
    let first_data_block = 4 + inode_table_blocks;
    let total_blocks_u64 = first_data_block as u64 + data_blocks_total;
    if total_blocks_u64 > MAX_BLOCKS_PER_GROUP as u64 {
        return Err(Ext4Error::TooLarge {
            blocks: total_blocks_u64,
        });
    }
    let total_blocks = total_blocks_u64 as u32;

    // 7. Allocate data blocks sequentially in inode order.
    let mut cursor = first_data_block;
    for p in planned.iter_mut() {
        if p.block_count > 0 {
            p.first_block = cursor;
            cursor += p.block_count;
        }
    }

    // 8. Emit.
    let mut img = Image::new(total_blocks);
    let block_bitmap_block = 2u32;
    let inode_bitmap_block = 3u32;
    let inode_table_block = 4u32;

    write_superblock(
        &mut img,
        total_blocks,
        inode_count,
        first_data_block,
        &planned,
    );
    write_group_desc(
        &mut img,
        block_bitmap_block,
        inode_bitmap_block,
        inode_table_block,
        total_blocks,
        first_data_block,
        inode_count,
        &planned,
    );
    write_block_bitmap(&mut img, block_bitmap_block, total_blocks);
    write_inode_bitmap(&mut img, inode_bitmap_block, inode_count);

    for p in &planned {
        write_inode(&mut img, inode_table_block, p);
        match p.kind {
            Kind::Dir => write_dir_block(&mut img, p),
            Kind::File => write_file_blocks(&mut img, p),
            Kind::Symlink => {
                if p.block_count > 0 {
                    // Long symlink: target in a data block.
                    let off = img.block_off(p.first_block);
                    let t = p.symlink_target.clone().unwrap_or_default();
                    img.put_bytes(off, t.as_bytes());
                }
            }
        }
    }

    Ok(img.bytes)
}

fn dir_bytes(children: &[(String, u32, u8)]) -> usize {
    // "." (12) + ".." (12) + each child rounded to 4.
    let mut n = 12 + 12;
    for (name, _, _) in children {
        n += dirent_len(name.len());
    }
    n
}

fn dirent_len(name_len: usize) -> usize {
    // 8-byte header + name, rounded up to 4.
    (8 + name_len + 3) & !3
}

fn write_superblock(
    img: &mut Image,
    total_blocks: u32,
    inode_count: u32,
    first_data_block: u32,
    planned: &[Planned],
) {
    let sb = 1024usize;
    let used_blocks = first_data_block + planned.iter().map(|p| p.block_count).sum::<u32>();
    let free_blocks = total_blocks - used_blocks;
    let free_inodes = inode_count.saturating_sub(reserved_plus_used(planned));

    img.put_u32(sb, inode_count);
    img.put_u32(sb + 0x04, total_blocks);
    img.put_u32(sb + 0x0C, free_blocks);
    img.put_u32(sb + 0x10, free_inodes);
    img.put_u32(sb + 0x14, 0); // first_data_block (0 for 4 KiB)
    img.put_u32(sb + 0x18, 2); // log_block_size: 1024<<2 = 4096
    img.put_u32(sb + 0x1C, 2); // log_cluster_size
    img.put_u32(sb + 0x20, MAX_BLOCKS_PER_GROUP); // blocks_per_group
    img.put_u32(sb + 0x24, MAX_BLOCKS_PER_GROUP); // clusters_per_group
    img.put_u32(sb + 0x28, inode_count); // inodes_per_group (single group)
    img.put_u16(sb + 0x38, EXT4_MAGIC);
    img.put_u16(sb + 0x3A, 1); // state: cleanly unmounted
    img.put_u16(sb + 0x3C, 1); // errors: continue
    img.put_u16(sb + 0x36, 0xFFFF); // max_mnt_count = -1
    img.put_u32(sb + 0x4C, 1); // rev_level: dynamic
    img.put_u32(sb + 0x54, FIRST_INO); // first_ino
    img.put_u16(sb + 0x58, INODE_SIZE); // inode_size
    img.put_u16(sb + 0x5A, 0); // block_group_nr
    img.put_u32(sb + 0x60, INCOMPAT_FILETYPE_EXTENTS); // feature_incompat
    // UUID + volume name left zero for determinism.
}

fn reserved_plus_used(planned: &[Planned]) -> u32 {
    // Inodes 1..=10 are reserved; our nodes occupy 2 and FIRST_INO.. .
    // Free = inode_count - (reserved_used + node_count). Root (2) is within the
    // reserved range, so count reserved as 10 and add non-root nodes.
    let non_root = planned.iter().filter(|p| p.ino >= FIRST_INO).count() as u32;
    10 + non_root
}

#[allow(clippy::too_many_arguments)]
fn write_group_desc(
    img: &mut Image,
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    total_blocks: u32,
    first_data_block: u32,
    inode_count: u32,
    planned: &[Planned],
) {
    let gd = img.block_off(1); // GDT at block 1
    img.put_u32(gd, block_bitmap);
    img.put_u32(gd + 0x04, inode_bitmap);
    img.put_u32(gd + 0x08, inode_table);
    let used_blocks = first_data_block + planned.iter().map(|p| p.block_count).sum::<u32>();
    let free_blocks = (total_blocks - used_blocks) as u16;
    let free_inodes = inode_count.saturating_sub(reserved_plus_used(planned)) as u16;
    let used_dirs = planned.iter().filter(|p| p.kind == Kind::Dir).count() as u16;
    img.put_u16(gd + 0x0C, free_blocks);
    img.put_u16(gd + 0x0E, free_inodes);
    img.put_u16(gd + 0x10, used_dirs);
}

fn write_block_bitmap(img: &mut Image, bitmap_block: u32, _total_blocks: u32) {
    let base = img.block_off(bitmap_block);
    // A sized-to-fit read-only image has no free space: every block we laid out
    // is in use, and the bitmap bits past the image end (up to blocks_per_group)
    // are marked used as padding. So the whole bitmap is 1s.
    for b in 0..MAX_BLOCKS_PER_GROUP {
        set_bit(&mut img.bytes, base, b as usize);
    }
}

fn write_inode_bitmap(img: &mut Image, bitmap_block: u32, inode_count: u32) {
    let base = img.block_off(bitmap_block);
    // Inodes are 1-based; bit i = inode i+1. Mark 1..=inode_count used, and pad
    // the rest of the group's inode range used.
    for i in 0..inode_count {
        set_bit(&mut img.bytes, base, i as usize);
    }
}

fn set_bit(bytes: &mut [u8], base: usize, bit: usize) {
    bytes[base + bit / 8] |= 1u8 << (bit % 8);
}

fn write_inode(img: &mut Image, inode_table_block: u32, p: &Planned) {
    let off = img.block_off(inode_table_block) + (p.ino as usize - 1) * INODE_SIZE as usize;
    img.put_u16(off, p.mode);
    img.put_u16(off + 0x02, 0); // uid
    img.put_u32(off + 0x04, (p.size & 0xFFFF_FFFF) as u32); // size_lo
    // atime/ctime/mtime/dtime = 0 (determinism).
    img.put_u16(off + 0x1A, p.links);
    let sectors = p.block_count * (BLOCK_SIZE / 512);
    img.put_u32(off + 0x1C, sectors); // i_blocks_lo
    img.put_u16(off + 0x80, 32); // i_extra_isize

    match p.kind {
        Kind::Symlink if p.block_count == 0 => {
            // Fast symlink: raw target in i_block, no extents flag.
            let target = p.symlink_target.clone().unwrap_or_default();
            img.put_bytes(off + 0x28, target.as_bytes());
        }
        _ => {
            // Extents: header + one contiguous extent (dirs = 1 block; files =
            // block_count blocks starting at first_block).
            img.put_u32(off + 0x20, EXTENTS_FL);
            let eh = off + 0x28;
            img.put_u16(eh, EXTENT_MAGIC);
            img.put_u16(eh + 0x02, if p.block_count > 0 { 1 } else { 0 }); // entries
            img.put_u16(eh + 0x04, 4); // max inline
            img.put_u16(eh + 0x06, 0); // depth (leaf)
            img.put_u32(eh + 0x08, 0); // generation
            if p.block_count > 0 {
                let ee = eh + 12;
                img.put_u32(ee, 0); // logical block 0
                img.put_u16(ee + 0x04, p.block_count as u16); // len
                img.put_u16(ee + 0x06, 0); // start_hi
                img.put_u32(ee + 0x08, p.first_block); // start_lo
            }
        }
    }
}

fn write_dir_block(img: &mut Image, p: &Planned) {
    let base = img.block_off(p.first_block);
    let mut pos = 0usize;
    // "." -> self
    pos += put_dirent(img, base + pos, p.ino, ".", FT_DIR, false);
    // ".." -> parent
    let dotdot_last = p.children.is_empty();
    pos += put_dirent(img, base + pos, p.parent, "..", FT_DIR, dotdot_last);
    for (i, (name, child, ft)) in p.children.iter().enumerate() {
        let last = i + 1 == p.children.len();
        pos += put_dirent(img, base + pos, *child, name, *ft, last);
    }
}

/// Write a directory entry; if `last`, its rec_len spans to the block end.
/// Returns the rec_len consumed.
fn put_dirent(img: &mut Image, off: usize, ino: u32, name: &str, ft: u8, last: bool) -> usize {
    let block_start = off - (off % BLOCK_SIZE as usize);
    let used = off - block_start;
    let rec_len = if last {
        BLOCK_SIZE as usize - used
    } else {
        dirent_len(name.len())
    };
    img.put_u32(off, ino);
    img.put_u16(off + 0x04, rec_len as u16);
    img.bytes[off + 0x06] = name.len() as u8;
    img.bytes[off + 0x07] = ft;
    img.put_bytes(off + 0x08, name.as_bytes());
    rec_len
}

fn write_file_blocks(img: &mut Image, p: &Planned) {
    if p.block_count == 0 {
        return;
    }
    let off = img.block_off(p.first_block);
    img.put_bytes(off, &p.data);
}

// ── path helpers ────────────────────────────────────────────────────────────

fn normalize(path: &str) -> Result<String, Ext4Error> {
    if !path.starts_with('/') {
        return Err(Ext4Error::BadPath(path.to_string()));
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => "/".to_string(),
    }
}

fn leaf_name(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[i + 1..].to_string(),
        None => path.to_string(),
    }
}
