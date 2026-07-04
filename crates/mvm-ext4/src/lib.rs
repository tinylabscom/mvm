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
//! surface.
//!
//! Images span **multiple block groups**, so total size is not capped at one
//! group's 128 MiB (at 4 KiB blocks): the layout is uniform per group (a
//! superblock + group-descriptor-table backup, then bitmaps and the inode
//! table, then data), and file data is allocated as extents across each group's
//! data region. A single file that would fragment into more than the four
//! inline extents an inode holds is rejected (an extent-tree interior node is a
//! future addition); the common rootfs — many modest files — needs one or a few
//! extents each.
//!
//! Correctness is validated by reading the output back through an independent
//! ext4 reader (`am-fs-ext4`, a dev-only test oracle) and, in CI, by mounting
//! it on Linux (both a single-group and a multi-group image).

#![forbid(unsafe_code)]

pub mod verity;

use std::collections::BTreeMap;

pub const BLOCK_SIZE: u32 = 4096;
const INODE_SIZE: u16 = 256;
const EXT4_MAGIC: u16 = 0xEF53;
const ROOT_INO: u32 = 2;
const FIRST_INO: u32 = 11;
const EXTENT_MAGIC: u16 = 0xF30A;
const EXTENTS_FL: u32 = 0x0008_0000;
const INCOMPAT_FILETYPE_EXTENTS: u32 = 0x2 | 0x40;
const BLOCKS_PER_GROUP: u32 = BLOCK_SIZE * 8; // 32768 at 4 KiB (block-bitmap bound)
// Inodes are floored at 16 per group so the inode table is a whole block and
// the reserved inodes (1..=10) + root live in group 0.
const MIN_INODES_PER_GROUP: u32 = 16;
// Sanity ceiling on group count: 4096 groups × 128 MiB ≈ 512 GiB, far past any
// rootfs. Hitting it means a pathologically large input, not a real image.
const MAX_GROUPS: u32 = 4096;
// An inode holds four extent entries inline (no extent-tree interior node yet).
const MAX_INLINE_EXTENTS: usize = 4;

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
    /// The image would need more block groups than the sanity ceiling allows.
    TooLarge { blocks: u64 },
    /// A single file fragments into more extents than fit inline in an inode
    /// (an extent-tree interior node is not yet implemented).
    FileTooFragmented { ino: u32, extents: usize },
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
                    "image needs {blocks} blocks, exceeding the {MAX_GROUPS}-group ceiling"
                )
            }
            Ext4Error::FileTooFragmented { ino, extents } => write!(
                f,
                "inode {ino} needs {extents} extents; only {MAX_INLINE_EXTENTS} fit inline \
                 (extent-tree interior nodes are not yet supported)"
            ),
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

/// One contiguous run of physical blocks backing a logical range of a file
/// (or the single block of a directory / long symlink). `len` is in blocks and
/// never exceeds a group's data region, so it always fits ext4's 15-bit
/// initialized-extent length.
#[derive(Debug, Clone, Copy)]
struct Extent {
    logical: u32,
    len: u32,
    phys: u32,
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
    // Physical extents backing this inode's data; empty for fast symlinks and
    // the (never-materialized) empty root. Directories carry exactly one.
    extents: Vec<Extent>,
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

/// Resolved on-disk geometry: how many block groups, where each group's
/// metadata and data live, and how inodes map to groups. Every field is a pure
/// function of `(inode_high, data_blocks_total)`, so the layout — and thus the
/// image bytes — are deterministic.
struct Layout {
    groups: u32,
    inodes_per_group: u32,
    gdt_blocks: u32,
    /// Metadata blocks at the start of every group: 1 (superblock/backup) +
    /// gdt_blocks + 1 (block bitmap) + 1 (inode bitmap) + inode-table blocks.
    prefix: u32,
    total_blocks: u32,
    inode_slots: u32,
    /// Highest inode number in use (inodes `1..=used_inodes` are all occupied:
    /// the reserved 1..=10, root at 2, then our nodes contiguously).
    used_inodes: u32,
}

impl Layout {
    fn plan(inode_high: u32, data_blocks_total: u64) -> Result<Self, Ext4Error> {
        let used_inodes = inode_high.saturating_sub(1);
        for groups in 1..=MAX_GROUPS {
            let gdt_blocks = ceil_div_u32(groups.saturating_mul(32), BLOCK_SIZE);
            let per_group_need = ceil_div_u32(inode_high, groups).max(MIN_INODES_PER_GROUP);
            let inodes_per_group = round_up_8(per_group_need);
            let itb_per_group = ceil_div_u32(inodes_per_group * INODE_SIZE as u32, BLOCK_SIZE);
            let prefix = 3 + gdt_blocks + itb_per_group;
            // A group whose metadata leaves no room for data can't help; a
            // larger group count shrinks inodes_per_group and thus the prefix.
            if prefix >= BLOCKS_PER_GROUP {
                continue;
            }
            let data_per_group = (BLOCKS_PER_GROUP - prefix) as u64;
            let capacity = groups as u64 * data_per_group;
            if capacity < data_blocks_total {
                continue;
            }
            // Trim the final group to exactly the data it holds so the image is
            // no larger than the tree needs (verity hashes every byte).
            let full_groups = (groups - 1) as u64;
            let last_data = data_blocks_total - full_groups * data_per_group; // >= 1
            let total = full_groups * BLOCKS_PER_GROUP as u64 + prefix as u64 + last_data;
            if total > u32::MAX as u64 {
                break;
            }
            return Ok(Self {
                groups,
                inodes_per_group,
                gdt_blocks,
                prefix,
                total_blocks: total as u32,
                inode_slots: inodes_per_group * groups,
                used_inodes,
            });
        }
        Err(Ext4Error::TooLarge {
            blocks: data_blocks_total,
        })
    }

    fn group_start(&self, g: u32) -> u32 {
        g * BLOCKS_PER_GROUP
    }
    fn block_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 1 + self.gdt_blocks
    }
    fn inode_bitmap(&self, g: u32) -> u32 {
        self.group_start(g) + 2 + self.gdt_blocks
    }
    fn inode_table(&self, g: u32) -> u32 {
        self.group_start(g) + 3 + self.gdt_blocks
    }
    fn data_start(&self, g: u32) -> u32 {
        self.group_start(g) + self.prefix
    }
    fn group_end(&self, g: u32) -> u32 {
        ((g + 1) * BLOCKS_PER_GROUP).min(self.total_blocks)
    }
    /// `(group, local index)` of an inode number (1-based).
    fn locate_inode(&self, ino: u32) -> (u32, u32) {
        (
            (ino - 1) / self.inodes_per_group,
            (ino - 1) % self.inodes_per_group,
        )
    }
    /// Per-group data regions, in order, that the allocator hands out.
    fn data_regions(&self) -> Vec<(u32, u32)> {
        (0..self.groups)
            .filter_map(|g| {
                let start = self.data_start(g);
                let end = self.group_end(g);
                (end > start).then_some((start, end - start))
            })
            .collect()
    }
}

/// Hands out physical blocks from each group's data region in order, splitting
/// a request into one [`Extent`] per region it spans (so no extent ever crosses
/// a group's metadata prefix).
struct RegionAllocator {
    regions: Vec<(u32, u32)>,
    ridx: usize,
    roff: u32,
}

impl RegionAllocator {
    fn new(layout: &Layout) -> Self {
        Self {
            regions: layout.data_regions(),
            ridx: 0,
            roff: 0,
        }
    }

    fn take(&mut self, blocks: u32) -> Vec<Extent> {
        let mut out = Vec::new();
        let mut logical = 0u32;
        let mut remaining = blocks;
        while remaining > 0 {
            let (start, len) = self.regions[self.ridx];
            let avail = len - self.roff;
            let n = avail.min(remaining);
            out.push(Extent {
                logical,
                len: n,
                phys: start + self.roff,
            });
            self.roff += n;
            logical += n;
            remaining -= n;
            if self.roff == len {
                self.ridx += 1;
                self.roff = 0;
            }
        }
        out
    }
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
    let inode_high = next;

    // 3. Build planned inodes (root first).
    let mut planned: Vec<Planned> = Vec::new();
    planned.push(Planned {
        ino: ROOT_INO,
        kind: Kind::Dir,
        mode: S_IFDIR | 0o755,
        parent: ROOT_INO,
        extents: Vec::new(),
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
            extents: Vec::new(),
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

    // 6. Resolve geometry (possibly many groups) from the inode + data counts.
    let layout = Layout::plan(inode_high, data_blocks_total)?;

    // 7. Allocate data blocks from the per-group regions, in inode order, as
    //    extents. Reject a file that fragments past the inline-extent limit.
    let mut alloc = RegionAllocator::new(&layout);
    for p in planned.iter_mut() {
        if p.block_count > 0 {
            let extents = alloc.take(p.block_count);
            if extents.len() > MAX_INLINE_EXTENTS {
                return Err(Ext4Error::FileTooFragmented {
                    ino: p.ino,
                    extents: extents.len(),
                });
            }
            p.extents = extents;
        }
    }

    // 8. Emit.
    let mut img = Image::new(layout.total_blocks);
    write_superblock(&mut img, &layout);
    write_group_descs(&mut img, &layout, &planned);
    write_bitmaps(&mut img, &layout);
    write_backups(&mut img, &layout);

    for p in &planned {
        write_inode(&mut img, &layout, p);
        match p.kind {
            Kind::Dir => write_dir_block(&mut img, p),
            Kind::File => write_file_blocks(&mut img, p),
            Kind::Symlink => {
                if let Some(ext) = p.extents.first() {
                    // Long symlink: target in a data block.
                    let off = img.block_off(ext.phys);
                    let t = p.symlink_target.clone().unwrap_or_default();
                    img.put_bytes(off, t.as_bytes());
                }
            }
        }
    }

    Ok(img.bytes)
}

fn ceil_div_u32(a: u32, b: u32) -> u32 {
    a.div_ceil(b)
}

fn round_up_8(x: u32) -> u32 {
    (x + 7) & !7
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

fn write_superblock(img: &mut Image, layout: &Layout) {
    let sb = 1024usize;
    let free_inodes = layout.inode_slots - layout.used_inodes;

    img.put_u32(sb, layout.inode_slots); // s_inodes_count
    img.put_u32(sb + 0x04, layout.total_blocks); // s_blocks_count_lo
    img.put_u32(sb + 0x0C, 0); // s_free_blocks_count_lo (RO image: none free)
    img.put_u32(sb + 0x10, free_inodes); // s_free_inodes_count
    img.put_u32(sb + 0x14, 0); // s_first_data_block (0 for 4 KiB)
    img.put_u32(sb + 0x18, 2); // s_log_block_size: 1024<<2 = 4096
    img.put_u32(sb + 0x1C, 2); // s_log_cluster_size
    img.put_u32(sb + 0x20, BLOCKS_PER_GROUP); // s_blocks_per_group
    img.put_u32(sb + 0x24, BLOCKS_PER_GROUP); // s_clusters_per_group
    img.put_u32(sb + 0x28, layout.inodes_per_group); // s_inodes_per_group
    img.put_u16(sb + 0x38, EXT4_MAGIC);
    img.put_u16(sb + 0x3A, 1); // s_state: cleanly unmounted
    img.put_u16(sb + 0x3C, 1); // s_errors: continue
    img.put_u16(sb + 0x36, 0xFFFF); // s_max_mnt_count = -1
    img.put_u32(sb + 0x4C, 1); // s_rev_level: dynamic
    img.put_u32(sb + 0x54, FIRST_INO); // s_first_ino
    img.put_u16(sb + 0x58, INODE_SIZE); // s_inode_size
    img.put_u16(sb + 0x5A, 0); // s_block_group_nr (primary)
    img.put_u32(sb + 0x60, INCOMPAT_FILETYPE_EXTENTS); // s_feature_incompat
    // s_feature_ro_compat left 0 (no sparse_super: SB+GDT backups sit at the
    // start of every group), UUID + volume name left zero for determinism.
}

fn write_group_descs(img: &mut Image, layout: &Layout, planned: &[Planned]) {
    for g in 0..layout.groups {
        let gd = img.block_off(1) + g as usize * 32; // 32-byte descriptors in the GDT
        img.put_u32(gd, layout.block_bitmap(g));
        img.put_u32(gd + 0x04, layout.inode_bitmap(g));
        img.put_u32(gd + 0x08, layout.inode_table(g));
        // RO image: no free blocks anywhere.
        img.put_u16(gd + 0x0C, 0); // bg_free_blocks_count_lo
        img.put_u16(gd + 0x0E, group_free_inodes(layout, g) as u16);
        img.put_u16(gd + 0x10, group_used_dirs(layout, planned, g) as u16);
    }
}

/// Count inode slots in group `g` that are past `used_inodes` (hence free).
fn group_free_inodes(layout: &Layout, g: u32) -> u32 {
    let base = g * layout.inodes_per_group; // ino = base + local + 1
    (0..layout.inodes_per_group)
        .filter(|local| base + local + 1 > layout.used_inodes)
        .count() as u32
}

fn group_used_dirs(layout: &Layout, planned: &[Planned], g: u32) -> u32 {
    planned
        .iter()
        .filter(|p| p.kind == Kind::Dir && layout.locate_inode(p.ino).0 == g)
        .count() as u32
}

fn write_bitmaps(img: &mut Image, layout: &Layout) {
    for g in 0..layout.groups {
        // Block bitmap: every block in the group is in use (metadata + data,
        // plus padding past the image end in the final partial group).
        let bb = img.block_off(layout.block_bitmap(g));
        for b in 0..BLOCKS_PER_GROUP {
            set_bit(&mut img.bytes, bb, b as usize);
        }
        // Inode bitmap: mark occupied inode slots used, pad the rest of the
        // bitmap block used (bits past inodes_per_group are not real inodes).
        let ib = img.block_off(layout.inode_bitmap(g));
        let base = g * layout.inodes_per_group;
        for local in 0..layout.inodes_per_group {
            if base + local < layout.used_inodes {
                set_bit(&mut img.bytes, ib, local as usize);
            }
        }
        for pad in layout.inodes_per_group..(BLOCK_SIZE * 8) {
            set_bit(&mut img.bytes, ib, pad as usize);
        }
    }
}

/// Copy the primary superblock + group-descriptor table into the backup slot at
/// the start of every group past 0 (no sparse_super feature is set, so a reader
/// expects a backup in each group). Kernel read-only mounts trust the primary;
/// the backups keep the image self-consistent for offline tools.
fn write_backups(img: &mut Image, layout: &Layout) {
    let sb_primary = img.bytes[1024..2048].to_vec();
    let gdt_bytes = layout.gdt_blocks as usize * BLOCK_SIZE as usize;
    let gdt_primary = img.bytes[img.block_off(1)..img.block_off(1) + gdt_bytes].to_vec();
    for g in 1..layout.groups {
        let sb_off = img.block_off(layout.group_start(g));
        img.put_bytes(sb_off, &sb_primary);
        img.put_u16(sb_off + 0x5A, g as u16); // s_block_group_nr in the backup
        let gdt_off = img.block_off(layout.group_start(g) + 1);
        img.put_bytes(gdt_off, &gdt_primary);
    }
}

fn set_bit(bytes: &mut [u8], base: usize, bit: usize) {
    bytes[base + bit / 8] |= 1u8 << (bit % 8);
}

fn write_inode(img: &mut Image, layout: &Layout, p: &Planned) {
    let (g, local) = layout.locate_inode(p.ino);
    let off = img.block_off(layout.inode_table(g)) + local as usize * INODE_SIZE as usize;
    img.put_u16(off, p.mode);
    img.put_u16(off + 0x02, 0); // uid
    img.put_u32(off + 0x04, (p.size & 0xFFFF_FFFF) as u32); // size_lo
    // atime/ctime/mtime/dtime = 0 (determinism).
    img.put_u16(off + 0x1A, p.links);
    let sectors = p.block_count * (BLOCK_SIZE / 512);
    img.put_u32(off + 0x1C, sectors); // i_blocks_lo
    img.put_u16(off + 0x80, 32); // i_extra_isize

    if p.kind == Kind::Symlink && p.extents.is_empty() {
        // Fast symlink: raw target in i_block, no extents flag.
        let target = p.symlink_target.clone().unwrap_or_default();
        img.put_bytes(off + 0x28, target.as_bytes());
        return;
    }

    // Extents: header + up to four inline entries (the planner rejects more).
    img.put_u32(off + 0x20, EXTENTS_FL);
    let eh = off + 0x28;
    img.put_u16(eh, EXTENT_MAGIC);
    img.put_u16(eh + 0x02, p.extents.len() as u16); // eh_entries
    img.put_u16(eh + 0x04, MAX_INLINE_EXTENTS as u16); // eh_max
    img.put_u16(eh + 0x06, 0); // eh_depth (leaf)
    img.put_u32(eh + 0x08, 0); // eh_generation
    for (i, ext) in p.extents.iter().enumerate() {
        let ee = eh + 12 + i * 12;
        img.put_u32(ee, ext.logical); // ee_block
        img.put_u16(ee + 0x04, ext.len as u16); // ee_len
        img.put_u16(ee + 0x06, 0); // ee_start_hi
        img.put_u32(ee + 0x08, ext.phys); // ee_start_lo
    }
}

fn write_dir_block(img: &mut Image, p: &Planned) {
    let Some(ext) = p.extents.first() else {
        return;
    };
    let base = img.block_off(ext.phys);
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
    let mut written = 0usize;
    for ext in &p.extents {
        if written >= p.data.len() {
            break;
        }
        let span = ext.len as usize * BLOCK_SIZE as usize;
        let end = (written + span).min(p.data.len());
        img.put_bytes(img.block_off(ext.phys), &p.data[written..end]);
        written += span;
    }
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
