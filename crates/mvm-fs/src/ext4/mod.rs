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
//! data region. A file that fragments past the four extents an inode holds
//! inline grows a **depth-1 extent tree** (up to four inline index entries, each
//! pointing to a leaf block of up to 340 extents), so single files up to
//! ~170 GiB are fine; the common rootfs — many modest files — still needs one or
//! a few inline extents each.
//!
//! Correctness is validated by reading the output back through an independent
//! ext4 reader (`am-fs-ext4`, a dev-only test oracle) and, in CI, by mounting
//! it on Linux (both a single-group and a multi-group image).

pub mod mkfs;
pub mod verity;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::parallel::par_map;

pub const BLOCK_SIZE: u32 = 4096;
const BLOCK_SIZE_USIZE: usize = BLOCK_SIZE as usize;
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
// An inode's 60-byte i_block holds an extent header (12 B) + four 12-byte
// entries — either data extents (a leaf inode) or index entries (a depth-1
// tree root).
const MAX_INLINE_EXTENTS: usize = 4;
// A 4 KiB leaf block holds a header (12 B) + `(4096 - 12) / 12` = 340 extents.
const LEAF_MAX_EXTENTS: usize = (BLOCK_SIZE as usize - 12) / 12;
// Depth-1 ceiling: four inline index entries, each pointing to one leaf of up
// to LEAF_MAX_EXTENTS extents. Beyond this a depth-2 tree would be needed — a
// >170 GiB single file, far past any rootfs, so it stays an error.
const MAX_TREE_EXTENTS: usize = MAX_INLINE_EXTENTS * LEAF_MAX_EXTENTS;

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
    /// A single file needs more extents than a depth-1 tree can address
    /// (> MAX_TREE_EXTENTS ≈ a 170 GiB file); a depth-2 tree is not implemented.
    FileTooFragmented { ino: u32, extents: usize },
    /// A node's parent directory was not present in the input.
    MissingParent(String),
    /// A path was empty or not rooted at `/`.
    BadPath(String),
    /// A node's parent path resolves to a non-directory (e.g. a regular file
    /// or symlink), so the node could never be reached on a mounted image.
    NotADirectory(String),
    /// Two nodes claim the same path (including a node re-claiming the implicit
    /// root `/`), which would emit duplicate directory entries.
    DuplicatePath(String),
    /// An inode's extended attributes don't fit the in-inode xattr area (an
    /// external xattr block is not implemented). Treated as a capacity limit so
    /// the run path falls back to the builder VM, which preserves them.
    XattrTooLarge { ino: u32 },
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
                "inode {ino} needs {extents} extents, past the depth-1 tree limit of \
                 {MAX_TREE_EXTENTS} (a depth-2 extent tree is not implemented)"
            ),
            Ext4Error::MissingParent(p) => {
                write!(f, "node {p} has no parent directory in the input")
            }
            Ext4Error::BadPath(p) => write!(f, "bad path {p:?} (must be absolute)"),
            Ext4Error::NotADirectory(p) => {
                write!(f, "parent of {p} is not a directory")
            }
            Ext4Error::DuplicatePath(p) => write!(f, "duplicate path {p}"),
            Ext4Error::XattrTooLarge { ino } => write!(
                f,
                "inode {ino}'s extended attributes exceed the in-inode xattr area \
                 (an external xattr block is not implemented)"
            ),
        }
    }
}

impl Ext4Error {
    /// Whether this failure is a *capacity limit* of the pure writer (the image
    /// is structurally too big / too fragmented for the current single-writer
    /// design) rather than a *malformed tree*. The run path retries a capacity
    /// limit via the builder VM (which has no such limits); a malformed-tree
    /// error is genuine and surfaces unchanged. A real OCI-unpacked FS tree can
    /// only ever produce capacity limits — the malformed variants require a
    /// synthetic node list.
    pub fn is_capacity_limit(&self) -> bool {
        matches!(
            self,
            Ext4Error::TooLarge { .. }
                | Ext4Error::FileTooFragmented { .. }
                | Ext4Error::XattrTooLarge { .. }
        )
    }
}

impl std::error::Error for Ext4Error {}

/// Error emitting an image through the streamed sparse-range API.
#[derive(Debug)]
pub enum EmitImageError<E> {
    Build(Ext4Error),
    Emit(E),
}

impl<E: std::fmt::Display> std::fmt::Display for EmitImageError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmitImageError::Build(err) => write!(f, "{err}"),
            EmitImageError::Emit(err) => write!(f, "{err}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for EmitImageError<E> {}

impl<E> From<Ext4Error> for EmitImageError<E> {
    fn from(value: Ext4Error) -> Self {
        Self::Build(value)
    }
}

/// A filesystem node to place in the image. Paths are absolute (`/`-rooted);
/// `/` (the root) is implicit and always present.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Node {
    Dir {
        path: String,
        mode: u16,
        xattrs: Vec<Xattr>,
    },
    File {
        path: String,
        mode: u16,
        data: Vec<u8>,
        xattrs: Vec<Xattr>,
    },
    /// A regular file whose bytes stay on the host until the emit pass reads
    /// them.
    ///
    /// `File` above holds its contents, so a walked tree costs its own size in
    /// memory before a single byte is written. That is fine for a rootfs and
    /// not fine for `--mount`, where the tree is a user's working directory and
    /// can be tens of gigabytes. This variant carries a path and the size the
    /// layout was planned against; [`emit_file_blocks`] reads it in
    /// block-sized chunks straight into the image.
    ///
    /// `len` is captured at walk time and is what the extent layout is built
    /// from, so the emit pass must produce exactly that many bytes whatever the
    /// file says later — see [`emit_file_blocks`] for what happens when a live
    /// tree changes underneath the walk.
    FileFromHost {
        path: String,
        mode: u16,
        source: PathBuf,
        len: u64,
        xattrs: Vec<Xattr>,
    },
    Symlink {
        path: String,
        target: String,
    },
}

/// An extended attribute (name + raw value) to store in an inode's inline xattr
/// area. `name` is fully-qualified (e.g. `security.capability`, `user.foo`);
/// `value` is preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Xattr {
    pub name: String,
    pub value: Vec<u8>,
}

/// Deterministic superblock metadata to stamp into a built image.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildOptions {
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
}

impl BuildOptions {
    pub fn with_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.uuid = uuid;
        self
    }

    pub fn with_volume_name(mut self, volume_name: &[u8]) -> Self {
        let len = volume_name.len().min(self.volume_name.len());
        self.volume_name[..len].copy_from_slice(&volume_name[..len]);
        self
    }
}

impl Node {
    /// The node's guest-absolute path — the identity callers merge and
    /// deduplicate node lists on.
    pub fn path(&self) -> &str {
        match self {
            Node::Dir { path, .. }
            | Node::File { path, .. }
            | Node::FileFromHost { path, .. }
            | Node::Symlink { path, .. } => path,
        }
    }

    /// The node's extended attributes (empty for symlinks).
    fn xattrs(&self) -> &[Xattr] {
        match self {
            Node::Dir { xattrs, .. }
            | Node::File { xattrs, .. }
            | Node::FileFromHost { xattrs, .. } => xattrs,
            Node::Symlink { .. } => &[],
        }
    }
}

/// One contiguous run of physical blocks backing a logical range of a file
/// (or the data blocks of a directory / long symlink). `len` is in blocks and
/// never exceeds a group's data region, so it always fits ext4's 15-bit
/// initialized-extent length.
#[derive(Debug, Clone, Copy)]
struct Extent {
    logical: u32,
    len: u32,
    phys: u32,
}

/// A little-endian byte writer over a fixed image buffer. Bounds-checked by
/// block-local slices (a bug returns/panics, never corrupts memory). Untouched
/// blocks are implicit zeros, so callers can emit only the sparse ranges they
/// actually wrote.
struct Image {
    total_blocks: u32,
    blocks: BTreeMap<u32, Box<[u8; BLOCK_SIZE_USIZE]>>,
}

impl Image {
    fn new(blocks: u32) -> Self {
        Self {
            total_blocks: blocks,
            blocks: BTreeMap::new(),
        }
    }
    fn put_u8(&mut self, off: usize, v: u8) {
        self.put_bytes(off, &[v]);
    }
    fn put_u16(&mut self, off: usize, v: u16) {
        self.put_bytes(off, &v.to_le_bytes());
    }
    fn put_u32(&mut self, off: usize, v: u32) {
        self.put_bytes(off, &v.to_le_bytes());
    }
    fn put_bytes(&mut self, off: usize, v: &[u8]) {
        let mut cursor = off;
        let mut remaining = v;
        while !remaining.is_empty() {
            let block = (cursor / BLOCK_SIZE_USIZE) as u32;
            let in_block = cursor % BLOCK_SIZE_USIZE;
            let take = (BLOCK_SIZE_USIZE - in_block).min(remaining.len());
            self.block_mut(block)[in_block..in_block + take].copy_from_slice(&remaining[..take]);
            cursor += take;
            remaining = &remaining[take..];
        }
    }
    fn block_off(&self, block: u32) -> usize {
        block as usize * BLOCK_SIZE_USIZE
    }
    fn read_bytes(&self, off: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut cursor = off;
        let mut written = 0usize;
        while written < len {
            let block = (cursor / BLOCK_SIZE_USIZE) as u32;
            let in_block = cursor % BLOCK_SIZE_USIZE;
            let take = (BLOCK_SIZE_USIZE - in_block).min(len - written);
            if let Some(bytes) = self.blocks.get(&block) {
                out[written..written + take].copy_from_slice(&bytes[in_block..in_block + take]);
            }
            cursor += take;
            written += take;
        }
        out
    }
    fn set_bit(&mut self, base: usize, bit: usize) {
        let off = base + bit / 8;
        let block = (off / BLOCK_SIZE_USIZE) as u32;
        let in_block = off % BLOCK_SIZE_USIZE;
        self.block_mut(block)[in_block] |= 1u8 << (bit % 8);
    }
    fn emit_chunks<E, F>(&self, emit: &mut F) -> Result<(), E>
    where
        F: FnMut(u64, &[u8]) -> Result<(), E>,
    {
        let mut current_start: Option<u64> = None;
        let mut current_block = 0u32;
        let mut current_bytes = Vec::new();

        for (&block, bytes) in &self.blocks {
            if let Some(start) = current_start {
                if block == current_block + 1 {
                    current_block = block;
                    current_bytes.extend_from_slice(bytes.as_ref());
                    continue;
                }
                emit(start, &current_bytes)?;
                current_bytes.clear();
            }
            current_start = Some(self.block_off(block) as u64);
            current_block = block;
            current_bytes.extend_from_slice(bytes.as_ref());
        }

        if let Some(start) = current_start {
            emit(start, &current_bytes)?;
        }
        Ok(())
    }
    fn total_bytes(&self) -> u64 {
        self.total_blocks as u64 * BLOCK_SIZE as u64
    }
    /// Merge all blocks from `other` into this image. The caller must ensure
    /// the two images have disjoint block sets; overlapping blocks are taken
    /// from `other`.
    fn merge_from(&mut self, other: Self) {
        self.blocks.extend(other.blocks);
    }
    fn block_mut(&mut self, block: u32) -> &mut [u8; BLOCK_SIZE_USIZE] {
        self.blocks
            .entry(block)
            .or_insert_with(|| Box::new([0u8; BLOCK_SIZE_USIZE]))
    }
}

// One parent→child link, recorded while the node list is consumed and wired
// into the parent's directory entries once every inode number is known.
struct ChildEdge {
    parent: u32,
    name: String,
    child: u32,
    ft: u8,
    // The child's normalized path, kept for the parent-is-not-a-directory
    // refusal so it can name the offending path rather than just the leaf.
    path: String,
}

// A planned inode: its number, kind, and the data blocks assigned to it.
/// Where a planned inode's bytes come from during the emit pass.
///
/// `Inline` is every caller that already holds its content — an OCI layer, a
/// generated file, a directory block. `FromHost` is a walked host tree that was
/// deliberately not read into memory; it costs one open and a block-sized
/// buffer at emit time instead of the file's whole size at walk time.
enum Content {
    Inline(Vec<u8>),
    FromHost { source: PathBuf, len: usize },
}

struct Planned {
    ino: u32,
    kind: Kind,
    mode: u16,
    parent: u32,
    // Physical extents backing this inode's data; empty for fast symlinks and
    // the (never-materialized) empty root. Directories carry exactly one.
    extents: Vec<Extent>,
    // Physical block numbers of the depth-1 extent-tree leaves, in logical
    // order. Empty when `extents` fits inline (≤ MAX_INLINE_EXTENTS); otherwise
    // one per LEAF_MAX_EXTENTS-sized chunk of `extents`.
    leaf_blocks: Vec<u32>,
    block_count: u32,
    size: u64,
    // File contents / symlink target for the emit pass.
    data: Content,
    symlink_target: Option<String>,
    // Directory children: (name, child_ino, child_ft). Filled after planning.
    children: Vec<(String, u32, u8)>,
    links: u16,
    // Pre-encoded in-inode xattr region (magic + entries + values), written
    // verbatim at inode offset 160. Empty when the inode has no xattrs.
    xattr_block: Vec<u8>,
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
pub fn build_image(nodes: Vec<Node>) -> Result<Vec<u8>, Ext4Error> {
    build_image_with_options(nodes, &BuildOptions::default())
}

/// Emit a deterministic read-only ext4 image containing `nodes` as a series of
/// sparse `(offset, bytes)` chunks. Returns the final image length in bytes so
/// callers can size the destination file without guessing.
pub fn emit_image<E, F>(nodes: Vec<Node>, emit: F) -> Result<u64, EmitImageError<E>>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    emit_image_with_options(nodes, &BuildOptions::default(), emit)
}

pub fn build_image_with_options(
    nodes: Vec<Node>,
    options: &BuildOptions,
) -> Result<Vec<u8>, Ext4Error> {
    let mut dense = Vec::new();
    let total_bytes = match emit_image_with_options(nodes, options, |offset, bytes| {
        let start = offset as usize;
        let end = start + bytes.len();
        if dense.len() < end {
            dense.resize(end, 0);
        }
        dense[start..end].copy_from_slice(bytes);
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(total_bytes) => total_bytes,
        Err(EmitImageError::Build(err)) => return Err(err),
        Err(EmitImageError::Emit(never)) => match never {},
    };
    dense.resize(total_bytes as usize, 0);
    Ok(dense)
}

pub fn emit_image_with_options<E, F>(
    nodes: Vec<Node>,
    options: &BuildOptions,
    mut emit: F,
) -> Result<u64, EmitImageError<E>>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    // 1. Deterministic order: sort by path so inode numbers + block layout are
    //    a pure function of the input set. Normalizing once here and carrying
    //    the result keeps a file's bytes moving through the planner exactly
    //    once — a walked tree holds every file in memory, so a second copy
    //    doubles the build's peak footprint.
    let mut sorted: Vec<(String, Node)> = nodes
        .into_iter()
        .map(|n| normalize(n.path()).map(|p| (p, n)))
        .collect::<Result<_, _>>()
        .map_err(EmitImageError::Build)?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    // 2. Assign inode numbers: root=2, then FIRST_INO.. in sorted order.
    let mut ino_of: BTreeMap<String, u32> = BTreeMap::new();
    ino_of.insert("/".to_string(), ROOT_INO);
    let mut next = FIRST_INO;
    for (path, _) in &sorted {
        // `ino_of` already holds "/" → ROOT_INO, so a node re-claiming root or
        // any repeated path collides here and is refused before layout.
        if ino_of.insert(path.clone(), next).is_some() {
            return Err(EmitImageError::Build(Ext4Error::DuplicatePath(
                path.clone(),
            )));
        }
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
        leaf_blocks: Vec::new(),
        block_count: 0,
        size: 0,
        data: Content::Inline(Vec::new()),
        symlink_target: None,
        children: Vec::new(),
        links: 2,
        xattr_block: Vec::new(),
    });
    // Collected here so step 4 can validate and wire the tree without
    // re-walking the node list, which step 3 consumes.
    let mut child_edges: Vec<ChildEdge> = Vec::with_capacity(sorted.len());
    for (path, node) in sorted {
        let ino = ino_of[&path];
        let parent_ino = *ino_of
            .get(&parent_of(&path))
            .ok_or_else(|| Ext4Error::MissingParent(path.clone()))
            .map_err(EmitImageError::Build)?;
        // Encode the inode's xattrs into its in-inode region now; an oversized
        // set surfaces as XattrTooLarge (a capacity limit → builder-VM fallback).
        let xattr_block = encode_inline_xattrs(node.xattrs())
            .ok_or(Ext4Error::XattrTooLarge { ino })
            .map_err(EmitImageError::Build)?;
        // `node` is consumed here: a file's bytes move into the plan rather
        // than being cloned out of it.
        let (kind, mode, data, symlink_target, size, ft) = match node {
            Node::Dir { mode, .. } => (
                Kind::Dir,
                S_IFDIR | (mode & 0o7777),
                Content::Inline(Vec::new()),
                None,
                0u64,
                FT_DIR,
            ),
            Node::File { mode, data, .. } => {
                let size = data.len() as u64;
                (
                    Kind::File,
                    S_IFREG | (mode & 0o7777),
                    Content::Inline(data),
                    None,
                    size,
                    FT_FILE,
                )
            }
            Node::FileFromHost {
                mode, source, len, ..
            } => (
                Kind::File,
                S_IFREG | (mode & 0o7777),
                Content::FromHost {
                    source,
                    len: len as usize,
                },
                None,
                len,
                FT_FILE,
            ),
            Node::Symlink { target, .. } => {
                let size = target.len() as u64;
                (
                    Kind::Symlink,
                    S_IFLNK | 0o777,
                    Content::Inline(Vec::new()),
                    Some(target),
                    size,
                    FT_SYMLINK,
                )
            }
        };
        child_edges.push(ChildEdge {
            parent: parent_ino,
            name: leaf_name(&path),
            child: ino,
            ft,
            path,
        });
        planned.push(Planned {
            ino,
            kind,
            mode,
            parent: parent_ino,
            extents: Vec::new(),
            leaf_blocks: Vec::new(),
            block_count: 0,
            size,
            data,
            symlink_target,
            children: Vec::new(),
            links: if kind == Kind::Dir { 2 } else { 1 },
            xattr_block,
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
    for edge in child_edges {
        // The parent must be a directory. A file/symlink parent would leave this
        // node orphaned (no dirent references it), so refuse rather than emit an
        // unreachable inode. Root (ROOT_INO) is always a directory.
        let pi = index[&edge.parent];
        if planned[pi].kind != Kind::Dir {
            return Err(EmitImageError::Build(Ext4Error::NotADirectory(edge.path)));
        }
        planned[pi].children.push((edge.name, edge.child, edge.ft));
        if edge.ft == FT_DIR {
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
                // Linear (non-htree) directory: "." + ".." + children pack into
                // as many blocks as they need, none crossing a block boundary.
                // The kernel and the fs_ext4 reader read this without an htree
                // index. A directory large enough to fragment past the extent
                // tree fails as `FileTooFragmented`, same as an oversized file.
                let nblocks = dir_block_count(&p.children);
                p.size = nblocks as u64 * BLOCK_SIZE as u64;
                nblocks
            }
            Kind::File => p.size.div_ceil(BLOCK_SIZE as u64) as u32,
            Kind::Symlink => {
                // Fast symlink: a target that fits strictly inside the 60-byte
                // i_block lives there with no data block. The boundary is `< 60`,
                // not `<= 60`: a 60-byte target fills i_block exactly, and readers
                // treat `i_size >= 60` as a slow symlink read from a data block —
                // so an inline 60-byte target reads back truncated.
                if p.size < 60 {
                    0
                } else {
                    p.size.div_ceil(BLOCK_SIZE as u64) as u32
                }
            }
        };
        p.block_count = nblocks;
        data_blocks_total += nblocks as u64;
    }

    // 6. Resolve geometry. A file whose data fragments past the four inline
    //    extents needs depth-1 extent-tree leaf blocks, which occupy
    //    data-region blocks of their own and so feed back into the sizing.
    //    Iterate to a fixpoint: leaves are tiny (one per 340 extents), so this
    //    converges in one or two passes.
    let mut meta_blocks: u64 = 0;
    let layout = loop {
        let layout = Layout::plan(inode_high, data_blocks_total + meta_blocks)
            .map_err(EmitImageError::Build)?;
        let mut alloc = RegionAllocator::new(&layout);
        let mut needed = 0u64;
        for p in &planned {
            if p.block_count > 0 {
                needed += leaves_for(alloc.take(p.block_count).len()) as u64;
            }
        }
        if needed == meta_blocks {
            break layout;
        }
        meta_blocks = needed;
    };

    // 7. Allocate for real from one shared cursor: every inode's data extents
    //    first (inode order), then the extent-tree leaf blocks for the files
    //    that need them. Leaves land right after the data — exactly the
    //    `data_blocks_total + meta_blocks` the layout was sized for.
    let mut alloc = RegionAllocator::new(&layout);
    for p in planned.iter_mut() {
        if p.block_count > 0 {
            p.extents = alloc.take(p.block_count);
        }
    }
    for p in planned.iter_mut() {
        if p.extents.len() <= MAX_INLINE_EXTENTS {
            continue;
        }
        if p.extents.len() > MAX_TREE_EXTENTS {
            // Would need a depth-2 tree (>170 GiB single file) — not supported.
            return Err(EmitImageError::Build(Ext4Error::FileTooFragmented {
                ino: p.ino,
                extents: p.extents.len(),
            }));
        }
        for _ in 0..leaves_for(p.extents.len()) {
            p.leaf_blocks.push(alloc.take(1)[0].phys);
        }
    }

    // 8. Emit.
    let mut img = Image::new(layout.total_blocks);
    write_superblock(&mut img, &layout, options);
    write_group_descs(&mut img, &layout, &planned);
    write_bitmaps(&mut img, &layout);
    write_backups(&mut img, &layout);

    // Inode writes stay sequential: multiple inodes share a 4 KiB inode-table
    // block, so parallel writers would race on the same block.
    for p in &planned {
        write_inode(&mut img, &layout, p);
    }

    // Directory and long-symlink data blocks are at disjoint physical extents,
    // so emit them in parallel and merge back into the shared image.
    let dir_and_symlink: Vec<&Planned> = planned
        .iter()
        .filter(|p| p.kind == Kind::Dir || (p.kind == Kind::Symlink && !p.extents.is_empty()))
        .collect();
    let data_images: Vec<Image> = par_map(dir_and_symlink, |p| {
        let mut local = Image::new(0);
        match p.kind {
            Kind::Dir => write_dir_blocks(&mut local, p),
            Kind::Symlink => {
                let ext = p.extents.first().expect("filtered above");
                let off = local.block_off(ext.phys);
                let t = p.symlink_target.clone().unwrap_or_default();
                local.put_bytes(off, t.as_bytes());
            }
            Kind::File => unreachable!(),
        }
        local
    });
    for local in data_images {
        img.merge_from(local);
    }

    img.emit_chunks(&mut emit).map_err(EmitImageError::Emit)?;
    for p in &planned {
        if p.kind == Kind::File {
            emit_file_blocks(&mut emit, &img, p).map_err(EmitImageError::Emit)?;
        }
    }
    Ok(img.total_bytes())
}

fn ceil_div_u32(a: u32, b: u32) -> u32 {
    a.div_ceil(b)
}

fn round_up_8(x: u32) -> u32 {
    (x + 7) & !7
}

/// Extent-tree leaf blocks needed to hold `num_extents`: zero when they fit
/// inline in the inode (≤ MAX_INLINE_EXTENTS), else one leaf per
/// LEAF_MAX_EXTENTS-sized chunk (a depth-1 tree).
fn leaves_for(num_extents: usize) -> usize {
    if num_extents <= MAX_INLINE_EXTENTS {
        0
    } else {
        num_extents.div_ceil(LEAF_MAX_EXTENTS)
    }
}

/// Block index (0-based) each ordered dirent lands in for a linear directory:
/// "." , "..", then `children` in order. An entry never crosses a block
/// boundary, so a block that can't fit the next entry pads out and the entry
/// starts the following block. The returned vec is parallel to the entry
/// sequence [`write_dir_blocks`] emits, so sizing and writing never disagree.
fn dir_block_layout(children: &[(String, u32, u8)]) -> Vec<u32> {
    // "." and ".." lead every directory; both encode to a 12-byte dirent.
    let name_lens = [1usize, 2]
        .into_iter()
        .chain(children.iter().map(|(name, _, _)| name.len()));
    let mut blocks = Vec::new();
    let mut blk = 0u32;
    let mut used = 0usize;
    for nl in name_lens {
        let need = dirent_len(nl);
        if used + need > BLOCK_SIZE as usize {
            blk += 1;
            used = 0;
        }
        used += need;
        blocks.push(blk);
    }
    blocks
}

/// Number of 4 KiB blocks a linear directory of `children` occupies.
fn dir_block_count(children: &[(String, u32, u8)]) -> u32 {
    dir_block_layout(children)
        .last()
        .map_or(1, |&last| last + 1)
}

fn dirent_len(name_len: usize) -> usize {
    // 8-byte header + name, rounded up to 4.
    (8 + name_len + 3) & !3
}

fn write_superblock(img: &mut Image, layout: &Layout, options: &BuildOptions) {
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
    img.put_bytes(sb + 0x68, &options.uuid);
    img.put_bytes(sb + 0x78, &options.volume_name);
    // s_feature_ro_compat left 0 (no sparse_super: SB+GDT backups sit at the
    // start of every group).
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
            img.set_bit(bb, b as usize);
        }
        // Inode bitmap: mark occupied inode slots used, pad the rest of the
        // bitmap block used (bits past inodes_per_group are not real inodes).
        let ib = img.block_off(layout.inode_bitmap(g));
        let base = g * layout.inodes_per_group;
        for local in 0..layout.inodes_per_group {
            if base + local < layout.used_inodes {
                img.set_bit(ib, local as usize);
            }
        }
        for pad in layout.inodes_per_group..(BLOCK_SIZE * 8) {
            img.set_bit(ib, pad as usize);
        }
    }
}

/// Copy the primary superblock + group-descriptor table into the backup slot at
/// the start of every group past 0 (no sparse_super feature is set, so a reader
/// expects a backup in each group). Kernel read-only mounts trust the primary;
/// the backups keep the image self-consistent for offline tools.
fn write_backups(img: &mut Image, layout: &Layout) {
    let sb_primary = img.read_bytes(1024, 1024);
    let gdt_bytes = layout.gdt_blocks as usize * BLOCK_SIZE_USIZE;
    let gdt_primary = img.read_bytes(img.block_off(1), gdt_bytes);
    for g in 1..layout.groups {
        let sb_off = img.block_off(layout.group_start(g));
        img.put_bytes(sb_off, &sb_primary);
        img.put_u16(sb_off + 0x5A, g as u16); // s_block_group_nr in the backup
        let gdt_off = img.block_off(layout.group_start(g) + 1);
        img.put_bytes(gdt_off, &gdt_primary);
    }
}

// In-inode xattr area: starts at 128 + i_extra_isize(32), runs to the end of
// the 256-byte inode. First 4 bytes are the magic; the rest holds entries
// (growing forward) + values (packed backward) + a 4-byte terminator.
const XATTR_REGION_OFFSET: usize = 128 + 32;
const XATTR_REGION_LEN: usize = INODE_SIZE as usize - XATTR_REGION_OFFSET; // 96
const XATTR_MAGIC: u32 = 0xEA02_0000;

/// Split a fully-qualified xattr name into its ext4 `e_name_index` + suffix.
/// `None` for a namespace the on-disk format doesn't encode.
fn split_xattr_name(name: &str) -> Option<(u8, &str)> {
    // Exact ACL names (their suffix is empty; the index implies the full name).
    match name {
        "system.posix_acl_access" => return Some((2, "")),
        "system.posix_acl_default" => return Some((3, "")),
        _ => {}
    }
    for (idx, prefix) in [
        (1u8, "user."),
        (4, "trusted."),
        (6, "security."),
        (7, "system."),
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return Some((idx, rest));
        }
    }
    None
}

/// Encode `xattrs` into an inode's in-inode xattr region (the bytes written at
/// [`XATTR_REGION_OFFSET`]: 4-byte magic + entries + values). Returns `None` if
/// they don't fit or carry an unencodable namespace, so the caller falls back to
/// the builder VM. Empty input yields an empty region (no xattr area emitted).
/// Deterministic: entries are sorted by (name_index, suffix).
fn encode_inline_xattrs(xattrs: &[Xattr]) -> Option<Vec<u8>> {
    if xattrs.is_empty() {
        return Some(Vec::new());
    }
    let mut items: Vec<(u8, &str, &[u8])> = Vec::with_capacity(xattrs.len());
    for x in xattrs {
        let (idx, suffix) = split_xattr_name(&x.name)?;
        items.push((idx, suffix, x.value.as_slice()));
    }
    items.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    // `e_value_offs` is relative to the entry area (region byte 4), matching the
    // reader. Entries grow from offset 0 of the entry area; values pack backward
    // from its end. `entry_end + 4-byte terminator` must not cross `value_cursor`.
    let entry_area = XATTR_REGION_LEN - 4;
    let mut region = vec![0u8; XATTR_REGION_LEN];
    region[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
    let mut entry_cursor = 0usize;
    let mut value_cursor = entry_area;
    for (idx, suffix, value) in items {
        let name = suffix.as_bytes();
        let entry_padded = (16 + name.len() + 3) & !3;
        let value_padded = (value.len() + 3) & !3;
        value_cursor = value_cursor.checked_sub(value_padded)?;
        if entry_cursor + entry_padded + 4 > value_cursor {
            return None;
        }
        let e = 4 + entry_cursor;
        region[e] = name.len() as u8; // e_name_len
        region[e + 1] = idx; // e_name_index
        region[e + 2..e + 4].copy_from_slice(&(value_cursor as u16).to_le_bytes()); // e_value_offs
        // e_value_inum (e+4..e+8) and e_hash (e+12..e+16) stay zero.
        region[e + 8..e + 12].copy_from_slice(&(value.len() as u32).to_le_bytes()); // e_value_size
        region[e + 16..e + 16 + name.len()].copy_from_slice(name);
        let v = 4 + value_cursor;
        region[v..v + value.len()].copy_from_slice(value);
        entry_cursor += entry_padded;
    }
    // 4-byte zero terminator after the last entry is already zeroed.
    Some(region)
}

fn write_inode(img: &mut Image, layout: &Layout, p: &Planned) {
    let (g, local) = layout.locate_inode(p.ino);
    let off = img.block_off(layout.inode_table(g)) + local as usize * INODE_SIZE as usize;
    img.put_u16(off, p.mode);
    img.put_u16(off + 0x02, 0); // uid
    img.put_u32(off + 0x04, (p.size & 0xFFFF_FFFF) as u32); // size_lo
    // atime/ctime/mtime/dtime = 0 (determinism).
    img.put_u16(off + 0x1A, p.links);
    // i_blocks counts data blocks + extent-tree leaf blocks (both occupy disk).
    let sectors = (p.block_count + p.leaf_blocks.len() as u32) * (BLOCK_SIZE / 512);
    img.put_u32(off + 0x1C, sectors); // i_blocks_lo
    img.put_u16(off + 0x80, 32); // i_extra_isize

    // In-inode extended attributes: pre-encoded region (magic + entries +
    // values) written at offset 160 (128 + i_extra_isize). Empty for symlinks
    // and inodes without xattrs. Sits above the i_block/extent region, so it
    // never overlaps file/dir data layout.
    if !p.xattr_block.is_empty() {
        img.put_bytes(off + XATTR_REGION_OFFSET, &p.xattr_block);
    }

    if p.kind == Kind::Symlink && p.extents.is_empty() {
        // Fast symlink: raw target in i_block, no extents flag.
        let target = p.symlink_target.clone().unwrap_or_default();
        img.put_bytes(off + 0x28, target.as_bytes());
        return;
    }

    img.put_u32(off + 0x20, EXTENTS_FL);
    let eh = off + 0x28;
    if p.leaf_blocks.is_empty() {
        // Leaf inode: header (depth 0) + up to four inline data extents.
        write_extent_header(
            img,
            eh,
            p.extents.len() as u16,
            MAX_INLINE_EXTENTS as u16,
            0,
        );
        for (i, ext) in p.extents.iter().enumerate() {
            write_extent(img, eh + 12 + i * 12, ext);
        }
    } else {
        // Depth-1 root: header (depth 1) + up to four inline index entries; the
        // data extents live in the leaf blocks.
        write_extent_header(
            img,
            eh,
            p.leaf_blocks.len() as u16,
            MAX_INLINE_EXTENTS as u16,
            1,
        );
        write_extent_leaves(img, eh, p);
    }
}

/// Write an `ext4_extent_header` (12 bytes) at `off`.
fn write_extent_header(img: &mut Image, off: usize, entries: u16, max: u16, depth: u16) {
    img.put_u16(off, EXTENT_MAGIC); // eh_magic
    img.put_u16(off + 0x02, entries); // eh_entries
    img.put_u16(off + 0x04, max); // eh_max
    img.put_u16(off + 0x06, depth); // eh_depth
    img.put_u32(off + 0x08, 0); // eh_generation
}

/// Write an `ext4_extent` (12 bytes) at `off`.
fn write_extent(img: &mut Image, off: usize, ext: &Extent) {
    img.put_u32(off, ext.logical); // ee_block
    img.put_u16(off + 0x04, ext.len as u16); // ee_len (<= 32768, always initialized)
    img.put_u16(off + 0x06, 0); // ee_start_hi
    img.put_u32(off + 0x08, ext.phys); // ee_start_lo
}

/// Fill a depth-1 tree: one `ext4_extent_idx` in the inode per leaf, and each
/// leaf block's own header + its slice of `p.extents`.
fn write_extent_leaves(img: &mut Image, inode_header: usize, p: &Planned) {
    for (li, &leaf_phys) in p.leaf_blocks.iter().enumerate() {
        let start = li * LEAF_MAX_EXTENTS;
        let end = ((li + 1) * LEAF_MAX_EXTENTS).min(p.extents.len());
        let chunk = &p.extents[start..end];

        // Index entry inline in the inode: the leaf's first logical block +
        // its physical block number.
        let idx = inode_header + 12 + li * 12;
        img.put_u32(idx, chunk[0].logical); // ei_block
        img.put_u32(idx + 0x04, leaf_phys); // ei_leaf_lo
        img.put_u16(idx + 0x08, 0); // ei_leaf_hi
        img.put_u16(idx + 0x0A, 0); // ei_unused

        // The leaf block: its own header (depth 0) + the chunk's extents.
        let lo = img.block_off(leaf_phys);
        write_extent_header(img, lo, chunk.len() as u16, LEAF_MAX_EXTENTS as u16, 0);
        for (i, ext) in chunk.iter().enumerate() {
            write_extent(img, lo + 12 + i * 12, ext);
        }
    }
}

fn write_dir_blocks(img: &mut Image, p: &Planned) {
    // Physical blocks backing this directory, in logical order.
    let phys: Vec<u32> = p
        .extents
        .iter()
        .flat_map(|ext| (0..ext.len).map(move |i| ext.phys + i))
        .collect();
    if phys.is_empty() {
        return;
    }
    // Entries in the exact order `dir_block_layout` assumed: "." , "..", children.
    let mut entries: Vec<(u32, &str, u8)> = Vec::with_capacity(2 + p.children.len());
    entries.push((p.ino, ".", FT_DIR));
    entries.push((p.parent, "..", FT_DIR));
    entries.extend(
        p.children
            .iter()
            .map(|(name, ino, ft)| (*ino, name.as_str(), *ft)),
    );
    let layout = dir_block_layout(&p.children);
    debug_assert_eq!(entries.len(), layout.len());

    let mut cur = 0u32;
    let mut pos = 0usize;
    for (i, (ino, name, ft)) in entries.iter().enumerate() {
        let blk = layout[i];
        if blk != cur {
            cur = blk;
            pos = 0;
        }
        // The last entry in each block pads its rec_len to the block end, so no
        // dirent straddles a block boundary (an ext4 linear-directory invariant).
        let last_in_block = i + 1 == entries.len() || layout[i + 1] != blk;
        let base = img.block_off(phys[blk as usize]);
        pos += put_dirent(img, base + pos, *ino, name, *ft, last_in_block);
    }
}

/// Write a directory entry; if `last`, its rec_len spans to the block end.
/// Returns the rec_len consumed.
fn put_dirent(img: &mut Image, off: usize, ino: u32, name: &str, ft: u8, last: bool) -> usize {
    let block_start = off - (off % BLOCK_SIZE as usize);
    let used = off - block_start;
    let rec_len = if last {
        BLOCK_SIZE_USIZE - used
    } else {
        dirent_len(name.len())
    };
    img.put_u32(off, ino);
    img.put_u16(off + 0x04, rec_len as u16);
    img.put_u8(off + 0x06, name.len() as u8);
    img.put_u8(off + 0x07, ft);
    img.put_bytes(off + 0x08, name.as_bytes());
    rec_len
}

fn emit_file_blocks<E, F>(emit: &mut F, img: &Image, p: &Planned) -> Result<(), E>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    match &p.data {
        Content::Inline(bytes) => {
            let mut written = 0usize;
            for ext in &p.extents {
                if written >= bytes.len() {
                    break;
                }
                let span = ext.len as usize * BLOCK_SIZE_USIZE;
                let end = (written + span).min(bytes.len());
                emit(img.block_off(ext.phys) as u64, &bytes[written..end])?;
                written += span;
            }
            Ok(())
        }
        Content::FromHost { source, len } => emit_host_file_blocks(emit, img, p, source, *len),
    }
}

/// Stream one host file's bytes into the extents planned for it.
///
/// The layout is already committed by the time this runs — inode numbers,
/// extents and the image's total size were all fixed from the size the walk
/// stat'd. So this emits exactly `len` bytes whatever the file says now:
///
/// * **Short read** (the file shrank, or was truncated mid-walk): the shortfall
///   is left as-is. Every block the layout allocated is inside the image and
///   the emit callback leaves untouched ranges as holes, which read back as
///   zeros — the same thing a sparse region gives. Emitting fewer bytes than
///   planned is safe; emitting them at the wrong offset would not be, which is
///   why the extent cursor advances by the planned span rather than by what was
///   read.
/// * **Long read** (the file grew): the extra is dropped. The inode's `i_size`
///   is the planned length, so bytes past it would be unreachable through the
///   filesystem and would corrupt whatever the allocator put in the next block.
///
/// Neither is silent corruption of *someone else's* data, which is the property
/// that matters: a live tree that changes under a snapshot yields a file that
/// is some prefix of one of its versions, and never another file's bytes.
fn emit_host_file_blocks<E, F>(
    emit: &mut F,
    img: &Image,
    p: &Planned,
    source: &std::path::Path,
    len: usize,
) -> Result<(), E>
where
    F: FnMut(u64, &[u8]) -> Result<(), E>,
{
    // A file that cannot be reopened leaves its extents as holes rather than
    // failing the build. The walk already accepted it; a tree that changes
    // between walk and emit is the case this whole path exists to tolerate,
    // and `VanishedNodePolicy` makes the same choice one stage earlier.
    let Ok(file) = std::fs::File::open(source) else {
        return Ok(());
    };
    let mut reader = std::io::BufReader::new(file);

    let mut buf = vec![0u8; BLOCK_SIZE_USIZE];
    let mut written = 0usize;
    for ext in &p.extents {
        if written >= len {
            break;
        }
        let span = ext.len as usize * BLOCK_SIZE_USIZE;
        let mut offset_in_extent = 0usize;
        while offset_in_extent < span && written + offset_in_extent < len {
            let want = buf
                .len()
                .min(span - offset_in_extent)
                .min(len - written - offset_in_extent);
            let got = read_up_to(&mut reader, &mut buf[..want]);
            if got == 0 {
                // Short file: stop. The rest of the layout stays a hole.
                return Ok(());
            }
            emit(
                img.block_off(ext.phys) as u64 + offset_in_extent as u64,
                &buf[..got],
            )?;
            offset_in_extent += got;
        }
        written += span;
    }
    Ok(())
}

/// Fill `buf` as far as the reader allows, returning how many bytes landed.
///
/// `Read::read` may return short without being at EOF, and a partial block
/// emitted as if it were a whole one would leave a gap in the middle of a
/// file. Looping here keeps the emit offsets contiguous.
fn read_up_to<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    filled
}

// ── path helpers ────────────────────────────────────────────────────────────

fn normalize(path: &str) -> Result<String, Ext4Error> {
    if !path.starts_with('/') {
        return Err(Ext4Error::BadPath(path.to_string()));
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    // Every component must be a valid directory-entry name: no empty segment
    // (`//`), no `.`/`..` (would alias another path or escape), and no NUL
    // (un-representable in an ext4 dirent). `trimmed[1..]` drops the leading '/'.
    for seg in trimmed[1..].split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('\0') {
            return Err(Ext4Error::BadPath(path.to_string()));
        }
    }
    Ok(trimmed.to_string())
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

#[cfg(test)]
mod tests {
    use super::{BuildOptions, EmitImageError, build_image_with_options, emit_image_with_options};

    #[test]
    fn build_options_stamp_superblock_uuid_and_volume_name() {
        let uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let image = build_image_with_options(
            Vec::new(),
            &BuildOptions::default()
                .with_uuid(uuid)
                .with_volume_name(b"mvm-rootfs"),
        )
        .expect("build image");

        assert_eq!(&image[1024 + 0x68..1024 + 0x78], &uuid);
        assert_eq!(&image[1024 + 0x78..1024 + 0x82], b"mvm-rootfs");
    }

    #[test]
    fn streamed_emission_matches_dense_image() {
        let nodes = vec![
            super::Node::Dir {
                path: "/etc".into(),
                mode: 0o755,
                xattrs: Vec::new(),
            },
            super::Node::Dir {
                path: "/bin".into(),
                mode: 0o755,
                xattrs: Vec::new(),
            },
            super::Node::File {
                path: "/etc/hosts".into(),
                mode: 0o644,
                data: b"127.0.0.1 localhost\n".to_vec(),
                xattrs: Vec::new(),
            },
            super::Node::File {
                path: "/bin/hello".into(),
                mode: 0o755,
                data: vec![0x7f; super::BLOCK_SIZE_USIZE + 31],
                xattrs: Vec::new(),
            },
        ];
        let dense =
            build_image_with_options(nodes.clone(), &BuildOptions::default()).expect("dense");
        let mut streamed = Vec::new();
        let total = emit_image_with_options(nodes, &BuildOptions::default(), |offset, bytes| {
            let start = offset as usize;
            let end = start + bytes.len();
            if streamed.len() < end {
                streamed.resize(end, 0);
            }
            streamed[start..end].copy_from_slice(bytes);
            Ok::<(), std::convert::Infallible>(())
        })
        .expect("streamed emit");
        streamed.resize(total as usize, 0);
        assert_eq!(streamed, dense, "streamed and dense bytes must match");
    }

    #[test]
    fn streamed_emission_surfaces_sink_errors() {
        let nodes = vec![super::Node::File {
            path: "/payload".into(),
            mode: 0o644,
            data: vec![1u8; super::BLOCK_SIZE_USIZE * 2],
            xattrs: Vec::new(),
        }];
        let err = emit_image_with_options(nodes, &BuildOptions::default(), |_offset, _bytes| {
            Err::<(), _>("synthetic sink failure")
        })
        .expect_err("sink error must surface");
        match err {
            EmitImageError::Emit(reason) => assert_eq!(reason, "synthetic sink failure"),
            other => panic!("expected sink failure, got {other:?}"),
        }
    }
}
