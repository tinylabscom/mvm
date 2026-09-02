//! Top-level filesystem handle. Composes block_io + superblock + bgd + inode + extent + dir.

use crate::bgd::{self, BlockGroupDescriptor};
use crate::block_io::BlockDevice;
use crate::checksum::Checksummer;
use crate::error::{Error, Result};
use crate::features;
use crate::inode::Inode;
use crate::superblock::Superblock;
use std::collections::BTreeMap;
use std::sync::Arc;

/// In-memory accumulator for journaled multi-block writes. Each helper
/// mutation reads the latest version of a block (from this buffer if
/// already touched, else from disk via the live `Filesystem`) and writes
/// back into the buffer. The op then commits the whole buffer atomically.
///
/// `BTreeMap` so the commit order is deterministic — replay applies
/// blocks in journal-stored order, matching the kernel's expected
/// transaction layout.
pub(crate) struct BlockBuffer {
    pub block_size: u32,
    pub dirty: BTreeMap<u64, Vec<u8>>,
}

impl BlockBuffer {
    pub fn new(block_size: u32) -> Self {
        Self {
            block_size,
            dirty: BTreeMap::new(),
        }
    }

    /// Fetch a mutable handle to `block`, loading from `fs` on first
    /// touch. Subsequent calls for the same block return the in-buffer
    /// copy so multiple helpers can compose patches.
    pub fn get_mut(&mut self, fs: &Filesystem, block: u64) -> Result<&mut Vec<u8>> {
        if let std::collections::btree_map::Entry::Vacant(e) = self.dirty.entry(block) {
            let buf = fs.read_block(block)?;
            e.insert(buf);
        }
        Ok(self.dirty.get_mut(&block).unwrap())
    }

    /// Stage an already-built block image directly (no read-modify cycle).
    /// Useful when the caller has the bytes in hand (e.g. data blocks of
    /// a file write).
    pub fn put(&mut self, block: u64, bytes: Vec<u8>) {
        self.dirty.insert(block, bytes);
    }
}

/// Patch a split u32 counter (lo: u16 + optional hi: u16) in `buf` by `delta`.
///
/// ext4 BGD counters are stored as a 16-bit low word at `lo_off` and an
/// optional 16-bit high word at `hi_off` (present when desc_size >= 64). The
/// combined 32-bit value is clamped to zero on underflow.
fn patch_counter_u32(buf: &mut [u8], lo_off: usize, hi_off: Option<usize>, delta: i32) {
    let cur_lo = u16::from_le_bytes(buf[lo_off..lo_off + 2].try_into().unwrap()) as u32;
    let cur_hi = hi_off
        .map(|h| u16::from_le_bytes(buf[h..h + 2].try_into().unwrap()) as u32)
        .unwrap_or(0);
    let cur = (cur_hi << 16) | cur_lo;
    let new = (cur as i64 + delta as i64).clamp(0, u32::MAX as i64) as u32;
    buf[lo_off..lo_off + 2].copy_from_slice(&((new & 0xFFFF) as u16).to_le_bytes());
    if let Some(h) = hi_off {
        buf[h..h + 2].copy_from_slice(&(((new >> 16) & 0xFFFF) as u16).to_le_bytes());
    }
}

/// Pack the low bits of an ext4 nanosecond timestamp field.
///
/// ext4 stores extra precision in a 32-bit extra field: bits [31:2] hold the
/// low 30 bits of the nanosecond value; bits [1:0] are the 2-bit epoch
/// extension that extends the 32-bit seconds counter beyond 2038.
#[inline]
fn pack_nsec_lo(nsec: u32) -> u32 {
    (nsec & 0x3FFF_FFFF) << 2
}

/// Split a `/a/b/c` path into (`/a/b`, `c`). Returns an error for empty or
/// `"/"` paths (no basename to act on).
fn split_parent_and_base(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument("empty path"));
    }
    let last_slash = trimmed
        .rfind('/')
        .ok_or(Error::InvalidArgument("relative path"))?;
    let base = &trimmed[last_slash + 1..];
    let parent = if last_slash == 0 {
        "/"
    } else {
        &trimmed[..last_slash]
    };
    if base.is_empty() {
        // Trailing slash on a non-dir path is POSIX ENOTDIR, not a generic arg error.
        return Err(Error::NotADirectory);
    }
    Ok((parent.to_string(), base.to_string()))
}

/// `DeepReader` adapter that pulls extent-tree internal/leaf node blocks
/// straight from a `Filesystem`'s underlying device (which at mount time
/// is wrapped in a `CachedDevice`, so reads benefit from the buffer cache
/// holding post-commit pre-checkpoint journaled writes).
///
/// Used by `apply_pwrite` to satisfy `plan_insert_extent_deep`'s
/// `&dyn DeepReader` argument when the inline extent root overflows and
/// the tree needs to be promoted to depth ≥ 1.
pub(crate) struct FsBlockReader<'a> {
    pub(crate) fs: &'a Filesystem,
}

impl<'a> crate::extent_mut::DeepReader for FsBlockReader<'a> {
    fn read_block(&self, block: u64, out: &mut [u8]) -> Result<()> {
        let bytes = self.fs.read_block(block)?;
        if bytes.len() != out.len() {
            return Err(Error::Corrupt(
                "FsBlockReader: block length mismatch (callers must pass a buffer sized to fs block_size)",
            ));
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }
}

/// Current wall time as a u32 — matches ext4's `i_dtime` field. Uses
/// `SystemTime::now()`; we don't care about monotonicity here, just that
/// `dtime > ctime` so `ext4 audit tool` recognises the slot as recently deleted.
fn now_unix_seconds() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// -----------------------------------------------------------------------
// Inode builder helpers (H2)
// -----------------------------------------------------------------------
// Shared across all build_*_inode functions. Extracted to avoid five
// identical copies of timestamps, generation, extra_isize, and checksum.

use std::sync::atomic::{AtomicU32, Ordering};
/// Process-lifetime counter shared by all inode builders so successive
/// creates within the same session produce distinct i_generation values.
static INODE_GEN_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Write atime, ctime, mtime (and crtime when the inode buffer is large
/// enough) from `now` into the raw inode bytes.
fn write_inode_timestamps(raw: &mut [u8], now: u32) {
    use crate::inode::{INODE_SIZE_WITH_CRTIME, OFF_ATIME, OFF_CRTIME, OFF_CTIME, OFF_MTIME};
    raw[OFF_ATIME..OFF_ATIME + 4].copy_from_slice(&now.to_le_bytes());
    raw[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&now.to_le_bytes());
    raw[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&now.to_le_bytes());
    // i_crtime (birth time) only exists in the extra section. Without it,
    // Darwin's st_birthtime / Finder "Created" date shows 1970-01-01.
    if raw.len() >= INODE_SIZE_WITH_CRTIME {
        raw[OFF_CRTIME..OFF_CRTIME + 4].copy_from_slice(&now.to_le_bytes());
    }
}

/// Allocate a unique i_generation value for a new inode: PID combined with
/// a per-process counter. Ensures distinct values across rapid successive
/// creates (NFS stale-handle detection depends on generation uniqueness).
fn alloc_inode_generation() -> u32 {
    std::process::id().wrapping_add(INODE_GEN_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Write a pre-allocated generation value into the raw inode bytes.
fn write_inode_generation(raw: &mut [u8], generation: u32) {
    use crate::inode::OFF_GENERATION;
    raw[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&generation.to_le_bytes());
}

/// Write i_extra_isize = 32 when the inode buffer is large enough.
/// 32 covers checksum_hi, nsec timestamps, and i_crtime beyond the 128-byte base.
fn write_inode_extra_isize(raw: &mut [u8]) {
    use crate::inode::{EXTRA_ISIZE_DEFAULT, INODE_SIZE_WITH_EXTRA, OFF_EXTRA_ISIZE};
    if raw.len() >= INODE_SIZE_WITH_EXTRA {
        raw[OFF_EXTRA_ISIZE..OFF_EXTRA_ISIZE + 2]
            .copy_from_slice(&EXTRA_ISIZE_DEFAULT.to_le_bytes());
    }
}

pub struct Filesystem {
    pub dev: Arc<dyn BlockDevice>,
    pub sb: Superblock,
    pub groups: Vec<BlockGroupDescriptor>,
    pub csum: Checksummer,
    /// Dialect detected at mount time from the superblock's feature flags.
    /// Drives runtime dispatch where ext2 / ext3 / ext4 differ — most
    /// notably the inode block-mapping scheme (extent vs indirect) used
    /// when allocating new inodes.
    pub flavor: features::FsFlavor,
    /// Live-write journal writer, present iff the FS has a journal AND
    /// the device is writable. `None` for read-only mounts and for ext2-
    /// style images. Locked per-op so mutating capi calls serialize on
    /// the JBD2 sequence cursor.
    pub journal: Option<std::sync::Mutex<crate::journal_writer::JournalWriter>>,
}

/// Encapsulates the common setup for creating a new inode in a directory:
/// resolved parent, pre-allocated inode number, and a `BlockBuffer` with the
/// inode-bitmap + BGD + SB counter updates already staged. Produced by
/// `Filesystem::plan_new_inode_in_dir`.
struct NewInodePlan {
    /// Newly allocated inode number (1-based).
    new_ino: u32,
    /// Inode number of the parent directory.
    parent_ino: u32,
    /// Parsed parent inode (for reading the directory block).
    parent_inode: crate::inode::Inode,
    /// Staged write buffer (bitmap + counter deltas already applied).
    buf: BlockBuffer,
    /// Final component of `path` — the name to add as a dir entry.
    base_name: String,
}

impl Filesystem {
    /// Mount the ext4 filesystem on `dev`. Read-only unless the device reports
    /// `is_writable()`, in which case a dirty journal is replayed before
    /// returning so callers see a consistent on-disk state.
    ///
    /// When `RO_COMPAT_METADATA_CSUM` is set, the superblock checksum is
    /// verified — failure aborts the mount with `Error::BadChecksum`.
    pub fn mount(dev: Arc<dyn BlockDevice>) -> Result<Self> {
        Self::mount_inner(dev, false)
    }

    /// Like `mount`, but skips the mount-time journal replay even when the
    /// device is writable. The caller is responsible for invoking
    /// [`Filesystem::replay_journal_if_dirty`] once the underlying write
    /// path is actually ready to service writes (e.g. in the FSKit case the
    /// kernel-level write FD on `FSBlockDeviceResource` only becomes
    /// writable AFTER `loadResource` returns successfully — replaying mid-
    /// `loadResource` produces EIO).
    ///
    /// Until replay runs, reads observe the on-disk pre-replay state and
    /// any write through this handle will fail (the journal still says
    /// dirty). This is the lazy/deferred-replay sibling of `mount`; for
    /// most callers `mount` is correct.
    pub fn mount_lazy(dev: Arc<dyn BlockDevice>) -> Result<Self> {
        Self::mount_inner(dev, true)
    }

    fn mount_inner(dev: Arc<dyn BlockDevice>, defer_replay: bool) -> Result<Self> {
        let sb = Superblock::read(dev.as_ref())?;
        features::check_mountable(sb.feature_incompat, sb.feature_ro_compat)?;
        let flavor = features::FsFlavor::detect(sb.feature_compat, sb.feature_incompat);
        let csum = Checksummer::from_superblock(&sb);
        if csum.enabled && !csum.verify_superblock(&sb.raw) {
            return Err(Error::BadChecksum { what: "superblock" });
        }
        let groups = bgd::read_all(dev.as_ref(), &sb, &csum)?;
        // Wrap the raw device in a write-through buffer cache. All
        // reads and writes for the rest of this mount session route
        // through the cache; `commit_block_buffer` populates pinned
        // entries with journaled-but-not-yet-checkpointed bytes so
        // allocator scans don't re-read stale on-disk bitmaps. This is
        // the role Linux's buffer cache plays for journaled
        // filesystems. Capacity 256 ≈ 1 MiB at 4 KiB blocks — enough
        // to cover hot metadata (BGD, bitmaps, recently-touched inode
        // blocks) for typical sessions; pinned entries are unbounded
        // until journal replay calls `unpin_all`.
        let dev: Arc<dyn BlockDevice> = Arc::new(crate::block_cache::CachedDevice::new(
            dev,
            sb.block_size(),
            256,
        ));
        let mut fs = Self {
            dev,
            sb,
            groups,
            csum,
            flavor,
            journal: None,
        };

        // Replay a dirty journal if the device is writable. Silently skips
        // for read-only mounts — the read path tolerates a non-clean journal
        // (pending transactions are invisible, which is correct for a
        // read-only view).
        //
        // Both the walker (`journal_block_to_physical`) and the writer
        // (`JournalWriter::open`) now dispatch on `indirect::map_logical_any`,
        // so ext3 (whose journal inode uses legacy indirect block pointers)
        // works the same as ext4 (extent tree). The Phase A blanket refusal
        // of ext3 RW is therefore lifted.
        if !defer_replay && fs.dev.is_writable() {
            // Best-effort: a replay failure here is logged via the returned
            // error but does NOT abort the mount, because many images have
            // cosmetic journal issues that shouldn't prevent read access.
            // The error surfaces up so the caller can decide whether to
            // retry or proceed; we fail loud rather than silent.
            crate::journal_apply::replay_if_dirty(&fs)?;
        }

        // Open the live-write journal writer once replay is done. Any
        // pending transactions are now applied; the writer can take over
        // the JBD2 cursor from a clean state. Returns None when there is
        // no journal at all (ext2), so the if-let handles every flavor
        // uniformly.
        if fs.dev.is_writable() {
            if let Some(jw) = crate::journal_writer::JournalWriter::open(&fs)? {
                fs.journal = Some(std::sync::Mutex::new(jw));
            }
        }

        // Phase 6.2 — orphan recovery. Runs after journal replay so any
        // pending kernel-level transactions have already played back;
        // any inode still on the orphan chain at this point is genuinely
        // dead and we can reclaim it. Best-effort: a recovery failure
        // surfaces as an error but doesn't abort the mount.
        if fs.dev.is_writable() && !defer_replay {
            let _ = fs.recover_orphans();
        }

        Ok(fs)
    }

    /// Run journal replay now if the journal is dirty. Idempotent — calling
    /// this on a clean (or read-only) volume is a no-op that returns 0.
    /// Designed to pair with [`Filesystem::mount_lazy`], but safe to call
    /// on any handle.
    pub fn replay_journal_if_dirty(&self) -> Result<usize> {
        let n = crate::journal_apply::replay_if_dirty(self)?;
        // Replay applied every pending journaled write to the data area,
        // so the device-layer cache's "pinned" entries (post-commit but
        // pre-checkpoint) are now consistent with disk. Tell the cache
        // it can stop pinning them — future evictions are safe.
        // Skip when nothing replayed: a clean journal returns 0, and
        // unpinning here would demote pinned-but-still-needed entries
        // from a live handle's prior journaled writes, letting later
        // cache misses serve stale data-area bytes.
        if n > 0 {
            self.dev.unpin_all();
        }
        Ok(n)
    }

    /// Phase 6.1 — walk the orphan inode chain rooted at `s_last_orphan`
    /// and return its members in chain order.
    ///
    /// Each orphan inode is a unlink-while-open candidate: its data
    /// blocks should be reclaimed by recovery. The chain is encoded by
    /// overloading `i_dtime` as "next orphan inode number"; the chain
    /// terminates when `dtime == 0`. We cap at `inodes_count` to avoid
    /// runaway loops on cycle-corrupted images.
    ///
    /// Read-only (no recovery yet — that's Phase 6.2). Returns `Ok([])`
    /// when there are no orphans.
    pub fn orphan_list(&self) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut cur = self.sb.last_orphan;
        let cap = self.sb.inodes_count;
        let mut steps = 0u32;
        while cur != 0 {
            if steps > cap {
                return Err(Error::Corrupt(
                    "orphan_list: chain longer than inodes_count (cycle?)",
                ));
            }
            out.push(cur);
            // Read the inode's i_dtime (offset 0x14..0x18) to find the
            // next link. Don't go through read_inode_verified because an
            // orphan inode's checksum may be stale by design.
            let raw = self.read_inode_raw(cur)?;
            if raw.len() < 0x18 {
                return Err(Error::Corrupt("orphan_list: inode too short"));
            }
            cur = u32::from_le_bytes(raw[0x14..0x18].try_into().unwrap());
            steps += 1;
        }
        Ok(out)
    }

    /// Phase 6.2 — orphan replay. For each inode on the
    /// `s_last_orphan` chain, free its data blocks + inode-bitmap slot,
    /// zero its inode body (with `i_dtime = now`), and clear
    /// `s_last_orphan`. Runs as ONE multi-block journaled transaction
    /// so a crash mid-recovery either commits all the frees or none of
    /// them.
    ///
    /// Returns the number of orphan inodes reclaimed. No-op (returns 0)
    /// when the chain is empty or the device is read-only.
    ///
    /// Designed to be called from the mount path AFTER journal replay,
    /// so the orphans we're about to reclaim are guaranteed not still in
    /// use by an in-flight kernel-level transaction.
    pub fn recover_orphans(&self) -> Result<usize> {
        if !self.dev.is_writable() {
            return Ok(0);
        }
        let chain = self.orphan_list()?;
        if chain.is_empty() {
            return Ok(0);
        }

        let bs = self.sb.block_size();
        let sectors_per_block = bs as u64 / 512;
        let mut buf = BlockBuffer::new(bs);
        let mut total_freed_blocks: u64 = 0;
        let mut reclaimed = 0usize;

        for &orphan_ino in &chain {
            // Read the orphan's raw bytes (skip csum verify — orphan
            // inodes routinely carry stale csums by design).
            let mut raw = self.read_inode_raw(orphan_ino)?;
            let parsed = match Inode::parse(&raw) {
                Ok(i) => i,
                Err(_) => continue, // unparseable orphan — skip + leak rather than panic
            };
            // Free data blocks (extents path only — orphan recovery for
            // legacy indirect inodes is a follow-up).
            if parsed.has_extents() && parsed.size > 0 {
                let (_sc, muts) = match crate::file_mut::plan_truncate_shrink(
                    parsed.size,
                    0,
                    &parsed.block,
                    bs,
                ) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                for m in &muts {
                    if let crate::extent_mut::ExtentMutation::FreePhysicalRun { start, len } = m {
                        total_freed_blocks +=
                            self.buffer_free_block_run_and_bgd(&mut buf, *start, *len as u64)?;
                    }
                }
            }
            // Free the inode bitmap slot + BGD free_inodes++.
            self.buffer_free_inode_slot(&mut buf, orphan_ino)?;

            // Zero the inode body (preserve generation), set dtime.
            let inode_size = self.sb.inode_size as usize;
            let old_gen = parsed.generation;
            for b in &mut raw[..inode_size] {
                *b = 0;
            }
            let dtime = now_unix_seconds();
            raw[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
            raw[0x64..0x68].copy_from_slice(&old_gen.to_le_bytes());
            self.finalize_inode_raw(orphan_ino, old_gen, &mut raw)?;
            self.buffer_write_inode(&mut buf, orphan_ino, &raw)?;

            reclaimed += 1;
        }

        // SB: free_blocks_count += total_freed, free_inodes_count +=
        // reclaimed, s_last_orphan = 0.
        self.buffer_patch_sb_counters(&mut buf, total_freed_blocks as i64, reclaimed as i32)?;
        self.buffer_patch_sb_last_orphan(&mut buf, 0)?;

        // i_blocks tracking on the freed inodes is moot (they're zero
        // now); their per-extent sectors are accounted for in the
        // BGD/SB counter updates above.
        let _ = sectors_per_block;

        self.commit_block_buffer(buf)?;
        Ok(reclaimed)
    }

    /// Read a whole block by its logical block number. Routes through
    /// `self.dev`, which at mount time is wrapped in a `CachedDevice` —
    /// so this single call benefits from the buffer cache that holds
    /// post-commit, pre-checkpoint journaled writes.
    pub fn read_block(&self, block_num: u64) -> Result<Vec<u8>> {
        let block_size = self.sb.block_size() as usize;
        let byte_offset = block_num
            .checked_mul(block_size as u64)
            .ok_or(Error::Corrupt("block byte offset overflow"))?;
        let mut buf = vec![0u8; block_size];
        self.dev.read_at(byte_offset, &mut buf)?;
        Ok(buf)
    }

    /// Read raw inode bytes for a given inode number (does not parse).
    pub fn read_inode_raw(&self, ino: u32) -> Result<Vec<u8>> {
        let (block, offset) = bgd::locate_inode(&self.sb, &self.groups, ino)?;
        let block_data = self.read_block(block)?;
        let inode_size = self.sb.inode_size as usize;
        let off = offset as usize;
        let end = off
            .checked_add(inode_size)
            .ok_or(Error::Corrupt("inode slice end overflows usize"))?;
        if end > block_data.len() {
            return Err(Error::Corrupt("inode slice exceeds block data"));
        }
        Ok(block_data[off..end].to_vec())
    }

    /// Read + parse + checksum-verify an inode in one shot.
    ///
    /// When `RO_COMPAT_METADATA_CSUM` is enabled the inode CRC32C is checked
    /// (salted by inode number + generation per ext4 spec). A mismatch
    /// returns `Error::BadChecksum { what: "inode" }`.
    pub fn read_inode_verified(&self, ino: u32) -> Result<(Inode, Vec<u8>)> {
        let raw = self.read_inode_raw(ino)?;
        let inode = Inode::parse(&raw)?;
        if self.csum.enabled && !self.csum.verify_inode(ino, inode.generation, &raw) {
            return Err(Error::BadChecksum { what: "inode" });
        }
        Ok((inode, raw))
    }

    /// Map a logical block within `inode` to its physical block, choosing
    /// between the extent tree and the legacy direct/indirect scheme based
    /// on `EXT4_EXTENTS_FL`. Returns `None` for sparse holes and (for the
    /// extent path) uninitialised extents — callers wanting zeros there
    /// must handle the `None` case explicitly.
    ///
    /// This is the per-inode dispatcher every directory traversal /
    /// extent-walking call site should use instead of touching
    /// `extent::map_logical` directly — without it, an ext2/3 inode with
    /// raw block pointers in `i_block` gets misparsed as an extent header
    /// (yielding `CorruptExtentTree("bad extent header magic")`).
    ///
    /// The indirect path internally maintains its own block cache for the
    /// duration of the call; sequential lookups via repeated calls don't
    /// share that cache (file_io's read paths build a longer-lived cache
    /// to amortize across blocks).
    pub fn map_inode_logical(&self, inode: &Inode, logical_block: u64) -> Result<Option<u64>> {
        let bs = self.sb.block_size();
        if (inode.flags & crate::inode::InodeFlags::EXTENTS.bits()) != 0 {
            crate::extent::map_logical(&inode.block, self.dev.as_ref(), bs, logical_block)
        } else {
            let mut cache = crate::indirect::IndirectCache::new();
            crate::indirect::lookup(
                &inode.block,
                self.dev.as_ref(),
                bs,
                logical_block,
                &mut cache,
            )
        }
    }

    /// Write the given raw inode bytes back to disk. Read-only devices return
    /// the default `Error::Corrupt` from `BlockDevice::write_at`.
    ///
    /// **Not checksum-aware**: callers that update fields affecting the inode
    /// CRC32C (anything except `checksum_lo` / `checksum_hi`) must recompute
    /// + patch the checksum into `raw` before calling this. Not wrapped in a
    /// journal transaction — see E11 / `journal_apply` for the journaled
    /// version. Use only when the caller has the full write-ordering story
    /// under control.
    pub fn write_inode_raw(&self, ino: u32, raw: &[u8]) -> Result<()> {
        if raw.len() != self.sb.inode_size as usize {
            return Err(Error::Corrupt("write_inode_raw: length != inode_size"));
        }
        let (block, offset) = bgd::locate_inode(&self.sb, &self.groups, ino)?;
        let block_size = self.sb.block_size() as u64;
        let byte_offset = block * block_size + offset as u64;
        self.dev.write_at(byte_offset, raw)?;
        Ok(())
    }

    /// Patch fields in a raw inode image: size, blocks_count. Leaves all
    /// other bytes (including the extent tree header + entries in `i_block`)
    /// intact. `new_block_count` is in 512-byte sectors per spec (same
    /// convention as `Inode::blocks`).
    pub fn patch_inode_size_and_blocks(
        raw: &mut [u8],
        new_size: u64,
        new_block_count: u64,
    ) -> Result<()> {
        if raw.len() < 128 {
            return Err(Error::Corrupt("patch_inode: buffer too small"));
        }
        // size = size_lo (0x04..0x08) + size_hi (0x6C..0x70)
        let size_lo = (new_size & 0xFFFF_FFFF) as u32;
        let size_hi = (new_size >> 32) as u32;
        raw[0x04..0x08].copy_from_slice(&size_lo.to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&size_hi.to_le_bytes());
        // blocks = blocks_lo (0x1C..0x20, u32) + blocks_hi (0x74..0x76, u16)
        let blocks_lo = (new_block_count & 0xFFFF_FFFF) as u32;
        let blocks_hi = ((new_block_count >> 32) & 0xFFFF) as u16;
        raw[0x1C..0x20].copy_from_slice(&blocks_lo.to_le_bytes());
        raw[0x74..0x76].copy_from_slice(&blocks_hi.to_le_bytes());
        Ok(())
    }

    /// Overwrite the 60-byte `i_block` area of an inode image with `new_root`.
    /// Used when an extent-tree mutation changes the inline root.
    pub fn patch_inode_block_area(raw: &mut [u8], new_root: &[u8]) -> Result<()> {
        if raw.len() < 128 {
            return Err(Error::Corrupt("patch_inode_block_area: buffer too small"));
        }
        if new_root.len() != 60 {
            return Err(Error::Corrupt(
                "patch_inode_block_area: new_root != 60 bytes",
            ));
        }
        raw[0x28..0x64].copy_from_slice(new_root);
        Ok(())
    }

    /// Shrink a file to `new_size`. Composes `file_mut::plan_truncate_shrink`
    /// (extent-tree updates + freed-block ranges) with actual disk writes —
    /// rewrites the inode and zeros the freed bitmap bits.
    ///
    /// Not journaled. Safe to call only in a context where crash consistency
    /// is handled elsewhere (e.g. a test scratch image). A future revision
    /// will route this through a JBD2 transaction so the inode write + bitmap
    /// writes are atomic with respect to a crash.
    pub fn apply_truncate_shrink(&self, ino: u32, new_size: u64) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if new_size > inode.size {
            return Err(Error::InvalidArgument(
                "truncate: new_size > old_size (grow not supported)",
            ));
        }

        let (_size_change, muts) = crate::file_mut::plan_truncate_shrink(
            inode.size,
            new_size,
            &inode.block,
            self.sb.block_size(),
        )?;

        let bs = self.sb.block_size() as u64;
        let mut freed_sectors: u64 = 0;
        let mut freed_blocks: u64 = 0;

        // Multi-block transaction: accumulate inode + bitmap + BGD + SB
        // mutations into one buffer, commit through the journal atomically.
        let mut buf = BlockBuffer::new(self.sb.block_size());

        for m in &muts {
            match m {
                crate::extent_mut::ExtentMutation::WriteRoot { bytes } => {
                    Self::patch_inode_block_area(&mut raw, bytes)?;
                }
                crate::extent_mut::ExtentMutation::FreePhysicalRun { start, len } => {
                    freed_blocks +=
                        self.buffer_free_block_run_and_bgd(&mut buf, *start, *len as u64)?;
                    freed_sectors += (*len as u64) * (bs / 512);
                }
                _ => {
                    return Err(Error::Corrupt(
                        "apply_truncate_shrink: unexpected mutation type",
                    ));
                }
            }
        }

        // Patch size + blocks_count in the inode image, finalize csum.
        let new_blocks = inode.blocks.saturating_sub(freed_sectors);
        Self::patch_inode_size_and_blocks(&mut raw, new_size, new_blocks)?;
        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.buffer_write_inode(&mut buf, ino, &raw)?;

        if freed_blocks > 0 {
            self.buffer_patch_sb_counters(&mut buf, freed_blocks as i64, 0)?;
        }

        self.commit_block_buffer(buf)
    }

    /// Extend a file to `new_size`. The new range is a sparse hole — ext4's
    /// extent tree treats unmapped logical blocks as zeros, so no extent
    /// mutation and no block allocation are required. Only `i_size`,
    /// `i_mtime`, `i_ctime`, and the inode checksum change.
    ///
    /// Caller (capi dispatch) guarantees `new_size >= inode.size`. If
    /// `new_size == inode.size` this is a no-op that still bumps the
    /// timestamps — matches `truncate(2)` semantics.
    pub fn apply_truncate_grow(&self, ino: u32, new_size: u64) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if new_size < inode.size {
            return Err(Error::InvalidArgument(
                "apply_truncate_grow: new_size < old_size (use apply_truncate_shrink)",
            ));
        }
        Self::patch_inode_size_and_blocks(&mut raw, new_size, inode.blocks)?;

        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes()); // ctime
        raw[0x10..0x14].copy_from_slice(&now.to_le_bytes()); // mtime

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.commit_inode_write(ino, &raw)
    }

    /// Phase 2.2: `fallocate(FALLOC_FL_KEEP_SIZE)` — preallocate blocks
    /// in the byte range `[offset, offset+len)` as uninitialized
    /// extents. The blocks are reserved (count against `i_blocks`) but
    /// reads return zeros until they're written. `i_size` is left
    /// unchanged per KEEP_SIZE semantics.
    ///
    /// v1 limitations:
    /// - Range must be entirely unmapped — partially-overlapping ranges
    ///   return `Error::InvalidArgument`. (Splitting around existing
    ///   extents is a follow-up.)
    /// - Single contiguous physical allocation. If the bitmap can't
    ///   serve `ceil(len / block_size)` contiguous blocks, returns
    ///   `Error::Corrupt("no group has a contiguous free run...")`.
    /// - Extent insertion must succeed against the inline-root depth-0
    ///   tree (or trigger the existing depth-1 promotion). Multi-level
    ///   trees aren't yet supported.
    pub fn apply_fallocate_keep_size(&self, ino: u32, offset: u64, len: u64) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        if len == 0 {
            return Ok(());
        }
        let bs = self.sb.block_size() as u64;
        let bs_u32 = self.sb.block_size();
        let first_block = offset / bs;
        let last_block_excl = offset
            .checked_add(len)
            .ok_or(Error::InvalidArgument("fallocate: offset+len overflow"))?
            .div_ceil(bs);
        let need_blocks_u64 = last_block_excl - first_block;
        if need_blocks_u64 > u32::MAX as u64 {
            return Err(Error::InvalidArgument(
                "fallocate: range exceeds u32 block count",
            ));
        }
        let need_blocks = need_blocks_u64 as u32;

        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument(
                "fallocate: target is not a regular file",
            ));
        }
        if !inode.has_extents() {
            return Err(Error::InvalidArgument(
                "fallocate: legacy (non-extents) inodes not supported",
            ));
        }

        // V1: refuse if any block in range is already mapped — handling
        // the partial-overlap case requires splitting existing extents
        // mid-range, deferred to a follow-up.
        for log in first_block..last_block_excl {
            if crate::extent::map_logical(&inode.block, self.dev.as_ref(), bs_u32, log)?.is_some() {
                return Err(Error::InvalidArgument(
                    "fallocate: range partially mapped (v1 limitation)",
                ));
            }
        }

        // Allocate one contiguous physical run.
        let inode_group = (ino - 1) / self.sb.inodes_per_group;
        let mut bitmap_reader = |block: u64| self.read_block(block);
        let plan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            need_blocks,
            inode_group,
            &mut bitmap_reader,
        )?;

        // Insert as an uninitialized extent so reads see zeros without
        // hitting disk. Clamp to u16 — the range check above already
        // bounded need_blocks, but the on-disk extent length is u16.
        if need_blocks > 0x7FFF {
            return Err(Error::InvalidArgument(
                "fallocate: single-extent length > 32K blocks (split needed)",
            ));
        }
        let new_extent = crate::extent::Extent {
            logical_block: first_block as u32,
            length: need_blocks as u16,
            physical_block: plan.first_block,
            uninitialized: true,
        };
        let muts = crate::extent_mut::plan_insert_extent(&inode.block, new_extent)?;

        // Apply via BlockBuffer — atomic across bitmap, BGD, SB, inode.
        let mut buf = BlockBuffer::new(self.sb.block_size());
        self.buffer_mark_block_run_used(&mut buf, plan.first_block, need_blocks as u64)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            plan.sb.free_blocks_delta,
            plan.sb.free_inodes_delta,
        )?;

        // Splice the new extent root into the inode image.
        for m in &muts {
            if let crate::extent_mut::ExtentMutation::WriteRoot { bytes } = m {
                Self::patch_inode_block_area(&mut raw, bytes)?;
            }
        }

        // Bump i_blocks (sectors). KEEP_SIZE: i_size unchanged.
        let sectors_per_block = bs / 512;
        let new_i_blocks = inode
            .blocks
            .saturating_add(need_blocks as u64 * sectors_per_block);
        Self::patch_inode_size_and_blocks(&mut raw, inode.size, new_i_blocks)?;

        // POSIX: fallocate bumps mtime + ctime.
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());
        raw[0x10..0x14].copy_from_slice(&now.to_le_bytes());

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.buffer_write_inode(&mut buf, ino, &raw)?;

        self.commit_block_buffer(buf)
    }

    /// Phase 2.3 — `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`.
    /// Frees the data blocks underlying `[offset, offset+len)`, splitting
    /// straddling extents as needed. Reads of the punched range return
    /// zeros (sparse hole) thereafter; `i_size` is unchanged.
    ///
    /// v1 limits:
    /// - Depth-0 inline-root extent trees only. Surviving entries must
    ///   fit in 4 slots (the inline-root capacity); anything larger
    ///   returns `Corrupt(...)`. A real punch on a heavily-fragmented
    ///   file may need depth ≥ 1, which is a Phase 4 follow-up.
    /// - Indirect-block (ext2/3) inodes return EINVAL — punch is an
    ///   ext4-specific kernel API.
    pub fn apply_fallocate_punch_hole(&self, ino: u32, offset: u64, len: u64) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        if len == 0 {
            return Ok(());
        }
        let bs = self.sb.block_size() as u64;
        let bs_u32 = self.sb.block_size();
        let punch_first = offset / bs;
        let punch_last_excl = offset
            .checked_add(len)
            .ok_or(Error::InvalidArgument("punch_hole: offset+len overflow"))?
            .div_ceil(bs);

        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument("punch_hole: not a regular file"));
        }
        if !inode.has_extents() {
            return Err(Error::InvalidArgument(
                "punch_hole: legacy (non-extents) inodes not supported",
            ));
        }

        let extents = crate::extent::collect_all(&inode.block, self.dev.as_ref(), bs_u32)?;
        let mut new_entries: Vec<crate::extent::Extent> = Vec::new();
        let mut freed_blocks: u64 = 0;
        let mut buf = BlockBuffer::new(bs_u32);

        for e in &extents {
            let el = e.logical_block as u64;
            let er = el + e.length as u64;

            if er <= punch_first || el >= punch_last_excl {
                // Fully outside the punch range — keep verbatim.
                new_entries.push(*e);
                continue;
            }
            if el >= punch_first && er <= punch_last_excl {
                // Fully inside punch — free entirely.
                freed_blocks += self.buffer_free_block_run_and_bgd(
                    &mut buf,
                    e.physical_block,
                    e.length as u64,
                )?;
                continue;
            }
            // Partial overlap. Compute the freed sub-range; emit head /
            // tail retains around it.
            let free_lo = el.max(punch_first);
            let free_hi = er.min(punch_last_excl);
            let free_offset_in_e = free_lo - el;
            let free_len = (free_hi - free_lo) as u32;
            let free_phys = e.physical_block + free_offset_in_e;
            freed_blocks +=
                self.buffer_free_block_run_and_bgd(&mut buf, free_phys, free_len as u64)?;

            if el < punch_first {
                new_entries.push(crate::extent::Extent {
                    logical_block: el as u32,
                    length: (punch_first - el) as u16,
                    physical_block: e.physical_block,
                    uninitialized: e.uninitialized,
                });
            }
            if er > punch_last_excl {
                new_entries.push(crate::extent::Extent {
                    logical_block: punch_last_excl as u32,
                    length: (er - punch_last_excl) as u16,
                    physical_block: e.physical_block + (punch_last_excl - el),
                    uninitialized: e.uninitialized,
                });
            }
        }

        if new_entries.len() > 4 {
            return Err(Error::Corrupt(
                "punch_hole: surviving entries exceed inline-root capacity (4); needs depth>=1",
            ));
        }

        // Rebuild the inline root with the surviving entries.
        let gen = u32::from_le_bytes(inode.block[8..12].try_into().unwrap());
        let mut root = vec![0u8; 60];
        root[0..2].copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
        root[2..4].copy_from_slice(&(new_entries.len() as u16).to_le_bytes());
        root[4..6].copy_from_slice(&4u16.to_le_bytes());
        // depth = 0 (zero already)
        root[8..12].copy_from_slice(&gen.to_le_bytes());
        for (i, e) in new_entries.iter().enumerate() {
            let off = 12 + i * 12;
            root[off..off + 4].copy_from_slice(&e.logical_block.to_le_bytes());
            let ee_len = if e.uninitialized {
                e.length + crate::extent::EXT_INIT_MAX_LEN
            } else {
                e.length
            };
            root[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
            let (phys_hi, phys_lo) = crate::extent_mut::split_phys_block(e.physical_block);
            root[off + 6..off + 8].copy_from_slice(&phys_hi.to_le_bytes());
            root[off + 8..off + 12].copy_from_slice(&phys_lo.to_le_bytes());
        }
        Self::patch_inode_block_area(&mut raw, &root)?;

        // i_blocks decreases; i_size unchanged (KEEP_SIZE semantics
        // built in — punch always preserves size).
        let sectors_per_block = bs / 512;
        let new_i_blocks = inode
            .blocks
            .saturating_sub(freed_blocks * sectors_per_block);
        Self::patch_inode_size_and_blocks(&mut raw, inode.size, new_i_blocks)?;
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());
        raw[0x10..0x14].copy_from_slice(&now.to_le_bytes());
        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.buffer_write_inode(&mut buf, ino, &raw)?;

        if freed_blocks > 0 {
            self.buffer_patch_sb_counters(&mut buf, freed_blocks as i64, 0)?;
        }

        self.commit_block_buffer(buf)
    }

    /// Phase 2.4 — `fallocate(FALLOC_FL_ZERO_RANGE)`. Logically zero the
    /// byte range `[offset, offset+len)` without writing actual data.
    /// Implemented as punch-hole + KEEP_SIZE preallocate of the same
    /// range, so reads return zeros (uninitialized-extent semantics) and
    /// future writes don't need an allocation.
    ///
    /// Two separate transactions today (punch then alloc); a future
    /// optimization could fold them into one.
    pub fn apply_fallocate_zero_range(&self, ino: u32, offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        self.apply_fallocate_punch_hole(ino, offset, len)?;
        self.apply_fallocate_keep_size(ino, offset, len)
    }

    /// Change the permission bits on `path`. Only the low 12 bits of `mode`
    /// (`S_ISUID|S_ISGID|S_ISVTX` plus rwx/rwx/rwx) are applied; the file-type
    /// bits (`S_IFMT`) are preserved from the existing inode.
    ///
    /// Updates `i_ctime = now` and recomputes the inode checksum on csum-
    /// enabled mounts. Returns `Error::NotFound` if the path doesn't resolve,
    /// `Error::ReadOnly` on a RO mount.
    pub fn apply_chmod(&self, path: &str, mode: u16) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        // Preserve file-type bits (high 4 bits of i_mode); only the low 12
        // permission/suid/sgid/sticky bits are user-settable.
        let file_type_bits = inode.mode & crate::inode::S_IFMT;
        let new_mode = file_type_bits | (mode & 0x0FFF);
        raw[0x00..0x02].copy_from_slice(&new_mode.to_le_bytes());

        // POSIX: chmod bumps ctime (not mtime).
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.commit_inode_write(ino, &raw)
    }

    /// Write a single mutated inode back, routing through the journal
    /// writer when one is available so the change is crash-safe. Falls
    /// back to a direct write + flush on unjournaled mounts.
    ///
    /// Used by every operation whose only mutation is one inode block:
    /// chmod, chown, utimens, and the in-place xattr ops once they're
    /// migrated to the journaled path.
    fn commit_inode_write(&self, ino: u32, new_inode_raw: &[u8]) -> Result<()> {
        let mut buf = BlockBuffer::new(self.sb.block_size());
        self.buffer_write_inode(&mut buf, ino, new_inode_raw)?;
        self.commit_block_buffer(buf)
    }

    // ----------------------------------------------------------------------
    // BlockBuffer helpers (Phase 5.2 multi-block transactions)
    // ----------------------------------------------------------------------
    //
    // These mirror the disk-touching helpers (free_block_run_and_bgd,
    // patch_bgd_counters, patch_sb_counters, write_inode_raw) but operate
    // on an in-memory BlockBuffer instead. A multi-block op accumulates
    // its mutations into one buffer and commits the whole thing atomically
    // — either through the journal writer (when present) or via a flush-
    // gated direct-write fallback.

    /// Splice a freshly-built inode into the inode-table block buffer.
    pub(crate) fn buffer_write_inode(
        &self,
        buf: &mut BlockBuffer,
        ino: u32,
        inode_raw: &[u8],
    ) -> Result<()> {
        let (block, offset) = bgd::locate_inode(&self.sb, &self.groups, ino)?;
        let it_buf = buf.get_mut(self, block)?;
        let off = offset as usize;
        it_buf[off..off + inode_raw.len()].copy_from_slice(inode_raw);
        Ok(())
    }

    /// Buffer-side equivalent of `free_block_run_and_bgd`: clears the
    /// bitmap bits AND patches the BGD counters in the buffer. Returns
    /// `len` so callers can accumulate a running freed-block total to
    /// feed to `buffer_patch_sb_counters`.
    pub(crate) fn buffer_free_block_run_and_bgd(
        &self,
        buf: &mut BlockBuffer,
        start: u64,
        len: u64,
    ) -> Result<u64> {
        let bpg = self.sb.blocks_per_group as u64;
        let first_data = self.sb.first_data_block as u64;
        let gi = ((start - first_data) / bpg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidBlock(start));
        }
        let group_start = first_data + gi as u64 * bpg;
        let bit_start = (start - group_start) as u32;
        let bitmap_block = self.groups[gi].block_bitmap;
        {
            let bm = buf.get_mut(self, bitmap_block)?;
            for i in 0..len {
                let bit = bit_start as u64 + i;
                let byte = (bit / 8) as usize;
                let mask = 1u8 << (bit % 8);
                if byte < bm.len() {
                    bm[byte] &= !mask;
                }
            }
        }
        self.buffer_refresh_bitmap_csum(buf, gi, false)?;
        self.buffer_patch_bgd_counters(buf, gi, len as i32, 0, 0)?;
        Ok(len)
    }

    /// Buffer-side equivalent of `mark_block_run_used`: sets the bitmap
    /// bits for `[start, start+len)` in the buffer's bitmap block.
    pub(crate) fn buffer_mark_block_run_used(
        &self,
        buf: &mut BlockBuffer,
        start: u64,
        len: u64,
    ) -> Result<()> {
        let bpg = self.sb.blocks_per_group as u64;
        let first_data = self.sb.first_data_block as u64;
        let gi = ((start - first_data) / bpg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidBlock(start));
        }
        let group_start = first_data + gi as u64 * bpg;
        let bit_start = (start - group_start) as u32;
        let bitmap_block = self.groups[gi].block_bitmap;
        let bm = buf.get_mut(self, bitmap_block)?;
        for i in 0..len {
            let bit = bit_start as u64 + i;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if byte < bm.len() {
                bm[byte] |= mask;
            }
        }
        self.buffer_refresh_bitmap_csum(buf, gi, false)?;
        Ok(())
    }

    /// Recompute a group's bitmap checksum (inode or block) after its bitmap
    /// block changed, then refresh the BGD checksum. metadata_csum stores the
    /// bitmap crc split lo + hi in the descriptor (inode: 0x1A/0x3A, block:
    /// 0x18/0x38); a stale value makes e2fsck and the kernel report "bitmap
    /// does not match checksum". No-op when checksums are disabled.
    pub(crate) fn buffer_refresh_bitmap_csum(
        &self,
        buf: &mut BlockBuffer,
        gi: usize,
        inode_bitmap: bool,
    ) -> Result<()> {
        if !self.csum.enabled {
            return Ok(());
        }
        let (bitmap_block, coverage, lo_off, hi_off) = if inode_bitmap {
            (
                self.groups[gi].inode_bitmap,
                (self.sb.inodes_per_group as usize).div_ceil(8),
                0x1A,
                0x3A,
            )
        } else {
            (
                self.groups[gi].block_bitmap,
                (self.sb.blocks_per_group as usize).div_ceil(8),
                0x18,
                0x38,
            )
        };
        let csum = {
            let bm = buf.get_mut(self, bitmap_block)?;
            let end = coverage.min(bm.len());
            crate::checksum::linux_crc32c(self.csum.seed, &bm[..end])
        };

        let bs = self.sb.block_size() as u64;
        let desc_size = self.sb.desc_size as u64;
        let bgt_first_block = self.sb.first_data_block as u64 + 1;
        let byte_in_bgt = gi as u64 * desc_size;
        let bgt_block = bgt_first_block + byte_in_bgt / bs;
        let off = (byte_in_bgt % bs) as usize;
        let has_hi = desc_size >= 0x40;
        let block = buf.get_mut(self, bgt_block)?;
        block[off + lo_off..off + lo_off + 2]
            .copy_from_slice(&((csum & 0xFFFF) as u16).to_le_bytes());
        if has_hi {
            block[off + hi_off..off + hi_off + 2]
                .copy_from_slice(&(((csum >> 16) & 0xFFFF) as u16).to_le_bytes());
        }
        // Refresh the BGD checksum (0x1E) so the descriptor stays consistent.
        let stored_at = off + 0x1E;
        let end_desc = off + desc_size as usize;
        block[stored_at..stored_at + 2].copy_from_slice(&[0, 0]);
        let mut c = crate::checksum::linux_crc32c(self.csum.seed, &(gi as u32).to_le_bytes());
        c = crate::checksum::linux_crc32c(c, &block[off..end_desc]);
        block[stored_at..stored_at + 2].copy_from_slice(&(c as u16).to_le_bytes());
        Ok(())
    }

    /// Buffer-side equivalent of `free_inode_slot`: clears the inode
    /// bitmap bit AND patches the BGD's `bg_free_inodes_count` (+1) in
    /// the buffer. Matches the kernel's pairing — the SB
    /// `s_free_inodes_count` is the caller's responsibility (one bump
    /// per high-level op, via `buffer_patch_sb_counters`).
    pub(crate) fn buffer_free_inode_slot(&self, buf: &mut BlockBuffer, ino: u32) -> Result<()> {
        let ipg = self.sb.inodes_per_group;
        let gi = ((ino - 1) / ipg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidInode(ino));
        }
        let bit = ((ino - 1) % ipg) as u64;
        let bitmap_block = self.groups[gi].inode_bitmap;
        {
            let bm = buf.get_mut(self, bitmap_block)?;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if byte < bm.len() {
                bm[byte] &= !mask;
            }
        }
        self.buffer_refresh_bitmap_csum(buf, gi, true)?;
        self.buffer_patch_bgd_counters(buf, gi, 0, 1, 0)
    }

    /// Buffer-side equivalent of `mark_inode_used`: sets the inode
    /// bitmap bit. BGD/SB counter patches are the caller's
    /// responsibility (different ops want different deltas — e.g.
    /// mkdir bumps `used_dirs_count`).
    pub(crate) fn buffer_mark_inode_used(&self, buf: &mut BlockBuffer, ino: u32) -> Result<()> {
        let ipg = self.sb.inodes_per_group;
        let gi = ((ino - 1) / ipg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidInode(ino));
        }
        let bit = ((ino - 1) % ipg) as u64;
        let bitmap_block = self.groups[gi].inode_bitmap;
        let bm = buf.get_mut(self, bitmap_block)?;
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte < bm.len() {
            bm[byte] |= mask;
        }
        self.buffer_refresh_bitmap_csum(buf, gi, true)?;

        // Maintain bg_itable_unused: this inode is now in use, so the count of
        // never-used inodes at the END of the group's table can be no larger
        // than the inodes after this one. A stale value makes e2fsck and the
        // kernel treat freshly-allocated inodes as unused ("references inode
        // found in unused inodes area" / "invalid unused inodes count"). lo at
        // 0x1C, hi at 0x32 (desc_size >= 64). The BGD checksum is recomputed so
        // the change stands alone; the following counter patch recomputes it
        // again harmlessly.
        let floor = ipg.saturating_sub(bit as u32 + 1);
        let bs = self.sb.block_size() as u64;
        let desc_size = self.sb.desc_size as u64;
        let bgt_first_block = self.sb.first_data_block as u64 + 1;
        let byte_in_bgt = gi as u64 * desc_size;
        let bgt_block = bgt_first_block + byte_in_bgt / bs;
        let off = (byte_in_bgt % bs) as usize;
        let has_hi = desc_size >= 0x40;
        let block = buf.get_mut(self, bgt_block)?;
        let cur_lo = u16::from_le_bytes(block[off + 0x1C..off + 0x1E].try_into().unwrap()) as u32;
        let cur_hi = if has_hi {
            u16::from_le_bytes(block[off + 0x32..off + 0x34].try_into().unwrap()) as u32
        } else {
            0
        };
        let cur = (cur_hi << 16) | cur_lo;
        if floor < cur {
            block[off + 0x1C..off + 0x1E].copy_from_slice(&((floor & 0xFFFF) as u16).to_le_bytes());
            if has_hi {
                block[off + 0x32..off + 0x34]
                    .copy_from_slice(&(((floor >> 16) & 0xFFFF) as u16).to_le_bytes());
            }
            if self.csum.enabled {
                let stored_at = off + 0x1E;
                let end_desc = off + desc_size as usize;
                block[stored_at..stored_at + 2].copy_from_slice(&[0, 0]);
                let seed = self.csum.seed;
                let mut c = crate::checksum::linux_crc32c(seed, &(gi as u32).to_le_bytes());
                c = crate::checksum::linux_crc32c(c, &block[off..end_desc]);
                block[stored_at..stored_at + 2].copy_from_slice(&(c as u16).to_le_bytes());
            }
        }
        Ok(())
    }

    /// Buffer-side BGD counter patch. Mirrors `patch_bgd_counters` byte
    /// for byte; only the I/O target differs (the BGD block is read from
    /// the buffer if already touched, else from disk).
    pub(crate) fn buffer_patch_bgd_counters(
        &self,
        buf: &mut BlockBuffer,
        gi: usize,
        free_blocks_delta: i32,
        free_inodes_delta: i32,
        used_dirs_delta: i32,
    ) -> Result<()> {
        let bs = self.sb.block_size() as u64;
        let desc_size = self.sb.desc_size as u64;
        let bgt_first_block = self.sb.first_data_block as u64 + 1;
        let byte_in_bgt = gi as u64 * desc_size;
        let bgt_block = bgt_first_block + byte_in_bgt / bs;
        let off_in_block = (byte_in_bgt % bs) as usize;

        let block = buf.get_mut(self, bgt_block)?;
        patch_counter_u32(
            block,
            off_in_block + 0x0C,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2A)
            } else {
                None
            },
            free_blocks_delta,
        );
        patch_counter_u32(
            block,
            off_in_block + 0x0E,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2C)
            } else {
                None
            },
            free_inodes_delta,
        );
        patch_counter_u32(
            block,
            off_in_block + 0x10,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2E)
            } else {
                None
            },
            used_dirs_delta,
        );

        if self.csum.enabled {
            let stored_at = off_in_block + 0x1E;
            let end_desc = off_in_block + desc_size as usize;
            block[stored_at..stored_at + 2].copy_from_slice(&[0, 0]);
            let seed = self.csum.seed;
            let mut c = crate::checksum::linux_crc32c(seed, &(gi as u32).to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[off_in_block..end_desc]);
            let new_csum = c as u16;
            block[stored_at..stored_at + 2].copy_from_slice(&new_csum.to_le_bytes());
        }
        Ok(())
    }

    /// Buffer-side SB counter patch. The SB lives at byte offset 1024
    /// inside the device; for 4 KiB blocks that's offset 1024 within fs
    /// block 0, for 1 KiB blocks the SB IS fs block 1. We patch the
    /// 1024-byte SB region in-place inside the relevant whole block, so
    /// the journal can transport it as a normal full-block write.
    pub(crate) fn buffer_patch_sb_counters(
        &self,
        buf: &mut BlockBuffer,
        free_blocks_delta: i64,
        free_inodes_delta: i32,
    ) -> Result<()> {
        let bs = self.sb.block_size() as u64;
        let sb_offset = crate::superblock::SUPERBLOCK_OFFSET; // 1024
        let sb_block = sb_offset / bs;
        let off_in_block = (sb_offset % bs) as usize;

        let block = buf.get_mut(self, sb_block)?;
        let sb = &mut block[off_in_block..off_in_block + 1024];

        // s_free_inodes_count at 0x10..0x14 (u32 le)
        let fi = u32::from_le_bytes(sb[0x10..0x14].try_into().unwrap()) as i64;
        let fi_new = (fi + free_inodes_delta as i64).max(0) as u32;
        sb[0x10..0x14].copy_from_slice(&fi_new.to_le_bytes());

        // s_free_blocks_count split lo (0x0C..0x10, u32) + hi (0x158..0x15C, u32)
        let lo = u32::from_le_bytes(sb[0x0C..0x10].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(sb[0x158..0x15C].try_into().unwrap()) as u64;
        let cur = ((hi << 32) | lo) as i64;
        let new = (cur + free_blocks_delta).max(0) as u64;
        sb[0x0C..0x10].copy_from_slice(&(new as u32).to_le_bytes());
        sb[0x158..0x15C].copy_from_slice(&((new >> 32) as u32).to_le_bytes());

        if self.csum.enabled {
            let csum = crate::checksum::linux_crc32c(!0, &sb[..0x3FC]);
            sb[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());
        }
        Ok(())
    }

    /// Buffer-side patch of the SB's `s_last_orphan` field at byte
    /// 0xE8. Used by orphan recovery (Phase 6.2) to clear / advance the
    /// chain head atomically with the inode/block frees.
    pub(crate) fn buffer_patch_sb_last_orphan(
        &self,
        buf: &mut BlockBuffer,
        value: u32,
    ) -> Result<()> {
        let bs = self.sb.block_size() as u64;
        let sb_offset = crate::superblock::SUPERBLOCK_OFFSET;
        let sb_block = sb_offset / bs;
        let off_in_block = (sb_offset % bs) as usize;
        let block = buf.get_mut(self, sb_block)?;
        let sb = &mut block[off_in_block..off_in_block + 1024];
        sb[0xE8..0xEC].copy_from_slice(&value.to_le_bytes());
        if self.csum.enabled {
            let csum = crate::checksum::linux_crc32c(!0, &sb[..0x3FC]);
            sb[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());
        }
        Ok(())
    }

    /// Buffer-side equivalent of `remove_dir_entry`: scans `parent`'s
    /// dir blocks, removes the named entry, recomputes the tail csum,
    /// stages the modified block in `buf`. Returns `Error::NotFound`
    /// when the name isn't present.
    pub(crate) fn buffer_remove_dir_entry(
        &self,
        buf: &mut BlockBuffer,
        parent_ino: u32,
        parent_inode: &Inode,
        name: &[u8],
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let n_blocks = parent_inode.size.div_ceil(bs as u64);
        for logical in 0..n_blocks {
            let Some(phys) = self.map_inode_logical(parent_inode, logical)? else {
                continue;
            };
            let block = buf.get_mut(self, phys)?;
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(block) {
                12
            } else {
                0
            };
            if crate::dir::remove_entry_from_block(block, name, has_ft, reserved_tail)? {
                if self.csum.enabled && reserved_tail == 12 {
                    let end = block.len();
                    let mut c =
                        crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                    block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Buffer-side equivalent of `update_dotdot`: rewrites the `..`
    /// entry in `dir_inode`'s first data block (in-buffer) to point at
    /// `new_parent_ino`, recomputes the tail csum.
    pub(crate) fn buffer_update_dotdot(
        &self,
        buf: &mut BlockBuffer,
        dir_ino: u32,
        dir_inode: &Inode,
        new_parent_ino: u32,
    ) -> Result<()> {
        let phys = self
            .map_inode_logical(dir_inode, 0)?
            .ok_or(Error::Corrupt("buffer_update_dotdot: dir block 0 missing"))?;
        let block = buf.get_mut(self, phys)?;
        if block.len() < 24 {
            return Err(Error::Corrupt("buffer_update_dotdot: dir block too small"));
        }
        block[12..16].copy_from_slice(&new_parent_ino.to_le_bytes());
        if self.csum.enabled && crate::dir::has_csum_tail(block) {
            let end = block.len();
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &dir_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &dir_inode.generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
            block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        }
        Ok(())
    }

    /// Buffer-side equivalent of `add_dir_entry` for the IN-PLACE case
    /// only (an existing parent block has room for the new entry). The
    /// dir block is read into the buffer (or reused if already touched),
    /// `add_entry_to_block` rewrites it, csum patched, returns Ok(()).
    ///
    /// Returns `Error::OutOfBounds` when no existing parent block has
    /// room — caller should then fall through to
    /// `buffer_extend_dir_and_add_entry` to grow the directory by one
    /// block (which has its own scope limits).
    pub(crate) fn buffer_add_dir_entry_inplace(
        &self,
        buf: &mut BlockBuffer,
        parent_ino: u32,
        parent_inode: &Inode,
        name: &[u8],
        target_ino: u32,
        file_type: crate::dir::DirEntryType,
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let n_blocks = parent_inode.size.div_ceil(bs as u64);
        for logical in 0..n_blocks {
            let Some(phys) = self.map_inode_logical(parent_inode, logical)? else {
                continue;
            };
            let block = buf.get_mut(self, phys)?;
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(block) {
                12
            } else {
                0
            };
            match crate::dir::add_entry_to_block(
                block,
                target_ino,
                name,
                file_type,
                has_ft,
                reserved_tail,
            ) {
                Ok(()) => {
                    if self.csum.enabled && reserved_tail == 12 {
                        let end = block.len();
                        let mut c = crate::checksum::linux_crc32c(
                            self.csum.seed,
                            &parent_ino.to_le_bytes(),
                        );
                        c = crate::checksum::linux_crc32c(
                            c,
                            &parent_inode.generation.to_le_bytes(),
                        );
                        c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                        block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                    }
                    return Ok(());
                }
                Err(Error::OutOfBounds) => continue,
                Err(e) => return Err(e),
            }
        }
        // No existing block has room — caller must extend the directory
        // (or fall back to the un-journaled extend path).
        Err(Error::OutOfBounds)
    }

    /// Commit a `BlockBuffer` atomically. Routes through the journal
    /// writer when one is available (crash-safe four-fence protocol);
    /// falls back to direct device writes + flush otherwise.
    ///
    /// In journaled mode, writes go to the **journal log** on disk —
    /// the *data area* on disk doesn't see them until journal replay
    /// (checkpointing). To make those bytes visible to subsequent reads
    /// **before** checkpoint (the read-after-write coherence Linux's
    /// buffer cache guarantees), every committed block is `populate`'d
    /// into the device-layer cache after the journal commit succeeds.
    /// Without this hook, allocators (inode/block bitmap) would re-read
    /// pre-commit on-disk bytes and produce duplicate allocations.
    pub(crate) fn commit_block_buffer(&self, buf: BlockBuffer) -> Result<()> {
        if buf.dirty.is_empty() {
            return Ok(());
        }
        if let Some(jw_mu) = &self.journal {
            let mut jw = jw_mu.lock().map_err(|_| {
                Error::Corrupt("journal writer mutex poisoned (prior write panicked)")
            })?;
            let mut tx = jw.begin();
            for (block, bytes) in &buf.dirty {
                tx.add_write(*block, bytes.clone())?;
            }
            jw.commit(self.dev.as_ref(), &tx)?;
            // Populate the buffer cache with the post-commit bytes so
            // any read (this thread or another) sees them before the
            // journal is checkpointed back to the data area.
            for (block, bytes) in buf.dirty {
                self.dev.populate_cache(block, bytes);
            }
            Ok(())
        } else {
            let bs = self.sb.block_size() as u64;
            for (block, bytes) in buf.dirty {
                self.dev.write_at(block * bs, &bytes)?;
            }
            self.dev.flush()
        }
    }

    /// Change the owner of `path` to (`uid`, `gid`). Both values are full
    /// 32-bit — the inode stores them as hi+lo u16 halves at different
    /// offsets per the ext4 on-disk format. Passing `u32::MAX` for either
    /// field leaves that value untouched (Linux lchown(2) convention).
    ///
    /// Updates `i_ctime = now` and recomputes the inode checksum on
    /// csum-enabled mounts.
    pub fn apply_chown(&self, path: &str, uid: u32, gid: u32) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        if uid != u32::MAX {
            let lo = (uid & 0xFFFF) as u16;
            let hi = ((uid >> 16) & 0xFFFF) as u16;
            raw[0x02..0x04].copy_from_slice(&lo.to_le_bytes());
            raw[0x78..0x7A].copy_from_slice(&hi.to_le_bytes());
        }
        if gid != u32::MAX {
            let lo = (gid & 0xFFFF) as u16;
            let hi = ((gid >> 16) & 0xFFFF) as u16;
            raw[0x18..0x1A].copy_from_slice(&lo.to_le_bytes());
            raw[0x7A..0x7C].copy_from_slice(&hi.to_le_bytes());
        }

        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.commit_inode_write(ino, &raw)
    }

    /// Set the `i_flags` field (FS_IOC_SETFLAGS) for the inode at `path`.
    ///
    /// Bumps ctime. Fails with `Error::ReadOnly` on read-only mounts, or
    /// `Error::InvalidArgument` if the caller attempts to flip any of the
    /// layout-critical flags managed internally (EXTENTS_FL, INLINE_DATA_FL,
    /// EA_INODE_FL) — changing those without rewriting the inode payload would
    /// corrupt the filesystem.
    pub fn apply_set_flags(&self, path: &str, flags: u32) -> Result<()> {
        use crate::inode::{InodeFlags, OFF_CTIME, OFF_FLAGS};
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        let managed = InodeFlags::EXTENTS.bits()
            | InodeFlags::INLINE_DATA.bits()
            | InodeFlags::EA_INODE.bits();
        if (flags ^ inode.flags) & managed != 0 {
            return Err(Error::InvalidArgument(
                "set_flags: cannot modify internally-managed inode flags (EXTENTS, INLINE_DATA, EA_INODE)",
            ));
        }

        raw[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());

        let now = now_unix_seconds();
        raw[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&now.to_le_bytes());

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.commit_inode_write(ino, &raw)
    }

    /// Remove the extended attribute named `name` from the inode at `path`.
    /// `name` must carry a known namespace prefix (e.g. `"user.color"`).
    ///
    /// v1 scope: **in-inode xattrs only.** The in-inode region (bytes
    /// between `128 + i_extra_isize` and the end of the on-disk inode)
    /// is decoded, the matching entry is dropped, and the region is
    /// re-encoded in place. External xattr blocks (pointed at by
    /// Search the in-inode region first, then the external xattr block. If
    /// the external block becomes empty after removal, free it and zero
    /// `i_file_acl` (matches kernel behavior — empty xattr blocks are
    /// reaped on the spot rather than left dangling).
    ///
    /// Returns:
    /// - `Ok(())` on success.
    /// - `Error::NotFound` if the entry isn't present in either region.
    /// - `Error::InvalidArgument` on namespace-prefix issues.
    pub fn apply_removexattr(&self, path: &str, name: &str) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        // Locate the in-inode xattr region (starts at 128 + i_extra_isize).
        let inode_size = self.sb.inode_size as usize;
        let i_extra_isize = if raw.len() >= 0x82 {
            u16::from_le_bytes(raw[0x80..0x82].try_into().unwrap()) as usize
        } else {
            0
        };
        let region_start = 128 + i_extra_isize;
        let region_end = inode_size.min(raw.len());
        if region_start + 4 <= region_end {
            let region = &mut raw[region_start..region_end];
            match crate::xattr::plan_remove_in_inode_region(region, name)? {
                crate::xattr::RemoveOutcome::Removed => {
                    self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
                    return self.commit_inode_write(ino, &raw);
                }
                crate::xattr::RemoveOutcome::NotFound => { /* check external */ }
            }
        }

        // External block path: read, plan-remove, write back (or free it
        // when it becomes empty).
        if inode.file_acl != 0 {
            let bs = self.sb.block_size();
            let bs_u64 = bs as u64;
            let block_nr = inode.file_acl;
            let mut block = vec![0u8; bs as usize];
            self.dev.read_at(block_nr * bs_u64, &mut block)?;
            match crate::xattr::plan_remove_from_external_block(&mut block, name, 1)? {
                crate::xattr::BlockRemoveOutcome::Removed => {
                    if self.csum.enabled {
                        self.csum.patch_xattr_block(block_nr, &mut block);
                    }
                    self.dev.write_at(block_nr * bs_u64, &block)?;
                    self.bump_inode_ctime(ino, inode.generation, &mut raw)?;
                    self.dev.flush()?;
                    return Ok(());
                }
                crate::xattr::BlockRemoveOutcome::RemovedNowEmpty => {
                    // Free the now-empty external block + clear i_file_acl + drop
                    // i_blocks, all in one journaled transaction. The previous
                    // direct path used free_block_run_and_bgd, which skipped the
                    // block-bitmap checksum recompute and wrote a stale BGD —
                    // corrupting the bitmap csum and the free counters. The
                    // buffer helpers do it correctly and atomically.
                    let mut buf = BlockBuffer::new(bs);
                    self.buffer_free_block_run_and_bgd(&mut buf, block_nr, 1)?;
                    self.buffer_patch_sb_counters(&mut buf, 1, 0)?;
                    raw[0x68..0x6C].copy_from_slice(&0u32.to_le_bytes());
                    if raw.len() >= 0x76 {
                        raw[0x74..0x76].copy_from_slice(&0u16.to_le_bytes());
                    }
                    let sectors_per_block = bs_u64 / 512;
                    let new_blocks = inode.blocks.saturating_sub(sectors_per_block);
                    Self::patch_inode_size_and_blocks(&mut raw, inode.size, new_blocks)?;
                    raw[0x0C..0x10].copy_from_slice(&now_unix_seconds().to_le_bytes());
                    self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
                    self.buffer_write_inode(&mut buf, ino, &raw)?;
                    return self.commit_block_buffer(buf);
                }
                crate::xattr::BlockRemoveOutcome::NotFound => { /* fall through */ }
            }
        }
        Err(Error::NotFound)
    }

    /// Set (create or replace) the extended attribute `name` with `value`
    /// on the inode at `path`. `name` must carry a known namespace prefix
    /// (e.g. `"user.com.apple.FinderInfo"`).
    ///
    /// Try-order, matching the kernel:
    /// 1. **In-inode region** — between `128 + i_extra_isize` and the end
    ///    of the on-disk inode. Cheapest; no extra block.
    /// 2. **External xattr block** — when in-inode is full, fall back to a
    ///    dedicated block referenced by `i_file_acl`. Allocates a fresh
    ///    block when none exists, otherwise rewrites the existing one.
    ///    Returns `Error::NoSpaceLeftOnDevice` if even a full block can't
    ///    hold the new layout.
    pub fn apply_setxattr(&self, path: &str, name: &str, value: &[u8]) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        let inode_size = self.sb.inode_size as usize;
        let i_extra_isize = if raw.len() >= 0x82 {
            u16::from_le_bytes(raw[0x80..0x82].try_into().unwrap()) as usize
        } else {
            0
        };
        let region_start = 128 + i_extra_isize;
        let region_end = inode_size.min(raw.len());
        let inline_capable = region_start + 8 <= region_end;

        // Try in-inode first; on overflow fall through to the external block.
        let inline_result = if inline_capable {
            let region = &mut raw[region_start..region_end];
            crate::xattr::plan_set_in_inode_region(region, name, value)
        } else {
            Err(Error::NoSpaceLeftOnDevice)
        };

        match inline_result {
            Ok(_) => {
                // In-inode rewrite already in `raw`. Refresh inode csum + commit.
                self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
                self.commit_inode_write(ino, &raw)
            }
            Err(Error::NoSpaceLeftOnDevice) => {
                self.apply_setxattr_external_block(ino, &inode, &mut raw, name, value)
            }
            Err(e) => Err(e),
        }
    }

    /// Recompute the inode checksum (when enabled) and splice both halves
    /// back into the inode image. No-op when csum disabled.
    fn finalize_inode_raw(&self, ino: u32, generation: u32, raw: &mut [u8]) -> Result<()> {
        if self.csum.enabled {
            if let Some((lo, hi)) = self.csum.compute_inode_checksum(ino, generation, raw) {
                raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if raw.len() >= 0x84 {
                    raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    /// Helper: route a setxattr that overflowed the in-inode region to the
    /// external xattr block. Either rewrites the existing block (when
    /// `i_file_acl != 0`) or allocates a fresh one.
    fn apply_setxattr_external_block(
        &self,
        ino: u32,
        inode: &crate::inode::Inode,
        raw: &mut [u8],
        name: &str,
        value: &[u8],
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let bs_u64 = bs as u64;

        // Multi-block transaction: xattr block bytes + (alloc-side bitmap +
        // BGD + SB when fresh-block) + inode body. Atomic across the op.
        let mut buf = BlockBuffer::new(bs);

        // Path A: existing external block — rewrite in-buffer, re-checksum.
        if inode.file_acl != 0 {
            let block_nr = inode.file_acl;
            let mut block = vec![0u8; bs as usize];
            self.dev.read_at(block_nr * bs_u64, &mut block)?;
            crate::xattr::plan_set_in_external_block(&mut block, name, value, 1)?;
            if self.csum.enabled {
                self.csum.patch_xattr_block(block_nr, &mut block);
            }
            buf.put(block_nr, block);
            // i_file_acl unchanged — only need to bump ctime.
            let now = now_unix_seconds();
            raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());
            self.finalize_inode_raw(ino, inode.generation, raw)?;
            self.buffer_write_inode(&mut buf, ino, raw)?;
            return self.commit_block_buffer(buf);
        }

        // Path B: no external block yet — allocate, build, stage, then
        // point i_file_acl + i_blocks at it.
        let mut bitmap_reader = |block: u64| self.read_block(block);
        let inode_group = (ino - 1) / self.sb.inodes_per_group;
        let plan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            1,
            inode_group,
            &mut bitmap_reader,
        )?;
        let block_nr = plan.first_block;

        let mut block = vec![0u8; bs as usize];
        crate::xattr::plan_set_in_external_block(&mut block, name, value, 1)?;
        if self.csum.enabled {
            self.csum.patch_xattr_block(block_nr, &mut block);
        }
        buf.put(block_nr, block);

        // Stage allocator side-effects in the buffer.
        self.buffer_mark_block_run_used(&mut buf, block_nr, 1)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            plan.sb.free_blocks_delta,
            plan.sb.free_inodes_delta,
        )?;

        // Splice block_nr into the inode: i_file_acl_lo at 0x68..0x6C, hi
        // at 0x74..0x76.
        let (acl_hi, acl_lo) = crate::extent_mut::split_phys_block(block_nr);
        raw[0x68..0x6C].copy_from_slice(&acl_lo.to_le_bytes());
        if raw.len() >= 0x76 {
            raw[0x74..0x76].copy_from_slice(&acl_hi.to_le_bytes());
        }
        // Bump i_blocks by sectors_per_block (the xattr block now belongs
        // to this inode for du purposes).
        let sectors_per_block = bs_u64 / 512;
        let new_blocks = inode.blocks.saturating_add(sectors_per_block);
        Self::patch_inode_size_and_blocks(raw, inode.size, new_blocks)?;
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());
        self.finalize_inode_raw(ino, inode.generation, raw)?;
        self.buffer_write_inode(&mut buf, ino, raw)?;

        self.commit_block_buffer(buf)
    }

    /// Bump `i_ctime` to now and re-checksum + write the inode. Used on
    /// attribute writes that touch external storage but don't otherwise
    /// modify the inode body.
    fn bump_inode_ctime(&self, ino: u32, generation: u32, raw: &mut [u8]) -> Result<()> {
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());
        self.finalize_inode_raw(ino, generation, raw)?;
        self.commit_inode_write(ino, raw)
    }

    /// Set the access + modification times on `path`. Mirrors POSIX
    /// `utimensat(2)`: `atime_sec/nsec` and `mtime_sec/nsec` each replace
    /// the inode's atime/mtime. `ctime` is bumped to now (POSIX requires
    /// the change-time stamp on any attribute write). The `u32::MAX`
    /// sentinel on either `_sec` leaves that pair unchanged (lets callers
    /// touch just atime or just mtime).
    ///
    /// `nsec` values are the sub-second timestamp in nanoseconds and are
    /// only written when the inode's `i_extra_isize` region is large
    /// enough to hold them (requires ≥ 160-byte inodes — the ext4 tooling
    /// default).
    pub fn apply_utimens(
        &self,
        path: &str,
        atime_sec: u32,
        atime_nsec: u32,
        mtime_sec: u32,
        mtime_nsec: u32,
    ) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;

        if atime_sec != u32::MAX {
            raw[0x08..0x0C].copy_from_slice(&atime_sec.to_le_bytes());
        }
        if mtime_sec != u32::MAX {
            raw[0x10..0x14].copy_from_slice(&mtime_sec.to_le_bytes());
        }
        // POSIX: any attribute write bumps ctime.
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes());

        // Extra-isize region carries the nsec fields on larger inodes.
        // Offsets (relative to inode start):
        //   0x84 i_ctime_extra  (needs i_extra_isize ≥  8)
        //   0x88 i_mtime_extra  (needs i_extra_isize ≥ 12)
        //   0x8C i_atime_extra  (needs i_extra_isize ≥ 16)
        // Linux packs these as `(nsec << 2) | epoch_bits` — leave
        // epoch_bits zero (matches the base 32-bit time counter's 2038
        // range).
        if raw.len() >= 0x82 {
            let i_extra_isize = u16::from_le_bytes(raw[0x80..0x82].try_into().unwrap());
            if i_extra_isize >= 8 && raw.len() >= 0x88 {
                // Bump ctime_nsec to 0 alongside the ctime bump above.
                raw[0x84..0x88].copy_from_slice(&0u32.to_le_bytes());
            }
            if mtime_sec != u32::MAX && i_extra_isize >= 12 && raw.len() >= 0x8C {
                let packed = pack_nsec_lo(mtime_nsec);
                raw[0x88..0x8C].copy_from_slice(&packed.to_le_bytes());
            }
            if atime_sec != u32::MAX && i_extra_isize >= 16 && raw.len() >= 0x90 {
                let packed = pack_nsec_lo(atime_nsec);
                raw[0x8C..0x90].copy_from_slice(&packed.to_le_bytes());
            }
        }

        self.finalize_inode_raw(ino, inode.generation, &mut raw)?;
        self.commit_inode_write(ino, &raw)
    }

    /// Unlink a regular file / symlink / special file at `path`.
    ///
    /// Semantics:
    /// - Refuses to unlink a directory (use a future `apply_rmdir`).
    /// - Decrements the target inode's `i_links_count`. When that reaches
    ///   zero, frees every data block via `plan_truncate_shrink(size → 0)`,
    ///   clears the inode bitmap bit, zeroes the inode body, and sets
    ///   `i_dtime = now`. When `links_count > 1` we only drop the dir entry
    ///   and decrement — matches POSIX unlink semantics for hard-linked files.
    /// - Mutates: parent-dir block (entry removal), target inode, block +
    ///   inode bitmaps, BGD counters, SB counters. No journaling yet —
    ///   safe only on scratch images (same caveat as `apply_truncate_shrink`).
    ///
    /// Returns `Error::NotFound` if the path doesn't exist,
    /// `Error::NotADirectory` if the parent isn't a directory, and
    /// `Error::IsADirectory` (POSIX EISDIR) if the target is a directory.
    pub fn apply_unlink(&self, path: &str) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        // POSIX: a trailing slash asserts the path refers to a directory,
        // which is incompatible with `unlink(2)` no matter what kind of file
        // the path resolves to. `split_parent_and_base` swallows the slash,
        // so snapshot the flag first and fail-fast on non-dirs below.
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let (parent_ino, base_name) = split_parent_and_base(path)?;

        // Resolve parent + target inodes.
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let parent_ino_num =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &parent_ino)?;
        let (parent_inode, _parent_raw) = self.read_inode_verified(parent_ino_num)?;
        if !parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }

        let target_ino = self.find_entry_in_dir(&parent_inode, base_name.as_bytes())?;
        let (target_inode, mut target_raw) = self.read_inode_verified(target_ino)?;
        if target_inode.is_dir() {
            // POSIX: unlink(2) on a directory must fail with EISDIR; the
            // caller should use rmdir(2) instead.
            return Err(Error::IsADirectory);
        }
        if trailing_slash {
            // `unlink("/foo/")` where /foo is a regular file → ENOTDIR per
            // POSIX: the trailing slash tells us the caller expected a dir.
            return Err(Error::NotADirectory);
        }

        // All mutations land in this buffer and commit as one transaction.
        let mut buf = BlockBuffer::new(self.sb.block_size());

        // Remove the dir entry from the parent. Scans each block until
        // `remove_entry_from_block` reports success.
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let bs = self.sb.block_size();
        let parent_blocks = parent_inode.size.div_ceil(bs as u64);
        let mut removed = false;
        for logical in 0..parent_blocks {
            let Some(phys) = self.map_inode_logical(&parent_inode, logical)? else {
                continue;
            };
            let block = buf.get_mut(self, phys)?;
            // `dir_entry_tail` occupies the last 12 bytes when metadata_csum
            // is on; don't scribble over it.
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(block) {
                12
            } else {
                0
            };
            if crate::dir::remove_entry_from_block(
                block,
                base_name.as_bytes(),
                has_ft,
                reserved_tail,
            )? {
                // Recompute the tail csum if present — entry-list shape changed.
                if self.csum.enabled && reserved_tail == 12 {
                    let end = block.len();
                    let mut c = crate::checksum::linux_crc32c(
                        self.csum.seed,
                        &parent_ino_num.to_le_bytes(),
                    );
                    c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                    block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                }
                removed = true;
                break;
            }
        }
        if !removed {
            return Err(Error::NotFound);
        }

        // Decrement link count. Non-zero after → just persist the new count.
        let new_links = target_inode.links_count.saturating_sub(1);
        target_raw[0x1A..0x1C].copy_from_slice(&new_links.to_le_bytes());

        if new_links > 0 {
            self.finalize_inode_raw(target_ino, target_inode.generation, &mut target_raw)?;
            self.buffer_write_inode(&mut buf, target_ino, &target_raw)?;
            return self.commit_block_buffer(buf);
        }

        // Last link gone — free data blocks + inode slot, all into the same
        // transaction so a crash either keeps everything or undoes everything.
        let mut freed_sectors: u64 = 0;
        let sectors_per_block = bs as u64 / 512;
        if target_inode.has_extents() && target_inode.size > 0 {
            let (_sc, muts) = crate::file_mut::plan_truncate_shrink(
                target_inode.size,
                0,
                &target_inode.block,
                bs,
            )?;
            for m in &muts {
                if let crate::extent_mut::ExtentMutation::FreePhysicalRun { start, len } = m {
                    self.buffer_free_block_run_and_bgd(&mut buf, *start, *len as u64)?;
                    freed_sectors += *len as u64 * sectors_per_block;
                }
            }
        }

        // Inode bitmap + BGD free_inodes_count; SB counter for both
        // freed_blocks AND +1 inode goes via one buffer_patch_sb_counters
        // call below.
        self.buffer_free_inode_slot(&mut buf, target_ino)?;

        let freed_blocks = freed_sectors.checked_div(sectors_per_block).unwrap_or(0);
        self.buffer_patch_sb_counters(&mut buf, freed_blocks as i64, 1)?;

        // Zero the inode body. Kernel sets dtime = now, mode = 0, and
        // leaves the generation intact (helps tooling detect the dead slot).
        let inode_size = self.sb.inode_size as usize;
        let old_gen = target_inode.generation;
        for b in &mut target_raw[..inode_size] {
            *b = 0;
        }
        let dtime = now_unix_seconds();
        target_raw[0x14..0x18].copy_from_slice(&dtime.to_le_bytes()); // dtime
        target_raw[0x64..0x68].copy_from_slice(&old_gen.to_le_bytes()); // generation
        self.finalize_inode_raw(target_ino, old_gen, &mut target_raw)?;
        self.buffer_write_inode(&mut buf, target_ino, &target_raw)?;

        self.commit_block_buffer(buf)
    }

    /// Common setup for creating a new inode inside a directory: resolves
    /// the parent, checks preconditions, allocates an inode, and stages the
    /// bitmap + counter updates into a fresh `BlockBuffer`. The caller then
    /// builds the inode bytes and adds the dir entry.
    fn plan_new_inode_in_dir(&self, path: &str) -> Result<NewInodePlan> {
        let (parent_path, base_name) = split_parent_and_base(path)?;
        if base_name.len() > 255 {
            return Err(Error::NameTooLong);
        }

        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &parent_path)?;
        let (parent_inode, _) = self.read_inode_verified(parent_ino)?;
        if !parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        if self
            .find_entry_in_dir(&parent_inode, base_name.as_bytes())
            .is_ok()
        {
            return Err(Error::AlreadyExists);
        }

        let parent_group = (parent_ino - 1) / self.sb.inodes_per_group;
        let bs = self.sb.block_size();
        let mut bitmap_reader = |block: u64| self.read_block(block);
        let plan = crate::alloc::plan_inode_allocation(
            &self.sb,
            &self.groups,
            false,
            parent_group,
            &mut bitmap_reader,
        )?;
        let new_ino = plan.inode;

        let mut buf = BlockBuffer::new(bs);
        self.buffer_mark_inode_used(&mut buf, new_ino)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            plan.sb.free_blocks_delta,
            plan.sb.free_inodes_delta,
        )?;

        Ok(NewInodePlan {
            new_ino,
            parent_ino,
            parent_inode,
            buf,
            base_name,
        })
    }

    /// Create a new regular file at `path` with permission bits `mode`
    /// (e.g. `0o644`). Returns the allocated inode number on success.
    ///
    /// Semantics:
    /// - Parent must exist and be a directory.
    /// - Refuses if `path` already exists.
    /// - Allocates an inode via `plan_inode_allocation` (hints to the
    ///   parent's group), marks the bitmap, bumps BGD + SB counters.
    /// - Initialises the inode as a regular file with EXTENTS flag and an
    ///   empty extent tree (size=0, blocks=0). Timestamps set to `now`.
    /// - Adds the directory entry into the first parent block with room
    ///   (linear; htree-extending dirs are a follow-up).
    /// - Not journaled — scratch-image safe, same caveat as other Phase-4
    ///   applies.
    pub fn apply_create(&self, path: &str, mode: u16) -> Result<u32> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let NewInodePlan {
            new_ino,
            parent_ino,
            parent_inode,
            mut buf,
            base_name,
        } = self.plan_new_inode_in_dir(path)?;

        let raw = self.build_regular_file_inode(new_ino, mode)?;
        self.buffer_write_inode(&mut buf, new_ino, &raw)?;

        // Multi-block transaction: inode bitmap + BGD + SB + new inode +
        // parent dir entry, all atomic. The fall-through to extend-dir
        // (when the parent has no room) must commit the buffer first
        // and then run extend un-journaled — see end of fn.
        match self.buffer_add_dir_entry_inplace(
            &mut buf,
            parent_ino,
            &parent_inode,
            base_name.as_bytes(),
            new_ino,
            crate::dir::DirEntryType::RegFile,
        ) {
            Ok(()) => {
                self.commit_block_buffer(buf)?;
                Ok(new_ino)
            }
            Err(Error::OutOfBounds) => {
                // Parent dir is full → commit what we have so the inode
                // allocation is durable, then run the un-journaled extend
                // path. If the extend crashes mid-way we leak the
                // already-allocated inode (orphan candidate); this is a
                // documented limitation until extend has a buffer-twin.
                self.commit_block_buffer(buf)?;
                self.extend_dir_and_add_entry(
                    parent_ino,
                    base_name.as_bytes(),
                    new_ino,
                    crate::dir::DirEntryType::RegFile,
                )?;
                Ok(new_ino)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a special file (FIFO, socket, char device, block device).
    /// `mode` must include the type bits (`S_IFIFO`, `S_IFSOCK`, `S_IFCHR`,
    /// or `S_IFBLK`) plus the permission bits. `major` and `minor` are the
    /// device numbers (both 0 for FIFOs and sockets). Mirrors POSIX `mknod`.
    pub fn apply_mknod(&self, path: &str, mode: u16, major: u32, minor: u32) -> Result<u32> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let file_type = mode & crate::inode::S_IFMT;
        let dir_entry_type = match file_type {
            crate::inode::S_IFCHR => crate::dir::DirEntryType::CharDev,
            crate::inode::S_IFBLK => crate::dir::DirEntryType::BlockDev,
            crate::inode::S_IFIFO => crate::dir::DirEntryType::Fifo,
            crate::inode::S_IFSOCK => crate::dir::DirEntryType::Socket,
            _ => {
                return Err(Error::InvalidArgument(
                    "mknod: unsupported type; use create/mkdir for reg/dir",
                ))
            }
        };
        let NewInodePlan {
            new_ino,
            parent_ino,
            parent_inode,
            mut buf,
            base_name,
        } = self.plan_new_inode_in_dir(path)?;

        let raw = self.build_special_file_inode(new_ino, mode, major, minor)?;
        self.buffer_write_inode(&mut buf, new_ino, &raw)?;

        match self.buffer_add_dir_entry_inplace(
            &mut buf,
            parent_ino,
            &parent_inode,
            base_name.as_bytes(),
            new_ino,
            dir_entry_type,
        ) {
            Ok(()) => {
                self.commit_block_buffer(buf)?;
                Ok(new_ino)
            }
            Err(Error::OutOfBounds) => {
                self.commit_block_buffer(buf)?;
                self.extend_dir_and_add_entry(
                    parent_ino,
                    base_name.as_bytes(),
                    new_ino,
                    dir_entry_type,
                )?;
                Ok(new_ino)
            }
            Err(e) => Err(e),
        }
    }

    /// Write inode checksum fields (lo at OFF_CHECKSUM_LO, hi at OFF_CHECKSUM_HI)
    /// when metadata checksums are enabled for this filesystem.
    fn stamp_inode_checksum(&self, raw: &mut [u8], ino: u32, generation: u32) {
        use crate::inode::{INODE_SIZE_WITH_EXTRA, OFF_CHECKSUM_HI, OFF_CHECKSUM_LO};
        if self.csum.enabled {
            if let Some((lo, hi)) = self.csum.compute_inode_checksum(ino, generation, raw) {
                raw[OFF_CHECKSUM_LO..OFF_CHECKSUM_LO + 2].copy_from_slice(&lo.to_le_bytes());
                if raw.len() >= INODE_SIZE_WITH_EXTRA {
                    raw[OFF_CHECKSUM_HI..OFF_CHECKSUM_HI + 2].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
    }

    fn build_special_file_inode(
        &self,
        ino: u32,
        mode: u16,
        major: u32,
        minor: u32,
    ) -> Result<Vec<u8>> {
        use crate::inode::{OFF_BLOCK, OFF_LINKS_COUNT, OFF_MODE};
        let inode_size = self.sb.inode_size as usize;
        let mut raw = vec![0u8; inode_size];

        raw[OFF_MODE..OFF_MODE + 2].copy_from_slice(&mode.to_le_bytes());
        raw[OFF_LINKS_COUNT..OFF_LINKS_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());

        // Device files: store encoded device number in i_block (no EXTENTS).
        // Linux stores old (i_block[0]) and new (i_block[1]) formats.
        let file_type = mode & crate::inode::S_IFMT;
        if file_type == crate::inode::S_IFBLK || file_type == crate::inode::S_IFCHR {
            let old_dev = (major << 8) | (minor & 0xff);
            raw[OFF_BLOCK..OFF_BLOCK + 4].copy_from_slice(&old_dev.to_le_bytes());
            let new_dev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
            raw[OFF_BLOCK + 4..OFF_BLOCK + 8].copy_from_slice(&new_dev.to_le_bytes());
        }

        let now = now_unix_seconds();
        write_inode_timestamps(&mut raw, now);
        let generation = alloc_inode_generation();
        write_inode_generation(&mut raw, generation);
        write_inode_extra_isize(&mut raw);
        self.stamp_inode_checksum(&mut raw, ino, generation);
        Ok(raw)
    }

    /// Create a symbolic link at `linkpath` whose target is `target`.
    /// Mirrors POSIX `symlink(target, linkpath)`: allocates a fresh inode
    /// with mode S_IFLNK, installs the target bytes, and adds a dir entry
    /// at the link path.
    ///
    /// Two storage paths:
    /// - **Fast symlink** (`target.len() <= 60`): target stored inline in
    ///   the 60-byte `i_block` area; no data-block allocation.
    /// - **Slow symlink** (`61..=255` bytes): one filesystem block is
    ///   allocated and the target is written there, with an EXTENTS
    ///   i_block pointing at it.
    ///
    /// POSIX caps symlink targets at SYMLINK_MAX (255 bytes on Linux +
    /// macOS). Longer returns `Error::NameTooLong` → ENAMETOOLONG.
    pub fn apply_symlink(&self, target: &str, linkpath: &str) -> Result<u32> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        if target.is_empty() {
            return Err(Error::InvalidArgument("symlink target is empty"));
        }
        // PATH_MAX cap (matches Linux). Slow path allocates exactly one fs
        // block, so we additionally require target.len() <= block_size — the
        // 4096 ceiling matches the typical ext4 block size and Linux PATH_MAX.
        let max_target = 4096usize.min(self.sb.block_size() as usize);
        if target.len() > max_target {
            return Err(Error::NameTooLong);
        }

        let NewInodePlan {
            new_ino,
            parent_ino,
            parent_inode,
            mut buf,
            base_name,
        } = self.plan_new_inode_in_dir(linkpath)?;

        let parent_group = (parent_ino - 1) / self.sb.inodes_per_group;
        let bs = self.sb.block_size();

        // Fast-symlink if target strictly fits inline (i_block is 60 bytes);
        // otherwise allocate a block and stage its bytes into the buffer.
        // Linux's `ext4_symlink` switches to the slow path when
        // `target.len() >= sizeof(i_block)` (i.e. >= 60), and our readlink
        // path mirrors that boundary, so we match here.
        let raw = if target.len() < 60 {
            self.build_fast_symlink_inode(new_ino, target.as_bytes())?
        } else {
            let mut bitmap_reader = |block: u64| self.read_block(block);
            let bplan = crate::alloc::plan_block_allocation(
                &self.sb,
                &self.groups,
                1,
                parent_group,
                &mut bitmap_reader,
            )?;
            let data_phys = bplan.first_block;

            self.buffer_mark_block_run_used(&mut buf, data_phys, 1)?;
            self.buffer_patch_bgd_counters(
                &mut buf,
                bplan.bgd.group_idx as usize,
                bplan.bgd.free_blocks_delta,
                bplan.bgd.free_inodes_delta,
                bplan.bgd.used_dirs_delta,
            )?;
            self.buffer_patch_sb_counters(
                &mut buf,
                bplan.sb.free_blocks_delta,
                bplan.sb.free_inodes_delta,
            )?;

            let mut block = vec![0u8; bs as usize];
            block[..target.len()].copy_from_slice(target.as_bytes());
            buf.put(data_phys, block);

            self.build_slow_symlink_inode(new_ino, target.as_bytes(), data_phys)?
        };
        self.buffer_write_inode(&mut buf, new_ino, &raw)?;

        match self.buffer_add_dir_entry_inplace(
            &mut buf,
            parent_ino,
            &parent_inode,
            base_name.as_bytes(),
            new_ino,
            crate::dir::DirEntryType::Symlink,
        ) {
            Ok(()) => {
                self.commit_block_buffer(buf)?;
                Ok(new_ino)
            }
            Err(Error::OutOfBounds) => {
                self.commit_block_buffer(buf)?;
                self.extend_dir_and_add_entry(
                    parent_ino,
                    base_name.as_bytes(),
                    new_ino,
                    crate::dir::DirEntryType::Symlink,
                )?;
                Ok(new_ino)
            }
            Err(e) => Err(e),
        }
    }

    /// Compose a fresh fast-symlink inode image: `S_IFLNK | 0o777`, 1 link,
    /// `i_size = target.len()`, 0 blocks, NO EXTENTS flag (fast symlinks
    /// store their target directly in the 60-byte `i_block` area — no
    /// extent tree).
    fn build_fast_symlink_inode(&self, ino: u32, target: &[u8]) -> Result<Vec<u8>> {
        use crate::inode::{OFF_BLOCK, OFF_FLAGS, OFF_LINKS_COUNT, OFF_MODE, OFF_SIZE_LO};
        debug_assert!(target.len() < 60);
        let mut raw = vec![0u8; self.sb.inode_size as usize];

        // Symlinks are traditionally rwxrwxrwx — the OS enforces access on
        // the *target*, not the symlink itself.
        let mode_bits = crate::inode::S_IFLNK | 0o0777;
        raw[OFF_MODE..OFF_MODE + 2].copy_from_slice(&mode_bits.to_le_bytes());
        raw[OFF_SIZE_LO..OFF_SIZE_LO + 4].copy_from_slice(&(target.len() as u32).to_le_bytes());
        raw[OFF_LINKS_COUNT..OFF_LINKS_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        // Fast symlinks store the target inline in the i_block area — no extent tree.
        raw[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        let inline_target_off = OFF_BLOCK;
        raw[inline_target_off..inline_target_off + target.len()].copy_from_slice(target);

        let now = now_unix_seconds();
        write_inode_timestamps(&mut raw, now);
        let generation = alloc_inode_generation();
        write_inode_generation(&mut raw, generation);
        write_inode_extra_isize(&mut raw);
        self.stamp_inode_checksum(&mut raw, ino, generation);
        Ok(raw)
    }

    /// Compose a slow-symlink inode image: `S_IFLNK | 0o777`, 1 link,
    /// `i_size = target.len()`, EXTENTS flag set with a single-entry leaf
    /// root pointing at `data_phys` (logical block 0, length 1). One fs
    /// block worth of 512-byte sectors charged to `i_blocks`.
    ///
    /// Caller must have already written the target bytes (zero-padded) to
    /// `data_phys * block_size`.
    fn build_slow_symlink_inode(&self, ino: u32, target: &[u8], data_phys: u64) -> Result<Vec<u8>> {
        use crate::inode::{
            OFF_BLOCK, OFF_BLOCKS_LO, OFF_FLAGS, OFF_LINKS_COUNT, OFF_MODE, OFF_SIZE_LO,
        };
        debug_assert!(target.len() >= 60 && target.len() <= 4096);
        let mut raw = vec![0u8; self.sb.inode_size as usize];

        let mode_bits = crate::inode::S_IFLNK | 0o0777;
        raw[OFF_MODE..OFF_MODE + 2].copy_from_slice(&mode_bits.to_le_bytes());
        raw[OFF_SIZE_LO..OFF_SIZE_LO + 4].copy_from_slice(&(target.len() as u32).to_le_bytes());
        raw[OFF_LINKS_COUNT..OFF_LINKS_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        let bs = self.sb.block_size() as u64;
        let sectors = bs / 512;
        raw[OFF_BLOCKS_LO..OFF_BLOCKS_LO + 4].copy_from_slice(&(sectors as u32).to_le_bytes());
        raw[OFF_FLAGS..OFF_FLAGS + 4]
            .copy_from_slice(&crate::inode::InodeFlags::EXTENTS.bits().to_le_bytes());

        // i_block: extent leaf header + one entry covering the single data block.
        let extent_header_off = OFF_BLOCK;
        raw[extent_header_off..extent_header_off + 2]
            .copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
        raw[extent_header_off + 2..extent_header_off + 4].copy_from_slice(&1u16.to_le_bytes());
        raw[extent_header_off + 4..extent_header_off + 6].copy_from_slice(&4u16.to_le_bytes());
        raw[extent_header_off + 6..extent_header_off + 8].copy_from_slice(&0u16.to_le_bytes());

        // Single leaf extent: logical block 0, length 1, physical = data_phys.
        let extent_entry_off = extent_header_off + 12;
        raw[extent_entry_off..extent_entry_off + 4].copy_from_slice(&0u32.to_le_bytes());
        raw[extent_entry_off + 4..extent_entry_off + 6].copy_from_slice(&1u16.to_le_bytes());
        let (extent_phys_hi, extent_phys_lo) = crate::extent_mut::split_phys_block(data_phys);
        raw[extent_entry_off + 6..extent_entry_off + 8]
            .copy_from_slice(&extent_phys_hi.to_le_bytes());
        raw[extent_entry_off + 8..extent_entry_off + 12]
            .copy_from_slice(&extent_phys_lo.to_le_bytes());

        let now = now_unix_seconds();
        write_inode_timestamps(&mut raw, now);
        let generation = alloc_inode_generation();
        write_inode_generation(&mut raw, generation);
        write_inode_extra_isize(&mut raw);
        self.stamp_inode_checksum(&mut raw, ino, generation);
        Ok(raw)
    }

    /// Compose a fresh regular-file inode image: `S_IFREG | mode`, 1 link,
    /// 0 size, 0 blocks, EXTENTS flag set with an empty 4-entry leaf root,
    /// timestamps = now, generation = process-id-derived counter, extra_isize
    /// = 32 so the inode has room for nsec timestamps + checksum_hi.
    fn build_regular_file_inode(&self, ino: u32, mode: u16) -> Result<Vec<u8>> {
        use crate::inode::{OFF_BLOCK, OFF_FLAGS, OFF_LINKS_COUNT, OFF_MODE};
        let mut raw = vec![0u8; self.sb.inode_size as usize];

        let mode_bits = crate::inode::S_IFREG | (mode & 0x0FFF);
        raw[OFF_MODE..OFF_MODE + 2].copy_from_slice(&mode_bits.to_le_bytes());
        raw[OFF_LINKS_COUNT..OFF_LINKS_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());

        // i_flags + i_block layout depend on the FS dialect:
        // - ext4 (FsFlavor::Ext4): EXTENTS_FL set, i_block holds an empty
        //   extent leaf header (magic + entries=0 + max=4 + depth=0).
        // - ext2 / ext3: no flag, i_block stays all-zero (no direct or
        //   indirect pointers — file is empty so there's nothing to map).
        if self.flavor.uses_extents() {
            raw[OFF_FLAGS..OFF_FLAGS + 4]
                .copy_from_slice(&crate::inode::InodeFlags::EXTENTS.bits().to_le_bytes());

            let extent_header_off = OFF_BLOCK;
            raw[extent_header_off..extent_header_off + 2]
                .copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
            raw[extent_header_off + 2..extent_header_off + 4].copy_from_slice(&0u16.to_le_bytes());
            raw[extent_header_off + 4..extent_header_off + 6].copy_from_slice(&4u16.to_le_bytes());
            raw[extent_header_off + 6..extent_header_off + 8].copy_from_slice(&0u16.to_le_bytes());
        }

        let now = now_unix_seconds();
        write_inode_timestamps(&mut raw, now);
        let generation = alloc_inode_generation();
        write_inode_generation(&mut raw, generation);
        write_inode_extra_isize(&mut raw);
        self.stamp_inode_checksum(&mut raw, ino, generation);
        Ok(raw)
    }

    /// Replace the content of `path` with `data`. The file must already
    /// exist. Frees every existing extent, allocates a single contiguous run
    /// of blocks large enough for `data`, writes the bytes (zero-padding the
    /// tail of the last block), then inserts one extent into the inode.
    ///
    /// This is the "Finder just saved a document" path — complete rewrite of
    /// a file. Piecewise writes / appends / sparse writes come later.
    ///
    /// Not journaled — scratch-image safe, same caveat as other Phase-4 ops.
    /// Returns the new file size on success.
    pub fn apply_replace_file_content(&self, path: &str, data: &[u8]) -> Result<u64> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument(
                "write_file target is not a regular file",
            ));
        }
        if !inode.has_extents() {
            // ext2 / ext3 (or ext4 inode without EXTENTS_FL): legacy
            // direct/indirect block-pointer scheme. Same overall shape as
            // the extent path below — free old → allocate → write data →
            // patch inode — but the i_block tree comes from `indirect_mut`
            // and any indirect-tree blocks are co-allocated with the data
            // run (one bitmap call covers both).
            return self.apply_replace_file_content_indirect(ino, inode, raw, data);
        }

        let bs = self.sb.block_size();
        let sectors_per_block = bs as u64 / 512;
        let group_idx_of_inode = ((ino - 1) / self.sb.inodes_per_group) as usize;

        // Multi-block transaction: free existing data + alloc new run +
        // bitmap + BGD + SB + new data block contents + inode update.
        // Atomic across the whole replace.
        let mut buf = BlockBuffer::new(bs);

        // Phase 1: free existing data blocks. Each freed run credits its
        // own group's BGD via `buffer_free_block_run_and_bgd`.
        let mut freed_fs_blocks: u64 = 0;
        if inode.size > 0 {
            let (_sc, muts) =
                crate::file_mut::plan_truncate_shrink(inode.size, 0, &inode.block, bs)?;
            for m in &muts {
                if let crate::extent_mut::ExtentMutation::FreePhysicalRun { start, len } = m {
                    freed_fs_blocks +=
                        self.buffer_free_block_run_and_bgd(&mut buf, *start, *len as u64)?;
                }
            }
        }

        // Reset the inode's extent root to an empty leaf.
        let mut root = vec![0u8; 60];
        root[0..2].copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
        root[4..6].copy_from_slice(&4u16.to_le_bytes()); // max entries
        Self::patch_inode_block_area(&mut raw, &root)?;

        // Empty write: BGDs already credited per-run above; only SB needs
        // a single update + inode rewrite.
        if data.is_empty() {
            self.finalize_inode_raw_after_write(ino, &mut raw, &inode, 0, 0)?;
            if freed_fs_blocks > 0 {
                self.buffer_patch_sb_counters(&mut buf, freed_fs_blocks as i64, 0)?;
            }
            self.buffer_write_inode(&mut buf, ino, &raw)?;
            self.commit_block_buffer(buf)?;
            return Ok(0);
        }

        // Phase 2: allocate one contiguous run for the whole payload.
        let needed_blocks: u32 = data.len().div_ceil(bs as usize) as u32;
        let mut bitmap_reader = |block: u64| self.read_block(block);
        let plan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            needed_blocks,
            group_idx_of_inode as u32,
            &mut bitmap_reader,
        )?;

        // Phase 3: mark allocated bitmap + patch destination BGD; SB nets
        // the alloc delta against the freed total computed above.
        self.buffer_mark_block_run_used(&mut buf, plan.first_block, needed_blocks as u64)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        let net_block_delta = freed_fs_blocks as i64 - needed_blocks as i64;
        self.buffer_patch_sb_counters(&mut buf, net_block_delta, 0)?;

        // Phase 4: stage the payload into the allocated physical run.
        for i in 0..needed_blocks as u64 {
            let off_in_data = (i as usize) * bs as usize;
            let chunk_end = ((i as usize + 1) * bs as usize).min(data.len());
            let mut block = vec![0u8; bs as usize];
            block[..chunk_end - off_in_data].copy_from_slice(&data[off_in_data..chunk_end]);
            buf.put(plan.first_block + i, block);
        }

        // Phase 5: insert the single extent into the (now-empty) inline
        // root and stage the inode.
        let new_extent = crate::extent::Extent {
            logical_block: 0,
            length: needed_blocks as u16,
            physical_block: plan.first_block,
            uninitialized: false,
        };
        let muts = crate::extent_mut::plan_insert_extent(&root, new_extent)?;
        for m in &muts {
            if let crate::extent_mut::ExtentMutation::WriteRoot { bytes } = m {
                Self::patch_inode_block_area(&mut raw, bytes)?;
            }
        }
        let new_size = data.len() as u64;
        let new_sectors = needed_blocks as u64 * sectors_per_block;
        self.finalize_inode_raw_after_write(ino, &mut raw, &inode, new_size, new_sectors)?;
        self.buffer_write_inode(&mut buf, ino, &raw)?;

        self.commit_block_buffer(buf)?;
        Ok(new_size)
    }

    /// ext2/ext3 sibling of `apply_replace_file_content`'s extent path.
    /// Frees the inode's existing direct/indirect tree, allocates one
    /// contiguous run sized for both the data payload AND the indirect-tree
    /// metadata blocks, builds the new tree via `indirect_mut::plan_contiguous`,
    /// then persists everything (data → indirect blocks → inode).
    ///
    /// No journal interaction: ext2 has no journal at all, and the user's
    /// `JournalWriter` returns `None` for those mounts so `self.journal` is
    /// already None at this point. ext3 mounts (Phase B) will plumb writes
    /// through the journal once the writer can address indirect-block
    /// journal inodes.
    fn apply_replace_file_content_indirect(
        &self,
        ino: u32,
        inode: Inode,
        mut raw: Vec<u8>,
        data: &[u8],
    ) -> Result<u64> {
        let bs = self.sb.block_size();
        let sectors_per_block = bs as u64 / 512;
        let group_idx_of_inode = ((ino - 1) / self.sb.inodes_per_group) as usize;

        // Phase 1: free existing data + indirect-tree blocks. `collect_for_free`
        // walks the tree and returns coalesced data runs + individual indirect
        // blocks, so cross-group fragmented files are accounted for correctly.
        let mut freed_fs_blocks: u64 = 0;
        if inode.size > 0 {
            let block_count = inode.size.div_ceil(bs as u64) as u32;
            let freed = crate::indirect_mut::collect_for_free(
                &inode.block,
                bs,
                block_count,
                self.dev.as_ref(),
            )?;
            for run in &freed.data_runs {
                freed_fs_blocks += self.free_block_run_and_bgd(run.start, run.len as u64)?;
            }
            for &iblk in &freed.indirect_blocks {
                freed_fs_blocks += self.free_block_run_and_bgd(iblk, 1)?;
            }
        }
        // Reset i_block to all zeros — no extent magic for legacy inodes.
        let zero_iblock = [0u8; 60];
        Self::patch_inode_block_area(&mut raw, &zero_iblock)?;

        if data.is_empty() {
            self.finalize_inode_after_write(ino, &mut raw, &inode, 0, 0)?;
            if freed_fs_blocks > 0 {
                self.patch_sb_counters(freed_fs_blocks as i64, 0)?;
            }
            self.dev.flush()?;
            return Ok(0);
        }

        // Phase 2: allocate one contiguous run sized for data + indirect tree.
        // Indirect blocks live at the head of the run, data at the tail.
        // `count_indirect_blocks` is exactly the number of allocator pulls
        // `plan_contiguous` will make, so the budget is tight (verified by
        // the `count_indirect_blocks_matches_plan_contiguous` unit test).
        let needed_data_blocks: u32 = data.len().div_ceil(bs as usize) as u32;
        let n_indirect: u32 = crate::indirect_mut::count_indirect_blocks(needed_data_blocks, bs)
            .try_into()
            .map_err(|_| Error::Corrupt("indirect_mut: indirect block count overflow"))?;
        let total_run = needed_data_blocks
            .checked_add(n_indirect)
            .ok_or(Error::Corrupt("indirect_mut: total run count overflow"))?;

        let mut bitmap_reader = |block: u64| self.read_block(block);
        let plan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            total_run,
            group_idx_of_inode as u32,
            &mut bitmap_reader,
        )?;
        let first_indirect = plan.first_block;
        let first_data = plan.first_block + n_indirect as u64;

        // Phase 3: build the indirect tree. The closure hands out blocks
        // sequentially from `first_indirect` — `plan_contiguous` doesn't
        // care about address ordering, so any allocation order is fine.
        let mut next_indirect = first_indirect;
        let i_plan =
            crate::indirect_mut::plan_contiguous(needed_data_blocks, first_data, bs, || {
                let v = next_indirect;
                next_indirect += 1;
                Ok(v)
            })?;

        // Phase 4: bitmap + BGD + SB counters cover the whole run in one
        // mark-used + one BGD-credit + one SB-update.
        self.set_block_run_used(plan.first_block, total_run as u64)?;
        self.patch_bgd_counters(
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        let net_block_delta = freed_fs_blocks as i64 - total_run as i64;
        self.patch_sb_counters(net_block_delta, 0)?;

        // Phase 5: write the data payload into the data-portion of the run.
        for i in 0..needed_data_blocks as u64 {
            let off_in_data = (i as usize) * bs as usize;
            let chunk_end = ((i as usize + 1) * bs as usize).min(data.len());
            let mut block = vec![0u8; bs as usize];
            block[..chunk_end - off_in_data].copy_from_slice(&data[off_in_data..chunk_end]);
            self.dev.write_at((first_data + i) * bs as u64, &block)?;
        }

        // Phase 6: write the indirect-tree blocks.
        for (blk, buf) in &i_plan.block_writes {
            self.dev.write_at(blk * bs as u64, buf)?;
        }

        // Phase 7: patch i_block region with the new tree root.
        Self::patch_inode_block_area(&mut raw, &i_plan.i_block)?;

        // Phase 8: finalize. ext2/3 i_blocks counts BOTH data AND indirect
        // blocks (in 512-byte sectors) — extent metadata blocks count the
        // same way for ext4 so the rule is consistent across flavors.
        let new_size = data.len() as u64;
        let new_sectors = (needed_data_blocks as u64 + n_indirect as u64) * sectors_per_block;
        self.finalize_inode_after_write(ino, &mut raw, &inode, new_size, new_sectors)?;
        self.dev.flush()?;
        Ok(new_size)
    }

    /// Positional write: splice `data` into the file at byte `offset`,
    /// allocating new physical blocks for any logical blocks that aren't
    /// yet mapped (sparse holes, or blocks past EOF). Existing mapped
    /// blocks are read-modify-written for partial overlap; full-block
    /// writes go in fresh.
    ///
    /// This is the primitive needed by streaming write paths
    /// (FUSE/WinFsp/FSKit cache-manager dispatches) — `apply_replace_file_content`
    /// is "save-as", `apply_pwrite` is `pwrite(2)`.
    ///
    /// Returns the new file size on success.
    ///
    /// Allocation behaviour:
    /// - Each unmapped logical run is satisfied by one or more physical
    ///   runs. If `plan_block_allocation` can't find a single contiguous
    ///   group-local run sized for the whole logical run, the request is
    ///   halved and retried — each successful sub-run becomes its own
    ///   extent. True ENOSPC (single-block allocation also fails)
    ///   surfaces as `Error::NoSpaceLeftOnDevice`.
    /// - Extent inserts try the inline-root path first; on
    ///   `LEAF_FULL_NEEDS_PROMOTION` they fall back to
    ///   `plan_insert_extent_deep`, which promotes the tree to depth ≥ 1
    ///   and allocates the additional internal/leaf node blocks via the
    ///   same buffer-aware allocator. Tail checksums on tree blocks are
    ///   patched when `metadata_csum` is on.
    ///
    /// v1 limitations:
    /// - Extent-tree inodes only. Legacy ext2/3 (direct/indirect blocks)
    ///   returns `Error::InvalidArgument`. The streaming-copy use case
    ///   for this path is on freshly-mkfs'd ext4 volumes that always
    ///   have `EXTENTS_FL`.
    /// - Pre-existing uninitialised extents (from `fallocate`) in the
    ///   write range: not handled — the unmapped-run walk treats them
    ///   the same as holes and tries to insert a fresh extent that
    ///   would overlap, hitting `CorruptExtentTree("extent overlaps
    ///   existing")`. Skipping fallocate-then-write, the streaming
    ///   copy path doesn't trigger this.
    pub fn apply_pwrite(&self, path: &str, offset: u64, data: &[u8]) -> Result<u64> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, path)?;
        let (inode, mut raw) = self.read_inode_verified(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument(
                "pwrite target is not a regular file",
            ));
        }
        if !inode.has_extents() {
            return Err(Error::InvalidArgument(
                "pwrite: legacy (non-extents) inodes not supported in v1",
            ));
        }

        if data.is_empty() {
            // No-op (no size change either — a zero-length pwrite at any
            // offset is a no-op per POSIX `pwrite(2)`).
            return Ok(inode.size);
        }

        let bs = self.sb.block_size() as u64;
        let bs_usize = bs as usize;
        let sectors_per_block = bs / 512;
        let len = data.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or(Error::InvalidArgument("pwrite: offset+len overflow"))?;
        let first_lb = offset / bs;
        let last_lb_excl = end.div_ceil(bs);

        // A single pwrite journals all its data blocks plus the inode/bitmap/
        // BGD/SB metadata in ONE transaction, whose descriptor block holds only
        // ~(block_size - 12)/16 tags. A write spanning more than that overflows
        // it ("descriptor block overflow"). Split large writes into block-
        // aligned chunks that each fit one transaction; every chunk commits
        // atomically (POSIX pwrite is not atomic across a large range anyway).
        let tags_per_desc = (bs_usize.saturating_sub(12)) / 16;
        // Reserve 8 tag slots for this transaction's own metadata: inode, block
        // bitmap, BGD, superblock, plus up to ~4 extent-tree node blocks when a
        // chunk's extents grow the tree. A chunk of (tags_per_desc - 8) data
        // blocks always lands in a single block group (247 blocks at 4 KiB, well
        // inside a 128 MiB group), so the real overhead is <= 4 — 8 is a
        // conservative ~2x bound.
        let max_data_blocks = tags_per_desc.saturating_sub(8).max(1) as u64;
        let max_chunk = max_data_blocks * bs;
        if len > max_chunk {
            let mut chunk_off = 0u64;
            while chunk_off < len {
                let take = max_chunk.min(len - chunk_off);
                let s = chunk_off as usize;
                let e = (chunk_off + take) as usize;
                self.apply_pwrite(path, offset + chunk_off, &data[s..e])?;
                chunk_off += take;
            }
            let (after, _) = self.read_inode_verified(ino)?;
            return Ok(after.size);
        }

        // Working copy of the 60-byte inline extent root. Updated in place
        // as we insert extents for each unmapped run; patched into `raw`
        // once at the end.
        let mut root_bytes: Vec<u8> = inode.block.to_vec();

        let mut buf = BlockBuffer::new(self.sb.block_size());
        let group_idx_of_inode = ((ino - 1) / self.sb.inodes_per_group) as u32;

        // Track which logical blocks were freshly allocated by this call.
        // Phase-2 writes for these MUST NOT read from disk (the prior
        // contents of those physical blocks are stale junk from whoever
        // freed them last); they get a zero-init buffer instead.
        let mut newly_alloc: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut alloc_total_blocks: u64 = 0;

        // Phase 1: walk affected logical blocks; allocate each contiguous
        // unmapped run as one physical extent and stage the bitmap/BGD
        // updates. Repeated `map_logical` calls re-parse `root_bytes` each
        // time, so the in-progress inserts are visible to subsequent
        // lookups in the same loop.
        let mut lb = first_lb;
        while lb < last_lb_excl {
            let mapped = crate::extent::map_logical(
                &root_bytes,
                self.dev.as_ref(),
                self.sb.block_size(),
                lb,
            )?;
            if mapped.is_some() {
                lb += 1;
                continue;
            }
            // Find the end of this unmapped run.
            let mut run_end = lb + 1;
            while run_end < last_lb_excl {
                let p = crate::extent::map_logical(
                    &root_bytes,
                    self.dev.as_ref(),
                    self.sb.block_size(),
                    run_end,
                )?;
                if p.is_some() {
                    break;
                }
                run_end += 1;
            }
            let run_len_u64 = run_end - lb;
            if run_len_u64 > u32::MAX as u64 {
                return Err(Error::InvalidArgument(
                    "pwrite: unmapped run exceeds u32 block count",
                ));
            }

            // Allocate physical blocks for this logical run, splitting
            // across smaller contiguous physical runs when no single
            // group has a free run that size. Each sub-allocation is
            // staged into the buffer (bitmap + BGD) and inserted as its
            // own extent. plan_insert_extent auto-merges adjacent extents
            // so the *common* sequential-write case still produces one
            // extent overall.
            let mut remaining_in_run = run_len_u64 as u32;
            let mut sub_lb = lb;
            while remaining_in_run > 0 {
                let mut want = remaining_in_run;
                let plan = loop {
                    let plan_result = {
                        let mut bitmap_reader = |b: u64| -> Result<Vec<u8>> {
                            if let Some(bytes) = buf.dirty.get(&b) {
                                return Ok(bytes.clone());
                            }
                            self.read_block(b)
                        };
                        crate::alloc::plan_block_allocation(
                            &self.sb,
                            &self.groups,
                            want,
                            group_idx_of_inode,
                            &mut bitmap_reader,
                        )
                    };
                    match plan_result {
                        Ok(p) => break p,
                        Err(Error::Corrupt(msg)) if msg.contains("contiguous free run") => {
                            if want == 1 {
                                // Even a single block isn't available
                                // anywhere — true ENOSPC.
                                return Err(Error::NoSpaceLeftOnDevice);
                            }
                            // Fragmented: halve the request and retry.
                            // Each successful sub-run becomes its own
                            // extent; the outer while loop keeps drawing
                            // until the whole logical run is covered.
                            want /= 2;
                        }
                        Err(e) => return Err(e),
                    }
                };

                let got = want;
                let got_u64 = got as u64;

                self.buffer_mark_block_run_used(&mut buf, plan.first_block, got_u64)?;
                self.buffer_patch_bgd_counters(
                    &mut buf,
                    plan.bgd.group_idx as usize,
                    plan.bgd.free_blocks_delta,
                    plan.bgd.free_inodes_delta,
                    plan.bgd.used_dirs_delta,
                )?;
                alloc_total_blocks += got_u64;

                let new_extent = crate::extent::Extent {
                    logical_block: sub_lb as u32,
                    length: got as u16,
                    physical_block: plan.first_block,
                    uninitialized: false,
                };

                // Try the inline-root insert first; on overflow fall back
                // to the depth-promoting deep insert. Both paths produce a
                // new 60-byte root that we splice into `raw` at the end.
                match crate::extent_mut::plan_insert_extent(&root_bytes, new_extent) {
                    Ok(muts) => {
                        for m in &muts {
                            if let crate::extent_mut::ExtentMutation::WriteRoot { bytes } = m {
                                root_bytes = bytes.clone();
                            }
                        }
                    }
                    Err(Error::CorruptExtentTree(msg))
                        if msg.contains("LEAF_FULL_NEEDS_PROMOTION")
                            || msg.contains("multi-level tree mutation") =>
                    {
                        // Two distinct failures both route to the deep path:
                        // 1. Inline leaf root has 4 entries already
                        //    (LEAF_FULL_NEEDS_PROMOTION) → promote to depth 1.
                        // 2. Root has *already* been promoted on a prior
                        //    insert in this same call → root is an index
                        //    node, so the inline-leaf-only `plan_insert_extent`
                        //    bails with "multi-level tree mutation". The
                        //    deep planner descends correctly.
                        // Allocate tree-meta blocks one at a time via the
                        // same buffer-aware allocator. Each call stages a
                        // bitmap + BGD update so subsequent allocations
                        // see the just-claimed bits.
                        let reader = FsBlockReader { fs: self };
                        let mut meta_blocks_alloc: u64 = 0;
                        let inode_generation = inode.generation;
                        let deep_plan = {
                            let mut alloc_closure = || -> Result<u64> {
                                let p = {
                                    let mut bitmap_reader = |b: u64| -> Result<Vec<u8>> {
                                        if let Some(bytes) = buf.dirty.get(&b) {
                                            return Ok(bytes.clone());
                                        }
                                        self.read_block(b)
                                    };
                                    crate::alloc::plan_block_allocation(
                                        &self.sb,
                                        &self.groups,
                                        1,
                                        group_idx_of_inode,
                                        &mut bitmap_reader,
                                    )?
                                };
                                self.buffer_mark_block_run_used(&mut buf, p.first_block, 1)?;
                                self.buffer_patch_bgd_counters(
                                    &mut buf,
                                    p.bgd.group_idx as usize,
                                    p.bgd.free_blocks_delta,
                                    0,
                                    0,
                                )?;
                                meta_blocks_alloc += 1;
                                Ok(p.first_block)
                            };
                            crate::extent_mut::plan_insert_extent_deep(
                                &root_bytes,
                                new_extent,
                                self.sb.block_size(),
                                &reader,
                                &mut alloc_closure,
                            )?
                        };
                        root_bytes = deep_plan.new_root;
                        let bs_u64 = self.sb.block_size() as u64;
                        for (block, bytes) in deep_plan.block_writes {
                            let mut bytes = bytes;
                            if self.csum.enabled {
                                self.csum
                                    .patch_extent_tail(ino, inode_generation, &mut bytes);
                            }
                            // Eager-write tree-meta blocks to disk so a
                            // *subsequent* plan_insert_extent_deep within
                            // this same apply_pwrite (when more sub-runs
                            // follow and need to descend the just-promoted
                            // tree) can fetch them via FsBlockReader. Also
                            // stage in buf so the final commit_block_buffer
                            // covers them inside the same transaction tail.
                            // On a pre-commit crash these become orphaned
                            // bytes that fsck reclaims (the block bitmap
                            // mark is in `buf` and only lands on commit).
                            self.dev.write_at(block * bs_u64, &bytes)?;
                            buf.put(block, bytes);
                        }
                        alloc_total_blocks += meta_blocks_alloc;
                    }
                    Err(e) => return Err(e),
                }

                // Mark these logical blocks as freshly-allocated so Phase 2
                // writes use put() (zero-init) instead of get_mut()
                // (read-from-disk-and-modify).
                for x in sub_lb..(sub_lb + got_u64) {
                    newly_alloc.insert(x);
                }

                sub_lb += got_u64;
                remaining_in_run -= got;
            }

            lb = run_end;
        }

        // Phase 2: splice the chunk into each affected block.
        let mut data_off: usize = 0;
        for cur_lb in first_lb..last_lb_excl {
            let block_byte_start = cur_lb * bs;
            let block_byte_end = block_byte_start + bs;
            let chunk_start = offset.max(block_byte_start);
            let chunk_end = end.min(block_byte_end);
            let in_block_off = (chunk_start - block_byte_start) as usize;
            let chunk_len = (chunk_end - chunk_start) as usize;

            let phys = crate::extent::map_logical(
                &root_bytes,
                self.dev.as_ref(),
                self.sb.block_size(),
                cur_lb,
            )?
            .ok_or(Error::Corrupt(
                "pwrite Phase 2: logical block unmapped after Phase 1 (allocator/extent insert mismatch)",
            ))?;

            if newly_alloc.contains(&cur_lb) {
                // Fresh block: zero-init then splice. Avoids reading stale
                // bytes from a previously-freed extent.
                let mut block = vec![0u8; bs_usize];
                block[in_block_off..in_block_off + chunk_len]
                    .copy_from_slice(&data[data_off..data_off + chunk_len]);
                buf.put(phys, block);
            } else {
                // Existing block: read-modify-write to preserve untouched
                // bytes (head before `chunk_start`, tail after `chunk_end`).
                let block = buf.get_mut(self, phys)?;
                if block.len() != bs_usize {
                    return Err(Error::Corrupt(
                        "pwrite Phase 2: existing block has wrong size",
                    ));
                }
                block[in_block_off..in_block_off + chunk_len]
                    .copy_from_slice(&data[data_off..data_off + chunk_len]);
            }

            data_off += chunk_len;
        }
        debug_assert_eq!(data_off, data.len());

        // Phase 3: patch the extent root onto `raw`, update size + sectors,
        // recompute the inode checksum, stage the inode write.
        Self::patch_inode_block_area(&mut raw, &root_bytes)?;
        let new_size = inode.size.max(end);
        let new_sectors = inode
            .blocks
            .checked_add(alloc_total_blocks * sectors_per_block)
            .ok_or(Error::Corrupt("pwrite: i_blocks overflow"))?;
        self.finalize_inode_raw_after_write(ino, &mut raw, &inode, new_size, new_sectors)?;
        self.buffer_write_inode(&mut buf, ino, &raw)?;

        // Phase 4: SB delta for the newly-allocated blocks.
        if alloc_total_blocks > 0 {
            self.buffer_patch_sb_counters(&mut buf, -(alloc_total_blocks as i64), 0)?;
        }

        // Phase 5: commit everything atomically (journaled if available).
        self.commit_block_buffer(buf)?;
        Ok(new_size)
    }

    /// Patch size + blocks counter on the inode image, recompute the csum
    /// if enabled, and write it back. Shared tail for apply_replace_file_content and
    /// any future writer that produces a new `raw` image.
    fn finalize_inode_after_write(
        &self,
        ino: u32,
        raw: &mut [u8],
        orig: &Inode,
        new_size: u64,
        new_sectors: u64,
    ) -> Result<()> {
        self.finalize_inode_raw_after_write(ino, raw, orig, new_size, new_sectors)?;
        self.write_inode_raw(ino, raw)
    }

    /// Buffer-friendly variant of `finalize_inode_after_write`: patches
    /// size, blocks, ctime, mtime, and checksum on `raw` IN PLACE without
    /// writing to disk. Caller stages the result via `buffer_write_inode`
    /// so the inode update is atomic with the surrounding multi-block tx.
    fn finalize_inode_raw_after_write(
        &self,
        ino: u32,
        raw: &mut [u8],
        orig: &Inode,
        new_size: u64,
        new_sectors: u64,
    ) -> Result<()> {
        Self::patch_inode_size_and_blocks(raw, new_size, new_sectors)?;
        let now = now_unix_seconds();
        raw[0x0C..0x10].copy_from_slice(&now.to_le_bytes()); // ctime
        raw[0x10..0x14].copy_from_slice(&now.to_le_bytes()); // mtime
        if self.csum.enabled {
            if let Some((lo, hi)) = self.csum.compute_inode_checksum(ino, orig.generation, raw) {
                raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if raw.len() >= 0x84 {
                    raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    /// Mark `len` bits starting at block `start` as USED in the containing
    /// block group's bitmap. Mirrors `free_block_run` but sets rather than
    /// clears. Assumes the run lies entirely within one group (same caveat).
    /// Phase 1.2: Apply a `BlockAllocationPlan` end-to-end on the un-
    /// journaled path — bitmap mark + BGD counter patch + SB counter
    /// patch in one call. Used by ops that haven't been migrated to the
    /// BlockBuffer pattern yet (apply_create's data write, etc.); the
    /// journaled path uses `buffer_mark_block_run_used` +
    /// `buffer_patch_bgd_counters` + `buffer_patch_sb_counters`
    /// against a `BlockBuffer` instead.
    fn commit_block_alloc(&self, plan: &crate::alloc::BlockAllocationPlan) -> Result<()> {
        self.set_block_run_used(plan.first_block, plan.count as u64)?;
        self.patch_bgd_counters(
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        self.patch_sb_counters(plan.sb.free_blocks_delta, plan.sb.free_inodes_delta)?;
        Ok(())
    }

    fn set_block_run_used(&self, start: u64, len: u64) -> Result<()> {
        let bpg = self.sb.blocks_per_group as u64;
        let first_data = self.sb.first_data_block as u64;
        let gi = ((start - first_data) / bpg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidBlock(start));
        }
        let group_start = first_data + gi as u64 * bpg;
        let bit_start = (start - group_start) as u32;
        let bitmap_block = self.groups[gi].block_bitmap;
        let bs = self.sb.block_size() as u64;
        let mut buf = vec![0u8; bs as usize];
        self.dev.read_at(bitmap_block * bs, &mut buf)?;
        for i in 0..len {
            let bit = bit_start as u64 + i;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if byte < buf.len() {
                buf[byte] |= mask;
            }
        }
        self.dev.write_at(bitmap_block * bs, &buf)?;
        Ok(())
    }

    /// Find `name` in directory `dir_inode` — scans each data block. Returns
    /// the inode number or `Error::NotFound`.
    fn find_entry_in_dir(&self, dir_inode: &Inode, name: &[u8]) -> Result<u32> {
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let bs = self.sb.block_size();
        let n_blocks = dir_inode.size.div_ceil(bs as u64);
        for logical in 0..n_blocks {
            let Some(phys) = self.map_inode_logical(dir_inode, logical)? else {
                continue;
            };
            let block = self.read_block(phys)?;
            for entry in crate::dir::DirBlockIter::new(&block, has_ft) {
                let e = entry?;
                if e.name == name {
                    return Ok(e.inode);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Clear the inode bitmap bit for `ino`. Does NOT touch counters — the
    /// caller pairs this with a `patch_bgd_counters` + `patch_sb_counters` call
    /// so BGD free_inodes_count and SB free_inodes_count land together.
    fn free_inode_slot(&self, ino: u32) -> Result<()> {
        let ipg = self.sb.inodes_per_group;
        let gi = ((ino - 1) / ipg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidInode(ino));
        }
        let bit = ((ino - 1) % ipg) as u64;
        let bitmap_block = self.groups[gi].inode_bitmap;
        let bs = self.sb.block_size() as u64;
        let mut buf = vec![0u8; bs as usize];
        self.dev.read_at(bitmap_block * bs, &mut buf)?;
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte < buf.len() {
            buf[byte] &= !mask;
        }
        self.dev.write_at(bitmap_block * bs, &buf)?;

        self.patch_bgd_counters(gi, 0, 1, 0)?;
        Ok(())
    }

    /// Set the inode bitmap bit for `ino`. Paired with `patch_bgd_counters`
    /// (`free_inodes_delta = -1` and, for dirs, `used_dirs_delta = +1`).
    fn mark_inode_used(&self, ino: u32) -> Result<()> {
        let ipg = self.sb.inodes_per_group;
        let gi = ((ino - 1) / ipg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidInode(ino));
        }
        let bit = ((ino - 1) % ipg) as u64;
        let bitmap_block = self.groups[gi].inode_bitmap;
        let bs = self.sb.block_size() as u64;
        let mut buf = vec![0u8; bs as usize];
        self.dev.read_at(bitmap_block * bs, &mut buf)?;
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte < buf.len() {
            buf[byte] |= mask;
        }
        self.dev.write_at(bitmap_block * bs, &buf)?;
        Ok(())
    }

    /// Apply per-group counter deltas on disk for group `gi`. Positive deltas
    /// increase the corresponding `bg_free_*` / `bg_used_dirs` counter,
    /// negative deltas decrease. Recomputes the BGD csum when `metadata_csum`
    /// is enabled. The in-memory `self.groups` copy is NOT updated — callers
    /// doing a sequence of allocations should `Filesystem::mount` fresh.
    pub(crate) fn patch_bgd_counters(
        &self,
        gi: usize,
        free_blocks_delta: i32,
        free_inodes_delta: i32,
        used_dirs_delta: i32,
    ) -> Result<()> {
        let bs = self.sb.block_size() as u64;
        let desc_size = self.sb.desc_size as u64;
        let bgt_first_block = self.sb.first_data_block as u64 + 1;
        let byte_in_bgt = gi as u64 * desc_size;
        let bgt_block = bgt_first_block + byte_in_bgt / bs;
        let off_in_block = (byte_in_bgt % bs) as usize;

        let mut block = self.read_block(bgt_block)?;

        // Free-blocks: 16-bit at 0x0C, hi at 0x2A when 64-bit
        patch_counter_u32(
            &mut block,
            off_in_block + 0x0C,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2A)
            } else {
                None
            },
            free_blocks_delta,
        );
        // Free-inodes: 16-bit at 0x0E, hi at 0x2C when 64-bit
        patch_counter_u32(
            &mut block,
            off_in_block + 0x0E,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2C)
            } else {
                None
            },
            free_inodes_delta,
        );
        // Used-dirs: 16-bit only (kernel defines u16+u16 hi at 0x2E too, but
        // dirs per group realistically fit in u16 — handle both anyway).
        patch_counter_u32(
            &mut block,
            off_in_block + 0x10,
            if desc_size >= 0x40 {
                Some(off_in_block + 0x2E)
            } else {
                None
            },
            used_dirs_delta,
        );

        if self.csum.enabled {
            let stored_at = off_in_block + 0x1E;
            let end_desc = off_in_block + desc_size as usize;
            block[stored_at..stored_at + 2].copy_from_slice(&[0, 0]);
            let seed = self.csum.seed;
            let mut c = crate::checksum::linux_crc32c(seed, &(gi as u32).to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[off_in_block..end_desc]);
            let new_csum = c as u16;
            block[stored_at..stored_at + 2].copy_from_slice(&new_csum.to_le_bytes());
        }
        self.dev.write_at(bgt_block * bs, &block)?;
        Ok(())
    }

    /// Apply deltas to SB `s_free_blocks_count` and `s_free_inodes_count`.
    /// Recomputes the SB checksum when enabled. Does not mutate `self.sb`.
    pub(crate) fn patch_sb_counters(
        &self,
        free_blocks_delta: i64,
        free_inodes_delta: i32,
    ) -> Result<()> {
        // Route through the cache-coherent buffer path (which reads the SB via
        // read_block) so consecutive ops accumulate against the CURRENT
        // on-disk superblock. The old body re-read the immutable mount-time
        // snapshot `self.sb.raw` every call, so within a single mount each
        // call rewrote the SB from mount-time values — a sequence of
        // frees/allocs clobbered each other (e.g. directory growth froze
        // free_blocks at mount-1 and reset free_inodes, which e2fsck flags as
        // "Free blocks/inodes count wrong").
        let mut buf = BlockBuffer::new(self.sb.block_size());
        self.buffer_patch_sb_counters(&mut buf, free_blocks_delta, free_inodes_delta)?;
        self.commit_block_buffer(buf)?;
        Ok(())
    }

    /// Zero the bitmap bits covering the physical block run
    /// `[start, start+len)`. Assumes the run lies entirely within one block
    /// group (true for allocator-produced runs; fragmentation across groups
    /// is a future concern).
    fn free_block_run(&self, start: u64, len: u64) -> Result<()> {
        let bpg = self.sb.blocks_per_group as u64;
        let first_data = self.sb.first_data_block as u64;
        // Block group index of the first block in the run.
        let gi = ((start - first_data) / bpg) as usize;
        if gi >= self.groups.len() {
            return Err(Error::InvalidBlock(start));
        }
        let group_start = first_data + gi as u64 * bpg;
        let bit_start = (start - group_start) as u32;
        let bg = &self.groups[gi];
        let bitmap_block = bg.block_bitmap;

        let bs = self.sb.block_size() as u64;
        let mut buf = vec![0u8; bs as usize];
        self.dev.read_at(bitmap_block * bs, &mut buf)?;
        for i in 0..len {
            let bit = bit_start as u64 + i;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if byte < buf.len() {
                buf[byte] &= !mask;
            }
        }
        self.dev.write_at(bitmap_block * bs, &buf)?;
        Ok(())
    }

    /// Free a physical-block run AND patch the containing group's
    /// `bg_free_blocks_count`. Returns `len` so the caller can accumulate a
    /// running total to feed `patch_sb_counters` once per high-level op.
    ///
    /// Per-call BGD updates correctly handle runs that span groups (each
    /// call lands in exactly one group per [`free_block_run`]'s contract).
    /// SB updates are deliberately deferred so freeing a 1000-extent file
    /// produces 1 SB write instead of 1000.
    fn free_block_run_and_bgd(&self, start: u64, len: u64) -> Result<u64> {
        self.free_block_run(start, len)?;
        let bpg = self.sb.blocks_per_group as u64;
        let first_data = self.sb.first_data_block as u64;
        let gi = ((start - first_data) / bpg) as usize;
        if gi < self.groups.len() {
            self.patch_bgd_counters(gi, len as i32, 0, 0)?;
        }
        Ok(len)
    }

    // -----------------------------------------------------------------------
    // mkdir / rmdir
    // -----------------------------------------------------------------------

    /// Build an on-disk inode image for a freshly-created directory. Sets
    /// `S_IFDIR | mode`, `i_links_count = 2` (for `.` and the dir entry in
    /// the parent), `i_size = block_size` (one data block), EXTENTS flag
    /// with a single leaf extent mapping logical 0 → `data_phys_block`,
    /// timestamps = now.
    fn build_directory_inode(&self, ino: u32, mode: u16, data_phys_block: u64) -> Result<Vec<u8>> {
        use crate::inode::{
            OFF_BLOCK, OFF_BLOCKS_HI, OFF_BLOCKS_LO, OFF_FLAGS, OFF_LINKS_COUNT, OFF_MODE,
            OFF_SIZE_HI, OFF_SIZE_LO,
        };
        let mut raw = vec![0u8; self.sb.inode_size as usize];

        let mode_bits = crate::inode::S_IFDIR | (mode & 0x0FFF);
        raw[OFF_MODE..OFF_MODE + 2].copy_from_slice(&mode_bits.to_le_bytes());
        // 2 hard links: one for "." and one for the parent's entry naming this dir.
        raw[OFF_LINKS_COUNT..OFF_LINKS_COUNT + 2].copy_from_slice(&2u16.to_le_bytes());
        raw[OFF_FLAGS..OFF_FLAGS + 4]
            .copy_from_slice(&crate::inode::InodeFlags::EXTENTS.bits().to_le_bytes());

        // i_block (60 B): extent header (leaf, 1 entry, max 4) + one Extent.
        let extent_header_off = OFF_BLOCK;
        raw[extent_header_off..extent_header_off + 2]
            .copy_from_slice(&crate::extent::EXT4_EXT_MAGIC.to_le_bytes());
        raw[extent_header_off + 2..extent_header_off + 4].copy_from_slice(&1u16.to_le_bytes());
        raw[extent_header_off + 4..extent_header_off + 6].copy_from_slice(&4u16.to_le_bytes());
        // depth=0 leaf, generation=0 — both stay zero from initial vec![0u8; ...]

        // Entry at extent_header_off+12: logical 0, len 1, phys = data_phys_block.
        let extent_entry_off = extent_header_off + 12;
        raw[extent_entry_off..extent_entry_off + 4].copy_from_slice(&0u32.to_le_bytes());
        raw[extent_entry_off + 4..extent_entry_off + 6].copy_from_slice(&1u16.to_le_bytes());
        let (extent_phys_hi, extent_phys_lo) = crate::extent_mut::split_phys_block(data_phys_block);
        raw[extent_entry_off + 6..extent_entry_off + 8]
            .copy_from_slice(&extent_phys_hi.to_le_bytes());
        raw[extent_entry_off + 8..extent_entry_off + 12]
            .copy_from_slice(&extent_phys_lo.to_le_bytes());

        // Size = block_size (the single data block fills the dir).
        let bs = self.sb.block_size() as u64;
        raw[OFF_SIZE_LO..OFF_SIZE_LO + 4]
            .copy_from_slice(&((bs & 0xFFFF_FFFF) as u32).to_le_bytes());
        raw[OFF_SIZE_HI..OFF_SIZE_HI + 4].copy_from_slice(&((bs >> 32) as u32).to_le_bytes());

        let sectors = bs / 512;
        raw[OFF_BLOCKS_LO..OFF_BLOCKS_LO + 4].copy_from_slice(&(sectors as u32).to_le_bytes());
        raw[OFF_BLOCKS_HI..OFF_BLOCKS_HI + 2]
            .copy_from_slice(&(((sectors >> 32) & 0xFFFF) as u16).to_le_bytes());

        let now = now_unix_seconds();
        write_inode_timestamps(&mut raw, now);
        let generation = alloc_inode_generation();
        write_inode_generation(&mut raw, generation);
        write_inode_extra_isize(&mut raw);
        self.stamp_inode_checksum(&mut raw, ino, generation);
        Ok(raw)
    }

    /// Seed a freshly-allocated dir block with the two canonical entries
    /// `.` (→ new_ino) and `..` (→ parent_ino). Handles the metadata-csum
    /// tail when required: the last 12 bytes are reserved, and the CRC is
    /// computed over everything before them.
    fn seed_directory_block(
        &self,
        new_ino: u32,
        parent_ino: u32,
        new_generation: u32,
    ) -> Result<Vec<u8>> {
        let bs = self.sb.block_size() as usize;
        let mut block = vec![0u8; bs];
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let reserved_tail = if self.csum.enabled { 12 } else { 0 };
        let usable = bs - reserved_tail;

        // "." entry: rec_len = 12
        block[0..4].copy_from_slice(&new_ino.to_le_bytes());
        block[4..6].copy_from_slice(&12u16.to_le_bytes());
        block[6] = 1; // name_len
        block[7] = if has_ft {
            crate::dir::DirEntryType::Directory as u8
        } else {
            0
        };
        block[8] = b'.';

        // ".." entry: rec_len absorbs the rest of the usable region.
        let off = 12;
        block[off..off + 4].copy_from_slice(&parent_ino.to_le_bytes());
        let rec_len = (usable - off) as u16;
        block[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
        block[off + 6] = 2;
        block[off + 7] = if has_ft {
            crate::dir::DirEntryType::Directory as u8
        } else {
            0
        };
        block[off + 8] = b'.';
        block[off + 9] = b'.';

        // Tail (when metadata_csum enabled): fake inode=0, rec_len=12,
        // name_len=0, file_type=0xDE, u32 checksum.
        if reserved_tail == 12 {
            let tail = bs - 12;
            block[tail..tail + 4].copy_from_slice(&0u32.to_le_bytes()); // inode=0
            block[tail + 4..tail + 6].copy_from_slice(&12u16.to_le_bytes()); // rec_len
            block[tail + 6] = 0; // name_len
            block[tail + 7] = 0xDE; // file_type marker
                                    // CRC32C over [0 .. bs - 12] salted by ino + gen.
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &new_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &new_generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..bs - 12]);
            block[bs - 4..bs].copy_from_slice(&c.to_le_bytes());
        }

        Ok(block)
    }

    /// Adjust `i_links_count` on a raw inode image. Recomputes CSUM.
    fn patch_inode_nlink(&self, ino: u32, raw: &mut [u8], inode: &Inode, delta: i32) -> Result<()> {
        let new_count = (inode.links_count as i32 + delta).max(0) as u16;
        raw[0x1A..0x1C].copy_from_slice(&new_count.to_le_bytes());
        if self.csum.enabled {
            if let Some((lo, hi)) = self.csum.compute_inode_checksum(ino, inode.generation, raw) {
                raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if raw.len() >= 0x84 {
                    raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    /// Create a subdirectory at `path` with POSIX mode bits (low 12 bits of
    /// `mode`). Returns the new directory's inode number. Steps: allocate
    /// inode (Orlov-hinted) → allocate one data block → seed it with `.` / `..`
    /// → build dir inode → write inode + data block → add dir entry in parent
    /// → bump parent's `i_links_count` → commit BGD/SB counters.
    ///
    /// Not journaled — safe only in scratch-image contexts until transaction
    /// wrapping lands.
    pub fn apply_mkdir(&self, path: &str, mode: u16) -> Result<u32> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let (parent_path, base_name) = split_parent_and_base(path)?;
        if base_name.len() > 255 {
            return Err(Error::NameTooLong);
        }

        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &parent_path)?;
        let (parent_inode, mut parent_raw) = self.read_inode_verified(parent_ino)?;
        if !parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        if self
            .find_entry_in_dir(&parent_inode, base_name.as_bytes())
            .is_ok()
        {
            return Err(Error::AlreadyExists);
        }

        let bs = self.sb.block_size();
        let parent_group = (parent_ino - 1) / self.sb.inodes_per_group;
        let mut bitmap_reader = |block: u64| self.read_block(block);

        // 1. Allocate inode (is_dir = true so Orlov picks a dir-friendly group).
        let iplan = crate::alloc::plan_inode_allocation(
            &self.sb,
            &self.groups,
            true,
            parent_group,
            &mut bitmap_reader,
        )?;
        let new_ino = iplan.inode;

        // 2. Allocate one data block for the dir contents.
        let bplan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            1,
            iplan.bgd.group_idx,
            &mut bitmap_reader,
        )?;
        let data_block = bplan.first_block;

        // Multi-block transaction: inode bitmap + block bitmap + counters
        // + new dir inode + seeded data block + parent dir entry +
        // parent nlink bump, all atomic.
        let mut buf = BlockBuffer::new(bs);
        self.buffer_mark_inode_used(&mut buf, new_ino)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            iplan.bgd.group_idx as usize,
            iplan.bgd.free_blocks_delta,
            iplan.bgd.free_inodes_delta,
            iplan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            iplan.sb.free_blocks_delta,
            iplan.sb.free_inodes_delta,
        )?;

        self.buffer_mark_block_run_used(&mut buf, data_block, 1)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            bplan.bgd.group_idx as usize,
            bplan.bgd.free_blocks_delta,
            bplan.bgd.free_inodes_delta,
            bplan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            bplan.sb.free_blocks_delta,
            bplan.sb.free_inodes_delta,
        )?;

        let raw = self.build_directory_inode(new_ino, mode, data_block)?;
        let gen = u32::from_le_bytes(raw[0x64..0x68].try_into().unwrap());
        self.buffer_write_inode(&mut buf, new_ino, &raw)?;

        // Seed the data block (`.` and `..` entries) and stage it.
        let seed = self.seed_directory_block(new_ino, parent_ino, gen)?;
        buf.put(data_block, seed);

        // Try to install the dir entry in the parent in-place first.
        let parent_extends = match self.buffer_add_dir_entry_inplace(
            &mut buf,
            parent_ino,
            &parent_inode,
            base_name.as_bytes(),
            new_ino,
            crate::dir::DirEntryType::Directory,
        ) {
            Ok(()) => false,
            Err(Error::OutOfBounds) => true,
            Err(e) => return Err(e),
        };

        if !parent_extends {
            // In-place add succeeded — bump parent's nlink in the same buffer.
            self.patch_inode_nlink(parent_ino, &mut parent_raw, &parent_inode, 1)?;
            self.buffer_write_inode(&mut buf, parent_ino, &parent_raw)?;
            self.commit_block_buffer(buf)?;
        } else {
            // Parent dir is full → commit what we have, then run the
            // un-journaled extend, then commit the parent nlink bump as a
            // small follow-up.
            self.commit_block_buffer(buf)?;
            self.extend_dir_and_add_entry(
                parent_ino,
                base_name.as_bytes(),
                new_ino,
                crate::dir::DirEntryType::Directory,
            )?;
            // Re-read parent (extend rewrote it) before patching nlink.
            let (refreshed_parent, mut refreshed_raw) = self.read_inode_verified(parent_ino)?;
            self.patch_inode_nlink(parent_ino, &mut refreshed_raw, &refreshed_parent, 1)?;
            self.commit_inode_write(parent_ino, &refreshed_raw)?;
        }

        Ok(new_ino)
    }

    /// Create a hard link at `dst` pointing to the same inode as `src`.
    ///
    /// Semantics:
    /// - `src` must exist and must NOT be a directory (POSIX forbids
    ///   directory hardlinks to avoid reference cycles).
    /// - `dst`'s parent must exist and be a directory.
    /// - `dst` must not already exist.
    /// - On success the shared inode's `i_links_count` is incremented by 1.
    ///
    /// Not journaled — same caveat as other Phase-4 ops.
    pub fn apply_link(&self, src: &str, dst: &str) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let (dst_parent_path, dst_name) = split_parent_and_base(dst)?;
        if dst_name.len() > 255 {
            return Err(Error::NameTooLong);
        }

        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let src_ino = crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, src)?;
        let (src_inode, mut src_raw) = self.read_inode_verified(src_ino)?;
        if src_inode.is_dir() {
            // POSIX: hard-linking a directory is forbidden. Map to EISDIR
            // (rather than EPERM) — matches our IsADirectory convention.
            return Err(Error::IsADirectory);
        }

        let dst_parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &dst_parent_path)?;
        let (dst_parent_inode, _) = self.read_inode_verified(dst_parent_ino)?;
        if !dst_parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        if self
            .find_entry_in_dir(&dst_parent_inode, dst_name.as_bytes())
            .is_ok()
        {
            return Err(Error::AlreadyExists);
        }

        let dir_type = match src_inode.file_type() {
            crate::inode::S_IFREG => crate::dir::DirEntryType::RegFile,
            crate::inode::S_IFLNK => crate::dir::DirEntryType::Symlink,
            crate::inode::S_IFCHR => crate::dir::DirEntryType::CharDev,
            crate::inode::S_IFBLK => crate::dir::DirEntryType::BlockDev,
            crate::inode::S_IFIFO => crate::dir::DirEntryType::Fifo,
            crate::inode::S_IFSOCK => crate::dir::DirEntryType::Socket,
            _ => crate::dir::DirEntryType::Unknown,
        };

        // Build the multi-block transaction: bump nlink + add dir entry,
        // both staged into one buffer so a crash either applies both or
        // neither.
        let mut buf = BlockBuffer::new(self.sb.block_size());
        self.patch_inode_nlink(src_ino, &mut src_raw, &src_inode, 1)?;
        self.buffer_write_inode(&mut buf, src_ino, &src_raw)?;

        match self.buffer_add_dir_entry_inplace(
            &mut buf,
            dst_parent_ino,
            &dst_parent_inode,
            dst_name.as_bytes(),
            src_ino,
            dir_type,
        ) {
            Ok(()) => self.commit_block_buffer(buf),
            Err(Error::OutOfBounds) => {
                // Parent dir is full → fall back to the un-journaled extend
                // path. Commit the inode-only buffer first so the nlink bump
                // is atomic w.r.t. itself, then run the legacy extend.
                self.commit_block_buffer(buf)?;
                self.extend_dir_and_add_entry(
                    dst_parent_ino,
                    dst_name.as_bytes(),
                    src_ino,
                    dir_type,
                )
            }
            Err(e) => Err(e),
        }
    }

    /// Rename `src` → `dst` within the same filesystem.
    ///
    /// Semantics:
    /// - Both endpoints are within this mount.
    /// - Works for files and directories.
    /// - Cross-parent moves update the moved dir's `..` entry + bump /
    ///   decrement both parents' `i_links_count`.
    /// - Refuses to move a directory into its own subtree (cycle check).
    /// - Same source and dest: no-op success.
    /// - When dst already exists:
    ///     - `replace_if_exists = false` → returns `Error::AlreadyExists`.
    ///     - `replace_if_exists = true` → atomically overwrites dst.
    ///       Type-compatibility rules (POSIX rename(2)):
    ///         * file→dir   → `Error::IsADirectory`
    ///         * dir→file   → `Error::NotADirectory`
    ///         * non-empty-dir overwrite → `Error::DirectoryNotEmpty`
    ///         * src and dst resolve to the same inode (hardlink) →
    ///           no-op success.
    ///       Otherwise the previous dst inode's link count is decremented
    ///       in the same buffer; if that drops it to zero the inode's
    ///       extents and slot are freed in the same atomic commit.
    pub fn apply_rename(&self, src: &str, dst: &str, replace_if_exists: bool) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        if src == dst {
            return Ok(());
        }

        let (src_parent_path, src_name) = split_parent_and_base(src)?;
        let (dst_parent_path, dst_name) = split_parent_and_base(dst)?;
        if dst_name.len() > 255 {
            return Err(Error::NameTooLong);
        }

        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let src_parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &src_parent_path)?;
        let dst_parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &dst_parent_path)?;
        let (src_parent_inode, _) = self.read_inode_verified(src_parent_ino)?;
        let (dst_parent_inode, _) = self.read_inode_verified(dst_parent_ino)?;
        if !src_parent_inode.is_dir() || !dst_parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }

        let src_ino = self.find_entry_in_dir(&src_parent_inode, src_name.as_bytes())?;
        let existing_dst_ino = self
            .find_entry_in_dir(&dst_parent_inode, dst_name.as_bytes())
            .ok();
        if existing_dst_ino.is_some() && !replace_if_exists {
            return Err(Error::AlreadyExists);
        }

        let (src_inode, _) = self.read_inode_verified(src_ino)?;
        let src_is_dir = src_inode.is_dir();

        // Cycle check: moving a dir INTO itself is illegal. Simple prefix
        // check on normalised paths — rejects rename /a /a/b/c.
        if src_is_dir {
            let src_slash = format!("{}/", src.trim_end_matches('/'));
            if dst == src || dst.starts_with(&src_slash) {
                return Err(Error::InvalidArgument(
                    "rename: cannot move directory into its own subtree",
                ));
            }
        }

        // Map POSIX mode bits to the directory-entry file-type byte.
        let dir_type = match src_inode.file_type() {
            crate::inode::S_IFREG => crate::dir::DirEntryType::RegFile,
            crate::inode::S_IFDIR => crate::dir::DirEntryType::Directory,
            crate::inode::S_IFLNK => crate::dir::DirEntryType::Symlink,
            _ => crate::dir::DirEntryType::Unknown,
        };

        // ===================================================================
        // Replace-overwrite branch — dst already exists and caller opted in.
        // ===================================================================
        if let Some(dst_old_ino) = existing_dst_ino {
            // Hardlink case: src and dst already share an inode. POSIX
            // rename(2) requires this to be a no-op success — entry count
            // is unchanged, and removing src would unconditionally drop the
            // shared link count by one which is wrong.
            if dst_old_ino == src_ino {
                return Ok(());
            }

            let (dst_old_inode, mut dst_old_raw) = self.read_inode_verified(dst_old_ino)?;
            let dst_is_dir = dst_old_inode.is_dir();

            // Type compatibility — rename(2) forbids crossing the
            // file/directory boundary.
            if !src_is_dir && dst_is_dir {
                return Err(Error::IsADirectory);
            }
            if src_is_dir && !dst_is_dir {
                return Err(Error::NotADirectory);
            }

            // Non-empty-dir overwrite is forbidden by POSIX. Walk every
            // block of dst and reject any entry that isn't `.` / `..`.
            if dst_is_dir {
                let bs = self.sb.block_size();
                let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
                let blocks = dst_old_inode.size.div_ceil(bs as u64);
                for logical in 0..blocks {
                    let Some(phys) = crate::extent::map_logical(
                        &dst_old_inode.block,
                        self.dev.as_ref(),
                        bs,
                        logical,
                    )?
                    else {
                        continue;
                    };
                    let block = self.read_block(phys)?;
                    for entry in crate::dir::DirBlockIter::new(&block, has_ft) {
                        let e = entry?;
                        if e.name != b"." && e.name != b".." {
                            return Err(Error::DirectoryNotEmpty);
                        }
                    }
                }
            }

            // Stage the whole overwrite into a single buffer so a crash
            // either fully replaces dst or leaves the FS in its prior
            // state.
            let mut buf = BlockBuffer::new(self.sb.block_size());

            // 1. Pop the existing dst entry from dst_parent so the
            //    in-place add below has somewhere to land.
            self.buffer_remove_dir_entry(
                &mut buf,
                dst_parent_ino,
                &dst_parent_inode,
                dst_name.as_bytes(),
            )?;

            // 2. Add the new dst entry pointing at src_ino. Try in-place
            //    first; if no block has room, mirror the dst_extends
            //    fall-back from the non-replace path.
            let dst_extends = match self.buffer_add_dir_entry_inplace(
                &mut buf,
                dst_parent_ino,
                &dst_parent_inode,
                dst_name.as_bytes(),
                src_ino,
                dir_type,
            ) {
                Ok(()) => false,
                Err(Error::OutOfBounds) => true,
                Err(e) => return Err(e),
            };
            if dst_extends {
                // Commit removal (and any prior in-buffer mutations) so
                // the un-journaled extend doesn't race with replays.
                self.commit_block_buffer(buf)?;
                self.extend_dir_and_add_entry(
                    dst_parent_ino,
                    dst_name.as_bytes(),
                    src_ino,
                    dir_type,
                )?;
                buf = BlockBuffer::new(self.sb.block_size());
            }

            // 3. Remove src entry from its parent.
            self.buffer_remove_dir_entry(
                &mut buf,
                src_parent_ino,
                &src_parent_inode,
                src_name.as_bytes(),
            )?;

            // 4. Cross-parent dir move: fix `..` + parent nlinks.
            //    For dir-replaces-dir the dst_parent gains the moved
            //    subdir but loses the dropped subdir → net zero. The
            //    -1 for the dropped subdir is applied below in the reap
            //    branch; suppress the +1 here when we'd otherwise apply
            //    both.
            if src_is_dir && src_parent_ino != dst_parent_ino {
                self.buffer_update_dotdot(&mut buf, src_ino, &src_inode, dst_parent_ino)?;

                // Source parent loses one subdir → -1 nlink.
                let (sp_inode, mut sp_raw) = self.read_inode_verified(src_parent_ino)?;
                self.patch_inode_nlink(src_parent_ino, &mut sp_raw, &sp_inode, -1)?;
                self.buffer_write_inode(&mut buf, src_parent_ino, &sp_raw)?;

                // Dest parent: only bump if NOT replacing a dir (which
                // would offset the bump). With dir-replaces-dir the
                // dropped subdir's -1 happens below, balancing the +1.
                if !dst_is_dir {
                    let (dp_inode, mut dp_raw) = self.read_inode_verified(dst_parent_ino)?;
                    self.patch_inode_nlink(dst_parent_ino, &mut dp_raw, &dp_inode, 1)?;
                    self.buffer_write_inode(&mut buf, dst_parent_ino, &dp_raw)?;
                }
            }

            // 5. Decrement dst_old_ino's link count. If it hits zero,
            //    free its data extents + inode slot in this same buffer.
            //    Directories always reap (they only ever have one external
            //    name in our v1 — directory hardlinks aren't supported).
            let new_links = dst_old_inode.links_count.saturating_sub(1);
            if new_links > 0 && !dst_is_dir {
                // Hardlinked file overwrite — just persist the new count.
                dst_old_raw[0x1A..0x1C].copy_from_slice(&new_links.to_le_bytes());
                self.finalize_inode_raw(dst_old_ino, dst_old_inode.generation, &mut dst_old_raw)?;
                self.buffer_write_inode(&mut buf, dst_old_ino, &dst_old_raw)?;
            } else {
                let bs = self.sb.block_size();
                let sectors_per_block = bs as u64 / 512;
                let mut freed_sectors: u64 = 0;
                if dst_old_inode.has_extents() && dst_old_inode.size > 0 {
                    if dst_is_dir {
                        // Directory data blocks aren't tracked through
                        // plan_truncate_shrink (that path expects regular
                        // files); use extent::collect_all + free per run.
                        let extents = crate::extent::collect_all(
                            &dst_old_inode.block,
                            self.dev.as_ref(),
                            bs,
                        )?;
                        for e in &extents {
                            self.buffer_free_block_run_and_bgd(
                                &mut buf,
                                e.physical_block,
                                e.length as u64,
                            )?;
                            freed_sectors += e.length as u64 * sectors_per_block;
                        }
                    } else {
                        let (_sc, muts) = crate::file_mut::plan_truncate_shrink(
                            dst_old_inode.size,
                            0,
                            &dst_old_inode.block,
                            bs,
                        )?;
                        for m in &muts {
                            if let crate::extent_mut::ExtentMutation::FreePhysicalRun {
                                start,
                                len,
                            } = m
                            {
                                self.buffer_free_block_run_and_bgd(&mut buf, *start, *len as u64)?;
                                freed_sectors += *len as u64 * sectors_per_block;
                            }
                        }
                    }
                }

                self.buffer_free_inode_slot(&mut buf, dst_old_ino)?;
                if dst_is_dir {
                    // Reaped a directory → bg_used_dirs_count -= 1.
                    let dst_old_gi = ((dst_old_ino - 1) / self.sb.inodes_per_group) as usize;
                    self.buffer_patch_bgd_counters(&mut buf, dst_old_gi, 0, 0, -1)?;
                }
                let freed_blocks = freed_sectors.checked_div(sectors_per_block).unwrap_or(0);
                self.buffer_patch_sb_counters(&mut buf, freed_blocks as i64, 1)?;

                // Zero the inode body, set dtime = now, preserve generation.
                let inode_size = self.sb.inode_size as usize;
                let old_gen = dst_old_inode.generation;
                for b in &mut dst_old_raw[..inode_size] {
                    *b = 0;
                }
                let dtime = now_unix_seconds();
                dst_old_raw[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
                dst_old_raw[0x64..0x68].copy_from_slice(&old_gen.to_le_bytes());
                self.finalize_inode_raw(dst_old_ino, old_gen, &mut dst_old_raw)?;
                self.buffer_write_inode(&mut buf, dst_old_ino, &dst_old_raw)?;

                // Dir-replaces-dir: dst_parent loses the removed subdir's
                // `..` reference → -1 nlink. Skipped for the cross-parent
                // dir move (the +1 above was already suppressed, so the
                // two deltas cancel without further work).
                if dst_is_dir && !(src_is_dir && src_parent_ino != dst_parent_ino) {
                    let (dp_inode, mut dp_raw) = self.read_inode_verified(dst_parent_ino)?;
                    self.patch_inode_nlink(dst_parent_ino, &mut dp_raw, &dp_inode, -1)?;
                    self.buffer_write_inode(&mut buf, dst_parent_ino, &dp_raw)?;
                }
            }

            return self.commit_block_buffer(buf);
        }

        // ===================================================================
        // No-overwrite path — dst doesn't exist. Mirrors the v1 behaviour.
        // ===================================================================
        // Multi-block transaction: insert dst entry + remove src entry +
        // (cross-parent dir) update .. + adjust parent nlinks. Atomic so
        // a crash either fully renames or leaves the original.
        let mut buf = BlockBuffer::new(self.sb.block_size());

        let dst_extends = match self.buffer_add_dir_entry_inplace(
            &mut buf,
            dst_parent_ino,
            &dst_parent_inode,
            dst_name.as_bytes(),
            src_ino,
            dir_type,
        ) {
            Ok(()) => false,
            Err(Error::OutOfBounds) => true,
            Err(e) => return Err(e),
        };

        if dst_extends {
            // Dest parent full → fall back to the un-journaled extend.
            // Commit any partial state first to avoid mixing journaled
            // and un-journaled writes that race.
            self.commit_block_buffer(buf)?;
            self.extend_dir_and_add_entry(dst_parent_ino, dst_name.as_bytes(), src_ino, dir_type)?;
            // Now the source removal + .. + nlink adjustments in a
            // fresh buffer.
            buf = BlockBuffer::new(self.sb.block_size());
        }

        self.buffer_remove_dir_entry(
            &mut buf,
            src_parent_ino,
            &src_parent_inode,
            src_name.as_bytes(),
        )?;

        if src_is_dir && src_parent_ino != dst_parent_ino {
            self.buffer_update_dotdot(&mut buf, src_ino, &src_inode, dst_parent_ino)?;

            // Source parent loses one subdir → -1 nlink.
            let (sp_inode, mut sp_raw) = self.read_inode_verified(src_parent_ino)?;
            self.patch_inode_nlink(src_parent_ino, &mut sp_raw, &sp_inode, -1)?;
            self.buffer_write_inode(&mut buf, src_parent_ino, &sp_raw)?;

            // Dest parent gains one → +1. Re-read in case extend
            // rewrote it above.
            let (dp_inode, mut dp_raw) = self.read_inode_verified(dst_parent_ino)?;
            self.patch_inode_nlink(dst_parent_ino, &mut dp_raw, &dp_inode, 1)?;
            self.buffer_write_inode(&mut buf, dst_parent_ino, &dp_raw)?;
        }

        self.commit_block_buffer(buf)
    }

    /// Insert `name → target_ino` into `parent_inode`'s linear directory
    /// blocks. Picks the first block with space; errors if the directory
    /// has no room (dir-extension is a follow-up). Recomputes the block's
    /// tail checksum when metadata_csum is on.
    fn add_dir_entry(
        &self,
        parent_ino: u32,
        parent_inode: &Inode,
        name: &[u8],
        target_ino: u32,
        file_type: crate::dir::DirEntryType,
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let n_blocks = parent_inode.size.div_ceil(bs as u64);
        for logical in 0..n_blocks {
            let Some(phys) =
                crate::extent::map_logical(&parent_inode.block, self.dev.as_ref(), bs, logical)?
            else {
                continue;
            };
            let mut block = self.read_block(phys)?;
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(&block) {
                12
            } else {
                0
            };
            match crate::dir::add_entry_to_block(
                &mut block,
                target_ino,
                name,
                file_type,
                has_ft,
                reserved_tail,
            ) {
                Ok(()) => {
                    if self.csum.enabled && reserved_tail == 12 {
                        let end = block.len();
                        let mut c = crate::checksum::linux_crc32c(
                            self.csum.seed,
                            &parent_ino.to_le_bytes(),
                        );
                        c = crate::checksum::linux_crc32c(
                            c,
                            &parent_inode.generation.to_le_bytes(),
                        );
                        c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                        block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                    }
                    self.dev.write_at(phys * bs as u64, &block)?;
                    return Ok(());
                }
                Err(Error::OutOfBounds) => continue,
                Err(e) => return Err(e),
            }
        }
        // All existing blocks are full → grow the directory by one fs block.
        self.extend_dir_and_add_entry(parent_ino, name, target_ino, file_type)
    }

    /// Grow `parent_ino`'s directory file by one fs block, seed that block
    /// with the entry `(name → target_ino)`, and update the parent inode
    /// image (size +block_size, +1 extent, recomputed CSUM). Assumes the
    /// parent's inline extent root still has a free slot (the common case
    /// until htree promotion lands).
    /// Mark a freshly-allocated single block used and apply its BGD + SB
    /// free-count deltas in one cache-coherent transaction. Routes through
    /// `buffer_mark_block_run_used`, which refreshes the block-bitmap
    /// checksum — the bare `mark_block_run_used` + `patch_*_counters` sequence
    /// the directory-grow path used to run left that csum stale, so e2fsck
    /// reported "block bitmap does not match checksum" once a directory grew a
    /// block (and on 1 KiB images, where dirs grow at far fewer entries).
    fn commit_dir_block_alloc(
        &self,
        phys: u64,
        plan: &crate::alloc::BlockAllocationPlan,
    ) -> Result<()> {
        let mut buf = BlockBuffer::new(self.sb.block_size());
        self.buffer_mark_block_run_used(&mut buf, phys, 1)?;
        self.buffer_patch_bgd_counters(
            &mut buf,
            plan.bgd.group_idx as usize,
            plan.bgd.free_blocks_delta,
            plan.bgd.free_inodes_delta,
            plan.bgd.used_dirs_delta,
        )?;
        self.buffer_patch_sb_counters(
            &mut buf,
            plan.sb.free_blocks_delta,
            plan.sb.free_inodes_delta,
        )?;
        self.commit_block_buffer(buf)
    }

    fn extend_dir_and_add_entry(
        &self,
        parent_ino: u32,
        name: &[u8],
        target_ino: u32,
        file_type: crate::dir::DirEntryType,
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let bs_u64 = bs as u64;
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;

        // Re-read parent so we operate on the freshest on-disk bytes.
        let (parent_inode, mut parent_raw) = self.read_inode_verified(parent_ino)?;
        if !parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        let new_logical_block = parent_inode.size.div_ceil(bs_u64);

        // 1. Allocate one fs block. Hint to parent's group.
        let parent_group = (parent_ino - 1) / self.sb.inodes_per_group;
        let mut bitmap_reader = |block: u64| self.read_block(block);
        let plan = crate::alloc::plan_block_allocation(
            &self.sb,
            &self.groups,
            1,
            parent_group,
            &mut bitmap_reader,
        )?;
        let new_phys = plan.first_block;

        // 2. Insert extent into parent's inline extent root. If the root is
        //    saturated at depth 0, promote to depth 1 by allocating a fresh
        //    leaf block, moving all entries into it, and writing a single
        //    index entry into the inline root.
        let new_extent = crate::extent::Extent {
            logical_block: new_logical_block as u32,
            length: 1,
            physical_block: new_phys,
            uninitialized: false,
        };
        // If the parent root is already promoted (depth ≥ 1), operate on the
        // leaf block directly instead of the 60-byte inline root. This keeps
        // the inode.block area unchanged; only the leaf-node physical block
        // gets rewritten.
        let root_header = crate::extent::ExtentHeader::parse(&parent_inode.block)?;
        if root_header.depth == 1 {
            return self.extend_dir_and_add_entry_depth1(
                parent_ino,
                &parent_inode,
                &mut parent_raw,
                name,
                target_ino,
                file_type,
                has_ft,
                new_phys,
                new_extent,
                plan,
            );
        }
        if root_header.depth > 1 {
            return self.extend_dir_and_add_entry_deep(
                parent_ino,
                &parent_inode,
                &mut parent_raw,
                name,
                target_ino,
                file_type,
                has_ft,
                new_phys,
                new_extent,
                plan,
            );
        }

        let (new_root, leaf_meta_alloc) =
            match crate::extent_mut::plan_insert_extent(&parent_inode.block, new_extent) {
                Ok(muts) => {
                    let root = muts
                        .into_iter()
                        .find_map(|m| match m {
                            crate::extent_mut::ExtentMutation::WriteRoot { bytes } => Some(bytes),
                            _ => None,
                        })
                        .ok_or(Error::Corrupt(
                            "extend_dir_and_add_entry: plan produced no WriteRoot",
                        ))?;
                    (root, None)
                }
                Err(Error::CorruptExtentTree(msg)) if msg.contains("LEAF_FULL_NEEDS_PROMOTION") => {
                    // Commit the data-block allocation NOW so the next plan picks
                    // a different run (plan_block_allocation reads the bitmap).
                    self.commit_dir_block_alloc(new_phys, &plan)?;

                    // Second allocation: the leaf node block.
                    let mut reader2 = |block: u64| -> Result<Vec<u8>> {
                        let mut buf = vec![0u8; bs as usize];
                        self.dev.read_at(block * bs_u64, &mut buf)?;
                        Ok(buf)
                    };
                    let meta_plan = crate::alloc::plan_block_allocation(
                        &self.sb,
                        &self.groups,
                        1,
                        parent_group,
                        &mut reader2,
                    )?;
                    let leaf_meta_phys = meta_plan.first_block;

                    let promo = crate::extent_mut::plan_promote_leaf(
                        &parent_inode.block,
                        new_extent,
                        bs as usize,
                        leaf_meta_phys,
                        self.csum.enabled,
                    )?;
                    let mut leaf = promo.leaf_bytes;
                    if self.csum.enabled {
                        self.csum
                            .patch_extent_tail(parent_ino, parent_inode.generation, &mut leaf);
                    }
                    self.dev.write_at(leaf_meta_phys * bs_u64, &leaf)?;
                    (promo.new_root_bytes, Some(meta_plan))
                }
                Err(e) => return Err(e),
            };
        Self::patch_inode_block_area(&mut parent_raw, &new_root)?;

        // 3. Patch size (+= block_size) and i_blocks. On the promotion path
        //    the inode claims both the data block AND the leaf-node block.
        let blocks_consumed: u64 = 1 + if leaf_meta_alloc.is_some() { 1 } else { 0 };
        let new_size = parent_inode.size + bs_u64;
        let new_blocks = parent_inode.blocks + (bs_u64 / 512) * blocks_consumed;
        Self::patch_inode_size_and_blocks(&mut parent_raw, new_size, new_blocks)?;

        // 4. Recompute parent inode CSUM and write it back.
        if self.csum.enabled {
            if let Some((lo, hi)) =
                self.csum
                    .compute_inode_checksum(parent_ino, parent_inode.generation, &parent_raw)
            {
                parent_raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if parent_raw.len() >= 0x84 {
                    parent_raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        self.write_inode_raw(parent_ino, &parent_raw)?;

        // 5. Seed the new data block with a "whole-block unused" placeholder
        //    that add_entry_to_block can split into (new entry + remainder).
        let reserved_tail = if self.csum.enabled { 12 } else { 0 };
        let usable = (bs as usize) - reserved_tail;
        let mut block = vec![0u8; bs as usize];
        block[0..4].copy_from_slice(&0u32.to_le_bytes());
        block[4..6].copy_from_slice(&(usable as u16).to_le_bytes());

        crate::dir::add_entry_to_block(
            &mut block,
            target_ino,
            name,
            file_type,
            has_ft,
            reserved_tail,
        )?;

        if self.csum.enabled && reserved_tail == 12 {
            let end = block.len();
            block[end - 12..end - 8].copy_from_slice(&0u32.to_le_bytes());
            block[end - 8..end - 6].copy_from_slice(&12u16.to_le_bytes());
            block[end - 6] = 0;
            block[end - 5] = 0xDE;
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
            block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        }
        self.dev.write_at(new_phys * bs_u64, &block)?;

        // 6. Commit block allocator side-effects. On the promotion path the
        //    data-block allocation was already committed above; here we only
        //    commit the leaf-node allocation. On the simple path we commit the
        //    data block as usual.
        if let Some(meta_plan) = leaf_meta_alloc {
            self.commit_dir_block_alloc(meta_plan.first_block, &meta_plan)?;
        } else {
            self.commit_dir_block_alloc(new_phys, &plan)?;
        }

        Ok(())
    }

    /// Grow a directory whose extent tree is already at depth ≥ 2.
    /// Uses `plan_insert_extent_deep` to navigate and split the tree,
    /// allocating index-node blocks on demand via `plan_block_allocation`.
    /// The pre-allocated data block `new_phys` is committed first so the
    /// alloc closure won't re-use it for tree-meta blocks.
    #[allow(clippy::too_many_arguments)]
    fn extend_dir_and_add_entry_deep(
        &self,
        parent_ino: u32,
        parent_inode: &Inode,
        parent_raw: &mut [u8],
        name: &[u8],
        target_ino: u32,
        file_type: crate::dir::DirEntryType,
        has_ft: bool,
        new_phys: u64,
        new_extent: crate::extent::Extent,
        data_plan: crate::alloc::BlockAllocationPlan,
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let bs_u64 = bs as u64;
        let parent_group = (parent_ino - 1) / self.sb.inodes_per_group;

        // Collect all allocation plans without committing them yet.  Committing
        // eagerly (old behaviour) leaked blocks permanently when
        // plan_insert_extent_deep or the subsequent writes failed — the bitmap
        // was marked used but no extent ever referenced those blocks.  Instead,
        // we gather all plans and commit them only after every write succeeds,
        // matching the late-commit ordering of extend_dir_and_add_entry_depth1.
        //
        // To prevent alloc_fn from picking data_plan.first_block for a meta
        // node (which plan_block_allocation could do since the bitmap is
        // unchanged), the closure skips that block and retries once.
        let data_block = data_plan.first_block;
        let mut pending_meta: Vec<crate::alloc::BlockAllocationPlan> = Vec::new();

        let reader = FsBlockReader { fs: self };
        let mut meta_block_count: u64 = 0;
        let mut alloc_fn = || -> Result<u64> {
            let mut bm_reader = |block: u64| -> Result<Vec<u8>> {
                let mut buf = vec![0u8; bs as usize];
                self.dev.read_at(block * bs_u64, &mut buf)?;
                Ok(buf)
            };
            let meta_plan = crate::alloc::plan_block_allocation(
                &self.sb,
                &self.groups,
                1,
                parent_group,
                &mut bm_reader,
            )?;
            if meta_plan.first_block == data_block {
                // The allocator returned the same block we reserved for the
                // data page.  There are no other free blocks in this group,
                // so the tree cannot grow further.
                return Err(Error::NoSpaceLeftOnDevice);
            }
            meta_block_count += 1;
            pending_meta.push(meta_plan);
            Ok(pending_meta.last().unwrap().first_block)
        };

        let deep_plan = crate::extent_mut::plan_insert_extent_deep(
            &parent_inode.block,
            new_extent,
            bs,
            &reader,
            &mut alloc_fn,
        )?;

        // Write tree-meta blocks (rewritten leaves + any new index nodes).
        for (block, mut bytes) in deep_plan.block_writes {
            if self.csum.enabled {
                self.csum
                    .patch_extent_tail(parent_ino, parent_inode.generation, &mut bytes);
            }
            self.dev.write_at(block * bs_u64, &bytes)?;
        }

        // Patch inode: root bytes, size (+1 data block), i_blocks.
        Self::patch_inode_block_area(parent_raw, &deep_plan.new_root)?;
        let new_size = parent_inode.size + bs_u64;
        let new_blocks = parent_inode.blocks + (bs_u64 / 512) * (1 + meta_block_count);
        Self::patch_inode_size_and_blocks(parent_raw, new_size, new_blocks)?;
        if self.csum.enabled {
            if let Some((lo, hi)) =
                self.csum
                    .compute_inode_checksum(parent_ino, parent_inode.generation, parent_raw)
            {
                parent_raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if parent_raw.len() >= 0x84 {
                    parent_raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        self.write_inode_raw(parent_ino, parent_raw)?;

        // Seed + write the new data block with the directory entry.
        let reserved_tail = if self.csum.enabled { 12 } else { 0 };
        let usable = (bs as usize) - reserved_tail;
        let mut block = vec![0u8; bs as usize];
        block[0..4].copy_from_slice(&0u32.to_le_bytes());
        block[4..6].copy_from_slice(&(usable as u16).to_le_bytes());
        crate::dir::add_entry_to_block(
            &mut block,
            target_ino,
            name,
            file_type,
            has_ft,
            reserved_tail,
        )?;
        if self.csum.enabled && reserved_tail == 12 {
            let end = block.len();
            block[end - 12..end - 8].copy_from_slice(&0u32.to_le_bytes());
            block[end - 8..end - 6].copy_from_slice(&12u16.to_le_bytes());
            block[end - 6] = 0;
            block[end - 5] = 0xDE;
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
            block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        }
        self.dev.write_at(new_phys * bs_u64, &block)?;

        // All writes succeeded — now commit the allocation accounting. Route
        // through commit_dir_block_alloc so the block-bitmap checksum is
        // refreshed together with the BGD + SB free-count deltas (the bare
        // mark_block_run_used + patch_*_counters sequence left the csum stale).
        self.commit_dir_block_alloc(data_plan.first_block, &data_plan)?;
        for plan in pending_meta {
            self.commit_dir_block_alloc(plan.first_block, &plan)?;
        }

        Ok(())
    }

    /// Grow a directory whose extent tree is already at depth 1 (i.e. has
    /// been promoted). The inline root holds a single index entry → one leaf
    /// block. The mutation happens entirely inside the leaf block; the inode
    /// root is unchanged.
    ///
    /// Leaf overflow (>340 entries in a 4 KiB block with csum) returns a
    /// clean error. Callers that hit this should retry via `extend_dir_and_add_entry_deep`.
    #[allow(clippy::too_many_arguments)]
    fn extend_dir_and_add_entry_depth1(
        &self,
        parent_ino: u32,
        parent_inode: &Inode,
        parent_raw: &mut [u8],
        name: &[u8],
        target_ino: u32,
        file_type: crate::dir::DirEntryType,
        has_ft: bool,
        new_phys: u64,
        new_extent: crate::extent::Extent,
        plan: crate::alloc::BlockAllocationPlan,
    ) -> Result<()> {
        let bs = self.sb.block_size();
        let bs_u64 = bs as u64;

        // Resolve the single index entry in the 60-byte inline root.
        let idx = crate::extent::ExtentIdx::parse(
            &parent_inode.block
                [crate::extent::EXT4_EXT_NODE_SIZE..2 * crate::extent::EXT4_EXT_NODE_SIZE],
        )?;
        let leaf_phys = idx.leaf_block;

        // Read the leaf block + run plan_insert_extent on its 4 KiB buffer.
        // `plan_insert_extent` operates on any depth-0 root — it uses
        // `header.max` for capacity, which was set to (bs-12-4)/12 = 340
        // when the leaf was built by `plan_promote_leaf`.
        let mut leaf = vec![0u8; bs as usize];
        self.dev.read_at(leaf_phys * bs_u64, &mut leaf)?;
        // CRC-verify before mutating — if the leaf's tail is corrupt we'd
        // write a false "fixed" version back.
        if self.csum.enabled
            && !self
                .csum
                .verify_extent_tail(parent_ino, parent_inode.generation, &leaf)
        {
            return Err(Error::BadChecksum {
                what: "extent block",
            });
        }

        let muts = match crate::extent_mut::plan_insert_extent(&leaf, new_extent) {
            Ok(muts) => muts,
            Err(Error::CorruptExtentTree(msg)) if msg.contains("LEAF_FULL_NEEDS_PROMOTION") => {
                // The single depth-1 leaf is full (≥340 extents in a 4 KiB block
                // with csum). Fall back to the deep path, which handles adding a
                // sibling leaf or promoting to depth 2. The data block hasn't
                // been committed yet, so pass `plan` unchanged.
                return self.extend_dir_and_add_entry_deep(
                    parent_ino,
                    parent_inode,
                    parent_raw,
                    name,
                    target_ino,
                    file_type,
                    has_ft,
                    new_phys,
                    new_extent,
                    plan,
                );
            }
            Err(e) => return Err(e),
        };
        let new_leaf = muts
            .into_iter()
            .find_map(|m| match m {
                crate::extent_mut::ExtentMutation::WriteRoot { bytes } => Some(bytes),
                _ => None,
            })
            .ok_or(Error::Corrupt(
                "extend_dir_and_add_entry_depth1: plan produced no WriteRoot",
            ))?;
        let mut new_leaf = new_leaf;
        if self.csum.enabled {
            self.csum
                .patch_extent_tail(parent_ino, parent_inode.generation, &mut new_leaf);
        }
        self.dev.write_at(leaf_phys * bs_u64, &new_leaf)?;

        // Inode root is unchanged — just grow size + blocks by one data block.
        let new_size = parent_inode.size + bs_u64;
        let new_blocks = parent_inode.blocks + (bs_u64 / 512);
        Self::patch_inode_size_and_blocks(parent_raw, new_size, new_blocks)?;
        if self.csum.enabled {
            if let Some((lo, hi)) =
                self.csum
                    .compute_inode_checksum(parent_ino, parent_inode.generation, parent_raw)
            {
                parent_raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                if parent_raw.len() >= 0x84 {
                    parent_raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                }
            }
        }
        self.write_inode_raw(parent_ino, parent_raw)?;

        // Seed + write the new data block (same recipe as the depth-0 path).
        let reserved_tail = if self.csum.enabled { 12 } else { 0 };
        let usable = (bs as usize) - reserved_tail;
        let mut block = vec![0u8; bs as usize];
        block[0..4].copy_from_slice(&0u32.to_le_bytes());
        block[4..6].copy_from_slice(&(usable as u16).to_le_bytes());

        crate::dir::add_entry_to_block(
            &mut block,
            target_ino,
            name,
            file_type,
            has_ft,
            reserved_tail,
        )?;

        if self.csum.enabled && reserved_tail == 12 {
            let end = block.len();
            block[end - 12..end - 8].copy_from_slice(&0u32.to_le_bytes());
            block[end - 8..end - 6].copy_from_slice(&12u16.to_le_bytes());
            block[end - 6] = 0;
            block[end - 5] = 0xDE;
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
            block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        }
        self.dev.write_at(new_phys * bs_u64, &block)?;

        // Commit data-block allocation.
        self.commit_dir_block_alloc(new_phys, &plan)?;

        Ok(())
    }

    /// Remove `name` from `parent_inode`'s linear directory blocks. Errors
    /// if the name isn't found in any block.
    fn remove_dir_entry(&self, parent_ino: u32, parent_inode: &Inode, name: &[u8]) -> Result<()> {
        let bs = self.sb.block_size();
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let n_blocks = parent_inode.size.div_ceil(bs as u64);
        for logical in 0..n_blocks {
            let Some(phys) =
                crate::extent::map_logical(&parent_inode.block, self.dev.as_ref(), bs, logical)?
            else {
                continue;
            };
            let mut block = self.read_block(phys)?;
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(&block) {
                12
            } else {
                0
            };
            if crate::dir::remove_entry_from_block(&mut block, name, has_ft, reserved_tail)? {
                if self.csum.enabled && reserved_tail == 12 {
                    let end = block.len();
                    let mut c =
                        crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                    block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                }
                self.dev.write_at(phys * bs as u64, &block)?;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Point a directory's `..` entry at `new_parent_ino`. The `..` entry
    /// lives in the directory's first data block, immediately after the `.`
    /// entry at byte offset 12. Recomputes the block's tail checksum when
    /// metadata_csum is on — the tail csum is keyed on this directory's own
    /// ino + generation, hence both are required.
    fn update_dotdot(&self, dir_ino: u32, dir_inode: &Inode, new_parent_ino: u32) -> Result<()> {
        let bs = self.sb.block_size();
        let phys = crate::extent::map_logical(&dir_inode.block, self.dev.as_ref(), bs, 0)?
            .ok_or(Error::Corrupt("update_dotdot: dir block 0 missing"))?;
        let mut block = self.read_block(phys)?;
        if block.len() < 24 {
            return Err(Error::Corrupt("update_dotdot: dir block too small"));
        }
        block[12..16].copy_from_slice(&new_parent_ino.to_le_bytes());

        if self.csum.enabled && crate::dir::has_csum_tail(&block) {
            let end = block.len();
            let mut c = crate::checksum::linux_crc32c(self.csum.seed, &dir_ino.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &dir_inode.generation.to_le_bytes());
            c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
            block[end - 4..end].copy_from_slice(&c.to_le_bytes());
        }
        self.dev.write_at(phys * bs as u64, &block)?;
        Ok(())
    }

    /// Remove an empty directory at `path`. Requires the target to contain
    /// only `.` and `..`. Frees the data block(s) + inode, removes the
    /// entry from the parent, decrements parent's `i_links_count`.
    pub fn apply_rmdir(&self, path: &str) -> Result<()> {
        if !self.dev.is_writable() {
            return Err(Error::ReadOnly);
        }
        let (parent_path, base_name) = split_parent_and_base(path)?;
        let mut reader = |ino: u32| self.read_inode_verified(ino).map(|(i, _)| i);
        let parent_ino =
            crate::path::lookup(self.dev.as_ref(), &self.sb, &mut reader, &parent_path)?;
        let (parent_inode, mut parent_raw) = self.read_inode_verified(parent_ino)?;
        if !parent_inode.is_dir() {
            return Err(Error::NotADirectory);
        }
        let target_ino = self.find_entry_in_dir(&parent_inode, base_name.as_bytes())?;
        let (target_inode, _) = self.read_inode_verified(target_ino)?;
        if !target_inode.is_dir() {
            return Err(Error::NotADirectory);
        }

        // Empty-check: walk every block, reject if any entry is not "." or "..".
        let bs = self.sb.block_size();
        let has_ft = self.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
        let blocks = target_inode.size.div_ceil(bs as u64);
        for logical in 0..blocks {
            let Some(phys) =
                crate::extent::map_logical(&target_inode.block, self.dev.as_ref(), bs, logical)?
            else {
                continue;
            };
            let block = self.read_block(phys)?;
            for entry in crate::dir::DirBlockIter::new(&block, has_ft) {
                let e = entry?;
                if e.name != b"." && e.name != b".." {
                    return Err(Error::DirectoryNotEmpty);
                }
            }
        }

        // Multi-block transaction: free target data blocks + free inode +
        // remove parent's dir entry + decrement parent nlink, all atomic.
        let mut buf = BlockBuffer::new(bs);

        // Free target's data blocks. Each freed run credits its own group's
        // BGD; SB credit accumulates and lands once below.
        let extents = crate::extent::collect_all(&target_inode.block, self.dev.as_ref(), bs)?;
        let mut freed_blocks: u64 = 0;
        for e in &extents {
            freed_blocks +=
                self.buffer_free_block_run_and_bgd(&mut buf, e.physical_block, e.length as u64)?;
        }

        // Free the inode slot. A removed dir decrements `bg_used_dirs_count`
        // — buffer_free_inode_slot already credits free_inodes by +1, so we
        // separately patch used_dirs by -1 here.
        self.buffer_free_inode_slot(&mut buf, target_ino)?;
        let target_gi = ((target_ino - 1) / self.sb.inodes_per_group) as usize;
        self.buffer_patch_bgd_counters(&mut buf, target_gi, 0, 0, -1)?;
        // SB: free_blocks_count += freed, free_inodes_count += 1.
        self.buffer_patch_sb_counters(&mut buf, freed_blocks as i64, 1)?;

        // Zero the freed directory inode body (mode/links -> 0, set dtime, keep
        // the generation) so the slot no longer reads as a live directory.
        // Without this the freed inode keeps S_IFDIR + its "." / ".." and
        // e2fsck reports "unconnected directory inode", a stale ".." and bad
        // refcounts — the same cleanup apply_unlink already does for files.
        let inode_size = self.sb.inode_size as usize;
        let mut target_raw = vec![0u8; inode_size];
        let dtime = now_unix_seconds();
        target_raw[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        target_raw[0x64..0x68].copy_from_slice(&target_inode.generation.to_le_bytes());
        self.finalize_inode_raw(target_ino, target_inode.generation, &mut target_raw)?;
        self.buffer_write_inode(&mut buf, target_ino, &target_raw)?;

        // Remove the entry from the parent directory.
        let parent_blocks = parent_inode.size.div_ceil(bs as u64);
        let mut removed = false;
        for logical in 0..parent_blocks {
            let Some(phys) = self.map_inode_logical(&parent_inode, logical)? else {
                continue;
            };
            let block = buf.get_mut(self, phys)?;
            let reserved_tail = if self.csum.enabled && crate::dir::has_csum_tail(block) {
                12
            } else {
                0
            };
            if crate::dir::remove_entry_from_block(
                block,
                base_name.as_bytes(),
                has_ft,
                reserved_tail,
            )? {
                if self.csum.enabled && reserved_tail == 12 {
                    let end = block.len();
                    let mut c =
                        crate::checksum::linux_crc32c(self.csum.seed, &parent_ino.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                    block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                }
                removed = true;
                break;
            }
        }
        if !removed {
            return Err(Error::Corrupt(
                "apply_rmdir: entry disappeared mid-operation",
            ));
        }

        // Parent loses the ".." reference from the removed child → nlink -1.
        self.patch_inode_nlink(parent_ino, &mut parent_raw, &parent_inode, -1)?;
        self.buffer_write_inode(&mut buf, parent_ino, &parent_raw)?;

        self.commit_block_buffer(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::{
        EXTRA_ISIZE_DEFAULT, INODE_SIZE_WITH_CRTIME, INODE_SIZE_WITH_EXTRA, OFF_ATIME, OFF_CRTIME,
        OFF_CTIME, OFF_EXTRA_ISIZE, OFF_GENERATION, OFF_MTIME,
    };

    fn read_le32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn read_le16(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }

    // --- write_inode_timestamps ---

    #[test]
    fn write_inode_timestamps_sets_atime_ctime_mtime() {
        let mut raw = vec![0u8; 256];
        write_inode_timestamps(&mut raw, 0xDEAD_BEEF);
        assert_eq!(read_le32(&raw, OFF_ATIME), 0xDEAD_BEEF);
        assert_eq!(read_le32(&raw, OFF_CTIME), 0xDEAD_BEEF);
        assert_eq!(read_le32(&raw, OFF_MTIME), 0xDEAD_BEEF);
    }

    #[test]
    fn write_inode_timestamps_sets_crtime_when_large_enough() {
        let mut raw = vec![0u8; INODE_SIZE_WITH_CRTIME + 4];
        write_inode_timestamps(&mut raw, 0x1234_5678);
        assert_eq!(read_le32(&raw, OFF_CRTIME), 0x1234_5678);
    }

    #[test]
    fn write_inode_timestamps_skips_crtime_when_too_small() {
        let mut raw = vec![0xAAu8; INODE_SIZE_WITH_CRTIME - 1];
        write_inode_timestamps(&mut raw, 0x1234_5678);
        // Buffer too small for crtime — no write, no panic.
        // atime/ctime/mtime still set.
        assert_eq!(read_le32(&raw, OFF_ATIME), 0x1234_5678);
    }

    #[test]
    fn write_inode_timestamps_zero_now() {
        let mut raw = vec![0xFFu8; 256];
        write_inode_timestamps(&mut raw, 0);
        assert_eq!(read_le32(&raw, OFF_ATIME), 0);
        assert_eq!(read_le32(&raw, OFF_CTIME), 0);
        assert_eq!(read_le32(&raw, OFF_MTIME), 0);
        assert_eq!(read_le32(&raw, OFF_CRTIME), 0);
    }

    // --- write_inode_generation ---

    #[test]
    fn write_inode_generation_writes_at_correct_offset() {
        let mut raw = vec![0u8; 256];
        write_inode_generation(&mut raw, 0xCAFE_BABE);
        assert_eq!(read_le32(&raw, OFF_GENERATION), 0xCAFE_BABE);
    }

    #[test]
    fn write_inode_generation_overwrites_existing() {
        let mut raw = vec![0xFFu8; 256];
        write_inode_generation(&mut raw, 0);
        assert_eq!(read_le32(&raw, OFF_GENERATION), 0);
    }

    // --- write_inode_extra_isize ---

    #[test]
    fn write_inode_extra_isize_sets_default_when_large_enough() {
        let mut raw = vec![0u8; INODE_SIZE_WITH_EXTRA + 4];
        write_inode_extra_isize(&mut raw);
        assert_eq!(read_le16(&raw, OFF_EXTRA_ISIZE), EXTRA_ISIZE_DEFAULT);
    }

    #[test]
    fn write_inode_extra_isize_skips_when_too_small() {
        let mut raw = vec![0u8; INODE_SIZE_WITH_EXTRA - 1];
        write_inode_extra_isize(&mut raw); // must not panic
                                           // No bytes should have been written — buffer too small.
    }

    // --- alloc_inode_generation ---

    #[test]
    fn alloc_inode_generation_produces_unique_values() {
        let g1 = alloc_inode_generation();
        let g2 = alloc_inode_generation();
        assert_ne!(g1, g2, "successive calls must produce distinct values");
    }
}
